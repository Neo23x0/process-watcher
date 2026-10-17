// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * process-watcher eBPF collector.
 *
 * Emits minimal system wide fork/exec/exit records through one ring buffer (one
 * buffer keeps causally related records in order across CPUs) and provides a
 * task iterator that dumps the living processes with the same identity fields.
 * The process graph and all filtering are done in Go: the kernel side never
 * decides which processes are interesting.
 */
#include "vmlinux_min.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"
#include "pw.h"

char LICENSE[] SEC("license") = "GPL";

/* Set by the loader before the programs are loaded. */
const volatile __u32 cfg_capture_args = 0; /* capture argv for every exec */
const volatile __u32 cfg_live_table = 0;   /* maintain pw_live (kill verification) */
const volatile __u32 cfg_live_size = 0;    /* entries of pw_live == pid_max */

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); /* resized by the loader (ring_buffer_mb) */
} pw_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, PW_STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} pw_stats SEC(".maps");

/*
 * tgid -> start_boottime of the process that currently owns this tgid, 0 when
 * none. Maintained by the fork/exit hooks and the iterator so that userspace can
 * verify the exact kernel start time of a pid in O(1) before signalling it.
 * Sized to pid_max by the loader, and only when the kill feature is enabled.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} pw_live SEC(".maps");

struct pw_pathbuf {
	char buf[PW_PATH_TMP + 256];
};

#define PW_OFF_MASK 0xfffu /* off never exceeds PW_PATH_TMP; see pw_file_path */

#define PW_EXEC_DATA_MASK 0x1fffu
struct pw_exec_scratch {
	struct pw_exec e;
	char data[(PW_EXEC_DATA_MASK + 1) + PW_ARGS_MAX];
};

#define PW_SNAP_DATA_MASK 0x7ffu /* image (<=255) + path (<=1024) fit below it */
struct pw_snap_scratch {
	struct pw_snap s;
	char data[(PW_SNAP_DATA_MASK + 1) + PW_PATH_OUT_MAX];
};

#define PW_PERCPU_SCRATCH(name, vtype)                      \
	struct {                                            \
		__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);    \
		__uint(max_entries, 1);                     \
		__type(key, __u32);                         \
		__type(value, vtype);                       \
	} name SEC(".maps")

PW_PERCPU_SCRATCH(pw_exec_scratch_map, struct pw_exec_scratch);
PW_PERCPU_SCRATCH(pw_exec_path_map, struct pw_pathbuf);
PW_PERCPU_SCRATCH(pw_snap_scratch_map, struct pw_snap_scratch);
PW_PERCPU_SCRATCH(pw_snap_path_map, struct pw_pathbuf);

/* Anchors that force the wire types into the object's BTF for the contract test. */
const struct pw_hdr *pw_anchor_hdr __attribute__((unused));
const struct pw_fork *pw_anchor_fork __attribute__((unused));
const struct pw_exit *pw_anchor_exit __attribute__((unused));
const struct pw_exec *pw_anchor_exec __attribute__((unused));
const struct pw_snap *pw_anchor_snap __attribute__((unused));
const enum pw_stat *pw_anchor_stat __attribute__((unused));
const enum pw_event_type *pw_anchor_type __attribute__((unused));

static __always_inline void pw_count(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&pw_stats, &idx);

	if (v)
		*v += 1;
}

static __always_inline void pw_live_set(__u32 tgid, __u64 start)
{
	if (!cfg_live_table)
		return;
	if (tgid >= cfg_live_size) {
		pw_count(PW_STAT_LIVE_OOR);
		return;
	}
	bpf_map_update_elem(&pw_live, &tgid, &start, BPF_ANY);
}

/* Identity of a process: the start time of its thread group leader. */
static __always_inline __u64 pw_start_ns(struct task_struct *t)
{
	return BPF_CORE_READ(t, group_leader, start_boottime);
}

/*
 * Offsets and lengths that end up in pointer arithmetic or helper sizes.
 *
 * The verifier of Linux 5.15 cannot correlate "len > 255" with a later
 * "len < 255" (the compiler turns the clamp into two compares). It explores the
 * impossible combination, carries a contradictory range (umin > umax) from
 * there, and a pointer plus such a scalar becomes an unknown scalar, which the
 * helper call rejects ("R1 type=inv"). Masking is not enough: the known bits
 * of the contradictory range survive an AND. A volatile 32 bit store and load
 * makes the verifier forget everything it knew about the value (narrow spills
 * are not tracked there), and the AND then gives it a plain [0, mask] on
 * every path. At run time this is a store and a load of 4 bytes.
 */
static __always_inline __u32 pw_bound(__u32 v, __u32 mask)
{
	volatile __u32 slot = v;

	return slot & mask;
}

/* Address inside a scratch buffer at a variable offset. */
static __always_inline char *pw_at(char *base, __u32 off, __u32 mask)
{
	return base + pw_bound(off, mask);
}

/* container_of(vfsmnt, struct mount, mnt) with a CO-RE offset. */
static __always_inline struct mount *pw_real_mount(struct vfsmount *m)
{
	return (struct mount *)((char *)m - bpf_core_field_offset(((struct mount *)0)->mnt));
}

/* Copy the basename of d (the real file name, not argv[0]) to dst. */
static __always_inline __u32 pw_dentry_name(struct dentry *d, char *dst, __u32 *flags)
{
	__u32 len = BPF_CORE_READ(d, d_name.len);
	const unsigned char *name = BPF_CORE_READ(d, d_name.name);

	if (len > PW_NAME_MAX) {
		len = PW_NAME_MAX;
		*flags |= PW_F_IMAGE_TRUNC;
		barrier_var(len); /* keeps this a branch: see pw_bound */
	}
	len = pw_bound(len, PW_NAME_MAX);
	if (bpf_probe_read_kernel(dst, len, name) < 0) {
		*flags |= PW_F_IMAGE_ERR;
		return 0;
	}
	return len;
}

/* Result of pw_path_walk: path length in bits 0..15, PW_F_* flags from bit 16 up. */
#define PW_PATH_FLAGS_SHIFT 16

/*
 * Build the absolute path of file backwards into the end of pb->buf: the path
 * starts at pb->buf[PW_PATH_TMP - length]. Mirrors the kernel's prepend_path():
 * prepend d_name, follow d_parent and hop over mount points up to the
 * namespace root. The path is relative to the root of the process' mount
 * namespace. A cut path keeps its tail and sets PW_F_PATH_TRUNC. The length is
 * at most PW_PATH_OUT_MAX; it is 0 with PW_F_PATH_ERR when the walk failed.
 *
 * This is a global function on purpose: the verifier checks the body of a
 * global function once, independent of the callers. Inlined, Linux 5.15 checks
 * the whole unrolled walk again for every distinct state the caller arrives
 * with, which multiplied its cost by up to 14 in the exec program.
 */
__attribute__((noinline)) __u32 pw_path_walk(__u64 file_addr, struct pw_pathbuf *pb)
{
	struct file *file = (struct file *)file_addr;
	struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
	struct vfsmount *vfsmnt = BPF_CORE_READ(file, f_path.mnt);
	struct mount *mnt;
	struct dentry *mnt_root;
	__u32 off = PW_PATH_TMP;
	__u32 flags = 0;
	__u32 plen;
	int complete = 0;

	if (!pb || !dentry || !vfsmnt)
		return PW_F_PATH_ERR << PW_PATH_FLAGS_SHIFT;
	mnt = pw_real_mount(vfsmnt);
	mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);

	/* An unhashed dentry that is not the root of its mount is what
	 * /proc/<pid>/exe reports as " (deleted)": unlinked files and anonymous
	 * pseudo files such as memfd (which are their own d_parent, so the kernel's
	 * d_unlinked() alone would miss them). */
	if (!BPF_CORE_READ(dentry, d_hash.pprev) && dentry != mnt_root)
		flags |= PW_F_PATH_DELETED;

#pragma unroll
	for (int i = 0; i < PW_PATH_DEPTH; i++) {
		struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
		__u32 len;
		const unsigned char *name;

		if (dentry == mnt_root) {
			struct mount *up = BPF_CORE_READ(mnt, mnt_parent);

			if (mnt == up) {
				complete = 1; /* namespace root */
				break;
			}
			dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
			mnt = up;
			mnt_root = BPF_CORE_READ(mnt, mnt.mnt_root);
			continue;
		}

		len = BPF_CORE_READ(dentry, d_name.len);
		name = BPF_CORE_READ(dentry, d_name.name);
		if (len > PW_NAME_MAX) /* longer than NAME_MAX: not a file name */
			return (flags | PW_F_PATH_ERR) << PW_PATH_FLAGS_SHIFT;
		len = pw_bound(len, PW_NAME_MAX);
		/* off and len have the same range at every iteration, which lets the
		 * verifier prune equivalent states. */
		off = pw_bound(off, PW_OFF_MASK);
		if (off < len + 1)
			break;
		off = pw_bound(off - (len + 1), PW_OFF_MASK);
		*pw_at(pb->buf, off, PW_PATH_TMP - 1) = '/';
		if (bpf_probe_read_kernel(pw_at(pb->buf, off + 1, PW_PATH_TMP - 1), len, name) < 0)
			return (flags | PW_F_PATH_ERR) << PW_PATH_FLAGS_SHIFT;

		if (dentry == parent) {
			complete = 1; /* anonymous root dentry (e.g. memfd): name is the path */
			break;
		}
		dentry = parent;
	}

	if (!complete)
		flags |= PW_F_PATH_TRUNC;
	plen = pw_bound(PW_PATH_TMP - pw_bound(off, PW_OFF_MASK), PW_OFF_MASK);
	if (plen == 0) {
		pb->buf[PW_PATH_TMP - 1] = '/';
		plen = 1;
	}
	if (plen > PW_PATH_OUT_MAX) {
		plen = PW_PATH_OUT_MAX;
		flags |= PW_F_PATH_TRUNC;
		barrier_var(plen);
	}
	return pw_bound(plen, 0x7ffu) | (flags << PW_PATH_FLAGS_SHIFT);
}

/* Absolute path of file at dst; returns its length (0 on failure, with PW_F_PATH_ERR). */
static __always_inline __u32 pw_file_path(struct file *file, struct pw_pathbuf *pb,
					  char *dst, __u32 *flags)
{
	__u32 r = pw_path_walk((__u64)file, pb);
	__u32 plen = pw_bound(r & 0xffffu, 0x7ffu); /* <= PW_PATH_OUT_MAX */

	*flags |= r >> PW_PATH_FLAGS_SHIFT;
	if (!plen)
		return 0;
	if (bpf_probe_read_kernel(dst, plen, pw_at(pb->buf, PW_PATH_TMP - plen, PW_PATH_TMP - 1)) < 0) {
		*flags |= PW_F_PATH_ERR;
		return 0;
	}
	return plen;
}

/*
 * A new process was created. CLONE_THREAD clones share the tgid and are not
 * processes; kernel threads are of no interest. The creating process is the
 * thread group of 'parent' even for CLONE_PARENT.
 */
SEC("tp_btf/sched_process_fork")
int BPF_PROG(pw_sched_process_fork, struct task_struct *parent, struct task_struct *child)
{
	__u32 child_tgid = BPF_CORE_READ(child, tgid);
	__u32 parent_tgid = BPF_CORE_READ(parent, tgid);
	__u64 child_start;
	struct pw_fork *e;

	if (child_tgid == parent_tgid) {
		pw_count(PW_STAT_THREAD_CLONE);
		return 0;
	}
	if (BPF_CORE_READ(child, flags) & PF_KTHREAD) {
		pw_count(PW_STAT_KTHREAD);
		return 0;
	}

	child_start = pw_start_ns(child);
	/* Publish the identity before the record so a reader that has seen the
	 * record also finds the live table entry. */
	pw_live_set(child_tgid, child_start);

	e = bpf_ringbuf_reserve(&pw_events, sizeof(*e), 0);
	if (!e) {
		pw_count(PW_STAT_LOST_FORK);
		return 0;
	}
	e->h.type = PW_EV_FORK;
	e->h.size = sizeof(*e);
	e->h.ktime_ns = bpf_ktime_get_boot_ns();
	e->parent_start_ns = pw_start_ns(parent);
	e->child_start_ns = child_start;
	e->parent_tgid = parent_tgid;
	e->parent_tid = BPF_CORE_READ(parent, pid);
	e->child_tgid = child_tgid;
	e->uid = BPF_CORE_READ(child, cred, uid.val);
	e->euid = BPF_CORE_READ(child, cred, euid.val);
	e->gid = BPF_CORE_READ(child, cred, gid.val);
	bpf_core_read(&e->comm, sizeof(e->comm), &child->comm);
	bpf_ringbuf_submit(e, 0);
	pw_count(PW_STAT_FORK);
	return 0;
}

/*
 * A thread exited. Only the final thread of a process produces a record: the
 * tracepoint runs after signal->live was decremented, so live == 0 identifies
 * the last one regardless of which thread it is.
 */
SEC("tp_btf/sched_process_exit")
int BPF_PROG(pw_sched_process_exit, struct task_struct *p)
{
	struct signal_struct *sig = BPF_CORE_READ(p, signal);
	struct task_struct *leader;
	struct pw_exit *e;
	__u32 tgid;
	__u64 start;
	int status;

	if (BPF_CORE_READ(p, flags) & PF_KTHREAD) {
		pw_count(PW_STAT_KTHREAD);
		return 0;
	}
	if (BPF_CORE_READ(sig, live.counter) != 0) {
		pw_count(PW_STAT_THREAD_EXIT);
		return 0;
	}

	leader = BPF_CORE_READ(p, group_leader);
	tgid = BPF_CORE_READ(p, tgid);
	start = BPF_CORE_READ(leader, start_boottime);

	/* What wait(2) will report: the group exit code during exit_group and
	 * fatal signals, else the leader's own exit code. */
	if (BPF_CORE_READ(sig, flags) & SIGNAL_GROUP_EXIT)
		status = BPF_CORE_READ(sig, group_exit_code);
	else if (leader == p)
		status = BPF_CORE_READ(p, exit_code);
	else
		status = BPF_CORE_READ(leader, exit_code);

	pw_live_set(tgid, 0);

	e = bpf_ringbuf_reserve(&pw_events, sizeof(*e), 0);
	if (!e) {
		pw_count(PW_STAT_LOST_EXIT);
		return 0;
	}
	e->h.type = PW_EV_EXIT;
	e->h.size = sizeof(*e);
	e->h.ktime_ns = bpf_ktime_get_boot_ns();
	e->start_ns = start;
	e->tgid = tgid;
	e->tid = BPF_CORE_READ(p, pid);
	e->status = status;
	e->flags = 0;
	bpf_ringbuf_submit(e, 0);
	pw_count(PW_STAT_EXIT);
	return 0;
}

/*
 * A successful execve/execveat (the tracepoint is not reached when the exec
 * fails). The executed file is bprm->file: for scripts that is the interpreter,
 * and its dentry name is the real file name even when the call went through a
 * symlink. The requested filename is kept separately.
 */
SEC("tp_btf/sched_process_exec")
int BPF_PROG(pw_sched_process_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	__u32 zero = 0;
	struct pw_exec_scratch *s = bpf_map_lookup_elem(&pw_exec_scratch_map, &zero);
	struct pw_pathbuf *pb = bpf_map_lookup_elem(&pw_exec_path_map, &zero);
	struct task_struct *rp;
	struct file *file;
	struct dentry *dentry;
	struct pw_exec *e;
	const char *filename;
	__u32 flags = 0;
	__u32 off = 0;
	__u32 tgid;
	long n;

	if (!s || !pb) {
		pw_count(PW_STAT_SCRATCH);
		pw_count(PW_STAT_LOST_EXEC);
		return 0;
	}
	e = &s->e;

	tgid = BPF_CORE_READ(p, tgid);
	rp = BPF_CORE_READ(p, real_parent);
	file = BPF_CORE_READ(bprm, file);
	dentry = BPF_CORE_READ(file, f_path.dentry);

	e->h.type = PW_EV_EXEC;
	e->h.ktime_ns = bpf_ktime_get_boot_ns();
	e->start_ns = pw_start_ns(p);
	e->tgid = tgid;
	e->tid_before = old_pid;
	if ((__u32)old_pid != tgid)
		flags |= PW_F_FROM_THREAD;
	e->uid = BPF_CORE_READ(p, cred, uid.val);
	e->euid = BPF_CORE_READ(p, cred, euid.val);
	e->gid = BPF_CORE_READ(p, cred, gid.val);
	e->parent_tgid = BPF_CORE_READ(rp, tgid);
	e->parent_start_ns = pw_start_ns(rp);
	bpf_core_read(&e->comm, sizeof(e->comm), &p->comm);
	bpf_core_read(&e->parent_comm, sizeof(e->parent_comm), &rp->comm);
	e->argc = 0;
	e->args_len = 0;
	e->reserved = 0;

	/* image: basename of the executed file */
	e->image_len = 0;
	if (dentry) {
		__u32 len = pw_dentry_name(dentry, pw_at(s->data, off, PW_EXEC_DATA_MASK), &flags);

		e->image_len = len;
		off = pw_bound(off + len, PW_EXEC_DATA_MASK);
	} else {
		flags |= PW_F_IMAGE_ERR;
	}

	/* requested exec filename (script name, relative path, /dev/fd/N/...) */
	e->filename_len = 0;
	filename = BPF_CORE_READ(bprm, filename);
	n = bpf_probe_read_kernel_str(pw_at(s->data, off, PW_EXEC_DATA_MASK), PW_FILENAME_MAX, filename);
	if (n > 0) {
		if (n == PW_FILENAME_MAX)
			flags |= PW_F_FILENAME_TRUNC;
		e->filename_len = n - 1;
		off = pw_bound(off + n - 1, PW_EXEC_DATA_MASK);
	} else {
		flags |= PW_F_FILENAME_ERR;
	}

	/* real parent's image (who started this process) */
	e->parent_image_len = 0;
	{
		struct mm_struct *pmm = BPF_CORE_READ(rp, mm);
		struct file *pexe = BPF_CORE_READ(pmm, exe_file);
		struct dentry *pd = BPF_CORE_READ(pexe, f_path.dentry);

		if (pd) {
			__u32 pflags = 0;
			__u32 len = pw_dentry_name(pd, pw_at(s->data, off, PW_EXEC_DATA_MASK), &pflags);

			e->parent_image_len = len;
			off = pw_bound(off + len, PW_EXEC_DATA_MASK);
		}
	}

	/* absolute path of the executed file */
	e->path_len = 0;
	{
		__u32 pflags = 0;
		__u32 len = pw_file_path(file, pb, pw_at(s->data, off, PW_EXEC_DATA_MASK), &pflags);

		flags |= pflags;
		if (pflags & PW_F_PATH_ERR)
			pw_count(PW_STAT_PATH_ERR);
		e->path_len = len;
		off = pw_bound(off + len, PW_EXEC_DATA_MASK);
	}

	/* raw argv bytes: NUL separated, split and limited to 32 arguments in Go */
	if (cfg_capture_args) {
		struct mm_struct *mm = BPF_CORE_READ(p, mm);
		unsigned long as = BPF_CORE_READ(mm, arg_start);
		unsigned long ae = BPF_CORE_READ(mm, arg_end);
		__u32 cnt = 0;

		flags |= PW_F_ARGS_CAPTURED;
		e->argc = BPF_CORE_READ(bprm, argc);
		if (ae > as) {
			unsigned long d = ae - as;

			if (d > PW_ARGS_MAX) {
				cnt = PW_ARGS_MAX;
				flags |= PW_F_ARGS_TRUNC;
			} else {
				cnt = d;
			}
		}
		cnt = pw_bound(cnt, 0x1fffu); /* PW_ARGS_MAX <= 0x1fff */
		if (cnt) {
			if (bpf_probe_read_user(pw_at(s->data, off, PW_EXEC_DATA_MASK), cnt, (const void *)as) == 0) {
				e->args_len = cnt;
				off = pw_bound(off + cnt, PW_EXEC_DATA_MASK);
			} else {
				flags |= PW_F_ARGS_ERR;
				pw_count(PW_STAT_ARGS_ERR);
			}
		}
	}

	e->flags = flags;
	off = pw_bound(off, PW_EXEC_DATA_MASK);
	e->h.size = sizeof(*e) + off;
	if (bpf_ringbuf_output(&pw_events, e, sizeof(*e) + off, 0))
		pw_count(PW_STAT_LOST_EXEC);
	else
		pw_count(PW_STAT_EXEC);
	return 0;
}

/*
 * Snapshot: one record per living user space process (thread group leaders
 * only). Zombies without any live thread and kernel threads are skipped. The
 * identity fields are read exactly like in the hooks above.
 */
SEC("iter/task")
int pw_dump_task(struct bpf_iter__task *ctx)
{
	struct task_struct *task = ctx->task;
	struct signal_struct *sig;
	struct task_struct *rp;
	struct mm_struct *mm;
	struct pw_snap_scratch *s;
	struct pw_pathbuf *pb;
	__u32 zero = 0;
	__u32 flags = 0;
	__u32 off = 0;
	__u32 tgid;
	__u64 start;
	int live;

	if (!task)
		return 0;
	if (BPF_CORE_READ(task, group_leader) != task)
		return 0;
	if (BPF_CORE_READ(task, flags) & PF_KTHREAD)
		return 0;
	sig = BPF_CORE_READ(task, signal);
	live = BPF_CORE_READ(sig, live.counter);
	if (live <= 0)
		return 0;

	s = bpf_map_lookup_elem(&pw_snap_scratch_map, &zero);
	pb = bpf_map_lookup_elem(&pw_snap_path_map, &zero);
	if (!s || !pb) {
		pw_count(PW_STAT_SCRATCH);
		return 0;
	}

	tgid = BPF_CORE_READ(task, tgid);
	start = BPF_CORE_READ(task, start_boottime);
	rp = BPF_CORE_READ(task, real_parent);
	mm = BPF_CORE_READ(task, mm);

	s->s.visit_ns = bpf_ktime_get_boot_ns();
	s->s.start_ns = start;
	s->s.parent_start_ns = pw_start_ns(rp);
	s->s.tgid = tgid;
	s->s.parent_tgid = BPF_CORE_READ(rp, tgid);
	s->s.uid = BPF_CORE_READ(task, cred, uid.val);
	s->s.euid = BPF_CORE_READ(task, cred, euid.val);
	s->s.gid = BPF_CORE_READ(task, cred, gid.val);
	s->s.live_threads = live;
	bpf_core_read(&s->s.comm, sizeof(s->s.comm), &task->comm);
	s->s.image_len = 0;
	s->s.path_len = 0;
	s->s.reserved = 0;

	pw_live_set(tgid, start);
	/* The last thread can exit between the liveness check above and this
	 * store. Its exit hook has already cleared the entry then, and the stale
	 * identity must not survive that: signal->live is decremented before the
	 * exit hook runs, so reading it after the store is enough. */
	if (BPF_CORE_READ(sig, live.counter) <= 0)
		pw_live_set(tgid, 0);

	if (!mm) {
		flags |= PW_F_NO_MM;
	} else {
		struct file *exe = BPF_CORE_READ(mm, exe_file);
		struct dentry *d = BPF_CORE_READ(exe, f_path.dentry);

		if (d) {
			__u32 len = pw_dentry_name(d, pw_at(s->data, off, PW_SNAP_DATA_MASK), &flags);

			s->s.image_len = len;
			off = pw_bound(off + len, PW_SNAP_DATA_MASK);
			len = pw_file_path(exe, pb, pw_at(s->data, off, PW_SNAP_DATA_MASK), &flags);
			s->s.path_len = len;
			off = pw_bound(off + len, PW_SNAP_DATA_MASK);
		} else {
			flags |= PW_F_IMAGE_ERR;
		}
	}

	s->s.flags = flags;
	off = pw_bound(off, PW_SNAP_DATA_MASK);
	s->s.size = sizeof(s->s) + off;
	bpf_seq_write(ctx->meta->seq, &s->s, sizeof(s->s) + off);
	return 0;
}
