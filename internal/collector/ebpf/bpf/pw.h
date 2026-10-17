/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Wire format between the eBPF programs and the Go collector.
 *
 * All integers are little endian (the object is built for bpfel and used on
 * amd64 and arm64). Every fixed part is a multiple of 8 bytes. The Go side
 * mirrors these layouts in wire.go; TestWireContract compares both through the
 * BTF of the embedded object, so a change here without a change there fails the
 * test.
 *
 * Time: every *_ns value is CLOCK_BOOTTIME nanoseconds (includes suspend).
 * Identity of a process instance: (tgid, start_ns) where start_ns is
 * task->group_leader->start_boottime, the same kernel field in every record.
 */
#ifndef __PW_H
#define __PW_H

#include "vmlinux_min.h"

enum pw_event_type {
	PW_EV_FORK = 1,
	PW_EV_EXEC = 2,
	PW_EV_EXIT = 3,
};

/* Index into the per-CPU pw_stats array. Counters never depend on a ring
 * buffer record being delivered. */
enum pw_stat {
	PW_STAT_LOST_FORK = 0,   /* ring buffer full: fork record lost */
	PW_STAT_LOST_EXEC,       /* ring buffer full / scratch missing: exec lost */
	PW_STAT_LOST_EXIT,       /* ring buffer full: exit record lost */
	PW_STAT_FORK,            /* records submitted */
	PW_STAT_EXEC,
	PW_STAT_EXIT,
	PW_STAT_THREAD_CLONE,    /* CLONE_THREAD forks skipped (not processes) */
	PW_STAT_KTHREAD,         /* kernel thread forks/exits skipped */
	PW_STAT_THREAD_EXIT,     /* exits of non-final threads skipped */
	PW_STAT_LIVE_OOR,        /* live table index beyond cfg_live_size */
	PW_STAT_SCRATCH,         /* per-CPU scratch lookup failed */
	PW_STAT_ARGS_ERR,        /* reading argv from user memory failed */
	PW_STAT_PATH_ERR,        /* image path could not be built */
	PW_STAT_MAX,
};

/* pw_exec.flags and pw_snap.flags */
#define PW_F_IMAGE_TRUNC    (1u << 0)  /* image name longer than the buffer */
#define PW_F_FILENAME_TRUNC (1u << 1)  /* requested exec filename cut */
#define PW_F_PATH_TRUNC     (1u << 2)  /* path cut: only a suffix is present */
#define PW_F_PATH_DELETED   (1u << 3)  /* executable file was unlinked */
#define PW_F_PATH_ERR       (1u << 4)  /* walk failed: path_len is 0 */
#define PW_F_ARGS_CAPTURED  (1u << 5)  /* argument capture was enabled */
#define PW_F_ARGS_TRUNC     (1u << 6)  /* args_len capped at PW_ARGS_MAX */
#define PW_F_ARGS_ERR       (1u << 7)  /* reading user memory failed */
#define PW_F_FROM_THREAD    (1u << 8)  /* exec called by a non-leader thread */
#define PW_F_IMAGE_ERR      (1u << 9)  /* image name could not be read */
#define PW_F_NO_MM          (1u << 10) /* snapshot: leader without mm */
#define PW_F_FILENAME_ERR   (1u << 11) /* requested filename unreadable */

#define PW_NAME_MAX        255   /* NAME_MAX: longest dentry name */
#define PW_FILENAME_MAX    256   /* requested exec filename incl. NUL */
#define PW_PATH_OUT_MAX    1024  /* longest image path put into a record */
#define PW_PATH_TMP        2048  /* path build buffer (power of two) */
#define PW_PATH_DEPTH      32    /* dentry/mount hops walked at most */
#define PW_ARGS_MAX        4096  /* raw argument bytes captured per exec */

struct pw_hdr {
	__u32 type;     /* enum pw_event_type */
	__u32 size;     /* payload bytes of the whole record, header included */
	__u64 ktime_ns; /* bpf_ktime_get_boot_ns() when the record was built */
};

/* A new process (not a thread) was created. parent_* identify the creating
 * process (the thread group of the forking thread), also for CLONE_PARENT. */
struct pw_fork {
	struct pw_hdr h;
	__u64 parent_start_ns;
	__u64 child_start_ns;
	__u32 parent_tgid;
	__u32 parent_tid;   /* creating thread */
	__u32 child_tgid;
	__u32 uid;
	__u32 euid;
	__u32 gid;
	char comm[16];      /* inherited comm */
};

/* The last thread of a process exited. status is a wait(2) style status:
 * (code << 8) for exit(), signal number | 0x80 (core) for fatal signals. */
struct pw_exit {
	struct pw_hdr h;
	__u64 start_ns;
	__u32 tgid;
	__u32 tid;          /* exiting (last) thread */
	__s32 status;
	__u32 flags;
};

/* A successful execve/execveat. Followed by variable data in this order:
 * image[image_len] filename[filename_len] parent_image[parent_image_len]
 * path[path_len] args[args_len] (no terminators). */
struct pw_exec {
	struct pw_hdr h;
	__u64 start_ns;
	__u64 parent_start_ns;  /* real_parent at exec time */
	__u32 tgid;
	__u32 tid_before;       /* thread that called exec (old_pid) */
	__u32 uid;
	__u32 euid;
	__u32 gid;
	__u32 parent_tgid;
	__u32 flags;
	__u32 argc;
	char comm[16];
	char parent_comm[16];
	__u16 image_len;
	__u16 filename_len;
	__u16 parent_image_len;
	__u16 path_len;
	__u32 args_len;
	__u32 reserved;
};

/* One living process, written by the iterator through bpf_seq_write. Followed
 * by image[image_len] path[path_len]. */
struct pw_snap {
	__u32 size;
	__u32 flags;
	__u64 visit_ns;         /* when the iterator looked at this task */
	__u64 start_ns;
	__u64 parent_start_ns;  /* real_parent at visit time */
	__u32 tgid;
	__u32 parent_tgid;
	__u32 uid;
	__u32 euid;
	__u32 gid;
	__u32 live_threads;
	char comm[16];
	__u16 image_len;
	__u16 path_len;
	__u32 reserved;
};

_Static_assert(sizeof(struct pw_hdr) == 16, "pw_hdr");
_Static_assert(sizeof(struct pw_fork) == 72, "pw_fork");
_Static_assert(sizeof(struct pw_exit) == 40, "pw_exit");
_Static_assert(sizeof(struct pw_exec) == 112, "pw_exec");
_Static_assert(sizeof(struct pw_snap) == 80, "pw_snap");

#endif /* __PW_H */
