/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Minimal, hand written subset of the kernel types used by the collector.
 *
 * Only the members that are actually read are declared. Every record is marked
 * preserve_access_index, so all member accesses become CO-RE relocations that
 * libbpf/cilium resolve by name against the BTF of the running kernel. Member
 * order and the omitted members therefore do not matter; anonymous unions and
 * structs must nest like in the kernel (see struct qstr).
 *
 * Hermetic on purpose: no kernel headers and no generated vmlinux.h are needed
 * to rebuild the objects.
 */
#ifndef __PW_VMLINUX_MIN_H
#define __PW_VMLINUX_MIN_H

typedef unsigned char __u8;
typedef short int __s16;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;
typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;
typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;
typedef __u16 __sum16;
typedef int pid_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;
typedef _Bool bool;

enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC = 0,
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_RINGBUF = 27,
};

enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST = 2,
};

/* include/linux/sched.h */
#define PF_KTHREAD 0x00200000
/* include/linux/sched/signal.h */
#define SIGNAL_GROUP_EXIT 0x00000004

#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)

typedef struct {
	int counter;
} atomic_t;

typedef struct {
	uid_t val;
} kuid_t;

typedef struct {
	gid_t val;
} kgid_t;

struct qstr {
	union {
		struct {
			u32 hash;
			u32 len;
		};
		u64 hash_len;
	};
	const unsigned char *name;
};

struct hlist_bl_node {
	struct hlist_bl_node *next, **pprev;
};

struct dentry {
	struct hlist_bl_node d_hash;
	struct dentry *d_parent;
	struct qstr d_name;
};

struct vfsmount {
	struct dentry *mnt_root;
};

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};

struct file {
	struct path f_path;
};

struct mount {
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
};

struct mm_struct {
	unsigned long arg_start;
	unsigned long arg_end;
	struct file *exe_file;
};

struct cred {
	kuid_t uid;
	kgid_t gid;
	kuid_t euid;
};

struct signal_struct {
	atomic_t live;
	unsigned int flags;
	int group_exit_code;
};

struct task_struct {
	unsigned int flags;
	struct mm_struct *mm;
	int exit_code;
	pid_t pid;
	pid_t tgid;
	struct task_struct *real_parent;
	struct task_struct *group_leader;
	u64 start_boottime;
	const struct cred *cred;
	char comm[16];
	struct signal_struct *signal;
};

struct linux_binprm {
	struct file *file;
	int argc;
	const char *filename;
};

struct seq_file;

struct bpf_iter_meta {
	struct seq_file *seq;
	u64 session_id;
	u64 seq_num;
};

struct bpf_iter__task {
	struct bpf_iter_meta *meta;
	struct task_struct *task;
};

#pragma clang attribute pop

#endif /* __PW_VMLINUX_MIN_H */
