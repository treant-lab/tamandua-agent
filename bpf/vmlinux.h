/* SPDX-License-Identifier: GPL-2.0 */
/* vmlinux.h - Kernel Type Definitions for BPF CO-RE
 *
 * This file is generated from the kernel's BTF (BPF Type Format) data
 * to provide type definitions for BPF programs.
 *
 * Generation:
 *   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
 *
 * For development, we include minimal type stubs. Production builds
 * should use the actual vmlinux.h from the target kernel.
 */

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

/* Basic types */
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

typedef signed char __s8;
typedef short __s16;
typedef int __s32;
typedef long long __s64;

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

typedef __s8 s8;
typedef __s16 s16;
typedef __s32 s32;
typedef __s64 s64;

/* Kernel types */
typedef long __kernel_long_t;
typedef unsigned long __kernel_ulong_t;
typedef __kernel_long_t __kernel_time_t;
typedef long long __kernel_loff_t;
typedef __kernel_ulong_t __kernel_size_t;

/* Standard types */
typedef __kernel_size_t size_t;
typedef __s64 time64_t;
typedef __u32 gfp_t;
typedef __u32 fmode_t;
typedef __u32 umode_t;
typedef __u64 sector_t;
typedef unsigned int uint;

/* PID types */
typedef int pid_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;

/* Socket types */
#define AF_UNIX     1
#define AF_INET     2
#define AF_INET6    10

#define SOCK_STREAM 1
#define SOCK_DGRAM  2

/* File permissions */
#define MAY_EXEC    0x00000001
#define MAY_WRITE   0x00000002
#define MAY_READ    0x00000004
#define MAY_APPEND  0x00000008

/* Memory protection flags */
#define PROT_READ   0x1
#define PROT_WRITE  0x2
#define PROT_EXEC   0x4
#define PROT_NONE   0x0

/* Forward declarations for kernel structures */
struct task_struct;
struct file;
struct inode;
struct dentry;
struct path;
struct socket;
struct sockaddr;
struct sockaddr_in;
struct sockaddr_in6;
struct in_addr;
struct in6_addr;
struct linux_binprm;
struct cred;
struct kernel_siginfo;
struct pt_regs;
struct vm_area_struct;

/* Minimal structure definitions for LSM hooks */

/* IPv4 address structure */
struct in_addr {
    __u32 s_addr;
};

/* IPv6 address structure */
struct in6_addr {
    union {
        __u8 u6_addr8[16];
        __u16 u6_addr16[8];
        __u32 u6_addr32[4];
    } in6_u;
};

/* IPv4 socket address */
struct sockaddr_in {
    __u16 sin_family;
    __u16 sin_port;
    struct in_addr sin_addr;
    __u8 __pad[8];
};

/* IPv6 socket address */
struct sockaddr_in6 {
    __u16 sin6_family;
    __u16 sin6_port;
    __u32 sin6_flowinfo;
    struct in6_addr sin6_addr;
    __u32 sin6_scope_id;
};

/* Generic socket address */
struct sockaddr {
    __u16 sa_family;
    char sa_data[14];
};

/* Task structure (minimal fields) */
struct task_struct {
    volatile long state;
    void *stack;
    unsigned int flags;
    int on_cpu;
    int prio;
    int static_prio;
    int normal_prio;
    unsigned int rt_priority;

    pid_t pid;
    pid_t tgid;

    struct task_struct *real_parent;
    struct task_struct *parent;

    uid_t uid;
    gid_t gid;

    char comm[16];

    /* Many more fields in real kernel... */
};

/* Credentials structure */
struct cred {
    uid_t uid;
    gid_t gid;
    uid_t suid;
    gid_t sgid;
    uid_t euid;
    gid_t egid;
    uid_t fsuid;
    gid_t fsgid;
    /* Capabilities, keyrings, etc. */
};

/* File structure */
struct file {
    struct path f_path;
    struct inode *f_inode;
    const struct file_operations *f_op;
    spinlock_t f_lock;
    atomic_long_t f_count;
    unsigned int f_flags;
    fmode_t f_mode;
    /* Many more fields... */
};

/* Socket structure */
struct socket {
    int state;
    short type;
    unsigned long flags;
    struct file *file;
    struct sock *sk;
    const struct proto_ops *ops;
};

/* Binary program structure (execve) */
struct linux_binprm {
    char buf[256];
    struct vm_area_struct *vma;
    unsigned long vma_pages;
    struct file *file;
    struct cred *cred;
    int unsafe;
    unsigned int per_clear;
    int argc, envc;
    const char *filename;
    const char *interp;
    /* More fields... */
};

/* Signal info structure */
struct kernel_siginfo {
    int si_signo;
    int si_errno;
    int si_code;
    /* Union of various signal-specific data */
};

/* Path structure */
struct path {
    struct vfsmount *mnt;
    struct dentry *dentry;
};

/* Directory entry */
struct dentry {
    unsigned int d_flags;
    struct inode *d_inode;
    struct dentry *d_parent;
    /* Name components */
};

/* Inode structure */
struct inode {
    umode_t i_mode;
    uid_t i_uid;
    gid_t i_gid;
    unsigned long i_ino;
    dev_t i_rdev;
    loff_t i_size;
    /* Many more fields... */
};

/* VM area structure (memory mappings) */
struct vm_area_struct {
    unsigned long vm_start;
    unsigned long vm_end;
    struct mm_struct *vm_mm;
    pgprot_t vm_page_prot;
    unsigned long vm_flags;
    struct file *vm_file;
    /* More fields... */
};

/* Spinlock (for completeness) */
typedef struct {
    int rlock;
} spinlock_t;

/* Atomic type */
typedef struct {
    long counter;
} atomic_long_t;

/* Page protection type */
typedef struct {
    unsigned long pgprot;
} pgprot_t;

/* Device type */
typedef __u32 dev_t;

/* File offset type */
typedef __kernel_loff_t loff_t;

/* File operations (stub) */
struct file_operations {
    void *owner;
    /* Many function pointers... */
};

/* Socket operations (stub) */
struct proto_ops {
    int family;
    /* Many function pointers... */
};

/* Socket structure (network layer) */
struct sock {
    int sk_family;
    int sk_type;
    int sk_protocol;
    /* Many more fields... */
};

/* VFS mount structure */
struct vfsmount {
    struct dentry *mnt_root;
    /* More fields... */
};

/* Memory management structure */
struct mm_struct {
    struct vm_area_struct *mmap;
    /* Many more fields... */
};

/* Namespace structures */
struct nsproxy {
    void *uts_ns;
    void *ipc_ns;
    void *mnt_ns;
    void *pid_ns_for_children;
    void *net_ns;
    void *cgroup_ns;
};

/* Registers structure (architecture-specific) */
struct pt_regs {
#if defined(__x86_64__)
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long bp;
    unsigned long bx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long ax;
    unsigned long cx;
    unsigned long dx;
    unsigned long si;
    unsigned long di;
    unsigned long orig_ax;
    unsigned long ip;
    unsigned long cs;
    unsigned long flags;
    unsigned long sp;
    unsigned long ss;
#elif defined(__aarch64__)
    unsigned long regs[31];
    unsigned long sp;
    unsigned long pc;
    unsigned long pstate;
#else
    unsigned long regs[32];
#endif
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __VMLINUX_H__ */
