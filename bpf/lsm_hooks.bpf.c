// SPDX-License-Identifier: Apache-2.0
//
// LSM BPF Hooks - Kernel >= 5.7
//
// This file contains LSM hook implementations using the BPF_LSM program type.
// For older kernels, the Rust loader will automatically fall back to kprobes.
//
// Compilation:
//   clang -O2 -g -target bpf -D__TARGET_ARCH_x86_64 -I/usr/include -c lsm_hooks.bpf.c -o lsm_hooks.o
//
// Verification:
//   llvm-objdump -d lsm_hooks.o
//   bpftool prog load lsm_hooks.o /sys/fs/bpf/tamandua_lsm

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// Maximum path length
#define MAX_PATH_LEN 256
#define MAX_COMM_LEN 64
#define MAX_FSTYPE_LEN 64

// Event types (must match Rust definitions)
#define EVENT_LSM_FILE_OPEN 101
#define EVENT_LSM_FILE_PERMISSION 102
#define EVENT_LSM_SOCKET_CONNECT 103
#define EVENT_LSM_SOCKET_BIND 104
#define EVENT_LSM_TASK_KILL 105
#define EVENT_LSM_BPRM_CHECK 100
#define EVENT_LSM_MMAP_FILE 106
#define EVENT_LSM_PTRACE_ACCESS 107

// Container escape detection (must match BpfEventType::MountEscape = 39)
#define EVENT_MOUNT_ESCAPE 39

// ============================================================================
// Maps - Shared with userspace
// ============================================================================

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024); // 4MB
} events SEC(".maps");

// High-priority events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024); // 1MB
} events_priority SEC(".maps");

// Configuration
struct ebpf_config {
    __u8 enabled;
    __u8 process_enabled;
    __u8 file_enabled;
    __u8 network_enabled;
    __u8 security_enabled;
    __u8 container_enabled;
    __u8 lsm_enabled;
    __u8 xdp_enabled;
    __u32 filter_uid;
    __u8 containers_only;
    __u8 sensitive_files_enabled;
    __u8 filter_low_pids;
    __u8 _pad[1];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct ebpf_config);
    __uint(max_entries, 1);
} config SEC(".maps");

// Statistics
struct ebpf_stats {
    __u64 events_generated;
    __u64 events_dropped_full;
    __u64 events_rate_limited;
    __u64 map_lookup_failures;
    __u64 probe_read_failures;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct ebpf_stats);
    __uint(max_entries, 1);
} stats SEC(".maps");

// ============================================================================
// Event Structures
// ============================================================================

struct event_header {
    __u32 event_type;
    __u32 pid;
    __u32 tid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u64 timestamp_ns;
    __u8 comm[MAX_COMM_LEN];
    __u64 cgroup_id;
    __u32 mnt_ns;
    __u32 pid_ns;
};

struct file_event {
    struct event_header header;
    __u8 path[MAX_PATH_LEN];
    __s32 fd;
    __u32 flags;
    __u32 mode;
    __u64 inode;
    __u64 dev;
    __u64 size;
};

struct socket_event {
    struct event_header header;
    __u8 addr[16];
    __u16 port;
    __u8 family;
    __u8 protocol;
    __u32 sock_type;
    __s32 ret;
    __u32 op; // 0=connect, 1=bind
};

struct task_kill_event {
    struct event_header header;
    __u32 target_pid;
    __s32 signal;
    __u32 perm;
    __s32 ret;
    __u8 target_comm[MAX_COMM_LEN];
};

struct bprm_event {
    struct event_header header;
    __u8 filename[MAX_PATH_LEN];
    __u8 interpreter[MAX_PATH_LEN];
    __s32 ret;
    __u8 is_suid;
    __u8 is_priv;
    __u8 _pad[2];
};

struct mmap_event {
    struct event_header header;
    __u8 path[MAX_PATH_LEN];
    __u64 addr;
    __u64 len;
    __u32 prot;
    __u32 flags;
    __s32 fd;
    __u64 offset;
    __u32 _pad;
};

struct mount_event {
    struct event_header header;
    __u8 source[MAX_PATH_LEN];   // 256
    __u8 target[MAX_PATH_LEN];   // 256
    __u8 fstype[MAX_FSTYPE_LEN]; // 64
    __u64 flags;
};

// ============================================================================
// Helper Functions
// ============================================================================

static __always_inline void fill_header(struct event_header *header, __u32 event_type) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    header->event_type = event_type;
    header->pid = pid_tgid >> 32;
    header->tid = (__u32)pid_tgid;
    header->ppid = 0; // Would read from task_struct in production
    header->uid = (__u32)uid_gid;
    header->gid = uid_gid >> 32;
    header->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&header->comm, sizeof(header->comm));
    header->cgroup_id = bpf_get_current_cgroup_id();
    header->mnt_ns = 0;
    header->pid_ns = 0;
}

static __always_inline int is_enabled() {
    __u32 key = 0;
    struct ebpf_config *cfg = bpf_map_lookup_elem(&config, &key);
    return cfg ? cfg->enabled : 1;
}

static __always_inline int file_monitoring_enabled() {
    __u32 key = 0;
    struct ebpf_config *cfg = bpf_map_lookup_elem(&config, &key);
    return cfg ? cfg->file_enabled : 1;
}

static __always_inline int network_monitoring_enabled() {
    __u32 key = 0;
    struct ebpf_config *cfg = bpf_map_lookup_elem(&config, &key);
    return cfg ? cfg->network_enabled : 1;
}

static __always_inline int security_monitoring_enabled() {
    __u32 key = 0;
    struct ebpf_config *cfg = bpf_map_lookup_elem(&config, &key);
    return cfg ? cfg->security_enabled : 1;
}

static __always_inline int container_monitoring_enabled() {
    __u32 key = 0;
    struct ebpf_config *cfg = bpf_map_lookup_elem(&config, &key);
    return cfg ? cfg->container_enabled : 1;
}

static __always_inline void increment_stat_events_generated() {
    __u32 key = 0;
    struct ebpf_stats *stats_ptr = bpf_map_lookup_elem(&stats, &key);
    if (stats_ptr) {
        __sync_fetch_and_add(&stats_ptr->events_generated, 1);
    }
}

static __always_inline void increment_stat_events_dropped() {
    __u32 key = 0;
    struct ebpf_stats *stats_ptr = bpf_map_lookup_elem(&stats, &key);
    if (stats_ptr) {
        __sync_fetch_and_add(&stats_ptr->events_dropped_full, 1);
    }
}

// ============================================================================
// LSM Hooks - BPF_LSM program type
// ============================================================================

SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file, int ret)
{
    if (!is_enabled() || !file_monitoring_enabled())
        return 0;

    struct file_event *event;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        increment_stat_events_dropped();
        return 0;
    }

    fill_header(&event->header, EVENT_LSM_FILE_OPEN);

    // Zero initialize
    __builtin_memset(event->path, 0, sizeof(event->path));

    // Read file path (simplified - full implementation would use d_path)
    // For now, we'll let userspace read the path from /proc
    event->fd = -1;
    event->flags = 0;
    event->mode = 0;
    event->inode = 0;
    event->dev = 0;
    event->size = 0;

    bpf_ringbuf_submit(event, 0);
    increment_stat_events_generated();

    return 0; // Allow operation
}

SEC("lsm/file_permission")
int BPF_PROG(lsm_file_permission, struct file *file, int mask, int ret)
{
    if (!is_enabled() || !file_monitoring_enabled())
        return 0;

    // Only log write operations or execute
    if (!(mask & (MAY_WRITE | MAY_EXEC)))
        return 0;

    struct file_event *event;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        increment_stat_events_dropped();
        return 0;
    }

    fill_header(&event->header, EVENT_LSM_FILE_PERMISSION);
    __builtin_memset(event->path, 0, sizeof(event->path));
    event->fd = -1;
    event->flags = mask;
    event->mode = 0;
    event->inode = 0;
    event->dev = 0;
    event->size = 0;

    bpf_ringbuf_submit(event, 0);
    increment_stat_events_generated();

    return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(lsm_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
    if (!is_enabled() || !network_monitoring_enabled())
        return 0;

    struct socket_event *event;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        increment_stat_events_dropped();
        return 0;
    }

    fill_header(&event->header, EVENT_LSM_SOCKET_CONNECT);

    // Read address family and port
    __u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family);
    event->family = (__u8)family;

    // Parse based on family
    if (family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)address;
        __u16 port = 0;
        __u32 ip = 0;

        bpf_probe_read_kernel(&port, sizeof(port), &addr_in->sin_port);
        bpf_probe_read_kernel(&ip, sizeof(ip), &addr_in->sin_addr.s_addr);

        event->port = __builtin_bswap16(port); // Network to host byte order
        event->addr[0] = ip & 0xFF;
        event->addr[1] = (ip >> 8) & 0xFF;
        event->addr[2] = (ip >> 16) & 0xFF;
        event->addr[3] = (ip >> 24) & 0xFF;
    } else if (family == AF_INET6) {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)address;
        __u16 port = 0;

        bpf_probe_read_kernel(&port, sizeof(port), &addr_in6->sin6_port);
        bpf_probe_read_kernel(event->addr, 16, &addr_in6->sin6_addr);

        event->port = __builtin_bswap16(port);
    }

    event->protocol = 6; // TCP
    event->sock_type = SOCK_STREAM;
    event->ret = ret;
    event->op = 0; // connect

    bpf_ringbuf_submit(event, 0);
    increment_stat_events_generated();

    return 0;
}

SEC("lsm/socket_bind")
int BPF_PROG(lsm_socket_bind, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
    if (!is_enabled() || !network_monitoring_enabled())
        return 0;

    struct socket_event *event;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        increment_stat_events_dropped();
        return 0;
    }

    fill_header(&event->header, EVENT_LSM_SOCKET_BIND);

    __u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family);
    event->family = (__u8)family;

    if (family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)address;
        __u16 port = 0;
        __u32 ip = 0;

        bpf_probe_read_kernel(&port, sizeof(port), &addr_in->sin_port);
        bpf_probe_read_kernel(&ip, sizeof(ip), &addr_in->sin_addr.s_addr);

        event->port = __builtin_bswap16(port);
        event->addr[0] = ip & 0xFF;
        event->addr[1] = (ip >> 8) & 0xFF;
        event->addr[2] = (ip >> 16) & 0xFF;
        event->addr[3] = (ip >> 24) & 0xFF;
    }

    event->protocol = 6;
    event->sock_type = SOCK_STREAM;
    event->ret = ret;
    event->op = 1; // bind

    bpf_ringbuf_submit(event, 0);
    increment_stat_events_generated();

    return 0;
}

SEC("lsm/task_kill")
int BPF_PROG(lsm_task_kill, struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred, int ret)
{
    if (!is_enabled() || !security_monitoring_enabled())
        return 0;

    // High-priority event
    struct task_kill_event *event;
    event = bpf_ringbuf_reserve(&events_priority, sizeof(*event), 0);
    if (!event) {
        increment_stat_events_dropped();
        return 0;
    }

    fill_header(&event->header, EVENT_LSM_TASK_KILL);

    // Read target PID and comm
    __u32 target_pid = 0;
    bpf_probe_read_kernel(&target_pid, sizeof(target_pid), &p->tgid);
    event->target_pid = target_pid;

    bpf_probe_read_kernel_str(&event->target_comm, sizeof(event->target_comm), &p->comm);

    event->signal = sig;
    event->perm = 0;
    event->ret = ret;

    bpf_ringbuf_submit(event, 0);
    increment_stat_events_generated();

    return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check_security, struct linux_binprm *bprm, int ret)
{
    if (!is_enabled() || !security_monitoring_enabled())
        return 0;

    // High-priority event
    struct bprm_event *event;
    event = bpf_ringbuf_reserve(&events_priority, sizeof(*event), 0);
    if (!event) {
        increment_stat_events_dropped();
        return 0;
    }

    fill_header(&event->header, EVENT_LSM_BPRM_CHECK);

    __builtin_memset(event->filename, 0, sizeof(event->filename));
    __builtin_memset(event->interpreter, 0, sizeof(event->interpreter));

    // Read filename from bprm
    // Simplified - full implementation would extract full path
    event->ret = ret;
    event->is_suid = 0;
    event->is_priv = (event->header.uid == 0) ? 1 : 0;

    bpf_ringbuf_submit(event, 0);
    increment_stat_events_generated();

    return 0;
}

SEC("lsm/mmap_file")
int BPF_PROG(lsm_mmap_file, struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags, int ret)
{
    if (!is_enabled() || !security_monitoring_enabled())
        return 0;

    // Only monitor executable mappings
    if (!(prot & PROT_EXEC))
        return 0;

    struct mmap_event *event;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        increment_stat_events_dropped();
        return 0;
    }

    fill_header(&event->header, EVENT_LSM_MMAP_FILE);

    __builtin_memset(event->path, 0, sizeof(event->path));
    event->addr = 0;
    event->len = 0;
    event->prot = (__u32)prot;
    event->flags = (__u32)flags;
    event->fd = -1;
    event->offset = 0;

    bpf_ringbuf_submit(event, 0);
    increment_stat_events_generated();

    return 0;
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(lsm_ptrace_access_check, struct task_struct *child, unsigned int mode, int ret)
{
    if (!is_enabled() || !security_monitoring_enabled())
        return 0;

    // Ptrace is critical security event - use priority ring buffer
    struct task_kill_event *event;
    event = bpf_ringbuf_reserve(&events_priority, sizeof(*event), 0);
    if (!event) {
        increment_stat_events_dropped();
        return 0;
    }

    fill_header(&event->header, EVENT_LSM_PTRACE_ACCESS);

    // Read target PID
    __u32 target_pid = 0;
    bpf_probe_read_kernel(&target_pid, sizeof(target_pid), &child->tgid);
    event->target_pid = target_pid;

    bpf_probe_read_kernel_str(&event->target_comm, sizeof(event->target_comm), &child->comm);

    event->signal = 0;
    event->perm = mode;
    event->ret = ret;

    bpf_ringbuf_submit(event, 0);
    increment_stat_events_generated();

    return 0;
}

// Mount hook for container escape detection (T1611)
// Requires kernel >= 5.7 with BPF_LSM enabled
// Fallback: tp/syscalls/sys_enter_mount for older kernels (implemented below).
// Both programs emit the same `struct mount_event` with EVENT_MOUNT_ESCAPE (39)
// to the `events_priority` ring buffer so the userspace parser
// (`parse_mount_event` in `ebpf_linux.rs`) consumes either source identically.
SEC("lsm/sb_mount")
int BPF_PROG(lsm_sb_mount, const char *dev_name, const struct path *path,
             const char *type, unsigned long flags, void *data, int ret)
{
    if (!is_enabled() || !container_monitoring_enabled())
        return 0;

    // Only emit for containerized processes (cgroup_id != 0 heuristic)
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (cgroup_id == 0)
        return 0;

    struct mount_event *event;
    event = bpf_ringbuf_reserve(&events_priority, sizeof(*event), 0);
    if (!event) {
        increment_stat_events_dropped();
        return 0;
    }

    fill_header(&event->header, EVENT_MOUNT_ESCAPE);

    // Zero initialize path buffers
    __builtin_memset(event->source, 0, sizeof(event->source));
    __builtin_memset(event->target, 0, sizeof(event->target));
    __builtin_memset(event->fstype, 0, sizeof(event->fstype));

    // Read source (dev_name), target (path), fstype (type)
    if (dev_name) {
        bpf_probe_read_kernel_str(event->source, sizeof(event->source), dev_name);
    }
    // Note: path->dentry->d_name extraction is complex; userspace enrichment handles it
    if (type) {
        bpf_probe_read_kernel_str(event->fstype, sizeof(event->fstype), type);
    }
    event->flags = flags;

    bpf_ringbuf_submit(event, 0);
    increment_stat_events_generated();

    return 0; // Allow operation (detection only, not blocking)
}

// ============================================================================
// Tracepoint fallback: tp/syscalls/sys_enter_mount
// ============================================================================
//
// For kernels < 5.7 (no BPF_LSM) or kernels where CONFIG_BPF_LSM=n, the Rust
// loader (LinuxEbpfCapabilities in ebpf_linux.rs) attaches this tracepoint
// instead of `lsm/sb_mount`. The emitted `mount_event` payload uses the same
// byte layout and the same EVENT_MOUNT_ESCAPE (39) discriminator, so the
// userspace parse_mount_event is hook-agnostic.
//
// Trade-offs vs the LSM hook:
//   - Fires on syscall ENTRY, so the operation has not been authorized yet
//     (vs LSM which fires after policy decisions are made). For detection-only
//     use this is acceptable; both hooks return 0 (do not block).
//   - Source/target/fstype are user-space pointers at syscall entry; we read
//     them with bpf_probe_read_user_str (Linux >= 5.5).
//   - Does NOT see kernel-internal remounts or do_mount() calls that bypass
//     the syscall (rare; the LSM hook covers those when available).
//
// Args layout matches /sys/kernel/debug/tracing/events/syscalls/sys_enter_mount/format:
//   common_type/flags/preempt/pid : 8 bytes
//   __syscall_nr (s32) + pad (u32): offset 8
//   dev_name  (char __user *)     : offset 16
//   dir_name  (char __user *)     : offset 24
//   type      (char __user *)     : offset 32
//   flags     (unsigned long)     : offset 40
//   data      (void __user *)     : offset 48

struct sys_enter_mount_args {
    __u64 _common;          // common_type/flags/preempt_count/pid (8 bytes)
    __s32 __syscall_nr;     // offset 8
    __u32 _pad;             // offset 12 (align to 8)
    __u64 dev_name_ptr;     // offset 16 (const char __user *)
    __u64 dir_name_ptr;     // offset 24 (const char __user *)
    __u64 type_ptr;         // offset 32 (const char __user *)
    __u64 flags;            // offset 40
    __u64 data_ptr;         // offset 48 (void __user *)
};

SEC("tracepoint/syscalls/sys_enter_mount")
int tp_sys_enter_mount(struct sys_enter_mount_args *ctx)
{
    if (!is_enabled() || !container_monitoring_enabled())
        return 0;

    // Same containerized-process gate as the LSM hook
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (cgroup_id == 0)
        return 0;

    struct mount_event *event;
    event = bpf_ringbuf_reserve(&events_priority, sizeof(*event), 0);
    if (!event) {
        increment_stat_events_dropped();
        return 0;
    }

    fill_header(&event->header, EVENT_MOUNT_ESCAPE);

    // Zero initialize path buffers (verifier requires bounded init before write)
    __builtin_memset(event->source, 0, sizeof(event->source));
    __builtin_memset(event->target, 0, sizeof(event->target));
    __builtin_memset(event->fstype, 0, sizeof(event->fstype));

    // Read user-space strings. Failures leave the buffer zeroed, which the
    // userspace parser treats as an empty string (no false positive).
    if (ctx->dev_name_ptr) {
        bpf_probe_read_user_str(event->source, sizeof(event->source),
                                (const void *)ctx->dev_name_ptr);
    }
    if (ctx->dir_name_ptr) {
        bpf_probe_read_user_str(event->target, sizeof(event->target),
                                (const void *)ctx->dir_name_ptr);
    }
    if (ctx->type_ptr) {
        bpf_probe_read_user_str(event->fstype, sizeof(event->fstype),
                                (const void *)ctx->type_ptr);
    }
    event->flags = ctx->flags;

    bpf_ringbuf_submit(event, 0);
    increment_stat_events_generated();

    return 0;
}

char LICENSE[] SEC("license") = "Apache-2.0";
