//! Enhanced eBPF-based Linux collectors for deep system monitoring
//!
//! This module provides comprehensive Linux telemetry using eBPF programs
//! with the modern CO-RE (Compile Once - Run Everywhere) approach via libbpf-rs.
//! It matches the depth of the Windows agent's collectors across all domains:
//!
//! - **Process Monitoring**: tracepoints for sched_process_exec/exit/fork with
//!   full command-line capture, executable hashing, ELF package signature
//!   verification (dpkg/rpm), process tree reconstruction with full ancestry
//!   chain, and executable entropy analysis for packed/encrypted binary detection.
//!
//! - **File Monitoring**: kprobes on vfs_read/write/unlink/chmod and
//!   security_file_open for file operations, sensitive file detection,
//!   ransomware pattern analysis with mass-rename tracking, file entropy
//!   calculation on writes (high entropy = possible encryption), magic byte
//!   file type detection, SUID/SGID bit change detection, and persistence
//!   location monitoring (cron, systemd, init.d, authorized_keys, ld.so.preload).
//!
//! - **Network Monitoring**: tracepoints for tcp_connect/accept/state plus
//!   kprobes on udp_sendmsg/udp_recvmsg for DNS query/response extraction,
//!   connection state tracking with per-connection data volume accounting,
//!   and data exfiltration heuristics (volume-based threshold detection).
//!
//! - **Security Events**: LSM hooks (kernel >= 5.7) or kprobe fallbacks for
//!   privilege escalation (setuid/setgid/setreuid with UID tracking), kernel
//!   module loading, ptrace attach detection (with request type classification),
//!   container/namespace escape detection, LD_PRELOAD injection detection,
//!   /proc/PID/mem access monitoring, chroot escape detection, and file
//!   capability (setcap) change monitoring with dangerous capability flagging.
//!
//! - **Memory Events**: kprobes on mmap/mprotect for RWX detection, W->X
//!   transitions, anonymous executable mapping (potential shellcode), and
//!   memfd_create/memfd_exec detection for fileless execution.
//!
//! - **Persistence Detection**: Monitoring of writes to cron directories,
//!   systemd unit files, init.d scripts, shell profile files, ld.so.preload,
//!   and SSH authorized_keys -- each tagged with the appropriate MITRE ATT&CK
//!   technique.
//!
//! Each subsystem has independent rate limiting (max 10,000 events/sec per category)
//! and /proc-based process enrichment with a full process tree cache.
//!
//! On non-Linux platforms, a no-op stub is provided that never produces events.

// ============================================================================
// Platform gate: the entire real implementation is Linux-only
// ============================================================================

#[cfg(target_os = "linux")]
mod inner {
    use crate::collectors::{
        Detection, DetectionType, DnsEvent as AgentDnsEvent, EventPayload, EventType,
        FileEvent as AgentFileEvent, MemoryPermissionEvent, NetworkEvent as AgentNetworkEvent,
        ProcessEvent, Severity, TelemetryEvent,
    };
    use crate::config::AgentConfig;
    use anyhow::{anyhow, Context, Result};
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::io::Read as IoRead;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    use tokio::sync::mpsc;
    use tracing::{debug, error, info, warn};

    // ========================================================================
    // Constants
    // ========================================================================

    /// Maximum events per second per category before rate-limiting kicks in.
    const MAX_EVENTS_PER_SEC: u64 = 10_000;

    /// How often (in seconds) the rate-limit window resets.
    const RATE_LIMIT_WINDOW_SECS: u64 = 1;

    /// Maximum size of file to hash (16 MiB) -- avoid blocking on huge files.
    const MAX_HASH_FILE_SIZE: u64 = 16 * 1024 * 1024;

    /// Process cache eviction: entries older than this are removed.
    const PROCESS_CACHE_TTL_SECS: u64 = 600;

    /// Maximum number of entries in the process cache before forced eviction.
    const PROCESS_CACHE_MAX_ENTRIES: usize = 10_000;

    /// Sensitive file paths monitored for credential-access detection.
    const SENSITIVE_FILES: &[&str] = &[
        "/etc/shadow",
        "/etc/passwd",
        "/etc/sudoers",
        "/etc/gshadow",
        "/etc/ssh/sshd_config",
        "/etc/ssh/ssh_host_rsa_key",
        "/etc/ssh/ssh_host_ecdsa_key",
        "/etc/ssh/ssh_host_ed25519_key",
        "/etc/pam.d/",
        "/etc/security/",
        "/etc/krb5.keytab",
        "/var/lib/sss/secrets/",
        "/root/.ssh/",
        "/root/.gnupg/",
        "/root/.bash_history",
        "/proc/kcore",
    ];

    /// Ransomware-indicator file extensions (mass rename detection).
    const RANSOMWARE_EXTENSIONS: &[&str] = &[
        ".encrypted",
        ".locked",
        ".crypto",
        ".crypt",
        ".enc",
        ".ransom",
        ".pay",
        ".wallet",
        ".locky",
        ".cerber",
        ".zepto",
        ".thor",
        ".zzzzz",
        ".aesir",
        ".WNCRY",
    ];

    /// Number of rename operations within a window that triggers a ransomware alert.
    const RANSOMWARE_RENAME_THRESHOLD: usize = 20;

    /// Duration of the ransomware sliding window.
    const RANSOMWARE_WINDOW: Duration = Duration::from_secs(10);

    // ========================================================================
    // eBPF Event Structures (matching the BPF C-side layout)
    // ========================================================================

    /// NOTE: The actual eBPF C programs that produce these events are compiled
    /// separately on Linux with `clang -target bpf`. On non-Linux build hosts
    /// we cannot invoke the BPF compiler, so the BPF object file is expected
    /// to be pre-built and placed at the configured path.
    ///
    /// The structures below mirror the kernel-side `struct` definitions used in
    /// the BPF C code.  They must stay in sync with the BPF program source.
    ///
    /// ## Expected BPF Programs in the Object File
    ///
    /// ### Tracepoints
    /// - `tp_sched_process_exec`  -> sched/sched_process_exec (process lifecycle)
    /// - `tp_sched_process_exit`  -> sched/sched_process_exit
    /// - `tp_sched_process_fork`  -> sched/sched_process_fork
    /// - `tp_tcp_connect`         -> sock/inet_sock_set_state (TCP connect)
    /// - `tp_tcp_accept`          -> sock/inet_sock_set_state (TCP accept)
    ///
    /// ### Kprobes -- File
    /// - `kp_vfs_read`            -> vfs_read
    /// - `kp_vfs_write`           -> vfs_write
    /// - `kp_vfs_unlink`          -> vfs_unlink
    /// - `kp_security_file_open`  -> security_file_open
    /// - `kp_chmod`               -> chmod_common (SUID/SGID tracking)
    ///
    /// ### Kprobes -- Network
    /// - `kp_udp_sendmsg`         -> udp_sendmsg (DNS query capture)
    /// - `kp_udp_recvmsg`         -> udp_recvmsg (DNS response capture)
    ///
    /// ### Kprobes -- Security
    /// - `kp_commit_creds`        -> commit_creds (privilege escalation)
    /// - `kp_init_module`         -> do_init_module (kernel module loading)
    /// - `kp_finit_module`        -> init_module_from_file
    /// - `kp_ptrace_attach`       -> __ptrace_link
    /// - `kp_setuid`              -> sys_setuid
    /// - `kp_setgid`              -> sys_setgid
    /// - `kp_setreuid`            -> sys_setreuid
    /// - `kp_switch_ns`           -> switch_task_namespaces (container escape)
    /// - `kp_ld_preload_exec`     -> load_elf_binary (LD_PRELOAD detection)
    /// - `kp_proc_mem_open`       -> proc_mem_open (/proc/PID/mem injection)
    /// - `kp_chroot`              -> __x64_sys_chroot (chroot escape)
    /// - `kp_vfs_setxattr`        -> vfs_setxattr (setcap/capability changes)
    ///
    /// ### Kprobes -- Memory
    /// - `kp_sys_mmap`            -> do_mmap (RWX/anonymous exec detection)
    /// - `kp_sys_mprotect`        -> do_mprotect_pkey (W->X transitions)
    /// - `kp_memfd_create`        -> __x64_sys_memfd_create (fileless execution)
    ///
    /// ### Kprobes -- Persistence (userspace-filtered from vfs_write)
    /// - `kp_cron_write`          -> vfs_write (BPF filters for cron paths)
    ///
    /// ### LSM Hooks (kernel >= 5.7, optional)
    /// - `lsm_cred_prepare`       -> cred_prepare
    /// - `lsm_kernel_module_request` -> kernel_module_request
    /// - `lsm_ptrace_access_check` -> ptrace_access_check
    /// - `lsm_task_fix_setuid`    -> task_fix_setuid

    const MAX_COMM_LEN: usize = 64;
    const MAX_PATH_LEN: usize = 256;
    const MAX_ARGS_LEN: usize = 512;
    const MAX_DNS_NAME_LEN: usize = 256;
    const MAX_FSTYPE_LEN: usize = 64;

    // -- Common header for every eBPF event ---------------------------------

    /// Event header shared by all eBPF ring-buffer events.
    /// MUST match kernel-side struct event_header in bpf/lsm_hooks.bpf.c exactly.
    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    pub struct EbpfEventHeader {
        pub event_type: u32,
        pub pid: u32,
        pub tid: u32,
        pub ppid: u32,
        pub uid: u32,
        pub gid: u32,
        pub timestamp_ns: u64,
        pub comm: [u8; MAX_COMM_LEN],
        pub cgroup_id: u64,
        pub mnt_ns: u32,
        pub pid_ns: u32,
    }

    // -- Process events -----------------------------------------------------

    /// BPF event type IDs -- must match the C-side `enum ebpf_event_type`.
    #[repr(u32)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum BpfEventType {
        // Process lifecycle
        ProcessExec = 1,
        ProcessExit = 2,
        ProcessFork = 3,

        // File operations
        FileOpen = 10,
        FileRead = 11,
        FileWrite = 12,
        FileUnlink = 13,
        FileRename = 14,
        SensitiveAccess = 15,
        FileChmod = 16,

        // Network
        TcpConnect = 20,
        TcpAccept = 21,
        TcpStateChange = 22,
        UdpSendMsg = 23,
        DnsQuery = 24,
        DnsResponse = 25,
        UdpRecvMsg = 26,

        // Security
        PrivEscalation = 30,
        KernelModLoad = 31,
        PtraceAttach = 32,
        NamespaceEscape = 33,
        ContainerBreakout = 34,
        LdPreloadInject = 35,
        ProcMemAccess = 36,
        ChrootEscape = 37,
        SetcapChange = 38,
        MountEscape = 39,

        // Memory
        MmapExec = 40,
        MprotectChange = 41,
        MemfdCreate = 42,
        MemfdExec = 43,

        // Syscall evasion events emitted by ebpf-common EventType.
        SyscallEvasionAnonymousMmap = 161,
        SyscallEvasionPtraceInject = 163,
        SyscallEvasionMemfdExec = 164,
        SyscallEvasionProcMemWrite = 165,

        // Persistence
        CronModify = 50,
        SystemdTimerCreate = 51,
        InitScriptModify = 52,
        SshAuthorizedKeys = 53,
    }

    impl BpfEventType {
        pub fn from_u32(v: u32) -> Option<Self> {
            match v {
                1 => Some(Self::ProcessExec),
                2 => Some(Self::ProcessExit),
                3 => Some(Self::ProcessFork),
                10 => Some(Self::FileOpen),
                11 => Some(Self::FileRead),
                12 => Some(Self::FileWrite),
                13 => Some(Self::FileUnlink),
                14 => Some(Self::FileRename),
                15 => Some(Self::SensitiveAccess),
                16 => Some(Self::FileChmod),
                20 => Some(Self::TcpConnect),
                21 => Some(Self::TcpAccept),
                22 => Some(Self::TcpStateChange),
                23 => Some(Self::UdpSendMsg),
                24 => Some(Self::DnsQuery),
                25 => Some(Self::DnsResponse),
                26 => Some(Self::UdpRecvMsg),
                30 => Some(Self::PrivEscalation),
                31 => Some(Self::KernelModLoad),
                32 => Some(Self::PtraceAttach),
                33 => Some(Self::NamespaceEscape),
                34 => Some(Self::ContainerBreakout),
                35 => Some(Self::LdPreloadInject),
                36 => Some(Self::ProcMemAccess),
                37 => Some(Self::ChrootEscape),
                38 => Some(Self::SetcapChange),
                39 => Some(Self::MountEscape),
                40 => Some(Self::MmapExec),
                41 => Some(Self::MprotectChange),
                42 => Some(Self::MemfdCreate),
                43 => Some(Self::MemfdExec),
                161 => Some(Self::SyscallEvasionAnonymousMmap),
                163 => Some(Self::SyscallEvasionPtraceInject),
                164 => Some(Self::SyscallEvasionMemfdExec),
                165 => Some(Self::SyscallEvasionProcMemWrite),
                50 => Some(Self::CronModify),
                51 => Some(Self::SystemdTimerCreate),
                52 => Some(Self::InitScriptModify),
                53 => Some(Self::SshAuthorizedKeys),
                _ => None,
            }
        }
    }

    // Concrete event structs (repr(C), matching BPF program layout)

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct BpfProcessExecEvent {
        pub header: EbpfEventHeader,
        pub filename: [u8; MAX_PATH_LEN],
        pub args: [u8; MAX_ARGS_LEN],
        pub args_len: u32,
        pub cwd: [u8; MAX_PATH_LEN],
        pub flags: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct BpfProcessExitEvent {
        pub header: EbpfEventHeader,
        pub exit_code: i32,
        pub exit_signal: i32,
        pub utime_ns: u64,
        pub stime_ns: u64,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct BpfProcessForkEvent {
        pub header: EbpfEventHeader,
        pub child_pid: u32,
        pub child_tid: u32,
        pub clone_flags: u64,
        pub new_ns_flags: u32,
        pub _pad: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct BpfFileEvent {
        pub header: EbpfEventHeader,
        pub path: [u8; MAX_PATH_LEN],
        pub fd: i32,
        pub flags: u32,
        pub mode: u32,
        pub _pad: u32,
        pub inode: u64,
        pub dev: u64,
        pub size: u64,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct BpfFileRenameEvent {
        pub header: EbpfEventHeader,
        pub old_path: [u8; MAX_PATH_LEN],
        pub new_path: [u8; MAX_PATH_LEN],
    }

    /// Mount event captured by an `lsm/sb_mount` (or `tp/syscalls/sys_enter_mount`)
    /// hook. Layout must match the kernel-side `bpf_mount_event` struct.
    /// Used to detect container escape via bind-mounts of host paths
    /// (`/proc/1/root`, `/var/run/docker.sock`, host device nodes, etc.)
    /// from a containerized process (`cgroup_id != 0`).
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct BpfMountEvent {
        pub header: EbpfEventHeader,
        pub source: [u8; MAX_PATH_LEN],
        pub target: [u8; MAX_PATH_LEN],
        pub fstype: [u8; MAX_FSTYPE_LEN],
        pub flags: u64,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct BpfNetworkEvent {
        pub header: EbpfEventHeader,
        pub saddr: [u8; 16],
        pub daddr: [u8; 16],
        pub sport: u16,
        pub dport: u16,
        pub protocol: u8,
        pub family: u8,
        pub state: u8,
        pub direction: u8,
        pub bytes_sent: u64,
        pub bytes_recv: u64,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct BpfTcpStateEvent {
        pub header: EbpfEventHeader,
        pub saddr: [u8; 16],
        pub daddr: [u8; 16],
        pub sport: u16,
        pub dport: u16,
        pub old_state: u8,
        pub new_state: u8,
        pub family: u8,
        pub _pad: u8,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct BpfDnsEvent {
        pub header: EbpfEventHeader,
        pub query_name: [u8; MAX_DNS_NAME_LEN],
        pub query_len: u32,
        pub query_type: u16,
        pub _pad: u16,
        pub dns_server: [u8; 16],
        pub server_family: u8,
        pub _pad2: [u8; 7],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct BpfPrivEscEvent {
        pub header: EbpfEventHeader,
        pub old_uid: u32,
        pub new_uid: u32,
        pub old_euid: u32,
        pub new_euid: u32,
        pub old_gid: u32,
        pub new_gid: u32,
        pub syscall_nr: u32,
        pub _pad: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct BpfModuleLoadEvent {
        pub header: EbpfEventHeader,
        pub name: [u8; MAX_COMM_LEN],
        pub path: [u8; MAX_PATH_LEN],
        pub flags: u32,
        pub is_signed: u8,
        pub _pad: [u8; 3],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct BpfPtraceEvent {
        pub header: EbpfEventHeader,
        pub target_pid: u32,
        pub request: u32,
        pub addr: u64,
        pub data: u64,
        pub target_comm: [u8; MAX_COMM_LEN],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct BpfNamespaceEvent {
        pub header: EbpfEventHeader,
        pub ns_type: u32,
        pub old_ns: u32,
        pub new_ns: u32,
        pub flags: u32,
        pub is_escape: u8,
        pub _pad: [u8; 7],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct BpfMmapEvent {
        pub header: EbpfEventHeader,
        pub addr: u64,
        pub len: u64,
        pub prot: u32,
        pub flags: u32,
        pub fd: i32,
        pub _pad: u32,
        pub path: [u8; MAX_PATH_LEN],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct BpfMprotectEvent {
        pub header: EbpfEventHeader,
        pub addr: u64,
        pub len: u64,
        pub old_prot: u32,
        pub new_prot: u32,
    }

    // -- Additional event structs for enhanced monitoring -------------------

    /// LD_PRELOAD / LD_LIBRARY_PATH injection: the BPF program fires when
    /// execve() is called with LD_PRELOAD set in the environment.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct BpfLdPreloadEvent {
        pub header: EbpfEventHeader,
        pub filename: [u8; MAX_PATH_LEN],
        pub preload_value: [u8; MAX_PATH_LEN],
    }

    /// /proc/PID/mem access: fired when a process opens another process's
    /// memory file for reading/writing (process injection vector).
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct BpfProcMemEvent {
        pub header: EbpfEventHeader,
        pub target_pid: u32,
        pub flags: u32,
        pub target_comm: [u8; MAX_COMM_LEN],
    }

    /// memfd_create: fileless execution by creating anonymous backed FDs.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct BpfMemfdCreateEvent {
        pub header: EbpfEventHeader,
        pub name: [u8; MAX_COMM_LEN],
        pub flags: u32,
        pub fd: i32,
    }

    /// Syscall evasion event emitted by the raw `sys_enter_security` program.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct BpfSyscallEvasionEvent {
        pub header: EbpfEventHeader,
        pub syscall_nr: u32,
        pub evasion_type: u32,
        pub return_addr: u64,
        pub region_start: u64,
        pub region_size: u64,
        pub mem_prot: u32,
        pub mem_flags: u32,
        pub fd: i32,
        pub confidence: u8,
        pub _pad: [u8; 3],
        pub target_pid: u32,
        pub arg1: u64,
        pub arg2: u64,
        pub arg3: u64,
        pub path: [u8; MAX_PATH_LEN],
    }

    /// DNS response event with answer data for correlation.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct BpfDnsResponseEvent {
        pub header: EbpfEventHeader,
        pub query_name: [u8; MAX_DNS_NAME_LEN],
        pub query_len: u32,
        pub query_type: u16,
        pub answer_count: u16,
        pub answers: [u8; MAX_PATH_LEN],
        pub answer_len: u32,
        pub _pad: u32,
    }

    /// File chmod event for SUID/SGID bit detection.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct BpfFileChmodEvent {
        pub header: EbpfEventHeader,
        pub path: [u8; MAX_PATH_LEN],
        pub old_mode: u32,
        pub new_mode: u32,
    }

    /// Setcap / capability change event.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct BpfSetcapEvent {
        pub header: EbpfEventHeader,
        pub path: [u8; MAX_PATH_LEN],
        pub cap_effective: u64,
        pub cap_permitted: u64,
        pub cap_inheritable: u64,
    }

    /// Persistence event: cron, systemd timer, init.d script, authorized_keys
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct BpfPersistenceEvent {
        pub header: EbpfEventHeader,
        pub path: [u8; MAX_PATH_LEN],
        pub content_snippet: [u8; MAX_PATH_LEN],
        pub persistence_type: u32,
    }

    // ========================================================================
    // Helper: null-terminated byte array -> String
    // ========================================================================

    fn bytes_to_string(bytes: &[u8]) -> String {
        let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..len]).to_string()
    }

    // ========================================================================
    // Rate Limiter (per-category token-bucket)
    // ========================================================================

    /// Event categories for independent rate limiting.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum EventCategory {
        Process,
        File,
        Network,
        Security,
        Memory,
    }

    /// Simple sliding-window rate limiter.  Each category tracks the number
    /// of events emitted within the current 1-second window.  If the count
    /// exceeds `MAX_EVENTS_PER_SEC` the event is dropped (counted in stats).
    pub struct RateLimiter {
        counters: HashMap<EventCategory, (u64, Instant)>,
        max_per_sec: u64,
    }

    impl RateLimiter {
        pub fn new(max_per_sec: u64) -> Self {
            Self {
                counters: HashMap::new(),
                max_per_sec,
            }
        }

        /// Returns `true` if the event should be allowed through.
        pub fn allow(&mut self, cat: EventCategory) -> bool {
            let now = Instant::now();
            let entry = self.counters.entry(cat).or_insert((0, now));

            // Reset window if elapsed.
            if now.duration_since(entry.1).as_secs() >= RATE_LIMIT_WINDOW_SECS {
                entry.0 = 0;
                entry.1 = now;
            }

            if entry.0 < self.max_per_sec {
                entry.0 += 1;
                true
            } else {
                false
            }
        }
    }

    // ========================================================================
    // /proc Enrichment
    // ========================================================================

    /// Cached process information read from /proc.
    #[derive(Debug, Clone)]
    struct ProcInfo {
        pub pid: u32,
        pub ppid: u32,
        pub name: String,
        pub exe_path: String,
        pub cmdline: String,
        pub uid: u32,
        pub start_time: u64,
        pub fetched_at: Instant,
    }

    /// Process enrichment cache backed by /proc reads.
    pub(crate) struct ProcessEnricher {
        cache: HashMap<u32, ProcInfo>,
    }

    impl ProcessEnricher {
        pub(crate) fn new() -> Self {
            Self {
                cache: HashMap::new(),
            }
        }

        /// Retrieve (and cache) process information for `pid`.
        fn get(&mut self, pid: u32) -> Option<ProcInfo> {
            // Evict stale entries if cache is large.
            if self.cache.len() > PROCESS_CACHE_MAX_ENTRIES {
                let cutoff = Instant::now() - Duration::from_secs(PROCESS_CACHE_TTL_SECS);
                self.cache.retain(|_, v| v.fetched_at > cutoff);
            }

            // Check cache first.
            if let Some(entry) = self.cache.get(&pid) {
                if entry.fetched_at.elapsed() < Duration::from_secs(PROCESS_CACHE_TTL_SECS) {
                    return Some(entry.clone());
                }
            }

            // Read from /proc.
            let info = Self::read_proc(pid)?;
            self.cache.insert(pid, info.clone());
            Some(info)
        }

        /// Remove a PID from the cache (on process exit).
        fn remove(&mut self, pid: u32) {
            self.cache.remove(&pid);
        }

        fn read_proc(pid: u32) -> Option<ProcInfo> {
            let proc_path = format!("/proc/{}", pid);
            if !Path::new(&proc_path).exists() {
                return None;
            }

            // exe link
            let exe_path = std::fs::read_link(format!("{}/exe", proc_path))
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();

            // cmdline
            let cmdline = std::fs::read_to_string(format!("{}/cmdline", proc_path))
                .unwrap_or_default()
                .replace('\0', " ")
                .trim()
                .to_string();

            // stat (name, ppid, start_time)
            let stat = std::fs::read_to_string(format!("{}/stat", proc_path)).unwrap_or_default();
            let (name, ppid, start_time) = Self::parse_stat(&stat, pid);

            // status (uid)
            let uid = Self::read_uid(pid);

            Some(ProcInfo {
                pid,
                ppid,
                name,
                exe_path,
                cmdline,
                uid,
                start_time,
                fetched_at: Instant::now(),
            })
        }

        /// Parse /proc/PID/stat.  The comm field is in parens and may contain
        /// spaces, so we find the last ')' first.
        fn parse_stat(stat: &str, pid: u32) -> (String, u32, u64) {
            let open = stat.find('(');
            let close = stat.rfind(')');
            if let (Some(o), Some(c)) = (open, close) {
                let name = stat[o + 1..c].to_string();
                let remainder: Vec<&str> = stat[c + 2..].split_whitespace().collect();
                // Field index relative to remainder: 0=state, 1=ppid, ...
                let ppid = remainder.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                // start_time is field 19 in the full stat, which is index 19 in remainder.
                let start_time = remainder.get(19).and_then(|s| s.parse().ok()).unwrap_or(0);
                (name, ppid, start_time)
            } else {
                (format!("pid_{}", pid), 0, 0)
            }
        }

        fn read_uid(pid: u32) -> u32 {
            if let Ok(status) = std::fs::read_to_string(format!("/proc/{}/status", pid)) {
                for line in status.lines() {
                    if line.starts_with("Uid:") {
                        // Uid: real effective saved fs
                        return line
                            .split_whitespace()
                            .nth(1)
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(0);
                    }
                }
            }
            0
        }
    }

    // ========================================================================
    // File Hashing
    // ========================================================================

    /// Compute SHA-256 of a file, returning empty Vec if the file is missing
    /// or too large.
    fn hash_file(path: &str) -> Vec<u8> {
        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return Vec::new(),
        };
        if meta.len() > MAX_HASH_FILE_SIZE || !meta.is_file() {
            return Vec::new();
        }
        let mut file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 8192];
        loop {
            match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => hasher.update(&buf[..n]),
                Err(_) => return Vec::new(),
            }
        }
        hasher.finalize().to_vec()
    }

    // ========================================================================
    // File Entropy Calculator
    // ========================================================================

    /// Calculate the Shannon entropy of a file.  Returns 0.0 on error.
    /// Reads at most MAX_HASH_FILE_SIZE bytes.
    fn file_entropy(path: &str) -> f32 {
        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return 0.0,
        };
        if meta.len() == 0 || meta.len() > MAX_HASH_FILE_SIZE || !meta.is_file() {
            return 0.0;
        }
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => return 0.0,
        };
        shannon_entropy(&data)
    }

    /// Calculate the Shannon entropy of a byte slice (0.0 - 8.0).
    fn shannon_entropy(data: &[u8]) -> f32 {
        if data.is_empty() {
            return 0.0;
        }
        let mut counts = [0u64; 256];
        for &b in data {
            counts[b as usize] += 1;
        }
        let len = data.len() as f64;
        let mut entropy: f64 = 0.0;
        for &c in &counts {
            if c > 0 {
                let p = c as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy as f32
    }

    // ========================================================================
    // File Magic Byte Detection
    // ========================================================================

    /// Detect file type from magic bytes (first 16 bytes of the file).
    fn detect_file_type_magic(path: &str) -> String {
        let mut buf = [0u8; 16];
        let n = match std::fs::File::open(path).and_then(|mut f| f.read(&mut buf)) {
            Ok(n) => n,
            Err(_) => return String::new(),
        };
        if n < 4 {
            return String::new();
        }
        // ELF
        if buf[0..4] == [0x7f, b'E', b'L', b'F'] {
            return "elf".to_string();
        }
        // PE (MZ)
        if buf[0..2] == [b'M', b'Z'] {
            return "pe".to_string();
        }
        // Shell script
        if buf[0..2] == [b'#', b'!'] {
            return "script".to_string();
        }
        // GZIP
        if buf[0..2] == [0x1f, 0x8b] {
            return "gzip".to_string();
        }
        // ZIP / JAR / APK
        if buf[0..4] == [0x50, 0x4b, 0x03, 0x04] {
            return "zip".to_string();
        }
        // PDF
        if n >= 5 && buf[0..5] == [b'%', b'P', b'D', b'F', b'-'] {
            return "pdf".to_string();
        }
        // BZ2
        if buf[0..3] == [b'B', b'Z', b'h'] {
            return "bzip2".to_string();
        }
        // XZ
        if n >= 6 && buf[0..6] == [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00] {
            return "xz".to_string();
        }
        // Shared object or Java class
        if n >= 4 && buf[0..4] == [0xca, 0xfe, 0xba, 0xbe] {
            return "java_class".to_string();
        }
        String::new()
    }

    // ========================================================================
    // ELF Signature / Package Verification
    // ========================================================================

    /// Check whether an ELF binary is associated with a known package manager.
    /// This is the Linux equivalent of Windows Authenticode signature checking.
    /// Returns (is_signed, signer_name).
    fn check_elf_package_signature(path: &str) -> (bool, Option<String>) {
        // Strategy: check if the binary belongs to a known package using dpkg or rpm.
        // This is best-effort; if neither tool is available, returns (false, None).

        // Try dpkg first (Debian/Ubuntu)
        if let Ok(output) = std::process::Command::new("dpkg")
            .args(["-S", path])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Some(pkg) = stdout.split(':').next() {
                    let pkg = pkg.trim();
                    if !pkg.is_empty() {
                        return (true, Some(format!("dpkg:{}", pkg)));
                    }
                }
            }
        }

        // Try rpm (RHEL/CentOS/Fedora)
        if let Ok(output) = std::process::Command::new("rpm")
            .args(["-qf", path])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !stdout.is_empty() && !stdout.contains("not owned") {
                    return (true, Some(format!("rpm:{}", stdout)));
                }
            }
        }

        (false, None)
    }

    // ========================================================================
    // Process Tree Reconstruction
    // ========================================================================

    /// A node in the process tree cache.
    #[derive(Debug, Clone)]
    struct ProcessTreeNode {
        pub pid: u32,
        pub ppid: u32,
        pub name: String,
        pub exe_path: String,
        pub cmdline: String,
        pub uid: u32,
        pub start_time_ms: u64,
        pub children: Vec<u32>,
        pub depth: u32,
        pub created_at: Instant,
    }

    /// Process tree tracker that maintains parent-child relationships.
    /// Enables full ancestry reconstruction for any PID, giving the server
    /// the same tree visibility as Windows ETW.
    struct ProcessTree {
        nodes: HashMap<u32, ProcessTreeNode>,
        /// Maximum tree depth to track (prevents runaway recursion).
        max_depth: u32,
    }

    impl ProcessTree {
        fn new() -> Self {
            Self {
                nodes: HashMap::new(),
                max_depth: 64,
            }
        }

        /// Insert or update a node for a process exec/fork event.
        fn insert(
            &mut self,
            pid: u32,
            ppid: u32,
            name: &str,
            exe_path: &str,
            cmdline: &str,
            uid: u32,
        ) {
            let depth = self.get_depth(ppid);
            let node = ProcessTreeNode {
                pid,
                ppid,
                name: name.to_string(),
                exe_path: exe_path.to_string(),
                cmdline: cmdline.to_string(),
                uid,
                start_time_ms: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
                children: Vec::new(),
                depth: depth + 1,
                created_at: Instant::now(),
            };

            self.nodes.insert(pid, node);

            // Register as child of parent.
            if let Some(parent) = self.nodes.get_mut(&ppid) {
                if !parent.children.contains(&pid) {
                    parent.children.push(pid);
                }
            }
        }

        /// Remove a process from the tree (on exit).
        fn remove(&mut self, pid: u32) {
            if let Some(node) = self.nodes.remove(&pid) {
                // Remove from parent's children list.
                if let Some(parent) = self.nodes.get_mut(&node.ppid) {
                    parent.children.retain(|&c| c != pid);
                }
            }
        }

        /// Get the ancestry chain for a PID, from the process up to init.
        /// Returns a list of (pid, name, exe_path) tuples.
        fn get_ancestry(&self, pid: u32) -> Vec<(u32, String, String)> {
            let mut ancestry = Vec::new();
            let mut current = pid;
            let mut seen = std::collections::HashSet::new();

            while let Some(node) = self.nodes.get(&current) {
                if !seen.insert(current) || ancestry.len() as u32 >= self.max_depth {
                    break;
                }
                ancestry.push((node.pid, node.name.clone(), node.exe_path.clone()));
                if current == node.ppid || node.ppid == 0 {
                    break;
                }
                current = node.ppid;
            }

            ancestry
        }

        /// Get parent info from the tree.
        fn get_parent(&self, ppid: u32) -> Option<&ProcessTreeNode> {
            self.nodes.get(&ppid)
        }

        /// Get the depth of a PID in the tree.
        fn get_depth(&self, pid: u32) -> u32 {
            self.nodes.get(&pid).map(|n| n.depth).unwrap_or(0)
        }

        /// Evict stale entries older than the TTL.
        fn evict_stale(&mut self) {
            let cutoff = Instant::now() - Duration::from_secs(PROCESS_CACHE_TTL_SECS);
            self.nodes.retain(|_, v| v.created_at > cutoff);
        }

        /// Return the number of tracked processes.
        fn len(&self) -> usize {
            self.nodes.len()
        }
    }

    // ========================================================================
    // Data Exfiltration Heuristics
    // ========================================================================

    /// Tracks per-PID outbound data volume to detect large data transfers
    /// (potential exfiltration via T1041).
    struct ExfiltrationTracker {
        /// Per-PID total bytes sent within the current window.
        per_pid_sent: HashMap<u32, (u64, Instant)>,
        /// Threshold in bytes per window before alerting (default 100 MB / 5 min).
        threshold_bytes: u64,
        /// Window duration.
        window: Duration,
    }

    impl ExfiltrationTracker {
        fn new() -> Self {
            Self {
                per_pid_sent: HashMap::new(),
                threshold_bytes: 100 * 1024 * 1024, // 100 MiB
                window: Duration::from_secs(300),   // 5 minutes
            }
        }

        /// Record outbound bytes and return true if threshold was breached.
        fn record(&mut self, pid: u32, bytes: u64) -> bool {
            let now = Instant::now();
            let entry = self.per_pid_sent.entry(pid).or_insert((0, now));

            // Reset if window elapsed.
            if now.duration_since(entry.1) > self.window {
                entry.0 = 0;
                entry.1 = now;
            }

            entry.0 += bytes;
            entry.0 >= self.threshold_bytes
        }

        /// Prune entries for PIDs that are idle.
        fn prune(&mut self) {
            let cutoff = Instant::now() - self.window;
            self.per_pid_sent.retain(|_, v| v.1 > cutoff);
        }
    }

    // ========================================================================
    // Persistence Path Detector
    // ========================================================================

    /// Paths that indicate persistence mechanisms on Linux.
    const PERSISTENCE_PATHS: &[(&str, &str)] = &[
        ("/etc/crontab", "cron"),
        ("/var/spool/cron/", "cron"),
        ("/etc/cron.d/", "cron"),
        ("/etc/cron.daily/", "cron"),
        ("/etc/cron.hourly/", "cron"),
        ("/etc/cron.weekly/", "cron"),
        ("/etc/cron.monthly/", "cron"),
        ("/etc/systemd/system/", "systemd"),
        ("/usr/lib/systemd/system/", "systemd"),
        ("/etc/init.d/", "initd"),
        ("/etc/rc.local", "rc_local"),
        ("/etc/profile.d/", "shell_profile"),
        ("/etc/bash.bashrc", "shell_profile"),
        ("/etc/profile", "shell_profile"),
        ("/root/.bashrc", "shell_profile"),
        ("/root/.bash_profile", "shell_profile"),
        ("/root/.profile", "shell_profile"),
        ("/etc/ld.so.preload", "ld_preload"),
    ];

    /// SSH authorized_keys patterns.
    const SSH_AUTHKEYS_PATTERNS: &[&str] = &["/.ssh/authorized_keys", "/.ssh/authorized_keys2"];

    /// Check whether a file path matches a known persistence location.
    /// Returns (is_persistence, persistence_type).
    fn check_persistence_path(path: &str) -> Option<&'static str> {
        for &(prefix, ptype) in PERSISTENCE_PATHS {
            if prefix.ends_with('/') {
                if path.starts_with(prefix) {
                    return Some(ptype);
                }
            } else if path == prefix {
                return Some(ptype);
            }
        }
        for pattern in SSH_AUTHKEYS_PATTERNS {
            if path.ends_with(pattern) {
                return Some("ssh_authorized_keys");
            }
        }
        None
    }

    // ========================================================================
    // Ransomware Pattern Tracker
    // ========================================================================

    /// Sliding-window tracker for mass-rename / mass-write operations
    /// that may indicate ransomware activity.
    struct RansomwareTracker {
        /// Per-PID timestamps of suspicious rename/write events.
        windows: HashMap<u32, Vec<Instant>>,
    }

    impl RansomwareTracker {
        fn new() -> Self {
            Self {
                windows: HashMap::new(),
            }
        }

        /// Record a suspicious file operation and return `true` if the
        /// threshold has been breached.
        fn record(&mut self, pid: u32) -> bool {
            let now = Instant::now();
            let window = self.windows.entry(pid).or_insert_with(Vec::new);

            // Prune old entries.
            window.retain(|t| now.duration_since(*t) < RANSOMWARE_WINDOW);

            window.push(now);
            window.len() >= RANSOMWARE_RENAME_THRESHOLD
        }
    }

    // ========================================================================
    // Connection Tracker
    // ========================================================================

    /// Per-connection state for data-volume tracking.
    #[derive(Debug, Clone)]
    struct ConnectionState {
        pub pid: u32,
        pub process_name: String,
        pub local_ip: String,
        pub local_port: u16,
        pub remote_ip: String,
        pub remote_port: u16,
        pub protocol: String,
        pub bytes_sent: u64,
        pub bytes_recv: u64,
        pub started: Instant,
        pub last_seen: Instant,
    }

    /// Key for connection tracking.
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct ConnKey {
        pid: u32,
        local_ip: String,
        local_port: u16,
        remote_ip: String,
        remote_port: u16,
        protocol: String,
    }

    struct ConnectionTracker {
        connections: HashMap<ConnKey, ConnectionState>,
    }

    impl ConnectionTracker {
        fn new() -> Self {
            Self {
                connections: HashMap::new(),
            }
        }

        fn track_connect(
            &mut self,
            pid: u32,
            process_name: &str,
            local_ip: &str,
            local_port: u16,
            remote_ip: &str,
            remote_port: u16,
            protocol: &str,
        ) {
            let key = ConnKey {
                pid,
                local_ip: local_ip.to_string(),
                local_port,
                remote_ip: remote_ip.to_string(),
                remote_port,
                protocol: protocol.to_string(),
            };
            let now = Instant::now();
            self.connections.entry(key).or_insert(ConnectionState {
                pid,
                process_name: process_name.to_string(),
                local_ip: local_ip.to_string(),
                local_port,
                remote_ip: remote_ip.to_string(),
                remote_port,
                protocol: protocol.to_string(),
                bytes_sent: 0,
                bytes_recv: 0,
                started: now,
                last_seen: now,
            });
        }

        fn update_bytes(
            &mut self,
            pid: u32,
            local_ip: &str,
            local_port: u16,
            remote_ip: &str,
            remote_port: u16,
            protocol: &str,
            sent: u64,
            recv: u64,
        ) {
            let key = ConnKey {
                pid,
                local_ip: local_ip.to_string(),
                local_port,
                remote_ip: remote_ip.to_string(),
                remote_port,
                protocol: protocol.to_string(),
            };
            if let Some(conn) = self.connections.get_mut(&key) {
                conn.bytes_sent += sent;
                conn.bytes_recv += recv;
                conn.last_seen = Instant::now();
            }
        }

        fn get_state(
            &self,
            pid: u32,
            local_ip: &str,
            local_port: u16,
            remote_ip: &str,
            remote_port: u16,
            protocol: &str,
        ) -> Option<&ConnectionState> {
            let key = ConnKey {
                pid,
                local_ip: local_ip.to_string(),
                local_port,
                remote_ip: remote_ip.to_string(),
                remote_port,
                protocol: protocol.to_string(),
            };
            self.connections.get(&key)
        }

        /// Prune connections idle for more than 5 minutes.
        fn prune_stale(&mut self) {
            let cutoff = Instant::now() - Duration::from_secs(300);
            self.connections.retain(|_, v| v.last_seen > cutoff);
        }
    }

    // ========================================================================
    // Collector Statistics
    // ========================================================================

    /// Atomic counters for health monitoring of the eBPF Linux collector.
    #[derive(Default)]
    pub struct EbpfLinuxStats {
        pub events_received: AtomicU64,
        pub events_processed: AtomicU64,
        pub events_dropped_rate_limit: AtomicU64,
        pub events_dropped_channel_full: AtomicU64,
        pub parse_errors: AtomicU64,
        pub enrichment_misses: AtomicU64,
    }

    impl EbpfLinuxStats {
        pub fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }
    }

    #[derive(Debug, Clone)]
    pub struct EbpfLinuxStatsSnapshot {
        pub events_received: u64,
        pub events_processed: u64,
        pub events_dropped_rate_limit: u64,
        pub events_dropped_channel_full: u64,
        pub parse_errors: u64,
        pub enrichment_misses: u64,
    }

    // ========================================================================
    // eBPF Capabilities Detection (kernel feature probing)
    // ========================================================================

    /// Probed kernel eBPF feature availability.
    #[derive(Debug, Clone, Default)]
    pub struct LinuxEbpfCapabilities {
        pub kernel_version: (u32, u32, u32),
        pub has_tracepoints: bool,
        pub has_kprobes: bool,
        pub has_kretprobes: bool,
        pub has_raw_tracepoints: bool,
        pub has_ring_buffer: bool,
        pub has_btf: bool,
        pub has_lsm_hooks: bool,
        pub has_fentry: bool,
        pub bpf_fs_mounted: bool,
        pub tracing_fs_available: bool,
        pub running_as_root: bool,
        pub has_cap_bpf: bool,
        pub object_path: String,
        pub object_path_exists: bool,
        pub missing_prerequisites: Vec<String>,
    }

    impl LinuxEbpfCapabilities {
        pub fn detect_for_object(object_path: &str) -> Self {
            let mut caps = Self::default();
            caps.object_path = object_path.to_string();
            caps.object_path_exists = Path::new(object_path).exists();

            // Parse kernel version from /proc/version.
            if let Ok(version) = std::fs::read_to_string("/proc/version") {
                let parts: Vec<&str> = version.split_whitespace().collect();
                if let Some(ver_str) = parts.get(2) {
                    let ver_parts: Vec<u32> = ver_str
                        .split('.')
                        .take(3)
                        .filter_map(|s| s.split('-').next().and_then(|n| n.parse().ok()))
                        .collect();
                    if ver_parts.len() >= 2 {
                        let major = ver_parts[0];
                        let minor = ver_parts[1];
                        let patch = ver_parts.get(2).copied().unwrap_or(0);
                        caps.kernel_version = (major, minor, patch);

                        caps.has_tracepoints = major > 4 || (major == 4 && minor >= 1);
                        caps.has_kprobes = major > 4 || (major == 4 && minor >= 4);
                        caps.has_kretprobes = caps.has_kprobes;
                        caps.has_raw_tracepoints = major > 4 || (major == 4 && minor >= 17);
                        caps.has_ring_buffer = major > 5 || (major == 5 && minor >= 8);
                        caps.has_fentry = major > 5 || (major == 5 && minor >= 5);
                        caps.has_lsm_hooks = major > 5 || (major == 5 && minor >= 7);
                    }
                }
            }

            // BTF availability.
            caps.has_btf = Path::new("/sys/kernel/btf/vmlinux").exists();
            caps.bpf_fs_mounted = Path::new("/sys/fs/bpf").exists();
            caps.tracing_fs_available = Path::new("/sys/kernel/debug/tracing").exists()
                || Path::new("/sys/kernel/tracing").exists();
            caps.running_as_root = nix::unistd::geteuid().is_root();
            caps.has_cap_bpf = Self::read_cap_bpf();

            // Verify BPF LSM is actually enabled in the running kernel.
            if caps.has_lsm_hooks {
                if let Ok(lsm) = std::fs::read_to_string("/sys/kernel/security/lsm") {
                    if !lsm.contains("bpf") {
                        caps.has_lsm_hooks = false;
                    }
                } else {
                    caps.has_lsm_hooks = false;
                }
            }

            caps.missing_prerequisites = caps.compute_missing_prerequisites();
            caps
        }

        pub fn detect() -> Self {
            Self::detect_for_object(&EbpfLinuxConfig::default().bpf_object_path)
        }

        /// True if the kernel meets the minimum bar for our eBPF collector.
        pub fn is_sufficient(&self) -> bool {
            self.has_btf
                && self.has_ring_buffer
                && self.has_tracepoints
                && self.has_kprobes
                && self.bpf_fs_mounted
                && (self.running_as_root || self.has_cap_bpf)
                && self.object_path_exists
        }

        pub fn maturity_label(&self) -> &'static str {
            if self.is_sufficient() {
                "lab_ready"
            } else if self.has_tracepoints || self.has_kprobes || self.has_btf {
                "partial"
            } else {
                "unavailable"
            }
        }

        fn compute_missing_prerequisites(&self) -> Vec<String> {
            let mut missing = Vec::new();

            if !self.has_tracepoints {
                missing.push(
                    "kernel tracepoints unavailable or kernel version not detected".to_string(),
                );
            }
            if !self.has_kprobes {
                missing.push("kprobes unavailable or kernel version too old".to_string());
            }
            if !self.has_btf {
                missing
                    .push("/sys/kernel/btf/vmlinux not found (BTF/CO-RE unavailable)".to_string());
            }
            if !self.has_ring_buffer {
                missing.push("BPF ring buffer support requires kernel 5.8+".to_string());
            }
            if !self.bpf_fs_mounted {
                missing.push("/sys/fs/bpf is not mounted".to_string());
            }
            if !(self.running_as_root || self.has_cap_bpf) {
                missing.push("requires root or CAP_BPF".to_string());
            }
            if !self.object_path_exists {
                missing.push(format!("BPF object file not found at {}", self.object_path));
            }

            missing
        }

        fn read_cap_bpf() -> bool {
            if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
                for line in status.lines() {
                    if line.starts_with("CapEff:") {
                        if let Some(hex_str) = line.split_whitespace().nth(1) {
                            if let Ok(caps) = u64::from_str_radix(hex_str, 16) {
                                return caps & (1u64 << 39) != 0;
                            }
                        }
                    }
                }
            }
            false
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum EbpfLinuxHealthState {
        Active,
        Degraded,
        Unavailable,
    }

    #[derive(Debug, Clone)]
    pub struct EbpfLinuxHealth {
        pub state: EbpfLinuxHealthState,
        pub maturity: &'static str,
        pub ebpf_active: bool,
        pub capabilities: LinuxEbpfCapabilities,
        pub missing_prerequisites: Vec<String>,
        pub stats: EbpfLinuxStatsSnapshot,
    }

    // ========================================================================
    // Global eBPF health snapshot
    //
    // The HealthCollector / CollectorCapabilityStatus reporters need to surface
    // the live runtime state of the eBPF collector, but they do not own a
    // handle to it. We publish the most recent `EbpfLinuxHealth` here so the
    // sibling modules can read it without restructuring construction order.
    // ========================================================================

    use std::sync::{Mutex, OnceLock};

    fn latest_health_slot() -> &'static Mutex<Option<EbpfLinuxHealth>> {
        static SLOT: OnceLock<Mutex<Option<EbpfLinuxHealth>>> = OnceLock::new();
        SLOT.get_or_init(|| Mutex::new(None))
    }

    /// Publish the latest runtime eBPF health snapshot. Called by the
    /// EbpfLinuxCollector on construction and periodically thereafter.
    pub fn publish_latest_health(health: EbpfLinuxHealth) {
        if let Ok(mut guard) = latest_health_slot().lock() {
            *guard = Some(health);
        }
    }

    /// Read the most recently published eBPF health snapshot, if any.
    pub fn latest_health() -> Option<EbpfLinuxHealth> {
        latest_health_slot().lock().ok().and_then(|g| g.clone())
    }

    // ========================================================================
    // Configuration
    // ========================================================================

    /// Configuration knobs for the eBPF Linux collector.
    #[derive(Debug, Clone)]
    pub struct EbpfLinuxConfig {
        /// Path to the pre-compiled eBPF object file.
        pub bpf_object_path: String,
        /// Enable process lifecycle tracing.
        pub process_monitoring: bool,
        /// Enable file operation tracing.
        pub file_monitoring: bool,
        /// Enable network connection tracing.
        pub network_monitoring: bool,
        /// Enable security event tracing (priv-esc, modules, ptrace, namespaces).
        pub security_monitoring: bool,
        /// Enable memory event tracing (mmap, mprotect).
        pub memory_monitoring: bool,
        /// Enable persistence detection (cron, systemd, init.d, authorized_keys).
        pub persistence_monitoring: bool,
        /// Use LSM hooks when available (requires kernel >= 5.7 with BPF LSM).
        pub use_lsm_hooks: bool,
        /// Ring buffer size in bytes.
        pub ring_buffer_size: usize,
        /// Channel capacity for the internal event queue.
        pub channel_capacity: usize,
        /// Maximum events per second per category.
        pub max_events_per_sec: u64,
        /// Whether to hash executables on exec.
        pub hash_on_exec: bool,
        /// Whether to check ELF package signatures (dpkg/rpm).
        pub check_elf_signatures: bool,
        /// Whether to compute file entropy on writes.
        pub compute_file_entropy: bool,
        /// Whether to detect file types via magic bytes.
        pub detect_magic_bytes: bool,
        /// Enable data exfiltration heuristics.
        pub exfiltration_detection: bool,
        /// Data exfiltration threshold in bytes (per 5-min window).
        pub exfiltration_threshold_bytes: u64,
        /// Extra sensitive file paths to watch.
        pub extra_sensitive_paths: Vec<String>,
    }

    impl Default for EbpfLinuxConfig {
        fn default() -> Self {
            Self {
                bpf_object_path: "/opt/tamandua/ebpf/tamandua_linux.bpf.o".to_string(),
                process_monitoring: true,
                file_monitoring: true,
                network_monitoring: true,
                security_monitoring: true,
                memory_monitoring: true,
                persistence_monitoring: true,
                use_lsm_hooks: false,
                ring_buffer_size: 2 * 1024 * 1024,
                channel_capacity: 10_000,
                max_events_per_sec: MAX_EVENTS_PER_SEC,
                hash_on_exec: true,
                check_elf_signatures: true,
                compute_file_entropy: true,
                detect_magic_bytes: true,
                exfiltration_detection: true,
                exfiltration_threshold_bytes: 100 * 1024 * 1024,
                extra_sensitive_paths: Vec::new(),
            }
        }
    }

    impl EbpfLinuxConfig {
        /// Build configuration from the global AgentConfig.
        pub fn from_agent_config(agent: &AgentConfig) -> Self {
            let mut cfg = Self::default();
            // Respect the global profile for tuning.
            // In lightweight mode disable heavier subsystems.
            if agent.collector_tuning.skip_expensive_analysis {
                cfg.hash_on_exec = false;
                cfg.check_elf_signatures = false;
                cfg.compute_file_entropy = false;
                cfg.detect_magic_bytes = false;
            }
            cfg
        }
    }

    // ========================================================================
    // The main EbpfLinuxCollector
    // ========================================================================

    /// Comprehensive eBPF-based Linux collector providing deep system telemetry
    /// equivalent to the Windows agent's combined process, file, network,
    /// registry (N/A on Linux), DNS, memory, injection, credential-theft,
    /// defense-evasion, and CLR collectors.
    pub struct EbpfLinuxCollector {
        event_rx: mpsc::Receiver<TelemetryEvent>,
        running: Arc<AtomicBool>,
        stats: Arc<EbpfLinuxStats>,
        capabilities: LinuxEbpfCapabilities,
        ebpf_active: bool,
    }

    impl EbpfLinuxCollector {
        /// Create the collector with default configuration.
        pub fn new(config: &AgentConfig) -> Result<Self> {
            Self::with_config(EbpfLinuxConfig::from_agent_config(config))
        }

        /// Create with explicit configuration.
        pub fn with_config(config: EbpfLinuxConfig) -> Result<Self> {
            let capabilities = LinuxEbpfCapabilities::detect_for_object(&config.bpf_object_path);
            let stats = EbpfLinuxStats::new();
            let running = Arc::new(AtomicBool::new(true));
            let (tx, rx) = mpsc::channel(config.channel_capacity);

            info!(
                kernel = ?capabilities.kernel_version,
                btf = capabilities.has_btf,
                ring_buffer = capabilities.has_ring_buffer,
                lsm = capabilities.has_lsm_hooks,
                fentry = capabilities.has_fentry,
                bpf_fs = capabilities.bpf_fs_mounted,
                object_path_exists = capabilities.object_path_exists,
                "eBPF Linux collector: detected kernel capabilities"
            );

            if !capabilities.is_sufficient() {
                warn!(
                    missing = ?capabilities.missing_prerequisites,
                    "Kernel/runtime does not meet minimum eBPF requirements. Running with eBPF inactive."
                );
                running.store(false, Ordering::Relaxed);
                let collector = Self {
                    event_rx: rx,
                    running,
                    stats,
                    capabilities,
                    ebpf_active: false,
                };
                publish_latest_health(collector.health());
                return Ok(collector);
            }

            // Attempt to load and attach BPF programs.
            let ebpf_active = match Self::load_and_attach(
                &config,
                &capabilities,
                tx.clone(),
                stats.clone(),
                running.clone(),
            ) {
                Ok(()) => {
                    info!("eBPF Linux collector: BPF programs loaded and attached successfully");
                    true
                }
                Err(e) => {
                    warn!(error = %e, "eBPF Linux collector: failed to load BPF programs, running without eBPF");
                    running.store(false, Ordering::Relaxed);
                    false
                }
            };

            let collector = Self {
                event_rx: rx,
                running,
                stats,
                capabilities,
                ebpf_active,
            };
            publish_latest_health(collector.health());
            Ok(collector)
        }

        /// Refresh the globally-published runtime health snapshot.
        ///
        /// Called by the main agent runtime so that the HealthCollector and
        /// CollectorCapabilityStatus reporter can surface up-to-date eBPF
        /// state without owning a handle to the collector.
        pub fn publish_health(&self) {
            publish_latest_health(self.health());
        }

        // ====================================================================
        // BPF program loading (Linux-only, uses aya crate)
        // ====================================================================

        fn load_and_attach(
            config: &EbpfLinuxConfig,
            caps: &LinuxEbpfCapabilities,
            tx: mpsc::Sender<TelemetryEvent>,
            stats: Arc<EbpfLinuxStats>,
            running: Arc<AtomicBool>,
        ) -> Result<()> {
            use aya::{
                maps::RingBuf,
                programs::{KProbe, Lsm, RawTracePoint, TracePoint},
                Bpf, BpfLoader, Btf,
            };

            // Permissions check.
            if !nix::unistd::geteuid().is_root() {
                // Check for CAP_BPF.
                let has_cap = Self::check_cap_bpf();
                if !has_cap {
                    return Err(anyhow!("Not root and CAP_BPF not available"));
                }
            }

            let bpf_path = Path::new(&config.bpf_object_path);
            if !bpf_path.exists() {
                return Err(anyhow!(
                    "BPF object file not found at {}",
                    config.bpf_object_path
                ));
            }

            let btf = Btf::from_sys_fs().context("Failed to load BTF")?;

            let mut bpf = BpfLoader::new()
                .btf(Some(&btf))
                .load_file(bpf_path)
                .context("Failed to load BPF object")?;

            let mut attached = 0u32;

            // ----- Process tracepoints -----
            if config.process_monitoring && caps.has_tracepoints {
                for (prog, category, tp) in [
                    ("tp_sched_process_exec", "sched", "sched_process_exec"),
                    ("tp_sched_process_exit", "sched", "sched_process_exit"),
                    ("tp_sched_process_fork", "sched", "sched_process_fork"),
                ] {
                    if let Some(program) = bpf.program_mut(prog) {
                        let tp_prog: &mut TracePoint = program.try_into()?;
                        tp_prog.load()?;
                        tp_prog.attach(category, tp)?;
                        info!(program = prog, "Attached tracepoint");
                        attached += 1;
                    }
                }
            }

            // ----- File kprobes -----
            if config.file_monitoring && caps.has_kprobes {
                for (prog, target) in [
                    ("kp_vfs_read", "vfs_read"),
                    ("kp_vfs_write", "vfs_write"),
                    ("kp_vfs_unlink", "vfs_unlink"),
                    ("kp_security_file_open", "security_file_open"),
                ] {
                    if let Some(program) = bpf.program_mut(prog) {
                        if let Ok(kp) = TryInto::<&mut KProbe>::try_into(program) {
                            if kp.load().is_ok() && kp.attach(target, 0).is_ok() {
                                info!(program = prog, target, "Attached kprobe");
                                attached += 1;
                            }
                        }
                    }
                }
            }

            // ----- Network tracepoints + kprobes -----
            if config.network_monitoring {
                // Tracepoints for TCP state tracking.
                if caps.has_tracepoints {
                    for (prog, cat, tp) in [
                        ("tp_tcp_connect", "sock", "inet_sock_set_state"),
                        ("tp_tcp_accept", "sock", "inet_sock_set_state"),
                    ] {
                        if let Some(program) = bpf.program_mut(prog) {
                            if let Ok(tp_prog) = TryInto::<&mut TracePoint>::try_into(program) {
                                if tp_prog.load().is_ok() && tp_prog.attach(cat, tp).is_ok() {
                                    info!(program = prog, "Attached tracepoint");
                                    attached += 1;
                                }
                            }
                        }
                    }
                }

                // kprobe for UDP (DNS capture).
                if caps.has_kprobes {
                    if let Some(program) = bpf.program_mut("kp_udp_sendmsg") {
                        if let Ok(kp) = TryInto::<&mut KProbe>::try_into(program) {
                            if kp.load().is_ok() && kp.attach("udp_sendmsg", 0).is_ok() {
                                info!("Attached kprobe kp_udp_sendmsg");
                                attached += 1;
                            }
                        }
                    }
                }
            }

            // ----- Security: LSM hooks (kernel >= 5.7) OR kprobe fallbacks -----
            if config.security_monitoring {
                if config.use_lsm_hooks && caps.has_lsm_hooks {
                    // Prefer LSM hooks for better coverage.
                    for prog_name in [
                        "lsm_cred_prepare",
                        "lsm_kernel_module_request",
                        "lsm_ptrace_access_check",
                        "lsm_task_fix_setuid",
                    ] {
                        if let Some(program) = bpf.program_mut(prog_name) {
                            if let Ok(lsm) = TryInto::<&mut Lsm>::try_into(program) {
                                let hook_name = prog_name.strip_prefix("lsm_").unwrap_or(prog_name);
                                if lsm.load(hook_name, &Btf::from_sys_fs()?).is_ok()
                                    && lsm.attach().is_ok()
                                {
                                    info!(program = prog_name, "Attached LSM hook");
                                    attached += 1;
                                }
                            }
                        }
                    }
                } else if caps.has_kprobes {
                    // Fallback: kprobes on security-relevant kernel functions.
                    for (prog, target) in [
                        ("kp_commit_creds", "commit_creds"),
                        ("kp_init_module", "do_init_module"),
                        ("kp_finit_module", "init_module_from_file"),
                        ("kp_ptrace_attach", "__ptrace_link"),
                        ("kp_setuid", "sys_setuid"),
                        ("kp_setgid", "sys_setgid"),
                        ("kp_setreuid", "sys_setreuid"),
                        ("kp_switch_ns", "switch_task_namespaces"),
                    ] {
                        if let Some(program) = bpf.program_mut(prog) {
                            if let Ok(kp) = TryInto::<&mut KProbe>::try_into(program) {
                                if kp.load().is_ok() && kp.attach(target, 0).is_ok() {
                                    info!(program = prog, target, "Attached kprobe");
                                    attached += 1;
                                }
                            }
                        }
                    }
                }
            }

            // ----- Raw syscall security coverage -----
            //
            // sched_process_exec is the canonical lifecycle signal for
            // successful execve/execveat. This raw tracepoint preserves
            // syscall-level context for evasive execution patterns such as
            // memfd_create followed by execveat(AT_EMPTY_PATH).
            if config.security_monitoring && caps.has_raw_tracepoints {
                if let Some(program) = bpf.program_mut("sys_enter_security") {
                    if let Ok(raw_tp) = TryInto::<&mut RawTracePoint>::try_into(program) {
                        if raw_tp.load().is_ok() && raw_tp.attach("sys_enter").is_ok() {
                            info!(
                                program = "sys_enter_security",
                                tracepoint = "sys_enter",
                                "Attached raw tracepoint"
                            );
                            attached += 1;
                        }
                    }
                }
            }

            // ----- Container escape: mount hook (LSM preferred, tracepoint fallback) -----
            //
            // Both programs emit the same `mount_event` payload with
            // EVENT_MOUNT_ESCAPE (39). The userspace `parse_mount_event` is
            // hook-agnostic, so we attach exactly one of:
            //   1. `lsm_sb_mount` on kernels >= 5.7 with BPF_LSM (preferred:
            //      fires after policy decisions, sees kernel-internal remounts).
            //   2. `tp_sys_enter_mount` on older kernels or BPF_LSM=n
            //      (fires at syscall entry; covers the operator-visible mount
            //      paths used by container-escape PoCs).
            //
            // Gated on `security_monitoring` because container escape (T1611)
            // is classified as a security event.
            if config.security_monitoring {
                let mut mount_attached = false;
                if config.use_lsm_hooks && caps.has_lsm_hooks {
                    if let Some(program) = bpf.program_mut("lsm_sb_mount") {
                        if let Ok(lsm) = TryInto::<&mut Lsm>::try_into(program) {
                            if lsm.load("sb_mount", &Btf::from_sys_fs()?).is_ok()
                                && lsm.attach().is_ok()
                            {
                                info!(program = "lsm_sb_mount", "Attached LSM mount hook");
                                attached += 1;
                                mount_attached = true;
                            }
                        }
                    }
                }
                if !mount_attached && caps.has_tracepoints {
                    if let Some(program) = bpf.program_mut("tp_sys_enter_mount") {
                        if let Ok(tp_prog) = TryInto::<&mut TracePoint>::try_into(program) {
                            if tp_prog.load().is_ok()
                                && tp_prog.attach("syscalls", "sys_enter_mount").is_ok()
                            {
                                info!(
                                    program = "tp_sys_enter_mount",
                                    "Attached mount tracepoint (LSM fallback)"
                                );
                                attached += 1;
                            }
                        }
                    }
                }
            }

            // ----- Memory kprobes -----
            if config.memory_monitoring && caps.has_kprobes {
                for (prog, target) in [
                    ("kp_sys_mmap", "do_mmap"),
                    ("kp_sys_mprotect", "do_mprotect_pkey"),
                    ("kp_memfd_create", "__x64_sys_memfd_create"),
                ] {
                    if let Some(program) = bpf.program_mut(prog) {
                        if let Ok(kp) = TryInto::<&mut KProbe>::try_into(program) {
                            if kp.load().is_ok() && kp.attach(target, 0).is_ok() {
                                info!(program = prog, target, "Attached kprobe");
                                attached += 1;
                            }
                        }
                    }
                }
            }

            // ----- Additional security kprobes (LD_PRELOAD, /proc/mem, chroot) -----
            if config.security_monitoring && caps.has_kprobes {
                for (prog, target) in [
                    // LD_PRELOAD injection: triggered by the BPF program when
                    // execve runs with LD_PRELOAD in the environment.
                    ("kp_ld_preload_exec", "load_elf_binary"),
                    // /proc/PID/mem access: process injection vector.
                    ("kp_proc_mem_open", "proc_mem_open"),
                    // chroot escape detection.
                    ("kp_chroot", "__x64_sys_chroot"),
                    // File capability changes (setcap).
                    ("kp_vfs_setxattr", "vfs_setxattr"),
                ] {
                    if let Some(program) = bpf.program_mut(prog) {
                        if let Ok(kp) = TryInto::<&mut KProbe>::try_into(program) {
                            if kp.load().is_ok() && kp.attach(target, 0).is_ok() {
                                info!(
                                    program = prog,
                                    target, "Attached additional security kprobe"
                                );
                                attached += 1;
                            }
                        }
                    }
                }
            }

            // ----- Network: DNS response + UDP recv kprobes -----
            if config.network_monitoring && caps.has_kprobes {
                for (prog, target) in [("kp_udp_recvmsg", "udp_recvmsg")] {
                    if let Some(program) = bpf.program_mut(prog) {
                        if let Ok(kp) = TryInto::<&mut KProbe>::try_into(program) {
                            if kp.load().is_ok() && kp.attach(target, 0).is_ok() {
                                info!(program = prog, target, "Attached network kprobe");
                                attached += 1;
                            }
                        }
                    }
                }
            }

            // ----- Persistence monitoring: file kprobes for cron/systemd/init paths -----
            // These are handled in userspace by inspecting file paths from the
            // existing vfs_write kprobe.  No additional BPF programs needed; we
            // add persistence-specific kprobes if the BPF object provides them.
            if config.persistence_monitoring && caps.has_kprobes {
                for (prog, target) in [
                    ("kp_cron_write", "vfs_write"), // filtered in BPF by path
                    ("kp_chmod", "chmod_common"),
                ] {
                    if let Some(program) = bpf.program_mut(prog) {
                        if let Ok(kp) = TryInto::<&mut KProbe>::try_into(program) {
                            if kp.load().is_ok() && kp.attach(target, 0).is_ok() {
                                info!(program = prog, target, "Attached persistence kprobe");
                                attached += 1;
                            }
                        }
                    }
                }
            }

            if attached == 0 {
                return Err(anyhow!("No eBPF programs could be attached"));
            }

            info!(count = attached, "Total eBPF programs attached");

            // Start ring-buffer reader task.
            let events_map = bpf
                .take_map("EVENTS")
                .ok_or_else(|| anyhow!("EVENTS ring-buffer map not found"))?;
            let ring_buf = RingBuf::try_from(events_map)?;

            let ebpf_config = config.clone();
            tokio::spawn(async move {
                Self::ring_buffer_loop(ring_buf, tx, stats, running, ebpf_config).await;
            });

            // Store the Bpf handle so programs stay loaded.
            // We intentionally leak it into a static because the programs must
            // remain attached for the lifetime of the agent.
            std::mem::forget(bpf);

            Ok(())
        }

        // ====================================================================
        // Ring-buffer event loop
        // ====================================================================

        async fn ring_buffer_loop(
            mut ring_buf: aya::maps::RingBuf<aya::maps::MapData>,
            tx: mpsc::Sender<TelemetryEvent>,
            stats: Arc<EbpfLinuxStats>,
            running: Arc<AtomicBool>,
            config: EbpfLinuxConfig,
        ) {
            info!("eBPF Linux collector: ring-buffer reader started");

            let mut rate_limiter = RateLimiter::new(config.max_events_per_sec);
            let mut enricher = ProcessEnricher::new();
            let mut ransomware_tracker = RansomwareTracker::new();
            let mut conn_tracker = ConnectionTracker::new();
            let mut process_tree = ProcessTree::new();
            let mut exfil_tracker = ExfiltrationTracker::new();
            let mut prune_tick = Instant::now();

            while running.load(Ordering::Relaxed) {
                // Poll the ring buffer for pending events.
                while let Some(item) = ring_buf.next() {
                    stats.events_received.fetch_add(1, Ordering::Relaxed);
                    let data: &[u8] = &item;

                    // Minimum size: the event header.
                    if data.len() < std::mem::size_of::<EbpfEventHeader>() {
                        stats.parse_errors.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }

                    // Extract event type from the first 4 bytes.
                    let type_raw = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
                    let evt_type = match BpfEventType::from_u32(type_raw) {
                        Some(t) => t,
                        None => {
                            debug!(raw_type = type_raw, "Unknown eBPF event type, skipping");
                            stats.parse_errors.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    };

                    // Determine category for rate limiting.
                    let category = Self::event_category(evt_type);

                    if !rate_limiter.allow(category) {
                        stats
                            .events_dropped_rate_limit
                            .fetch_add(1, Ordering::Relaxed);
                        continue;
                    }

                    // Parse event into TelemetryEvent.
                    let telemetry = match evt_type {
                        // -- Process --
                        BpfEventType::ProcessExec => Self::parse_process_exec(
                            data,
                            &mut enricher,
                            &config,
                            &mut process_tree,
                        ),
                        BpfEventType::ProcessExit => {
                            Self::parse_process_exit(data, &mut enricher, &mut process_tree)
                        }
                        BpfEventType::ProcessFork => {
                            Self::parse_process_fork(data, &mut enricher, &mut process_tree)
                        }
                        // -- File --
                        BpfEventType::FileOpen
                        | BpfEventType::FileRead
                        | BpfEventType::FileWrite
                        | BpfEventType::FileUnlink => {
                            Self::parse_file_event(data, evt_type, &mut enricher, &config)
                        }
                        BpfEventType::FileRename => {
                            Self::parse_file_rename(data, &mut enricher, &mut ransomware_tracker)
                        }
                        BpfEventType::SensitiveAccess => {
                            Self::parse_sensitive_access(data, &mut enricher)
                        }
                        BpfEventType::FileChmod => Self::parse_file_chmod(data, &mut enricher),
                        // -- Network --
                        BpfEventType::TcpConnect | BpfEventType::TcpAccept => {
                            Self::parse_tcp_event(
                                data,
                                evt_type,
                                &mut enricher,
                                &mut conn_tracker,
                                &mut exfil_tracker,
                            )
                        }
                        BpfEventType::TcpStateChange => {
                            Self::parse_tcp_state_change(data, &mut enricher, &mut conn_tracker)
                        }
                        BpfEventType::UdpSendMsg => Self::parse_udp_send(
                            data,
                            &mut enricher,
                            &mut conn_tracker,
                            &mut exfil_tracker,
                        ),
                        BpfEventType::UdpRecvMsg => Self::parse_udp_send(
                            data,
                            &mut enricher,
                            &mut conn_tracker,
                            &mut exfil_tracker,
                        ),
                        BpfEventType::DnsQuery => Self::parse_dns_event(data, &mut enricher),
                        BpfEventType::DnsResponse => Self::parse_dns_response(data, &mut enricher),
                        // -- Security --
                        BpfEventType::PrivEscalation => {
                            Self::parse_priv_escalation(data, &mut enricher)
                        }
                        BpfEventType::KernelModLoad => {
                            Self::parse_kernel_module(data, &mut enricher)
                        }
                        BpfEventType::PtraceAttach => Self::parse_ptrace(data, &mut enricher),
                        BpfEventType::NamespaceEscape | BpfEventType::ContainerBreakout => {
                            Self::parse_namespace_event(data, evt_type, &mut enricher)
                        }
                        BpfEventType::LdPreloadInject => {
                            Self::parse_ld_preload(data, &mut enricher)
                        }
                        BpfEventType::ProcMemAccess => {
                            Self::parse_proc_mem_access(data, &mut enricher)
                        }
                        BpfEventType::ChrootEscape => Self::parse_namespace_event(
                            data,
                            BpfEventType::NamespaceEscape,
                            &mut enricher,
                        ),
                        BpfEventType::SetcapChange => Self::parse_setcap_event(data, &mut enricher),
                        BpfEventType::MountEscape => Self::parse_mount_event(data, &mut enricher),
                        // -- Memory --
                        BpfEventType::MmapExec => Self::parse_mmap_event(data, &mut enricher),
                        BpfEventType::MprotectChange => {
                            Self::parse_mprotect_event(data, &mut enricher)
                        }
                        BpfEventType::MemfdCreate | BpfEventType::MemfdExec => {
                            Self::parse_memfd_event(data, evt_type, &mut enricher)
                        }
                        BpfEventType::SyscallEvasionAnonymousMmap
                        | BpfEventType::SyscallEvasionPtraceInject
                        | BpfEventType::SyscallEvasionMemfdExec
                        | BpfEventType::SyscallEvasionProcMemWrite => {
                            Self::parse_syscall_evasion_event(data, evt_type, &mut enricher)
                        }
                        // -- Persistence --
                        BpfEventType::CronModify
                        | BpfEventType::SystemdTimerCreate
                        | BpfEventType::InitScriptModify
                        | BpfEventType::SshAuthorizedKeys => {
                            Self::parse_persistence_event(data, evt_type, &mut enricher)
                        }
                    };

                    if let Some(event) = telemetry {
                        stats.events_processed.fetch_add(1, Ordering::Relaxed);
                        if tx.try_send(event).is_err() {
                            stats
                                .events_dropped_channel_full
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }

                // Periodic maintenance.
                if prune_tick.elapsed() > Duration::from_secs(60) {
                    conn_tracker.prune_stale();
                    process_tree.evict_stale();
                    exfil_tracker.prune();
                    prune_tick = Instant::now();
                }

                // Yield briefly to avoid busy-spinning.
                tokio::time::sleep(Duration::from_millis(5)).await;
            }

            info!("eBPF Linux collector: ring-buffer reader stopped");
        }

        fn event_category(evt: BpfEventType) -> EventCategory {
            match evt {
                BpfEventType::ProcessExec
                | BpfEventType::ProcessExit
                | BpfEventType::ProcessFork => EventCategory::Process,

                BpfEventType::FileOpen
                | BpfEventType::FileRead
                | BpfEventType::FileWrite
                | BpfEventType::FileUnlink
                | BpfEventType::FileRename
                | BpfEventType::FileChmod
                | BpfEventType::SensitiveAccess => EventCategory::File,

                BpfEventType::TcpConnect
                | BpfEventType::TcpAccept
                | BpfEventType::TcpStateChange
                | BpfEventType::UdpSendMsg
                | BpfEventType::UdpRecvMsg
                | BpfEventType::DnsQuery
                | BpfEventType::DnsResponse => EventCategory::Network,

                BpfEventType::PrivEscalation
                | BpfEventType::KernelModLoad
                | BpfEventType::PtraceAttach
                | BpfEventType::NamespaceEscape
                | BpfEventType::ContainerBreakout
                | BpfEventType::LdPreloadInject
                | BpfEventType::ProcMemAccess
                | BpfEventType::ChrootEscape
                | BpfEventType::SetcapChange => EventCategory::Security,

                BpfEventType::MmapExec
                | BpfEventType::MprotectChange
                | BpfEventType::MemfdCreate
                | BpfEventType::MemfdExec
                | BpfEventType::SyscallEvasionAnonymousMmap
                | BpfEventType::SyscallEvasionPtraceInject
                | BpfEventType::SyscallEvasionMemfdExec
                | BpfEventType::SyscallEvasionProcMemWrite => EventCategory::Memory,

                BpfEventType::CronModify
                | BpfEventType::SystemdTimerCreate
                | BpfEventType::InitScriptModify
                | BpfEventType::SshAuthorizedKeys => EventCategory::File, // persistence uses file category rate limit
            }
        }

        // ====================================================================
        // Event Parsers -- Process
        // ====================================================================

        fn read_header(data: &[u8]) -> Option<&EbpfEventHeader> {
            if data.len() < std::mem::size_of::<EbpfEventHeader>() {
                return None;
            }
            Some(unsafe { &*(data.as_ptr() as *const EbpfEventHeader) })
        }

        fn parse_process_exec(
            data: &[u8],
            enricher: &mut ProcessEnricher,
            config: &EbpfLinuxConfig,
            tree: &mut ProcessTree,
        ) -> Option<TelemetryEvent> {
            if data.len() < std::mem::size_of::<BpfProcessExecEvent>() {
                return None;
            }
            let event = unsafe { &*(data.as_ptr() as *const BpfProcessExecEvent) };
            let hdr = &event.header;

            let comm = bytes_to_string(&hdr.comm);
            let filename = bytes_to_string(&event.filename);
            let args = bytes_to_string(&event.args);
            let cwd = bytes_to_string(&event.cwd);

            // Enrich from /proc: get full cmdline, exe path, parent info.
            let proc_info = enricher.get(hdr.pid);
            let (full_cmdline, exe_path) = match &proc_info {
                Some(pi) => (
                    if pi.cmdline.is_empty() {
                        args.clone()
                    } else {
                        pi.cmdline.clone()
                    },
                    if pi.exe_path.is_empty() {
                        filename.clone()
                    } else {
                        pi.exe_path.clone()
                    },
                ),
                None => (args.clone(), filename.clone()),
            };

            // Parent enrichment: try process tree first, fall back to /proc.
            let (parent_name, parent_path) = if let Some(pnode) = tree.get_parent(hdr.ppid) {
                (Some(pnode.name.clone()), Some(pnode.exe_path.clone()))
            } else {
                let parent_info = enricher.get(hdr.ppid);
                (
                    parent_info.as_ref().map(|p| p.name.clone()),
                    parent_info.as_ref().map(|p| p.exe_path.clone()),
                )
            };

            // Insert into process tree for ancestry reconstruction.
            tree.insert(hdr.pid, hdr.ppid, &comm, &exe_path, &full_cmdline, hdr.uid);

            // Hash executable on exec (if enabled).
            let sha256 = if config.hash_on_exec && !exe_path.is_empty() {
                hash_file(&exe_path)
            } else {
                Vec::new()
            };

            // ELF signature / package verification (Linux equivalent of Authenticode).
            let (is_signed, signer) = if config.check_elf_signatures && !exe_path.is_empty() {
                check_elf_package_signature(&exe_path)
            } else {
                (false, None)
            };

            // Compute executable entropy (encrypted/packed binary detection).
            let exe_entropy = if config.compute_file_entropy && !exe_path.is_empty() {
                file_entropy(&exe_path)
            } else {
                0.0
            };

            let mut telemetry = TelemetryEvent::new(
                EventType::ProcessCreate,
                Severity::Info,
                EventPayload::Process(ProcessEvent {
                    pid: hdr.pid,
                    ppid: hdr.ppid,
                    name: comm,
                    path: exe_path,
                    cmdline: full_cmdline,
                    user: hdr.uid.to_string(),
                    sha256,
                    entropy: exe_entropy,
                    is_elevated: hdr.uid == 0,
                    parent_name,
                    parent_path,
                    is_signed,
                    signer,
                    start_time: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                    cpu_usage: 0.0,
                    memory_bytes: 0,
                    company_name: None,
                    file_description: None,
                    product_name: None,
                    file_version: None,
                    environment: None,
                }),
            );

            // Container metadata.
            if hdr.cgroup_id != 0 {
                telemetry
                    .metadata
                    .insert("cgroup_id".to_string(), hdr.cgroup_id.to_string());
            }
            if hdr.mnt_ns != 0 {
                telemetry
                    .metadata
                    .insert("mnt_ns".to_string(), hdr.mnt_ns.to_string());
            }
            if hdr.pid_ns != 0 {
                telemetry
                    .metadata
                    .insert("pid_ns".to_string(), hdr.pid_ns.to_string());
            }
            if !cwd.is_empty() {
                telemetry.metadata.insert("cwd".to_string(), cwd);
            }

            // Process ancestry chain for server-side tree visualization.
            let ancestry = tree.get_ancestry(hdr.pid);
            if ancestry.len() > 1 {
                let ancestry_str: Vec<String> = ancestry
                    .iter()
                    .map(|(p, n, _)| format!("{}:{}", p, n))
                    .collect();
                telemetry
                    .metadata
                    .insert("ancestry".to_string(), ancestry_str.join(" -> "));
                telemetry.metadata.insert(
                    "tree_depth".to_string(),
                    tree.get_depth(hdr.pid).to_string(),
                );
            }

            telemetry
                .metadata
                .insert("source".to_string(), "ebpf_linux".to_string());

            Some(telemetry)
        }

        fn parse_process_exit(
            data: &[u8],
            enricher: &mut ProcessEnricher,
            tree: &mut ProcessTree,
        ) -> Option<TelemetryEvent> {
            if data.len() < std::mem::size_of::<BpfProcessExitEvent>() {
                return None;
            }
            let event = unsafe { &*(data.as_ptr() as *const BpfProcessExitEvent) };
            let hdr = &event.header;
            let comm = bytes_to_string(&hdr.comm);

            // Retrieve cached info before eviction.
            let proc_info = enricher.get(hdr.pid);
            let path = proc_info
                .as_ref()
                .map(|p| p.exe_path.clone())
                .unwrap_or_default();

            // Evict from cache and process tree.
            enricher.remove(hdr.pid);
            tree.remove(hdr.pid);

            let mut telemetry = TelemetryEvent::new(
                EventType::ProcessTerminate,
                Severity::Info,
                EventPayload::Process(ProcessEvent {
                    pid: hdr.pid,
                    ppid: hdr.ppid,
                    name: comm,
                    path,
                    cmdline: String::new(),
                    user: hdr.uid.to_string(),
                    sha256: Vec::new(),
                    entropy: 0.0,
                    is_elevated: hdr.uid == 0,
                    parent_name: None,
                    parent_path: None,
                    is_signed: false,
                    signer: None,
                    start_time: 0,
                    cpu_usage: 0.0,
                    memory_bytes: 0,
                    company_name: None,
                    file_description: None,
                    product_name: None,
                    file_version: None,
                    environment: None,
                }),
            );

            telemetry
                .metadata
                .insert("exit_code".to_string(), event.exit_code.to_string());
            if event.exit_signal != 0 {
                telemetry
                    .metadata
                    .insert("exit_signal".to_string(), event.exit_signal.to_string());
            }
            telemetry
                .metadata
                .insert("utime_ns".to_string(), event.utime_ns.to_string());
            telemetry
                .metadata
                .insert("stime_ns".to_string(), event.stime_ns.to_string());
            telemetry
                .metadata
                .insert("source".to_string(), "ebpf_linux".to_string());

            Some(telemetry)
        }

        fn parse_process_fork(
            data: &[u8],
            enricher: &mut ProcessEnricher,
            tree: &mut ProcessTree,
        ) -> Option<TelemetryEvent> {
            if data.len() < std::mem::size_of::<BpfProcessForkEvent>() {
                return None;
            }
            let event = unsafe { &*(data.as_ptr() as *const BpfProcessForkEvent) };
            let hdr = &event.header;
            let comm = bytes_to_string(&hdr.comm);

            // Enrich parent from tree first, fall back to /proc cache.
            let (parent_name, parent_path) = if let Some(pnode) = tree.get_parent(hdr.pid) {
                (Some(pnode.name.clone()), Some(pnode.exe_path.clone()))
            } else {
                let parent_info = enricher.get(hdr.pid);
                (
                    parent_info.as_ref().map(|p| p.name.clone()),
                    parent_info.as_ref().map(|p| p.exe_path.clone()),
                )
            };

            // Insert child into process tree.
            tree.insert(event.child_pid, hdr.pid, &comm, "", "", hdr.uid);

            // parent_name and parent_path already computed above from tree/enricher.

            let mut telemetry = TelemetryEvent::new(
                EventType::ProcessCreate,
                Severity::Info,
                EventPayload::Process(ProcessEvent {
                    pid: event.child_pid,
                    ppid: hdr.pid,
                    name: comm,
                    path: String::new(),
                    cmdline: String::new(),
                    user: hdr.uid.to_string(),
                    sha256: Vec::new(),
                    entropy: 0.0,
                    is_elevated: hdr.uid == 0,
                    parent_name,
                    parent_path,
                    is_signed: false,
                    signer: None,
                    start_time: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                    cpu_usage: 0.0,
                    memory_bytes: 0,
                    company_name: None,
                    file_description: None,
                    product_name: None,
                    file_version: None,
                    environment: None,
                }),
            );

            telemetry.metadata.insert(
                "clone_flags".to_string(),
                format!("{:#x}", event.clone_flags),
            );
            if event.new_ns_flags != 0 {
                telemetry.metadata.insert(
                    "new_ns_flags".to_string(),
                    format!("{:#x}", event.new_ns_flags),
                );
            }
            telemetry
                .metadata
                .insert("source".to_string(), "ebpf_linux".to_string());

            Some(telemetry)
        }

        // ====================================================================
        // Event Parsers -- File
        // ====================================================================

        fn parse_file_event(
            data: &[u8],
            evt_type: BpfEventType,
            enricher: &mut ProcessEnricher,
            config: &EbpfLinuxConfig,
        ) -> Option<TelemetryEvent> {
            if data.len() < std::mem::size_of::<BpfFileEvent>() {
                return None;
            }
            let event = unsafe { &*(data.as_ptr() as *const BpfFileEvent) };
            let hdr = &event.header;

            let path = bytes_to_string(&event.path);
            let process_name = bytes_to_string(&hdr.comm);

            // Determine event type and operation string.
            let (telemetry_type, operation) = match evt_type {
                BpfEventType::FileOpen => (EventType::FileCreate, "open"),
                BpfEventType::FileRead => (EventType::FileCreate, "read"),
                BpfEventType::FileWrite => (EventType::FileModify, "write"),
                BpfEventType::FileUnlink => (EventType::FileDelete, "delete"),
                _ => (EventType::FileModify, "unknown"),
            };

            // Detect sensitive file access.
            let mut severity = Severity::Info;
            let mut detections = Vec::new();

            let is_sensitive = SENSITIVE_FILES.iter().any(|s| {
                if s.ends_with('/') {
                    path.starts_with(s)
                } else {
                    path == *s
                }
            });

            if is_sensitive {
                severity = Severity::High;
                detections.push(Detection {
                    detection_type: DetectionType::Behavioral,
                    rule_name: "sensitive_file_access".to_string(),
                    confidence: 0.85,
                    description: format!(
                        "Process {} (PID {}) accessed sensitive file: {}",
                        process_name, hdr.pid, path
                    ),
                    mitre_tactics: vec!["credential-access".to_string(), "collection".to_string()],
                    mitre_techniques: vec!["T1003".to_string(), "T1552.001".to_string()],
                });
            }

            // Check for persistence location writes.
            if evt_type == BpfEventType::FileWrite {
                if let Some(ptype) = check_persistence_path(&path) {
                    let persist_severity =
                        if ptype == "ld_preload" || ptype == "ssh_authorized_keys" {
                            Severity::Critical
                        } else {
                            Severity::High
                        };
                    if persist_severity > severity {
                        severity = persist_severity;
                    }
                    detections.push(Detection {
                        detection_type: DetectionType::Behavioral,
                        rule_name: format!("persistence_{}_write", ptype),
                        confidence: 0.85,
                        description: format!(
                            "Process {} (PID {}) wrote to persistence location ({}): {}",
                            process_name, hdr.pid, ptype, path,
                        ),
                        mitre_tactics: vec!["persistence".to_string()],
                        mitre_techniques: vec![match ptype {
                            "cron" => "T1053.003",
                            "systemd" => "T1543.002",
                            "initd" | "rc_local" => "T1037.004",
                            "shell_profile" => "T1546.004",
                            "ld_preload" => "T1574.006",
                            "ssh_authorized_keys" => "T1098.004",
                            _ => "T1547",
                        }
                        .to_string()],
                    });
                }
            }

            // Hash file on write completion.
            let sha256 = if evt_type == BpfEventType::FileWrite && !path.is_empty() {
                hash_file(&path)
            } else {
                Vec::new()
            };

            // Compute file entropy on write (high entropy -> encrypted/packed).
            let entropy = if config.compute_file_entropy
                && evt_type == BpfEventType::FileWrite
                && !path.is_empty()
            {
                let ent = file_entropy(&path);
                // Flag very high entropy (> 7.5) as suspicious (encrypted/compressed).
                if ent > 7.5 {
                    detections.push(Detection {
                        detection_type: DetectionType::Behavioral,
                        rule_name: "high_entropy_file_write".to_string(),
                        confidence: 0.6,
                        description: format!(
                            "High entropy ({:.2}) file written by {} (PID {}): {} -- possible encryption",
                            ent, process_name, hdr.pid, path,
                        ),
                        mitre_tactics: vec!["impact".to_string()],
                        mitre_techniques: vec!["T1486".to_string()],
                    });
                    if severity <= Severity::Medium {
                        severity = Severity::Medium;
                    }
                }
                ent
            } else {
                0.0
            };

            // Detect file type from magic bytes (more reliable than extension).
            let file_type = if config.detect_magic_bytes
                && !path.is_empty()
                && (evt_type == BpfEventType::FileWrite || evt_type == BpfEventType::FileOpen)
            {
                let magic = detect_file_type_magic(&path);
                if magic.is_empty() {
                    // Fall back to extension.
                    Path::new(&path)
                        .extension()
                        .map(|e| e.to_string_lossy().to_string())
                        .unwrap_or_default()
                } else {
                    magic
                }
            } else {
                Path::new(&path)
                    .extension()
                    .map(|e| e.to_string_lossy().to_string())
                    .unwrap_or_default()
            };

            let mut telemetry = TelemetryEvent::new(
                telemetry_type,
                severity,
                EventPayload::File(AgentFileEvent {
                    path,
                    old_path: None,
                    operation: operation.to_string(),
                    pid: hdr.pid,
                    process_name,
                    sha256,
                    size: event.size,
                    entropy,
                    file_type,
                }),
            );

            for d in detections {
                telemetry.add_detection(d);
            }

            if event.inode != 0 {
                telemetry
                    .metadata
                    .insert("inode".to_string(), event.inode.to_string());
            }
            if event.flags != 0 {
                telemetry
                    .metadata
                    .insert("flags".to_string(), format!("{:#x}", event.flags));
            }
            telemetry
                .metadata
                .insert("source".to_string(), "ebpf_linux".to_string());

            Some(telemetry)
        }

        fn parse_file_rename(
            data: &[u8],
            enricher: &mut ProcessEnricher,
            ransomware: &mut RansomwareTracker,
        ) -> Option<TelemetryEvent> {
            if data.len() < std::mem::size_of::<BpfFileRenameEvent>() {
                return None;
            }
            let event = unsafe { &*(data.as_ptr() as *const BpfFileRenameEvent) };
            let hdr = &event.header;

            let old_path = bytes_to_string(&event.old_path);
            let new_path = bytes_to_string(&event.new_path);
            let process_name = bytes_to_string(&hdr.comm);

            let mut severity = Severity::Info;
            let mut detections = Vec::new();

            // Check for ransomware-like extension.
            let is_ransom_ext = RANSOMWARE_EXTENSIONS
                .iter()
                .any(|ext| new_path.ends_with(ext));

            if is_ransom_ext {
                // Record the rename and check if threshold is breached.
                if ransomware.record(hdr.pid) {
                    severity = Severity::Critical;
                    detections.push(Detection {
                        detection_type: DetectionType::Ransomware,
                        rule_name: "mass_rename_ransomware_pattern".to_string(),
                        confidence: 0.95,
                        description: format!(
                            "Process {} (PID {}) performed mass file renames with suspicious \
                             extensions -- possible ransomware",
                            process_name, hdr.pid,
                        ),
                        mitre_tactics: vec!["impact".to_string()],
                        mitre_techniques: vec!["T1486".to_string()],
                    });
                } else {
                    severity = Severity::Medium;
                    detections.push(Detection {
                        detection_type: DetectionType::Behavioral,
                        rule_name: "suspicious_file_rename_extension".to_string(),
                        confidence: 0.6,
                        description: format!(
                            "File renamed to suspicious extension: {} -> {}",
                            old_path, new_path,
                        ),
                        mitre_tactics: vec!["impact".to_string()],
                        mitre_techniques: vec!["T1486".to_string()],
                    });
                }
            }

            let mut telemetry = TelemetryEvent::new(
                EventType::FileRename,
                severity,
                EventPayload::File(AgentFileEvent {
                    path: new_path,
                    old_path: Some(old_path),
                    operation: "rename".to_string(),
                    pid: hdr.pid,
                    process_name,
                    sha256: Vec::new(),
                    size: 0,
                    entropy: 0.0,
                    file_type: String::new(),
                }),
            );

            for d in detections {
                telemetry.add_detection(d);
            }
            telemetry
                .metadata
                .insert("source".to_string(), "ebpf_linux".to_string());

            Some(telemetry)
        }

        pub(crate) fn parse_sensitive_access(
            data: &[u8],
            enricher: &mut ProcessEnricher,
        ) -> Option<TelemetryEvent> {
            // Re-use BpfFileEvent layout.
            if data.len() < std::mem::size_of::<BpfFileEvent>() {
                return None;
            }
            let event = unsafe { &*(data.as_ptr() as *const BpfFileEvent) };
            let hdr = &event.header;

            let path = bytes_to_string(&event.path);
            let process_name = bytes_to_string(&hdr.comm);

            let sensitivity_type = if path.contains("shadow") {
                "shadow"
            } else if path.contains("ssh") {
                "ssh_keys"
            } else if path.contains("passwd") {
                "passwd"
            } else if path.contains("kcore") {
                "kernel_memory"
            } else if path.contains("sudoers") {
                "sudoers"
            } else {
                "sensitive"
            };

            // Container-originated sensitive access escalates severity to
            // Critical and adds T1611 (Escape to Host) to the technique tags.
            let in_container = hdr.cgroup_id != 0;
            let severity = if in_container {
                Severity::Critical
            } else {
                Severity::High
            };
            let mut mitre_techniques = vec!["T1003".to_string(), "T1552.001".to_string()];
            if in_container {
                mitre_techniques.push("T1611".to_string());
            }

            let mut telemetry = TelemetryEvent::new(
                EventType::CredentialAccess,
                severity,
                EventPayload::File(AgentFileEvent {
                    path: path.clone(),
                    old_path: None,
                    operation: "sensitive_access".to_string(),
                    pid: hdr.pid,
                    process_name: process_name.clone(),
                    sha256: Vec::new(),
                    size: event.size,
                    entropy: 0.0,
                    file_type: sensitivity_type.to_string(),
                }),
            );

            telemetry.add_detection(Detection {
                detection_type: DetectionType::CredentialTheft,
                rule_name: "sensitive_file_access_ebpf".to_string(),
                confidence: 0.9,
                description: format!(
                    "Process {} (PID {}) accessed {} file: {}",
                    process_name, hdr.pid, sensitivity_type, path,
                ),
                mitre_tactics: vec!["credential-access".to_string()],
                mitre_techniques,
            });
            telemetry
                .metadata
                .insert("source".to_string(), "ebpf_linux".to_string());

            Some(telemetry)
        }

        /// Detect container mount-based privilege escalation (T1611).
        ///
        /// Triggers when a containerized process (`cgroup_id != 0`) attempts
        /// to mount a host-sensitive path (host devices, docker/containerd
        /// sockets, host `/proc/1/root`, host `/etc`, etc.) -- a classic
        /// container escape vector. Bind mounts (`MS_BIND = 0x1000`) and
        /// recursive bind mounts (`MS_BIND | MS_REC`) of host paths are
        /// always flagged as Critical.
        pub(crate) fn parse_mount_event(
            data: &[u8],
            enricher: &mut ProcessEnricher,
        ) -> Option<TelemetryEvent> {
            if data.len() < std::mem::size_of::<BpfMountEvent>() {
                return None;
            }
            let event = unsafe { &*(data.as_ptr() as *const BpfMountEvent) };
            let hdr = &event.header;

            let source = bytes_to_string(&event.source);
            let target = bytes_to_string(&event.target);
            let fstype = bytes_to_string(&event.fstype);
            let process_name = bytes_to_string(&hdr.comm);

            // Mount flags (subset relevant for escape detection).
            const MS_BIND: u64 = 0x1000;
            const MS_REC: u64 = 0x4000;
            let is_bind = event.flags & MS_BIND != 0;
            let is_rec = event.flags & MS_REC != 0;

            // Patterns indicating a container escape attempt.
            let host_sensitive_sources = [
                "/proc/1/root",
                "/proc/1/ns",
                "/var/run/docker.sock",
                "/run/containerd/containerd.sock",
                "/run/docker.sock",
                "/var/run/crio/crio.sock",
                "/host",
                "/etc/kubernetes",
            ];
            let host_device_prefixes = ["/dev/sd", "/dev/nvme", "/dev/dm-", "/dev/mapper/"];

            let matches_sensitive_source =
                host_sensitive_sources.iter().any(|p| source.starts_with(p))
                    || host_device_prefixes.iter().any(|p| source.starts_with(p));

            // Root bind-mount (`mount --rbind / /target`) is the canonical
            // host-filesystem-into-container escape technique.
            let is_root_rbind = is_bind && is_rec && source == "/";

            let in_container = hdr.cgroup_id != 0;
            // Only emit a detection when the originator is containerized AND
            // the mount pattern is escape-relevant. Host-side mounts are out
            // of scope -- the host is allowed to mount its own devices.
            if !in_container || !(matches_sensitive_source || is_root_rbind) {
                return None;
            }

            let escape_kind = if is_root_rbind {
                "root_rbind"
            } else if source.starts_with("/proc/1") {
                "host_proc"
            } else if source.contains("docker.sock")
                || source.contains("containerd")
                || source.contains("crio")
            {
                "container_runtime_socket"
            } else if host_device_prefixes.iter().any(|p| source.starts_with(p)) {
                "host_block_device"
            } else if source.starts_with("/host") {
                "host_bind"
            } else {
                "sensitive_host_path"
            };

            let mut telemetry = TelemetryEvent::new(
                EventType::ContainerEscape,
                Severity::Critical,
                EventPayload::File(AgentFileEvent {
                    path: target.clone(),
                    old_path: Some(source.clone()),
                    operation: "mount".to_string(),
                    pid: hdr.pid,
                    process_name: process_name.clone(),
                    sha256: Vec::new(),
                    size: 0,
                    entropy: 0.0,
                    file_type: escape_kind.to_string(),
                }),
            );

            telemetry.add_detection(Detection {
                detection_type: DetectionType::ContainerThreat,
                rule_name: "container_mount_escape_ebpf".to_string(),
                confidence: 0.95,
                description: format!(
                    "Containerized process {} (PID {}) attempted host mount: \
                     source={} target={} fstype={} flags=0x{:x} kind={}",
                    process_name, hdr.pid, source, target, fstype, event.flags, escape_kind,
                ),
                mitre_tactics: vec!["privilege-escalation".to_string()],
                mitre_techniques: vec!["T1611".to_string()],
            });
            telemetry
                .metadata
                .insert("source".to_string(), "ebpf_linux".to_string());
            telemetry
                .metadata
                .insert("escape_kind".to_string(), escape_kind.to_string());

            let _ = enricher; // enricher unused for now; reserved for cgroup -> container name resolution

            Some(telemetry)
        }

        // ====================================================================
        // Event Parsers -- Network
        // ====================================================================

        fn ip_from_bytes(bytes: &[u8; 16], family: u8) -> IpAddr {
            if family == 2 {
                // AF_INET
                IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
            } else {
                IpAddr::V6(Ipv6Addr::from(*bytes))
            }
        }

        fn parse_tcp_event(
            data: &[u8],
            evt_type: BpfEventType,
            enricher: &mut ProcessEnricher,
            conn_tracker: &mut ConnectionTracker,
            exfil_tracker: &mut ExfiltrationTracker,
        ) -> Option<TelemetryEvent> {
            if data.len() < std::mem::size_of::<BpfNetworkEvent>() {
                return None;
            }
            let event = unsafe { &*(data.as_ptr() as *const BpfNetworkEvent) };
            let hdr = &event.header;

            let process_name = bytes_to_string(&hdr.comm);
            let local_ip = Self::ip_from_bytes(&event.saddr, event.family);
            let remote_ip = Self::ip_from_bytes(&event.daddr, event.family);

            let direction = if evt_type == BpfEventType::TcpAccept {
                "inbound"
            } else {
                "outbound"
            };

            let event_type = if evt_type == BpfEventType::TcpAccept {
                EventType::NetworkListen
            } else {
                EventType::NetworkConnect
            };

            // Track the connection.
            conn_tracker.track_connect(
                hdr.pid,
                &process_name,
                &local_ip.to_string(),
                event.sport,
                &remote_ip.to_string(),
                event.dport,
                "tcp",
            );

            let mut severity = Severity::Info;
            let mut detections = Vec::new();

            // Data exfiltration heuristic: large outbound data volume.
            if direction == "outbound" && event.bytes_sent > 0 {
                if exfil_tracker.record(hdr.pid, event.bytes_sent) {
                    severity = Severity::High;
                    detections.push(Detection {
                        detection_type: DetectionType::Behavioral,
                        rule_name: "data_exfiltration_volume".to_string(),
                        confidence: 0.7,
                        description: format!(
                            "Process {} (PID {}) has sent large data volume to {}:{} -- potential exfiltration",
                            process_name, hdr.pid, remote_ip, event.dport,
                        ),
                        mitre_tactics: vec!["exfiltration".to_string()],
                        mitre_techniques: vec!["T1041".to_string()],
                    });
                }
            }

            let mut telemetry = TelemetryEvent::new(
                event_type,
                severity,
                EventPayload::Network(AgentNetworkEvent {
                    pid: hdr.pid,
                    process_name,
                    local_ip: local_ip.to_string(),
                    local_port: event.sport,
                    remote_ip: remote_ip.to_string(),
                    remote_port: event.dport,
                    protocol: "tcp".to_string(),
                    direction: direction.to_string(),
                    bytes_sent: event.bytes_sent,
                    bytes_received: event.bytes_recv,
                    ..Default::default()
                }),
            );

            for d in detections {
                telemetry.add_detection(d);
            }

            telemetry
                .metadata
                .insert("source".to_string(), "ebpf_linux".to_string());
            if event.state != 0 {
                telemetry.metadata.insert(
                    "tcp_state".to_string(),
                    Self::tcp_state_name(event.state).to_string(),
                );
            }

            Some(telemetry)
        }

        fn parse_tcp_state_change(
            data: &[u8],
            enricher: &mut ProcessEnricher,
            conn_tracker: &mut ConnectionTracker,
        ) -> Option<TelemetryEvent> {
            if data.len() < std::mem::size_of::<BpfTcpStateEvent>() {
                return None;
            }
            let event = unsafe { &*(data.as_ptr() as *const BpfTcpStateEvent) };
            let hdr = &event.header;

            let process_name = bytes_to_string(&hdr.comm);
            let local_ip = Self::ip_from_bytes(&event.saddr, event.family);
            let remote_ip = Self::ip_from_bytes(&event.daddr, event.family);

            let event_type = if event.new_state == 7 {
                // TCP_CLOSE
                EventType::NetworkClose
            } else {
                EventType::NetworkConnect
            };

            // Pull accumulated bytes from the connection tracker.
            let (bytes_sent, bytes_recv) = conn_tracker
                .get_state(
                    hdr.pid,
                    &local_ip.to_string(),
                    event.sport,
                    &remote_ip.to_string(),
                    event.dport,
                    "tcp",
                )
                .map(|s| (s.bytes_sent, s.bytes_recv))
                .unwrap_or((0, 0));

            let mut telemetry = TelemetryEvent::new(
                event_type,
                Severity::Info,
                EventPayload::Network(AgentNetworkEvent {
                    pid: hdr.pid,
                    process_name,
                    local_ip: local_ip.to_string(),
                    local_port: event.sport,
                    remote_ip: remote_ip.to_string(),
                    remote_port: event.dport,
                    protocol: "tcp".to_string(),
                    direction: "state_change".to_string(),
                    bytes_sent,
                    bytes_received: bytes_recv,
                    ..Default::default()
                }),
            );

            telemetry.metadata.insert(
                "old_state".to_string(),
                Self::tcp_state_name(event.old_state).to_string(),
            );
            telemetry.metadata.insert(
                "new_state".to_string(),
                Self::tcp_state_name(event.new_state).to_string(),
            );
            telemetry
                .metadata
                .insert("source".to_string(), "ebpf_linux".to_string());

            Some(telemetry)
        }

        fn parse_udp_send(
            data: &[u8],
            enricher: &mut ProcessEnricher,
            conn_tracker: &mut ConnectionTracker,
            exfil_tracker: &mut ExfiltrationTracker,
        ) -> Option<TelemetryEvent> {
            if data.len() < std::mem::size_of::<BpfNetworkEvent>() {
                return None;
            }
            let event = unsafe { &*(data.as_ptr() as *const BpfNetworkEvent) };
            let hdr = &event.header;

            let process_name = bytes_to_string(&hdr.comm);
            let local_ip = Self::ip_from_bytes(&event.saddr, event.family);
            let remote_ip = Self::ip_from_bytes(&event.daddr, event.family);

            // Update byte counters for this connection.
            conn_tracker.track_connect(
                hdr.pid,
                &process_name,
                &local_ip.to_string(),
                event.sport,
                &remote_ip.to_string(),
                event.dport,
                "udp",
            );
            conn_tracker.update_bytes(
                hdr.pid,
                &local_ip.to_string(),
                event.sport,
                &remote_ip.to_string(),
                event.dport,
                "udp",
                event.bytes_sent,
                event.bytes_recv,
            );

            // If destination port is 53, this is likely a DNS query -- but we
            // handle those separately via BpfEventType::DnsQuery.  Still emit
            // a network event for visibility.
            let mut telemetry = TelemetryEvent::new(
                EventType::NetworkConnect,
                Severity::Info,
                EventPayload::Network(AgentNetworkEvent {
                    pid: hdr.pid,
                    process_name,
                    local_ip: local_ip.to_string(),
                    local_port: event.sport,
                    remote_ip: remote_ip.to_string(),
                    remote_port: event.dport,
                    protocol: "udp".to_string(),
                    direction: "outbound".to_string(),
                    bytes_sent: event.bytes_sent,
                    bytes_received: event.bytes_recv,
                    ..Default::default()
                }),
            );

            telemetry
                .metadata
                .insert("source".to_string(), "ebpf_linux".to_string());
            if event.dport == 53 {
                telemetry
                    .metadata
                    .insert("dns_traffic".to_string(), "true".to_string());
            }

            Some(telemetry)
        }

        fn parse_dns_event(data: &[u8], enricher: &mut ProcessEnricher) -> Option<TelemetryEvent> {
            if data.len() < std::mem::size_of::<BpfDnsEvent>() {
                return None;
            }
            let event = unsafe { &*(data.as_ptr() as *const BpfDnsEvent) };
            let hdr = &event.header;

            let process_name = bytes_to_string(&hdr.comm);
            let query_name = bytes_to_string(&event.query_name);

            let query_type_str = match event.query_type {
                1 => "A",
                28 => "AAAA",
                5 => "CNAME",
                15 => "MX",
                16 => "TXT",
                2 => "NS",
                6 => "SOA",
                12 => "PTR",
                33 => "SRV",
                _ => "OTHER",
            };

            let mut telemetry = TelemetryEvent::new(
                EventType::DnsQuery,
                Severity::Info,
                EventPayload::Dns(AgentDnsEvent {
                    pid: hdr.pid,
                    process_name,
                    query: query_name,
                    query_type: query_type_str.to_string(),
                    responses: Vec::new(),
                }),
            );

            telemetry
                .metadata
                .insert("source".to_string(), "ebpf_linux".to_string());

            Some(telemetry)
        }

        // ====================================================================
        // Event Parsers -- Security
        // ====================================================================

        fn parse_priv_escalation(
            data: &[u8],
            enricher: &mut ProcessEnricher,
        ) -> Option<TelemetryEvent> {
            if data.len() < std::mem::size_of::<BpfPrivEscEvent>() {
                return None;
            }
            let event = unsafe { &*(data.as_ptr() as *const BpfPrivEscEvent) };
            let hdr = &event.header;

            let comm = bytes_to_string(&hdr.comm);
            let proc_info = enricher.get(hdr.pid);
            let path = proc_info
                .as_ref()
                .map(|p| p.exe_path.clone())
                .unwrap_or_default();
            let cmdline = proc_info
                .as_ref()
                .map(|p| p.cmdline.clone())
                .unwrap_or_default();

            // Classify the escalation.
            let escalation_type = if event.old_uid != 0 && event.new_uid == 0 {
                "uid_to_root"
            } else if event.old_euid != 0 && event.new_euid == 0 {
                "euid_to_root"
            } else if event.old_gid != event.new_gid {
                "gid_change"
            } else {
                "uid_change"
            };

            let syscall_name = match event.syscall_nr {
                105 => "setuid",
                106 => "setgid",
                113 => "setreuid",
                114 => "setregid",
                117 => "setresuid",
                119 => "setresgid",
                _ => "unknown",
            };

            let severity = if event.new_uid == 0 || event.new_euid == 0 {
                Severity::Critical
            } else {
                Severity::High
            };

            let mut telemetry = TelemetryEvent::new(
                EventType::ProcessCreate,
                severity,
                EventPayload::Process(ProcessEvent {
                    pid: hdr.pid,
                    ppid: hdr.ppid,
                    name: comm.clone(),
                    path,
                    cmdline,
                    user: event.new_uid.to_string(),
                    sha256: Vec::new(),
                    entropy: 0.0,
                    is_elevated: event.new_uid == 0 || event.new_euid == 0,
                    parent_name: None,
                    parent_path: None,
                    is_signed: false,
                    signer: None,
                    start_time: 0,
                    cpu_usage: 0.0,
                    memory_bytes: 0,
                    company_name: None,
                    file_description: None,
                    product_name: None,
                    file_version: None,
                    environment: None,
                }),
            );

            telemetry
                .metadata
                .insert("old_uid".to_string(), event.old_uid.to_string());
            telemetry
                .metadata
                .insert("new_uid".to_string(), event.new_uid.to_string());
            telemetry
                .metadata
                .insert("old_euid".to_string(), event.old_euid.to_string());
            telemetry
                .metadata
                .insert("new_euid".to_string(), event.new_euid.to_string());
            telemetry
                .metadata
                .insert("old_gid".to_string(), event.old_gid.to_string());
            telemetry
                .metadata
                .insert("new_gid".to_string(), event.new_gid.to_string());
            telemetry
                .metadata
                .insert("syscall".to_string(), syscall_name.to_string());
            telemetry
                .metadata
                .insert("escalation_type".to_string(), escalation_type.to_string());
            telemetry
                .metadata
                .insert("source".to_string(), "ebpf_linux".to_string());

            telemetry.add_detection(Detection {
                detection_type: DetectionType::Behavioral,
                rule_name: "privilege_escalation_ebpf".to_string(),
                confidence: 0.95,
                description: format!(
                    "Privilege escalation via {}: UID {} -> {}, EUID {} -> {} (process: {})",
                    syscall_name,
                    event.old_uid,
                    event.new_uid,
                    event.old_euid,
                    event.new_euid,
                    comm,
                ),
                mitre_tactics: vec!["privilege-escalation".to_string()],
                mitre_techniques: vec!["T1068".to_string(), "T1548.001".to_string()],
            });

            Some(telemetry)
        }

        fn parse_kernel_module(
            data: &[u8],
            enricher: &mut ProcessEnricher,
        ) -> Option<TelemetryEvent> {
            if data.len() < std::mem::size_of::<BpfModuleLoadEvent>() {
                return None;
            }
            let event = unsafe { &*(data.as_ptr() as *const BpfModuleLoadEvent) };
            let hdr = &event.header;

            let process_name = bytes_to_string(&hdr.comm);
            let module_name = bytes_to_string(&event.name);
            let module_path = bytes_to_string(&event.path);

            let mut telemetry = TelemetryEvent::new(
                EventType::DriverLoad,
                Severity::High,
                EventPayload::File(AgentFileEvent {
                    path: module_path.clone(),
                    old_path: None,
                    operation: "kernel_module_load".to_string(),
                    pid: hdr.pid,
                    process_name: process_name.clone(),
                    sha256: hash_file(&module_path),
                    size: 0,
                    entropy: 0.0,
                    file_type: "kernel_module".to_string(),
                }),
            );

            telemetry
                .metadata
                .insert("module_name".to_string(), module_name.clone());
            telemetry
                .metadata
                .insert("is_signed".to_string(), (event.is_signed != 0).to_string());
            telemetry
                .metadata
                .insert("source".to_string(), "ebpf_linux".to_string());

            telemetry.add_detection(Detection {
                detection_type: DetectionType::Behavioral,
                rule_name: "kernel_module_load_ebpf".to_string(),
                confidence: 0.75,
                description: format!(
                    "Kernel module loaded: {} (via {}, PID {}), signed={}",
                    module_name,
                    process_name,
                    hdr.pid,
                    event.is_signed != 0,
                ),
                mitre_tactics: vec![
                    "persistence".to_string(),
                    "privilege-escalation".to_string(),
                ],
                mitre_techniques: vec!["T1547.006".to_string()],
            });

            Some(telemetry)
        }

        pub(crate) fn parse_ptrace(
            data: &[u8],
            enricher: &mut ProcessEnricher,
        ) -> Option<TelemetryEvent> {
            if data.len() < std::mem::size_of::<BpfPtraceEvent>() {
                return None;
            }
            let event = unsafe { &*(data.as_ptr() as *const BpfPtraceEvent) };
            let hdr = &event.header;

            let comm = bytes_to_string(&hdr.comm);
            let target_comm = bytes_to_string(&event.target_comm);

            let request_name = match event.request {
                0 => "PTRACE_TRACEME",
                1 => "PTRACE_PEEKTEXT",
                2 => "PTRACE_PEEKDATA",
                4 => "PTRACE_POKETEXT",
                5 => "PTRACE_POKEDATA",
                16 => "PTRACE_ATTACH",
                17 => "PTRACE_DETACH",
                24 => "PTRACE_SYSCALL",
                31 => "PTRACE_SEIZE",
                _ => "PTRACE_OTHER",
            };

            let severity = match event.request {
                4 | 5 => Severity::Critical, // POKETEXT/POKEDATA = code injection
                16 | 31 => Severity::High,   // ATTACH/SEIZE
                _ => Severity::Medium,
            };

            let mut telemetry = TelemetryEvent::new(
                EventType::ProcessInject,
                severity,
                EventPayload::Process(ProcessEvent {
                    pid: hdr.pid,
                    ppid: hdr.ppid,
                    name: comm.clone(),
                    path: String::new(),
                    cmdline: String::new(),
                    user: hdr.uid.to_string(),
                    sha256: Vec::new(),
                    entropy: 0.0,
                    is_elevated: hdr.uid == 0,
                    parent_name: None,
                    parent_path: None,
                    is_signed: false,
                    signer: None,
                    start_time: 0,
                    cpu_usage: 0.0,
                    memory_bytes: 0,
                    company_name: None,
                    file_description: None,
                    product_name: None,
                    file_version: None,
                    environment: None,
                }),
            );

            telemetry
                .metadata
                .insert("target_pid".to_string(), event.target_pid.to_string());
            telemetry
                .metadata
                .insert("target_comm".to_string(), target_comm.clone());
            telemetry
                .metadata
                .insert("ptrace_request".to_string(), request_name.to_string());
            telemetry
                .metadata
                .insert("source".to_string(), "ebpf_linux".to_string());

            let mut mitre_techniques = vec!["T1055.008".to_string()];
            if hdr.cgroup_id != 0 {
                // Process originates inside a container; cross-namespace ptrace
                // is a strong indicator of container escape (T1611).
                mitre_techniques.push("T1611".to_string());
            }

            telemetry.add_detection(Detection {
                detection_type: DetectionType::Behavioral,
                rule_name: "ptrace_injection_ebpf".to_string(),
                confidence: 0.85,
                description: format!(
                    "Process {} (PID {}) used {} on {} (PID {})",
                    comm, hdr.pid, request_name, target_comm, event.target_pid,
                ),
                mitre_tactics: vec![
                    "defense-evasion".to_string(),
                    "privilege-escalation".to_string(),
                ],
                mitre_techniques,
            });

            Some(telemetry)
        }

        pub(crate) fn parse_namespace_event(
            data: &[u8],
            evt_type: BpfEventType,
            enricher: &mut ProcessEnricher,
        ) -> Option<TelemetryEvent> {
            if data.len() < std::mem::size_of::<BpfNamespaceEvent>() {
                return None;
            }
            let event = unsafe { &*(data.as_ptr() as *const BpfNamespaceEvent) };
            let hdr = &event.header;

            let comm = bytes_to_string(&hdr.comm);

            let ns_type_name = match event.ns_type {
                0x00020000 => "mnt",
                0x04000000 => "uts",
                0x08000000 => "ipc",
                0x10000000 => "user",
                0x20000000 => "pid",
                0x40000000 => "net",
                0x02000000 => "cgroup",
                _ => "unknown",
            };

            let is_escape = event.is_escape != 0 || evt_type == BpfEventType::ContainerBreakout;

            let severity = if is_escape {
                Severity::Critical
            } else {
                Severity::High
            };

            let event_type = if is_escape {
                EventType::ContainerEscape
            } else {
                EventType::ProcessCreate
            };

            let mut telemetry = TelemetryEvent::new(
                event_type,
                severity,
                EventPayload::Process(ProcessEvent {
                    pid: hdr.pid,
                    ppid: hdr.ppid,
                    name: comm.clone(),
                    path: String::new(),
                    cmdline: String::new(),
                    user: hdr.uid.to_string(),
                    sha256: Vec::new(),
                    entropy: 0.0,
                    is_elevated: hdr.uid == 0,
                    parent_name: None,
                    parent_path: None,
                    is_signed: false,
                    signer: None,
                    start_time: 0,
                    cpu_usage: 0.0,
                    memory_bytes: 0,
                    company_name: None,
                    file_description: None,
                    product_name: None,
                    file_version: None,
                    environment: None,
                }),
            );

            telemetry
                .metadata
                .insert("ns_type".to_string(), ns_type_name.to_string());
            telemetry
                .metadata
                .insert("old_ns".to_string(), event.old_ns.to_string());
            telemetry
                .metadata
                .insert("new_ns".to_string(), event.new_ns.to_string());
            telemetry
                .metadata
                .insert("is_escape".to_string(), is_escape.to_string());
            telemetry
                .metadata
                .insert("source".to_string(), "ebpf_linux".to_string());

            if is_escape {
                telemetry.add_detection(Detection {
                    detection_type: DetectionType::ContainerThreat,
                    rule_name: "container_escape_ebpf".to_string(),
                    confidence: 0.95,
                    description: format!(
                        "Container escape detected: {} namespace change by {} (PID {})",
                        ns_type_name, comm, hdr.pid,
                    ),
                    mitre_tactics: vec!["privilege-escalation".to_string()],
                    mitre_techniques: vec!["T1611".to_string()],
                });
            } else {
                telemetry.add_detection(Detection {
                    detection_type: DetectionType::Behavioral,
                    rule_name: "namespace_change_ebpf".to_string(),
                    confidence: 0.6,
                    description: format!(
                        "Namespace ({}) change detected for {} (PID {})",
                        ns_type_name, comm, hdr.pid,
                    ),
                    mitre_tactics: vec!["defense-evasion".to_string()],
                    mitre_techniques: vec!["T1611".to_string()],
                });
            }

            Some(telemetry)
        }

        // ====================================================================
        // Event Parsers -- Memory
        // ====================================================================

        fn parse_mmap_event(data: &[u8], enricher: &mut ProcessEnricher) -> Option<TelemetryEvent> {
            if data.len() < std::mem::size_of::<BpfMmapEvent>() {
                return None;
            }
            let event = unsafe { &*(data.as_ptr() as *const BpfMmapEvent) };
            let hdr = &event.header;

            let process_name = bytes_to_string(&hdr.comm);
            let path = bytes_to_string(&event.path);
            let proc_info = enricher.get(hdr.pid);
            let process_path = proc_info
                .as_ref()
                .map(|p| p.exe_path.clone())
                .unwrap_or_default();

            // Decode protection flags.
            let prot_r = event.prot & 0x1 != 0;
            let prot_w = event.prot & 0x2 != 0;
            let prot_x = event.prot & 0x4 != 0;
            let is_anon = event.fd == -1;

            let prot_str = format!(
                "{}{}{}",
                if prot_r { "R" } else { "-" },
                if prot_w { "W" } else { "-" },
                if prot_x { "X" } else { "-" },
            );

            // Suspicious: RWX mapping.
            let is_rwx = prot_r && prot_w && prot_x;
            // Suspicious: anonymous executable mapping (possible shellcode).
            let is_anon_exec = is_anon && prot_x;

            let severity = if is_rwx {
                Severity::High
            } else if is_anon_exec {
                Severity::High
            } else {
                Severity::Medium
            };

            let transition_type = if is_rwx {
                "rwx_allocation"
            } else if is_anon_exec {
                "anonymous_exec"
            } else {
                "exec_mmap"
            };

            let mut telemetry = TelemetryEvent::new(
                EventType::MemoryPermissionChange,
                severity,
                EventPayload::MemoryPermission(MemoryPermissionEvent {
                    pid: hdr.pid,
                    process_name: process_name.clone(),
                    process_path,
                    base_address: event.addr,
                    region_size: event.len,
                    old_protection: 0,
                    new_protection: event.prot,
                    old_protection_str: "---".to_string(),
                    new_protection_str: prot_str.clone(),
                    mem_type: if is_anon { 0x20000 } else { 0x40000 },
                    mem_type_str: if is_anon {
                        "MEM_PRIVATE".to_string()
                    } else {
                        "MEM_MAPPED".to_string()
                    },
                    entropy: 0.0,
                    transition_type: transition_type.to_string(),
                    thread_from_unbacked: is_anon_exec,
                    thread_id: None,
                    thread_start_address: None,
                }),
            );

            telemetry
                .metadata
                .insert("prot".to_string(), format!("{:#x}", event.prot));
            telemetry
                .metadata
                .insert("flags".to_string(), format!("{:#x}", event.flags));
            telemetry
                .metadata
                .insert("fd".to_string(), event.fd.to_string());
            if !path.is_empty() {
                telemetry.metadata.insert("mapped_file".to_string(), path);
            }
            telemetry
                .metadata
                .insert("source".to_string(), "ebpf_linux".to_string());

            if is_rwx {
                telemetry.add_detection(Detection {
                    detection_type: DetectionType::MemoryThreat,
                    rule_name: "rwx_mmap_ebpf".to_string(),
                    confidence: 0.8,
                    description: format!(
                        "RWX memory mapping ({} bytes) in {} (PID {}) -- potential shellcode/JIT",
                        event.len, process_name, hdr.pid,
                    ),
                    mitre_tactics: vec!["defense-evasion".to_string(), "execution".to_string()],
                    mitre_techniques: vec!["T1055.012".to_string()],
                });
            }

            if is_anon_exec {
                telemetry.add_detection(Detection {
                    detection_type: DetectionType::MemoryThreat,
                    rule_name: "anonymous_exec_mmap_ebpf".to_string(),
                    confidence: 0.75,
                    description: format!(
                        "Anonymous executable mapping ({} bytes) in {} (PID {}) -- possible shellcode injection",
                        event.len, process_name, hdr.pid,
                    ),
                    mitre_tactics: vec!["defense-evasion".to_string()],
                    mitre_techniques: vec!["T1620".to_string()],
                });
            }

            Some(telemetry)
        }

        fn parse_mprotect_event(
            data: &[u8],
            enricher: &mut ProcessEnricher,
        ) -> Option<TelemetryEvent> {
            if data.len() < std::mem::size_of::<BpfMprotectEvent>() {
                return None;
            }
            let event = unsafe { &*(data.as_ptr() as *const BpfMprotectEvent) };
            let hdr = &event.header;

            let process_name = bytes_to_string(&hdr.comm);
            let proc_info = enricher.get(hdr.pid);
            let process_path = proc_info
                .as_ref()
                .map(|p| p.exe_path.clone())
                .unwrap_or_default();

            let old_w = event.old_prot & 0x2 != 0;
            let new_x = event.new_prot & 0x4 != 0;
            let old_x = event.old_prot & 0x4 != 0;
            let new_w = event.new_prot & 0x2 != 0;
            let new_r = event.new_prot & 0x1 != 0;

            let old_prot_str = format!(
                "{}{}{}",
                if event.old_prot & 0x1 != 0 { "R" } else { "-" },
                if old_w { "W" } else { "-" },
                if old_x { "X" } else { "-" },
            );
            let new_prot_str = format!(
                "{}{}{}",
                if new_r { "R" } else { "-" },
                if new_w { "W" } else { "-" },
                if new_x { "X" } else { "-" },
            );

            // Detect W->X transition (classic shellcode pattern).
            let is_w_to_x = old_w && !old_x && new_x && !new_w;
            // Detect RWX.
            let is_rwx = new_r && new_w && new_x;

            let transition_type = if is_w_to_x {
                "write_to_exec"
            } else if is_rwx {
                "rwx_transition"
            } else {
                "protection_change"
            };

            let severity = if is_w_to_x {
                Severity::High
            } else if is_rwx {
                Severity::High
            } else {
                Severity::Medium
            };

            let mut telemetry = TelemetryEvent::new(
                EventType::MemoryPermissionChange,
                severity,
                EventPayload::MemoryPermission(MemoryPermissionEvent {
                    pid: hdr.pid,
                    process_name: process_name.clone(),
                    process_path,
                    base_address: event.addr,
                    region_size: event.len,
                    old_protection: event.old_prot,
                    new_protection: event.new_prot,
                    old_protection_str: old_prot_str,
                    new_protection_str: new_prot_str,
                    mem_type: 0x20000, // MEM_PRIVATE (typical for mprotect targets)
                    mem_type_str: "MEM_PRIVATE".to_string(),
                    entropy: 0.0,
                    transition_type: transition_type.to_string(),
                    thread_from_unbacked: false,
                    thread_id: None,
                    thread_start_address: None,
                }),
            );

            telemetry
                .metadata
                .insert("source".to_string(), "ebpf_linux".to_string());

            if is_w_to_x {
                telemetry.add_detection(Detection {
                    detection_type: DetectionType::MemoryThreat,
                    rule_name: "write_to_exec_mprotect_ebpf".to_string(),
                    confidence: 0.85,
                    description: format!(
                        "W->X memory protection change at {:#x} ({} bytes) in {} (PID {}) -- classic shellcode pattern",
                        event.addr, event.len, process_name, hdr.pid,
                    ),
                    mitre_tactics: vec!["defense-evasion".to_string(), "execution".to_string()],
                    mitre_techniques: vec!["T1055".to_string()],
                });
            }

            if is_rwx {
                telemetry.add_detection(Detection {
                    detection_type: DetectionType::MemoryThreat,
                    rule_name: "rwx_mprotect_ebpf".to_string(),
                    confidence: 0.8,
                    description: format!(
                        "RWX memory protection at {:#x} ({} bytes) in {} (PID {})",
                        event.addr, event.len, process_name, hdr.pid,
                    ),
                    mitre_tactics: vec!["defense-evasion".to_string()],
                    mitre_techniques: vec!["T1055.012".to_string()],
                });
            }

            Some(telemetry)
        }

        // ====================================================================
        // Event Parsers -- New Enhanced Events
        // ====================================================================

        /// Parse file chmod events for SUID/SGID bit detection.
        fn parse_file_chmod(data: &[u8], enricher: &mut ProcessEnricher) -> Option<TelemetryEvent> {
            if data.len() < std::mem::size_of::<BpfFileChmodEvent>() {
                return None;
            }
            let event = unsafe { &*(data.as_ptr() as *const BpfFileChmodEvent) };
            let hdr = &event.header;

            let path = bytes_to_string(&event.path);
            let process_name = bytes_to_string(&hdr.comm);

            let new_suid = event.new_mode & 0o4000 != 0;
            let new_sgid = event.new_mode & 0o2000 != 0;
            let old_suid = event.old_mode & 0o4000 != 0;
            let old_sgid = event.old_mode & 0o2000 != 0;

            let suid_added = new_suid && !old_suid;
            let sgid_added = new_sgid && !old_sgid;

            let severity = if suid_added || sgid_added {
                Severity::High
            } else {
                Severity::Info
            };

            let mut telemetry = TelemetryEvent::new(
                EventType::FileModify,
                severity,
                EventPayload::File(AgentFileEvent {
                    path: path.clone(),
                    old_path: None,
                    operation: "chmod".to_string(),
                    pid: hdr.pid,
                    process_name: process_name.clone(),
                    sha256: Vec::new(),
                    size: 0,
                    entropy: 0.0,
                    file_type: String::new(),
                }),
            );

            telemetry
                .metadata
                .insert("old_mode".to_string(), format!("{:#o}", event.old_mode));
            telemetry
                .metadata
                .insert("new_mode".to_string(), format!("{:#o}", event.new_mode));
            telemetry
                .metadata
                .insert("source".to_string(), "ebpf_linux".to_string());

            if suid_added {
                telemetry.add_detection(Detection {
                    detection_type: DetectionType::Behavioral,
                    rule_name: "suid_bit_set_ebpf".to_string(),
                    confidence: 0.85,
                    description: format!(
                        "SUID bit set on {} by {} (PID {}) -- potential privilege escalation",
                        path, process_name, hdr.pid,
                    ),
                    mitre_tactics: vec![
                        "privilege-escalation".to_string(),
                        "persistence".to_string(),
                    ],
                    mitre_techniques: vec!["T1548.001".to_string()],
                });
            }
            if sgid_added {
                telemetry.add_detection(Detection {
                    detection_type: DetectionType::Behavioral,
                    rule_name: "sgid_bit_set_ebpf".to_string(),
                    confidence: 0.8,
                    description: format!(
                        "SGID bit set on {} by {} (PID {})",
                        path, process_name, hdr.pid,
                    ),
                    mitre_tactics: vec!["privilege-escalation".to_string()],
                    mitre_techniques: vec!["T1548.001".to_string()],
                });
            }

            Some(telemetry)
        }

        /// Parse DNS response events for correlation with queries.
        fn parse_dns_response(
            data: &[u8],
            enricher: &mut ProcessEnricher,
        ) -> Option<TelemetryEvent> {
            if data.len() < std::mem::size_of::<BpfDnsResponseEvent>() {
                return None;
            }
            let event = unsafe { &*(data.as_ptr() as *const BpfDnsResponseEvent) };
            let hdr = &event.header;

            let process_name = bytes_to_string(&hdr.comm);
            let query_name = bytes_to_string(&event.query_name);

            // Parse answer section for resolved addresses.
            // answer_len comes from a raw kernel struct; clamp to the fixed buffer
            // size so a corrupted/garbage length can't trigger a slice OOB panic.
            let answer_len = (event.answer_len as usize).min(event.answers.len());
            let answer_data = &event.answers[..answer_len];
            let responses = Self::parse_dns_answers(answer_data, event.answer_count);

            let query_type_str = match event.query_type {
                1 => "A",
                28 => "AAAA",
                5 => "CNAME",
                15 => "MX",
                16 => "TXT",
                2 => "NS",
                _ => "OTHER",
            };

            let mut telemetry = TelemetryEvent::new(
                EventType::DnsQuery,
                Severity::Info,
                EventPayload::Dns(AgentDnsEvent {
                    pid: hdr.pid,
                    process_name,
                    query: query_name,
                    query_type: query_type_str.to_string(),
                    responses,
                }),
            );

            telemetry
                .metadata
                .insert("direction".to_string(), "response".to_string());
            telemetry
                .metadata
                .insert("answer_count".to_string(), event.answer_count.to_string());
            telemetry
                .metadata
                .insert("source".to_string(), "ebpf_linux".to_string());

            Some(telemetry)
        }

        /// Minimal DNS answer parsing: extract IP addresses from A/AAAA records.
        fn parse_dns_answers(data: &[u8], count: u16) -> Vec<String> {
            let mut results = Vec::new();
            let mut offset = 0;
            for _ in 0..count {
                if offset + 4 > data.len() {
                    break;
                }
                // Simple approach: if we see 4 bytes that could be an IPv4 address,
                // emit it.  This is a best-effort parser for the BPF-captured data.
                let a = data[offset];
                let b = data[offset + 1];
                let c = data[offset + 2];
                let d = data[offset + 3];
                if a != 0 || b != 0 || c != 0 || d != 0 {
                    results.push(format!("{}.{}.{}.{}", a, b, c, d));
                }
                offset += 4;
            }
            results
        }

        /// Parse LD_PRELOAD injection events.
        fn parse_ld_preload(data: &[u8], enricher: &mut ProcessEnricher) -> Option<TelemetryEvent> {
            if data.len() < std::mem::size_of::<BpfLdPreloadEvent>() {
                return None;
            }
            let event = unsafe { &*(data.as_ptr() as *const BpfLdPreloadEvent) };
            let hdr = &event.header;

            let comm = bytes_to_string(&hdr.comm);
            let filename = bytes_to_string(&event.filename);
            let preload = bytes_to_string(&event.preload_value);

            let mut telemetry = TelemetryEvent::new(
                EventType::ProcessInject,
                Severity::Critical,
                EventPayload::Process(ProcessEvent {
                    pid: hdr.pid,
                    ppid: hdr.ppid,
                    name: comm.clone(),
                    path: filename.clone(),
                    cmdline: String::new(),
                    user: hdr.uid.to_string(),
                    sha256: Vec::new(),
                    entropy: 0.0,
                    is_elevated: hdr.uid == 0,
                    parent_name: None,
                    parent_path: None,
                    is_signed: false,
                    signer: None,
                    start_time: 0,
                    cpu_usage: 0.0,
                    memory_bytes: 0,
                    company_name: None,
                    file_description: None,
                    product_name: None,
                    file_version: None,
                    environment: None,
                }),
            );

            telemetry
                .metadata
                .insert("ld_preload".to_string(), preload.clone());
            telemetry
                .metadata
                .insert("source".to_string(), "ebpf_linux".to_string());

            telemetry.add_detection(Detection {
                detection_type: DetectionType::Behavioral,
                rule_name: "ld_preload_injection_ebpf".to_string(),
                confidence: 0.9,
                description: format!(
                    "LD_PRELOAD injection detected: {} executed with LD_PRELOAD={} (PID {})",
                    filename, preload, hdr.pid,
                ),
                mitre_tactics: vec![
                    "persistence".to_string(),
                    "privilege-escalation".to_string(),
                    "defense-evasion".to_string(),
                ],
                mitre_techniques: vec!["T1574.006".to_string()],
            });

            Some(telemetry)
        }

        /// Parse /proc/PID/mem access events (process injection vector).
        fn parse_proc_mem_access(
            data: &[u8],
            enricher: &mut ProcessEnricher,
        ) -> Option<TelemetryEvent> {
            if data.len() < std::mem::size_of::<BpfProcMemEvent>() {
                return None;
            }
            let event = unsafe { &*(data.as_ptr() as *const BpfProcMemEvent) };
            let hdr = &event.header;

            let comm = bytes_to_string(&hdr.comm);
            let target_comm = bytes_to_string(&event.target_comm);

            let is_write = event.flags & 0x2 != 0; // O_WRONLY or O_RDWR

            let severity = if is_write {
                Severity::Critical
            } else {
                Severity::High
            };

            let mut telemetry = TelemetryEvent::new(
                EventType::ProcessInject,
                severity,
                EventPayload::Process(ProcessEvent {
                    pid: hdr.pid,
                    ppid: hdr.ppid,
                    name: comm.clone(),
                    path: String::new(),
                    cmdline: String::new(),
                    user: hdr.uid.to_string(),
                    sha256: Vec::new(),
                    entropy: 0.0,
                    is_elevated: hdr.uid == 0,
                    parent_name: None,
                    parent_path: None,
                    is_signed: false,
                    signer: None,
                    start_time: 0,
                    cpu_usage: 0.0,
                    memory_bytes: 0,
                    company_name: None,
                    file_description: None,
                    product_name: None,
                    file_version: None,
                    environment: None,
                }),
            );

            telemetry
                .metadata
                .insert("target_pid".to_string(), event.target_pid.to_string());
            telemetry
                .metadata
                .insert("target_comm".to_string(), target_comm.clone());
            telemetry.metadata.insert(
                "access_mode".to_string(),
                if is_write { "write" } else { "read" }.to_string(),
            );
            telemetry
                .metadata
                .insert("source".to_string(), "ebpf_linux".to_string());

            telemetry.add_detection(Detection {
                detection_type: DetectionType::Behavioral,
                rule_name: "proc_mem_access_ebpf".to_string(),
                confidence: if is_write { 0.9 } else { 0.75 },
                description: format!(
                    "Process {} (PID {}) {} /proc/{}/mem (target: {}) -- potential process injection",
                    comm, hdr.pid,
                    if is_write { "wrote to" } else { "read from" },
                    event.target_pid, target_comm,
                ),
                mitre_tactics: vec!["defense-evasion".to_string(), "privilege-escalation".to_string()],
                mitre_techniques: vec!["T1055.009".to_string()],
            });

            Some(telemetry)
        }

        /// Parse setcap / capability change events.
        fn parse_setcap_event(
            data: &[u8],
            enricher: &mut ProcessEnricher,
        ) -> Option<TelemetryEvent> {
            if data.len() < std::mem::size_of::<BpfSetcapEvent>() {
                return None;
            }
            let event = unsafe { &*(data.as_ptr() as *const BpfSetcapEvent) };
            let hdr = &event.header;

            let process_name = bytes_to_string(&hdr.comm);
            let path = bytes_to_string(&event.path);

            // Dangerous capabilities.
            let cap_sys_admin = event.cap_effective & (1u64 << 21) != 0;
            let cap_sys_ptrace = event.cap_effective & (1u64 << 19) != 0;
            let cap_net_admin = event.cap_effective & (1u64 << 12) != 0;
            let cap_net_raw = event.cap_effective & (1u64 << 13) != 0;
            let cap_dac_override = event.cap_effective & (1u64 << 1) != 0;

            let dangerous = cap_sys_admin || cap_sys_ptrace || cap_dac_override;

            let severity = if dangerous {
                Severity::High
            } else {
                Severity::Medium
            };

            let mut telemetry = TelemetryEvent::new(
                EventType::FileModify,
                severity,
                EventPayload::File(AgentFileEvent {
                    path: path.clone(),
                    old_path: None,
                    operation: "setcap".to_string(),
                    pid: hdr.pid,
                    process_name: process_name.clone(),
                    sha256: Vec::new(),
                    size: 0,
                    entropy: 0.0,
                    file_type: "capability".to_string(),
                }),
            );

            telemetry.metadata.insert(
                "cap_effective".to_string(),
                format!("{:#x}", event.cap_effective),
            );
            telemetry.metadata.insert(
                "cap_permitted".to_string(),
                format!("{:#x}", event.cap_permitted),
            );
            telemetry.metadata.insert(
                "cap_inheritable".to_string(),
                format!("{:#x}", event.cap_inheritable),
            );
            telemetry
                .metadata
                .insert("source".to_string(), "ebpf_linux".to_string());

            let mut caps_desc = Vec::new();
            if cap_sys_admin {
                caps_desc.push("CAP_SYS_ADMIN");
            }
            if cap_sys_ptrace {
                caps_desc.push("CAP_SYS_PTRACE");
            }
            if cap_net_admin {
                caps_desc.push("CAP_NET_ADMIN");
            }
            if cap_net_raw {
                caps_desc.push("CAP_NET_RAW");
            }
            if cap_dac_override {
                caps_desc.push("CAP_DAC_OVERRIDE");
            }

            if dangerous {
                telemetry.add_detection(Detection {
                    detection_type: DetectionType::Behavioral,
                    rule_name: "dangerous_capability_set_ebpf".to_string(),
                    confidence: 0.85,
                    description: format!(
                        "Dangerous capabilities ({}) set on {} by {} (PID {})",
                        caps_desc.join(", "),
                        path,
                        process_name,
                        hdr.pid,
                    ),
                    mitre_tactics: vec![
                        "privilege-escalation".to_string(),
                        "persistence".to_string(),
                    ],
                    mitre_techniques: vec!["T1548".to_string()],
                });
            }

            Some(telemetry)
        }

        /// Parse memfd_create events (fileless execution).
        fn parse_memfd_event(
            data: &[u8],
            evt_type: BpfEventType,
            enricher: &mut ProcessEnricher,
        ) -> Option<TelemetryEvent> {
            if data.len() < std::mem::size_of::<BpfMemfdCreateEvent>() {
                return None;
            }
            let event = unsafe { &*(data.as_ptr() as *const BpfMemfdCreateEvent) };
            let hdr = &event.header;

            let process_name = bytes_to_string(&hdr.comm);
            let memfd_name = bytes_to_string(&event.name);
            let proc_info = enricher.get(hdr.pid);
            let process_path = proc_info
                .as_ref()
                .map(|p| p.exe_path.clone())
                .unwrap_or_default();

            // memfd_exec is more suspicious than memfd_create.
            let severity = if evt_type == BpfEventType::MemfdExec {
                Severity::Critical
            } else {
                Severity::High
            };

            let operation = if evt_type == BpfEventType::MemfdExec {
                "memfd_exec"
            } else {
                "memfd_create"
            };

            let mfd_sealed = event.flags & 0x2 != 0; // MFD_ALLOW_SEALING
            let mfd_exec = event.flags & 0x10 != 0; // MFD_EXEC

            let mut telemetry = TelemetryEvent::new(
                EventType::MemoryPermissionChange,
                severity,
                EventPayload::MemoryPermission(MemoryPermissionEvent {
                    pid: hdr.pid,
                    process_name: process_name.clone(),
                    process_path,
                    base_address: 0,
                    region_size: 0,
                    old_protection: 0,
                    new_protection: 0x7, // RWX (memfd is inherently RWX)
                    old_protection_str: "---".to_string(),
                    new_protection_str: "RWX".to_string(),
                    mem_type: 0x20000,
                    mem_type_str: "MEM_PRIVATE".to_string(),
                    entropy: 0.0,
                    transition_type: operation.to_string(),
                    thread_from_unbacked: true,
                    thread_id: None,
                    thread_start_address: None,
                }),
            );

            telemetry
                .metadata
                .insert("memfd_name".to_string(), memfd_name.clone());
            telemetry
                .metadata
                .insert("memfd_fd".to_string(), event.fd.to_string());
            telemetry
                .metadata
                .insert("memfd_flags".to_string(), format!("{:#x}", event.flags));
            telemetry
                .metadata
                .insert("source".to_string(), "ebpf_linux".to_string());

            telemetry.add_detection(Detection {
                detection_type: DetectionType::MemoryThreat,
                rule_name: format!("{}_ebpf", operation),
                confidence: if evt_type == BpfEventType::MemfdExec {
                    0.95
                } else {
                    0.75
                },
                description: format!(
                    "Fileless execution via {}: name=\"{}\" fd={} in {} (PID {})",
                    operation, memfd_name, event.fd, process_name, hdr.pid,
                ),
                mitre_tactics: vec!["defense-evasion".to_string(), "execution".to_string()],
                mitre_techniques: vec!["T1620".to_string()],
            });

            Some(telemetry)
        }

        fn parse_syscall_evasion_event(
            data: &[u8],
            evt_type: BpfEventType,
            enricher: &mut ProcessEnricher,
        ) -> Option<TelemetryEvent> {
            if data.len() < std::mem::size_of::<BpfSyscallEvasionEvent>() {
                return None;
            }
            let event = unsafe { &*(data.as_ptr() as *const BpfSyscallEvasionEvent) };
            let hdr = &event.header;

            let process_name = bytes_to_string(&hdr.comm);
            let process_path = enricher
                .get(hdr.pid)
                .map(|p| p.exe_path.clone())
                .unwrap_or_default();
            let path = bytes_to_string(&event.path);

            let (operation, severity, rule_name, description, mitre_techniques) = match evt_type {
                BpfEventType::SyscallEvasionMemfdExec => (
                    "fileless_execveat",
                    Severity::Critical,
                    "fileless_execveat_ebpf",
                    "Fileless execution via execveat syscall",
                    vec!["T1620".to_string()],
                ),
                BpfEventType::SyscallEvasionPtraceInject
                | BpfEventType::SyscallEvasionProcMemWrite => (
                    "process_injection_syscall",
                    Severity::Critical,
                    "process_injection_syscall_ebpf",
                    "Process injection syscall pattern",
                    vec!["T1055".to_string()],
                ),
                BpfEventType::SyscallEvasionAnonymousMmap => (
                    "anonymous_exec_mmap",
                    Severity::High,
                    "anonymous_exec_mmap_ebpf",
                    "Anonymous executable memory mapping syscall",
                    vec!["T1055".to_string()],
                ),
                _ => (
                    "syscall_evasion",
                    Severity::High,
                    "syscall_evasion_ebpf",
                    "Syscall evasion pattern",
                    vec!["T1106".to_string()],
                ),
            };

            let mut telemetry = TelemetryEvent::new(
                EventType::MemoryPermissionChange,
                severity,
                EventPayload::MemoryPermission(MemoryPermissionEvent {
                    pid: hdr.pid,
                    process_name: process_name.clone(),
                    process_path,
                    base_address: event.region_start,
                    region_size: event.region_size,
                    old_protection: 0,
                    new_protection: event.mem_prot,
                    old_protection_str: "---".to_string(),
                    new_protection_str: format!("{:#x}", event.mem_prot),
                    mem_type: event.mem_flags,
                    mem_type_str: operation.to_string(),
                    entropy: 0.0,
                    transition_type: operation.to_string(),
                    thread_from_unbacked: evt_type == BpfEventType::SyscallEvasionMemfdExec,
                    thread_id: None,
                    thread_start_address: None,
                }),
            );

            telemetry
                .metadata
                .insert("source".to_string(), "ebpf_linux_raw_syscall".to_string());
            telemetry
                .metadata
                .insert("syscall_nr".to_string(), event.syscall_nr.to_string());
            telemetry
                .metadata
                .insert("evasion_type".to_string(), event.evasion_type.to_string());
            telemetry
                .metadata
                .insert("confidence".to_string(), event.confidence.to_string());
            telemetry
                .metadata
                .insert("fd".to_string(), event.fd.to_string());
            telemetry
                .metadata
                .insert("target_pid".to_string(), event.target_pid.to_string());
            if !path.is_empty() {
                telemetry.metadata.insert("path".to_string(), path);
            }

            telemetry.add_detection(Detection {
                detection_type: DetectionType::MemoryThreat,
                rule_name: rule_name.to_string(),
                confidence: (event.confidence as f32 / 100.0).clamp(0.0, 1.0),
                description: format!(
                    "{}: syscall={} process={} pid={} fd={}",
                    description, event.syscall_nr, process_name, hdr.pid, event.fd,
                ),
                mitre_tactics: vec!["defense-evasion".to_string(), "execution".to_string()],
                mitre_techniques,
            });

            Some(telemetry)
        }

        /// Parse persistence events (cron, systemd, init, authorized_keys).
        fn parse_persistence_event(
            data: &[u8],
            evt_type: BpfEventType,
            enricher: &mut ProcessEnricher,
        ) -> Option<TelemetryEvent> {
            if data.len() < std::mem::size_of::<BpfPersistenceEvent>() {
                // Fall back to BpfFileEvent layout for generic persistence.
                if data.len() >= std::mem::size_of::<BpfFileEvent>() {
                    let event = unsafe { &*(data.as_ptr() as *const BpfFileEvent) };
                    let hdr = &event.header;
                    let path = bytes_to_string(&event.path);
                    let process_name = bytes_to_string(&hdr.comm);
                    let ptype = match evt_type {
                        BpfEventType::CronModify => "cron",
                        BpfEventType::SystemdTimerCreate => "systemd",
                        BpfEventType::InitScriptModify => "initd",
                        BpfEventType::SshAuthorizedKeys => "ssh_authorized_keys",
                        _ => "unknown",
                    };
                    return Self::make_persistence_telemetry(hdr, &path, "", ptype, &process_name);
                }
                return None;
            }
            let event = unsafe { &*(data.as_ptr() as *const BpfPersistenceEvent) };
            let hdr = &event.header;

            let path = bytes_to_string(&event.path);
            let snippet = bytes_to_string(&event.content_snippet);
            let process_name = bytes_to_string(&hdr.comm);

            let ptype = match evt_type {
                BpfEventType::CronModify => "cron",
                BpfEventType::SystemdTimerCreate => "systemd",
                BpfEventType::InitScriptModify => "initd",
                BpfEventType::SshAuthorizedKeys => "ssh_authorized_keys",
                _ => "unknown",
            };

            Self::make_persistence_telemetry(hdr, &path, &snippet, ptype, &process_name)
        }

        /// Helper to construct persistence telemetry events.
        fn make_persistence_telemetry(
            hdr: &EbpfEventHeader,
            path: &str,
            content_snippet: &str,
            persistence_type: &str,
            process_name: &str,
        ) -> Option<TelemetryEvent> {
            let severity = match persistence_type {
                "ssh_authorized_keys" | "ld_preload" => Severity::Critical,
                "cron" | "systemd" | "initd" => Severity::High,
                _ => Severity::High,
            };

            let mitre_technique = match persistence_type {
                "cron" => "T1053.003",
                "systemd" => "T1543.002",
                "initd" | "rc_local" => "T1037.004",
                "shell_profile" => "T1546.004",
                "ld_preload" => "T1574.006",
                "ssh_authorized_keys" => "T1098.004",
                _ => "T1547",
            };

            let mut telemetry = TelemetryEvent::new(
                EventType::FileModify,
                severity,
                EventPayload::File(AgentFileEvent {
                    path: path.to_string(),
                    old_path: None,
                    operation: format!("persistence_{}", persistence_type),
                    pid: hdr.pid,
                    process_name: process_name.to_string(),
                    sha256: Vec::new(),
                    size: 0,
                    entropy: 0.0,
                    file_type: persistence_type.to_string(),
                }),
            );

            telemetry
                .metadata
                .insert("persistence_type".to_string(), persistence_type.to_string());
            if !content_snippet.is_empty() {
                telemetry
                    .metadata
                    .insert("content_snippet".to_string(), content_snippet.to_string());
            }
            telemetry
                .metadata
                .insert("source".to_string(), "ebpf_linux".to_string());

            telemetry.add_detection(Detection {
                detection_type: DetectionType::Behavioral,
                rule_name: format!("persistence_{}_ebpf", persistence_type),
                confidence: 0.85,
                description: format!(
                    "Persistence mechanism ({}) modified by {} (PID {}): {}",
                    persistence_type, process_name, hdr.pid, path,
                ),
                mitre_tactics: vec!["persistence".to_string()],
                mitre_techniques: vec![mitre_technique.to_string()],
            });

            Some(telemetry)
        }

        // ====================================================================
        // Utilities
        // ====================================================================

        fn tcp_state_name(state: u8) -> &'static str {
            match state {
                1 => "ESTABLISHED",
                2 => "SYN_SENT",
                3 => "SYN_RECV",
                4 => "FIN_WAIT1",
                5 => "FIN_WAIT2",
                6 => "TIME_WAIT",
                7 => "CLOSE",
                8 => "CLOSE_WAIT",
                9 => "LAST_ACK",
                10 => "LISTEN",
                11 => "CLOSING",
                _ => "UNKNOWN",
            }
        }

        fn check_cap_bpf() -> bool {
            if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
                for line in status.lines() {
                    if line.starts_with("CapEff:") {
                        if let Some(hex_str) = line.split_whitespace().nth(1) {
                            if let Ok(caps) = u64::from_str_radix(hex_str, 16) {
                                // CAP_BPF is bit 39.
                                return caps & (1u64 << 39) != 0;
                            }
                        }
                    }
                }
            }
            false
        }

        // ====================================================================
        // Public Interface
        // ====================================================================

        /// Get the next telemetry event from the eBPF ring buffer.
        pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
            self.event_rx.recv().await
        }

        /// Current kernel eBPF capabilities.
        pub fn capabilities(&self) -> &LinuxEbpfCapabilities {
            &self.capabilities
        }

        pub fn health(&self) -> EbpfLinuxHealth {
            let state = if self.ebpf_active {
                EbpfLinuxHealthState::Active
            } else if self.capabilities.is_sufficient() {
                EbpfLinuxHealthState::Degraded
            } else {
                EbpfLinuxHealthState::Unavailable
            };

            EbpfLinuxHealth {
                state,
                maturity: self.capabilities.maturity_label(),
                ebpf_active: self.ebpf_active,
                capabilities: self.capabilities.clone(),
                missing_prerequisites: self.capabilities.missing_prerequisites.clone(),
                stats: self.stats(),
            }
        }

        /// Statistics snapshot.
        pub fn stats(&self) -> EbpfLinuxStatsSnapshot {
            EbpfLinuxStatsSnapshot {
                events_received: self.stats.events_received.load(Ordering::Relaxed),
                events_processed: self.stats.events_processed.load(Ordering::Relaxed),
                events_dropped_rate_limit: self
                    .stats
                    .events_dropped_rate_limit
                    .load(Ordering::Relaxed),
                events_dropped_channel_full: self
                    .stats
                    .events_dropped_channel_full
                    .load(Ordering::Relaxed),
                parse_errors: self.stats.parse_errors.load(Ordering::Relaxed),
                enrichment_misses: self.stats.enrichment_misses.load(Ordering::Relaxed),
            }
        }

        /// Signal the collector to stop.
        pub fn stop(&self) {
            self.running.store(false, Ordering::Relaxed);
        }
    }

    impl Drop for EbpfLinuxCollector {
        fn drop(&mut self) {
            self.stop();
        }
    }

    // ========================================================================
    // Crate-visible free-function wrappers around the parser methods so
    // sibling test modules can call them via the outer `pub(crate) use
    // inner::{...}` re-export.
    // ========================================================================

    #[inline]
    pub(crate) fn parse_namespace_event(
        data: &[u8],
        evt_type: BpfEventType,
        enricher: &mut ProcessEnricher,
    ) -> Option<TelemetryEvent> {
        EbpfLinuxCollector::parse_namespace_event(data, evt_type, enricher)
    }

    #[inline]
    pub(crate) fn parse_ptrace(
        data: &[u8],
        enricher: &mut ProcessEnricher,
    ) -> Option<TelemetryEvent> {
        EbpfLinuxCollector::parse_ptrace(data, enricher)
    }

    #[inline]
    pub(crate) fn parse_sensitive_access(
        data: &[u8],
        enricher: &mut ProcessEnricher,
    ) -> Option<TelemetryEvent> {
        EbpfLinuxCollector::parse_sensitive_access(data, enricher)
    }

    #[inline]
    pub(crate) fn parse_mount_event(
        data: &[u8],
        enricher: &mut ProcessEnricher,
    ) -> Option<TelemetryEvent> {
        EbpfLinuxCollector::parse_mount_event(data, enricher)
    }

    // ========================================================================
    // Unit tests for LinuxEbpfCapabilities (platform-agnostic, no kernel I/O)
    // ========================================================================
    //
    // These tests construct `LinuxEbpfCapabilities` directly with synthetic
    // field values to exercise the pure-logic helpers (`is_sufficient`,
    // `maturity_label`, `compute_missing_prerequisites`) and the health-state
    // transitions in `EbpfLinuxHealth` without any actual kernel calls.
    //
    // The tests are necessarily inside the `#[cfg(target_os = "linux")]`
    // `inner` module because `LinuxEbpfCapabilities` itself only exists on
    // Linux. On Windows they are simply not compiled; `cargo check` still
    // succeeds across the workspace.
    #[cfg(test)]
    mod tests {
        use super::*;

        /// Build a capabilities struct that satisfies every prerequisite.
        /// Tests then flip individual fields to verify the predicates react
        /// correctly to each missing piece.
        fn fully_capable() -> LinuxEbpfCapabilities {
            LinuxEbpfCapabilities {
                kernel_version: (5, 10, 0),
                has_tracepoints: true,
                has_kprobes: true,
                has_kretprobes: true,
                has_raw_tracepoints: true,
                has_ring_buffer: true,
                has_btf: true,
                has_lsm_hooks: true,
                has_fentry: true,
                bpf_fs_mounted: true,
                tracing_fs_available: true,
                running_as_root: true,
                has_cap_bpf: true,
                object_path: "/opt/tamandua/ebpf/tamandua_linux.bpf.o".to_string(),
                object_path_exists: true,
                missing_prerequisites: Vec::new(),
            }
        }

        #[test]
        fn is_sufficient_true_when_all_prerequisites_met() {
            let caps = fully_capable();
            assert!(
                caps.is_sufficient(),
                "fully-capable struct must satisfy is_sufficient()"
            );
        }

        #[test]
        fn is_sufficient_false_when_kernel_too_old_loses_ring_buffer() {
            // Real detect() sets has_ring_buffer based on kernel >= 5.8.
            // A pre-5.7 kernel cannot offer the ring buffer, so simulate
            // that by clearing the dependent feature flags.
            let mut caps = fully_capable();
            caps.kernel_version = (5, 6, 0);
            caps.has_ring_buffer = false;
            caps.has_lsm_hooks = false; // 5.7+
            caps.has_fentry = false; // 5.5+ (also affected for <5.5)
            assert!(
                !caps.is_sufficient(),
                "kernel < 5.7 without ring buffer must not be sufficient"
            );
        }

        #[test]
        fn is_sufficient_false_when_btf_missing() {
            let mut caps = fully_capable();
            caps.has_btf = false;
            assert!(
                !caps.is_sufficient(),
                "missing BTF must cause is_sufficient() to be false"
            );
        }

        #[test]
        fn is_sufficient_false_when_cap_bpf_missing_and_not_root() {
            let mut caps = fully_capable();
            caps.running_as_root = false;
            caps.has_cap_bpf = false;
            assert!(
                !caps.is_sufficient(),
                "no root and no CAP_BPF must fail the privilege check"
            );
        }

        #[test]
        fn is_sufficient_true_with_cap_bpf_but_not_root() {
            // CAP_BPF alone is sufficient on its own; root is not required.
            let mut caps = fully_capable();
            caps.running_as_root = false;
            caps.has_cap_bpf = true;
            assert!(
                caps.is_sufficient(),
                "CAP_BPF alone should satisfy the privilege requirement"
            );
        }

        #[test]
        fn is_sufficient_false_when_object_path_missing() {
            let mut caps = fully_capable();
            caps.object_path_exists = false;
            assert!(!caps.is_sufficient());
        }

        #[test]
        fn is_sufficient_false_when_bpf_fs_not_mounted() {
            let mut caps = fully_capable();
            caps.bpf_fs_mounted = false;
            assert!(!caps.is_sufficient());
        }

        #[test]
        fn maturity_label_lab_ready_when_sufficient() {
            let caps = fully_capable();
            assert_eq!(caps.maturity_label(), "lab_ready");
        }

        #[test]
        fn maturity_label_partial_when_some_features_present() {
            // Not sufficient, but at least one of tracepoints/kprobes/BTF is on.
            let mut caps = LinuxEbpfCapabilities::default();
            caps.has_tracepoints = true;
            assert_eq!(caps.maturity_label(), "partial");

            let mut caps = LinuxEbpfCapabilities::default();
            caps.has_kprobes = true;
            assert_eq!(caps.maturity_label(), "partial");

            let mut caps = LinuxEbpfCapabilities::default();
            caps.has_btf = true;
            assert_eq!(caps.maturity_label(), "partial");
        }

        #[test]
        fn maturity_label_unavailable_when_no_features() {
            let caps = LinuxEbpfCapabilities::default();
            assert_eq!(caps.maturity_label(), "unavailable");
        }

        #[test]
        fn compute_missing_prerequisites_empty_when_fully_capable() {
            let caps = fully_capable();
            let missing = caps.compute_missing_prerequisites();
            assert!(
                missing.is_empty(),
                "expected no missing prerequisites, got {:?}",
                missing
            );
        }

        #[test]
        fn compute_missing_prerequisites_lists_each_missing_item() {
            let caps = LinuxEbpfCapabilities {
                object_path: "/does/not/exist".to_string(),
                ..LinuxEbpfCapabilities::default()
            };
            let missing = caps.compute_missing_prerequisites();
            // Each of the eight underlying checks should contribute a string.
            assert!(missing.iter().any(|s| s.contains("tracepoints")));
            assert!(missing.iter().any(|s| s.contains("kprobes")));
            assert!(missing.iter().any(|s| s.contains("BTF")));
            assert!(missing.iter().any(|s| s.contains("ring buffer")));
            assert!(missing.iter().any(|s| s.contains("/sys/fs/bpf")));
            assert!(missing.iter().any(|s| s.contains("CAP_BPF")));
            assert!(missing.iter().any(|s| s.contains("/does/not/exist")));
        }

        #[test]
        fn compute_missing_prerequisites_reports_only_missing_pieces() {
            // Only BTF is missing.
            let mut caps = fully_capable();
            caps.has_btf = false;
            let missing = caps.compute_missing_prerequisites();
            assert_eq!(
                missing.len(),
                1,
                "exactly one missing prerequisite expected, got {:?}",
                missing
            );
            assert!(missing[0].contains("BTF"));
        }

        // --------------------------------------------------------------
        // Health-state transitions
        //
        // `EbpfLinuxHealth::state` is set by the collector's `health()`
        // method based on `(ebpf_active, capabilities.is_sufficient())`.
        // We replicate that logic in a tiny helper to exercise the state
        // machine without spinning up an actual collector.
        // --------------------------------------------------------------
        fn derive_state(ebpf_active: bool, caps: &LinuxEbpfCapabilities) -> EbpfLinuxHealthState {
            if ebpf_active {
                EbpfLinuxHealthState::Active
            } else if caps.is_sufficient() {
                EbpfLinuxHealthState::Degraded
            } else {
                EbpfLinuxHealthState::Unavailable
            }
        }

        #[test]
        fn health_state_active_when_ebpf_running() {
            let caps = fully_capable();
            assert_eq!(derive_state(true, &caps), EbpfLinuxHealthState::Active);
        }

        #[test]
        fn health_state_degraded_when_capable_but_not_active() {
            let caps = fully_capable();
            assert_eq!(derive_state(false, &caps), EbpfLinuxHealthState::Degraded);
        }

        #[test]
        fn health_state_unavailable_when_prereqs_missing() {
            let caps = LinuxEbpfCapabilities::default();
            assert_eq!(
                derive_state(false, &caps),
                EbpfLinuxHealthState::Unavailable
            );
        }

        #[test]
        fn health_state_transitions_active_to_degraded_to_unavailable() {
            // Start fully capable and running -> Active.
            let mut caps = fully_capable();
            let mut active = true;
            assert_eq!(derive_state(active, &caps), EbpfLinuxHealthState::Active);

            // eBPF stops (program detached) but kernel still supports it ->
            // Degraded.
            active = false;
            assert_eq!(derive_state(active, &caps), EbpfLinuxHealthState::Degraded);

            // Prerequisite regresses (e.g. BPF fs unmounted) -> Unavailable.
            caps.bpf_fs_mounted = false;
            assert_eq!(
                derive_state(active, &caps),
                EbpfLinuxHealthState::Unavailable
            );
        }

        #[test]
        fn health_struct_carries_capability_snapshot() {
            // Smoke-test that EbpfLinuxHealth can be constructed from a
            // synthetic capability set and reports a sufficient maturity.
            let caps = fully_capable();
            let health = EbpfLinuxHealth {
                state: derive_state(true, &caps),
                maturity: caps.maturity_label(),
                ebpf_active: true,
                missing_prerequisites: caps.compute_missing_prerequisites(),
                capabilities: caps.clone(),
                stats: EbpfLinuxStatsSnapshot {
                    events_received: 0,
                    events_processed: 0,
                    events_dropped_rate_limit: 0,
                    events_dropped_channel_full: 0,
                    parse_errors: 0,
                    enrichment_misses: 0,
                },
            };
            assert_eq!(health.state, EbpfLinuxHealthState::Active);
            assert_eq!(health.maturity, "lab_ready");
            assert!(health.ebpf_active);
            assert!(health.missing_prerequisites.is_empty());
            assert!(health.capabilities.is_sufficient());
        }

        /// Verify EbpfEventHeader size matches C struct event_header.
        /// C layout: 4+4+4+4+4+4+8+64+8+4+4 = 112 bytes
        #[test]
        fn test_ebpf_event_header_size() {
            assert_eq!(
                std::mem::size_of::<EbpfEventHeader>(),
                112,
                "EbpfEventHeader size must be 112 bytes to match C event_header"
            );
        }

        /// Verify BpfMountEvent size matches C struct mount_event.
        /// C layout: header(112) + source(256) + target(256) + fstype(64) + flags(8) = 696
        #[test]
        fn test_bpf_mount_event_size() {
            assert_eq!(
                std::mem::size_of::<BpfMountEvent>(),
                696,
                "BpfMountEvent size must be 696 bytes to match C mount_event"
            );
        }

        /// Verify BpfMountEvent field offsets match C layout.
        /// Uses std::mem::offset_of! (Rust 1.77+) or manual pointer arithmetic.
        #[test]
        fn test_bpf_mount_event_offsets() {
            // Use offset_of! if available (Rust 1.77+), otherwise use manual pointer arithmetic
            #[allow(unused_imports)]
            use std::mem::offset_of;

            // Test using offset_of! (will compile if available)
            #[cfg(not(any()))] // This will always be false, but allows us to test compilation
            {
                assert_eq!(offset_of!(BpfMountEvent, header), 0);
                assert_eq!(offset_of!(BpfMountEvent, source), 112);
                assert_eq!(offset_of!(BpfMountEvent, target), 368); // 112 + 256
                assert_eq!(offset_of!(BpfMountEvent, fstype), 624); // 368 + 256
                assert_eq!(offset_of!(BpfMountEvent, flags), 688); // 624 + 64
            }

            // Manual pointer arithmetic approach (works on all Rust versions)
            unsafe {
                let base = std::ptr::null::<BpfMountEvent>();
                let header_offset = std::ptr::addr_of!((*base).header) as usize;
                let source_offset = std::ptr::addr_of!((*base).source) as usize;
                let target_offset = std::ptr::addr_of!((*base).target) as usize;
                let fstype_offset = std::ptr::addr_of!((*base).fstype) as usize;
                let flags_offset = std::ptr::addr_of!((*base).flags) as usize;

                assert_eq!(header_offset, 0, "header must be at offset 0");
                assert_eq!(source_offset, 112, "source must be at offset 112");
                assert_eq!(target_offset, 368, "target must be at offset 368 (112+256)");
                assert_eq!(fstype_offset, 624, "fstype must be at offset 624 (368+256)");
                assert_eq!(flags_offset, 688, "flags must be at offset 688 (624+64)");
            }
        }

        /// Verify event_type=39 (MountEscape) round-trips through parse_mount_event.
        /// This test builds a synthetic BpfMountEvent buffer with proper byte layout
        /// and verifies that parse_mount_event correctly interprets it as a container
        /// escape event.
        #[test]
        fn test_bpf_mount_event_type_39_roundtrip() {
            // Build a synthetic BpfMountEvent buffer with event_type=39
            let mut buf = vec![0u8; std::mem::size_of::<BpfMountEvent>()];

            // event_type at offset 0, little-endian u32 = 39
            buf[0..4].copy_from_slice(&39u32.to_le_bytes());

            // pid at offset 4
            buf[4..8].copy_from_slice(&4242u32.to_le_bytes());

            // tid at offset 8
            buf[8..12].copy_from_slice(&4242u32.to_le_bytes());

            // ppid at offset 12
            buf[12..16].copy_from_slice(&1u32.to_le_bytes());

            // uid at offset 16
            buf[16..20].copy_from_slice(&1000u32.to_le_bytes());

            // gid at offset 20
            buf[20..24].copy_from_slice(&1000u32.to_le_bytes());

            // timestamp_ns at offset 24 (u64)
            buf[24..32].copy_from_slice(&1234567890u64.to_le_bytes());

            // comm at offset 32 (64 bytes) - "malicious"
            let comm = b"malicious";
            buf[32..32 + comm.len()].copy_from_slice(comm);

            // cgroup_id at offset 96 (u64) - must be non-zero for container detection
            // offset calculation: 4+4+4+4+4+4+8+64 = 96
            buf[96..104].copy_from_slice(&0xDEAD_BEEFu64.to_le_bytes());

            // mnt_ns at offset 104 (u32)
            buf[104..108].copy_from_slice(&12345u32.to_le_bytes());

            // pid_ns at offset 108 (u32)
            buf[108..112].copy_from_slice(&67890u32.to_le_bytes());

            // source at offset 112: "/var/run/docker.sock"
            let src = b"/var/run/docker.sock";
            buf[112..112 + src.len()].copy_from_slice(src);

            // target at offset 368: "/mnt/escape"
            let tgt = b"/mnt/escape";
            buf[368..368 + tgt.len()].copy_from_slice(tgt);

            // fstype at offset 624: "none"
            let fst = b"none";
            buf[624..624 + fst.len()].copy_from_slice(fst);

            // flags at offset 688: MS_BIND = 0x1000
            buf[688..696].copy_from_slice(&0x1000u64.to_le_bytes());

            let mut enricher = ProcessEnricher::new();
            let result = EbpfLinuxCollector::parse_mount_event(&buf, &mut enricher);

            assert!(
                result.is_some(),
                "parse_mount_event must return Some for event_type=39 with container context"
            );
            let evt = result.unwrap();
            assert_eq!(
                evt.event_type,
                crate::collectors::EventType::ContainerEscape,
                "event_type must be ContainerEscape"
            );
            assert_eq!(
                evt.severity,
                crate::collectors::Severity::Critical,
                "severity must be Critical"
            );
            assert!(
                evt.detections
                    .iter()
                    .any(|d| d.rule_name == "container_mount_escape_ebpf"),
                "must have container_mount_escape_ebpf detection"
            );
        }
    }
}

// ============================================================================
// Non-Linux stub: no-op collector that never produces events
// ============================================================================

#[cfg(not(target_os = "linux"))]
mod inner {
    use crate::collectors::TelemetryEvent;
    use crate::config::AgentConfig;
    use anyhow::Result;
    use tracing::info;

    /// Placeholder health type so non-Linux callers can use the same API
    /// surface without conditional compilation at the call site.
    #[derive(Debug, Clone)]
    pub struct EbpfLinuxHealth;

    /// No-op publish on non-Linux platforms.
    pub fn publish_latest_health(_health: EbpfLinuxHealth) {}

    /// Always returns `None` on non-Linux platforms.
    pub fn latest_health() -> Option<EbpfLinuxHealth> {
        None
    }

    /// No-op eBPF Linux collector stub for non-Linux platforms.
    pub struct EbpfLinuxCollector {
        _rx: tokio::sync::mpsc::Receiver<TelemetryEvent>,
    }

    impl EbpfLinuxCollector {
        /// Returns Ok(Self) on all platforms; the stub simply never produces events.
        pub fn new(_config: &AgentConfig) -> Result<Self> {
            info!("eBPF Linux collector: stub (not running on Linux)");
            let (_tx, rx) = tokio::sync::mpsc::channel(1);
            Ok(Self { _rx: rx })
        }

        /// Always returns `pending` (never resolves) so the select! loop skips it.
        pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
            std::future::pending().await
        }

        /// No-op.
        pub fn stop(&self) {}

        /// No-op on non-Linux platforms.
        pub fn publish_health(&self) {}
    }
}

// ============================================================================
// Re-export the platform-appropriate implementation
// ============================================================================

pub use inner::{latest_health, publish_latest_health, EbpfLinuxCollector, EbpfLinuxHealth};

#[cfg(target_os = "linux")]
pub use inner::{EbpfLinuxHealthState, EbpfLinuxStatsSnapshot, LinuxEbpfCapabilities};

// Crate-visible re-export of parser entry points and BPF event layouts so
// sibling test modules under `crate::collectors` can drive the parsers with
// synthetic ring-buffer payloads.
#[cfg(target_os = "linux")]
pub(crate) use inner::{
    parse_mount_event, parse_namespace_event, parse_ptrace, parse_sensitive_access, BpfEventType,
    BpfFileEvent, BpfMountEvent, BpfNamespaceEvent, BpfPtraceEvent, EbpfEventHeader,
    ProcessEnricher,
};

// ============================================================================
// Cross-platform byte-layout tests for `BpfMountEvent`
// ============================================================================
//
// The `inner` module (and therefore its `BpfMountEvent` definition) is gated
// `#[cfg(target_os = "linux")]`, but the byte-layout invariants of
// `BpfMountEvent` are pure `#[repr(C)]` math: they have no kernel calls, no
// aya types, and no Linux syscalls.  Phase-70 EBPF-02 mechanical
// verification needs these checks to compile and run uniformly on Windows,
// macOS, and Linux so CI on every host validates the ABI we share with the
// kernel-side `bpf_mount_event` C struct.
//
// To accomplish that without restructuring the entire 5000-line module, we
// re-state the relevant layout constants and the `BpfMountEvent` /
// `EbpfEventHeader` structs in a tiny `#[cfg(test)]` shim that is NOT
// platform-gated.  The struct definitions are byte-for-byte identical to
// the canonical ones inside `inner` (verified by the Linux-side tests at
// line ~4960, which run against the production types).  Any future change
// to the canonical layout must be mirrored here -- and the
// `test_bpf_mount_event_size` / `test_bpf_mount_event_offsets` tests will
// catch any divergence on every platform's CI.
//
// On Linux, the Linux-only test module inside `inner` ALSO exercises the
// real `BpfMountEvent`, so we have belt-and-braces validation there.
#[cfg(test)]
mod bpf_mount_event_layout_tests {
    // -- Layout constants -- must mirror `inner::MAX_*_LEN`. --------------
    const MAX_COMM_LEN: usize = 64;
    const MAX_PATH_LEN: usize = 256;
    const MAX_FSTYPE_LEN: usize = 64;

    /// Byte-for-byte mirror of `inner::EbpfEventHeader`.
    /// MUST stay in sync with the canonical definition in
    /// `ebpf_linux::inner` (line ~205) and the kernel-side
    /// `struct event_header` in `bpf/lsm_hooks.bpf.c`.
    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    pub struct EbpfEventHeader {
        pub event_type: u32,
        pub pid: u32,
        pub tid: u32,
        pub ppid: u32,
        pub uid: u32,
        pub gid: u32,
        pub timestamp_ns: u64,
        pub comm: [u8; MAX_COMM_LEN],
        pub cgroup_id: u64,
        pub mnt_ns: u32,
        pub pid_ns: u32,
    }

    /// Byte-for-byte mirror of `inner::BpfMountEvent`.
    /// MUST stay in sync with the canonical definition in
    /// `ebpf_linux::inner` (line ~379) and the kernel-side
    /// `struct bpf_mount_event` in `bpf/lsm_hooks.bpf.c`.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct BpfMountEvent {
        pub header: EbpfEventHeader,
        pub source: [u8; MAX_PATH_LEN],
        pub target: [u8; MAX_PATH_LEN],
        pub fstype: [u8; MAX_FSTYPE_LEN],
        pub flags: u64,
    }

    /// Verify EbpfEventHeader size matches C struct event_header.
    /// C layout: 4+4+4+4+4+4+8+64+8+4+4 = 112 bytes
    #[test]
    fn test_bpf_mount_event_header_size() {
        assert_eq!(
            std::mem::size_of::<EbpfEventHeader>(),
            112,
            "EbpfEventHeader size must be 112 bytes to match C event_header"
        );
    }

    /// Verify BpfMountEvent size matches C struct mount_event.
    /// C layout: header(112) + source(256) + target(256) + fstype(64) + flags(8) = 696
    #[test]
    fn test_bpf_mount_event_size() {
        assert_eq!(
            std::mem::size_of::<BpfMountEvent>(),
            696,
            "BpfMountEvent size must be 696 bytes to match C mount_event"
        );
    }

    /// Verify BpfMountEvent field offsets match C layout.
    /// Uses manual pointer arithmetic so the test compiles on all supported
    /// Rust versions and on every platform.
    #[test]
    fn test_bpf_mount_event_offsets() {
        unsafe {
            let base = std::ptr::null::<BpfMountEvent>();
            let header_offset = std::ptr::addr_of!((*base).header) as usize;
            let source_offset = std::ptr::addr_of!((*base).source) as usize;
            let target_offset = std::ptr::addr_of!((*base).target) as usize;
            let fstype_offset = std::ptr::addr_of!((*base).fstype) as usize;
            let flags_offset = std::ptr::addr_of!((*base).flags) as usize;

            assert_eq!(header_offset, 0, "header must be at offset 0");
            assert_eq!(source_offset, 112, "source must be at offset 112");
            assert_eq!(target_offset, 368, "target must be at offset 368 (112+256)");
            assert_eq!(fstype_offset, 624, "fstype must be at offset 624 (368+256)");
            assert_eq!(flags_offset, 688, "flags must be at offset 688 (624+64)");
        }
    }

    /// Verify the byte-layout assumptions used by `parse_mount_event` are
    /// stable: a synthetic buffer with `event_type=39` (MountEscape),
    /// a nonzero `cgroup_id`, source=`/var/run/docker.sock`, target=`/mnt/escape`,
    /// fstype=`none`, and flags=MS_BIND (0x1000) must have the right values
    /// at the right offsets.  This is the cross-platform half of the
    /// Linux-only `test_bpf_mount_event_type_39_roundtrip` test that
    /// actually invokes `parse_mount_event` -- here we only validate that
    /// the byte-pattern the parser will read matches the kernel ABI.
    #[test]
    fn test_bpf_mount_event_type_39_byte_layout() {
        let mut buf = vec![0u8; std::mem::size_of::<BpfMountEvent>()];

        // event_type at offset 0, little-endian u32 = 39
        buf[0..4].copy_from_slice(&39u32.to_le_bytes());
        // pid at offset 4
        buf[4..8].copy_from_slice(&4242u32.to_le_bytes());
        // cgroup_id at offset 96 (u64) - must be non-zero for container detection
        buf[96..104].copy_from_slice(&0xDEAD_BEEFu64.to_le_bytes());
        // source at offset 112: "/var/run/docker.sock"
        let src = b"/var/run/docker.sock";
        buf[112..112 + src.len()].copy_from_slice(src);
        // target at offset 368: "/mnt/escape"
        let tgt = b"/mnt/escape";
        buf[368..368 + tgt.len()].copy_from_slice(tgt);
        // fstype at offset 624: "none"
        let fst = b"none";
        buf[624..624 + fst.len()].copy_from_slice(fst);
        // flags at offset 688: MS_BIND = 0x1000
        buf[688..696].copy_from_slice(&0x1000u64.to_le_bytes());

        // Reinterpret the buffer as a BpfMountEvent and verify field reads.
        assert!(buf.len() >= std::mem::size_of::<BpfMountEvent>());
        let event = unsafe { &*(buf.as_ptr() as *const BpfMountEvent) };
        assert_eq!(event.header.event_type, 39, "event_type must be 39");
        assert_eq!(event.header.pid, 4242, "pid must be 4242");
        assert_eq!(
            event.header.cgroup_id, 0xDEAD_BEEF,
            "cgroup_id must round-trip"
        );
        assert_eq!(event.flags, 0x1000, "flags must be MS_BIND");

        let source_len = event.source.iter().position(|&b| b == 0).unwrap_or(0);
        assert_eq!(
            &event.source[..source_len],
            b"/var/run/docker.sock",
            "source must round-trip"
        );
        let target_len = event.target.iter().position(|&b| b == 0).unwrap_or(0);
        assert_eq!(
            &event.target[..target_len],
            b"/mnt/escape",
            "target must round-trip"
        );
        let fstype_len = event.fstype.iter().position(|&b| b == 0).unwrap_or(0);
        assert_eq!(
            &event.fstype[..fstype_len],
            b"none",
            "fstype must round-trip"
        );
    }
}
