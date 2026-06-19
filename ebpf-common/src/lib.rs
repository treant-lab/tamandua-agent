//! Common types shared between eBPF programs and userspace.
//!
//! These types are used for communication via ring buffers.
//! All types must be #[repr(C)] for memory layout compatibility.
//!
//! The `user` feature enables aya integration for userspace programs.

#![no_std]

// When building for userspace with aya, implement Pod trait for map value types
#[cfg(feature = "user")]
use aya::Pod;

/// Maximum length for process command/path strings
pub const MAX_COMM_LEN: usize = 64;
pub const MAX_PATH_LEN: usize = 256;
pub const MAX_FILENAME_LEN: usize = 256;
pub const MAX_ARGS_LEN: usize = 256;
pub const MAX_CGROUP_PATH_LEN: usize = 128;
pub const MAX_CONTAINER_ID_LEN: usize = 64;

/// Maximum length for LLM request data (4KB truncation for prompt data)
pub const LLM_DATA_MAX_LEN: usize = 4096;

// ============================================================================
// Event Type Discriminators
// ============================================================================

/// Event type discriminator
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventType {
    // Process Events (1-19)
    ProcessExec = 1,
    ProcessExit = 2,
    ProcessFork = 3,
    ProcessClone = 4,
    PtraceAttach = 5,
    PtraceDetach = 6,

    // File Events (20-39)
    FileOpen = 20,
    FileWrite = 21,
    FileUnlink = 22,
    FileRename = 23,
    FileCreate = 24,
    FileMmap = 25,
    FilePermission = 26,
    SensitiveFileAccess = 27,
    FileRead = 28,

    // Network Events (40-59)
    NetworkConnect = 40,
    NetworkAccept = 41,
    NetworkBind = 42,
    NetworkClose = 43,
    TcpStateChange = 44,
    XdpPacket = 45,
    DnsQuery = 46,
    DnsResponse = 47,

    // Security Events (60-79)
    PrivilegeEscalation = 60,
    CredentialChange = 61,
    CapabilityUse = 62,
    SelinuxDenial = 63,

    // Syscall Events (80-99)
    SyscallExecve = 80,
    SyscallExecveat = 81,
    SyscallOpenat = 82,
    SyscallMount = 83,
    SyscallUmount = 84,
    SyscallKill = 85,
    SyscallMmapExec = 86,
    SyscallMemfdCreate = 87,
    SyscallPtrace = 88,

    // LSM Events (100-119)
    LsmBprmCheckSecurity = 100,
    LsmFileOpen = 101,
    LsmFilePermission = 102,
    LsmSocketConnect = 103,
    LsmSocketBind = 104,
    LsmTaskKill = 105,
    LsmMmapFile = 106,

    // Container Events (120-139)
    ContainerStart = 120,
    ContainerStop = 121,
    NamespaceChange = 122,
    CgroupChange = 123,
    ContainerEscape = 124,

    // Kernel Events (140-159)
    ModuleLoad = 140,
    ModuleUnload = 141,
    KernelSymbolLookup = 142,

    // Syscall Evasion Events (160-179)
    SyscallEvasionDirectSyscall = 160,
    SyscallEvasionAnonymousMmap = 161,
    SyscallEvasionSeccompBypass = 162,
    SyscallEvasionPtraceInject = 163,
    SyscallEvasionMemfdExec = 164,
    SyscallEvasionProcMemWrite = 165,
    SyscallEvasionLdPreload = 166,

    // LLM Events (180-199)
    LlmRequest = 180,
}

impl EventType {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::ProcessExec),
            2 => Some(Self::ProcessExit),
            3 => Some(Self::ProcessFork),
            4 => Some(Self::ProcessClone),
            5 => Some(Self::PtraceAttach),
            6 => Some(Self::PtraceDetach),

            20 => Some(Self::FileOpen),
            21 => Some(Self::FileWrite),
            22 => Some(Self::FileUnlink),
            23 => Some(Self::FileRename),
            24 => Some(Self::FileCreate),
            25 => Some(Self::FileMmap),
            26 => Some(Self::FilePermission),
            27 => Some(Self::SensitiveFileAccess),
            28 => Some(Self::FileRead),

            40 => Some(Self::NetworkConnect),
            41 => Some(Self::NetworkAccept),
            42 => Some(Self::NetworkBind),
            43 => Some(Self::NetworkClose),
            44 => Some(Self::TcpStateChange),
            45 => Some(Self::XdpPacket),
            46 => Some(Self::DnsQuery),
            47 => Some(Self::DnsResponse),

            60 => Some(Self::PrivilegeEscalation),
            61 => Some(Self::CredentialChange),
            62 => Some(Self::CapabilityUse),
            63 => Some(Self::SelinuxDenial),

            80 => Some(Self::SyscallExecve),
            81 => Some(Self::SyscallExecveat),
            82 => Some(Self::SyscallOpenat),
            83 => Some(Self::SyscallMount),
            84 => Some(Self::SyscallUmount),
            85 => Some(Self::SyscallKill),
            86 => Some(Self::SyscallMmapExec),
            87 => Some(Self::SyscallMemfdCreate),
            88 => Some(Self::SyscallPtrace),

            100 => Some(Self::LsmBprmCheckSecurity),
            101 => Some(Self::LsmFileOpen),
            102 => Some(Self::LsmFilePermission),
            103 => Some(Self::LsmSocketConnect),
            104 => Some(Self::LsmSocketBind),
            105 => Some(Self::LsmTaskKill),
            106 => Some(Self::LsmMmapFile),

            120 => Some(Self::ContainerStart),
            121 => Some(Self::ContainerStop),
            122 => Some(Self::NamespaceChange),
            123 => Some(Self::CgroupChange),
            124 => Some(Self::ContainerEscape),

            140 => Some(Self::ModuleLoad),
            141 => Some(Self::ModuleUnload),
            142 => Some(Self::KernelSymbolLookup),

            160 => Some(Self::SyscallEvasionDirectSyscall),
            161 => Some(Self::SyscallEvasionAnonymousMmap),
            162 => Some(Self::SyscallEvasionSeccompBypass),
            163 => Some(Self::SyscallEvasionPtraceInject),
            164 => Some(Self::SyscallEvasionMemfdExec),
            165 => Some(Self::SyscallEvasionProcMemWrite),
            166 => Some(Self::SyscallEvasionLdPreload),

            180 => Some(Self::LlmRequest),

            _ => None,
        }
    }
}

// ============================================================================
// Common Event Header
// ============================================================================

/// Common header for all events
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EventHeader {
    /// Event type discriminator
    pub event_type: u32,
    /// Process ID (tgid in kernel terms)
    pub pid: u32,
    /// Thread ID (pid in kernel terms)
    pub tid: u32,
    /// Parent process ID
    pub ppid: u32,
    /// User ID
    pub uid: u32,
    /// Group ID
    pub gid: u32,
    /// Timestamp in nanoseconds since boot
    pub timestamp_ns: u64,
    /// Process command name
    pub comm: [u8; MAX_COMM_LEN],
    /// cgroup ID for container tracking
    pub cgroup_id: u64,
    /// Mount namespace ID
    pub mnt_ns: u32,
    /// PID namespace ID
    pub pid_ns: u32,
}

// ============================================================================
// Process Events
// ============================================================================

/// Process execution event (execve/execveat)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessExecEvent {
    /// Common header
    pub header: EventHeader,
    /// Executable path
    pub filename: [u8; MAX_PATH_LEN],
    /// Command line arguments (truncated)
    pub args: [u8; MAX_ARGS_LEN],
    /// Length of args actually used
    pub args_len: u32,
    /// Current working directory
    pub cwd: [u8; MAX_PATH_LEN],
    /// Interpreter path (for scripts)
    pub interpreter: [u8; MAX_PATH_LEN],
    /// Flags (e.g., AT_EMPTY_PATH for execveat)
    pub flags: u32,
    /// File descriptor for execveat
    pub fd: i32,
}

/// Process exit event
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessExitEvent {
    /// Common header
    pub header: EventHeader,
    /// Exit code
    pub exit_code: i32,
    /// Exit signal (if killed by signal)
    pub exit_signal: i32,
    /// CPU time used (user)
    pub utime: u64,
    /// CPU time used (system)
    pub stime: u64,
}

/// Process fork/clone event
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessForkEvent {
    /// Common header (for parent)
    pub header: EventHeader,
    /// Child PID
    pub child_pid: u32,
    /// Child TID
    pub child_tid: u32,
    /// Clone flags
    pub clone_flags: u64,
    /// New namespace flags
    pub new_ns_flags: u32,
    /// Padding
    pub _pad: u32,
}

/// Ptrace event (debugging/injection detection)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PtraceEvent {
    /// Common header (tracer process)
    pub header: EventHeader,
    /// Target PID being traced
    pub target_pid: u32,
    /// Ptrace request type (PTRACE_ATTACH, etc.)
    pub request: u32,
    /// Address argument
    pub addr: u64,
    /// Data argument
    pub data: u64,
    /// Target process name
    pub target_comm: [u8; MAX_COMM_LEN],
}

// ============================================================================
// File Events
// ============================================================================

/// File operation event (open, create, write, etc.)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileEvent {
    /// Common header
    pub header: EventHeader,
    /// File path
    pub path: [u8; MAX_PATH_LEN],
    /// File descriptor
    pub fd: i32,
    /// File flags (O_RDONLY, O_WRONLY, etc.)
    pub flags: u32,
    /// File mode (for create)
    pub mode: u32,
    /// Inode number
    pub inode: u64,
    /// Device ID
    pub dev: u64,
    /// File size (if available)
    pub size: u64,
}

/// File rename event
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileRenameEvent {
    /// Common header
    pub header: EventHeader,
    /// Old path
    pub old_path: [u8; MAX_PATH_LEN],
    /// New path
    pub new_path: [u8; MAX_PATH_LEN],
    /// Old directory fd
    pub old_dfd: i32,
    /// New directory fd
    pub new_dfd: i32,
}

/// Memory map event (mmap with PROT_EXEC)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MmapEvent {
    /// Common header
    pub header: EventHeader,
    /// File path (if file-backed)
    pub path: [u8; MAX_PATH_LEN],
    /// Mapped address
    pub addr: u64,
    /// Mapped length
    pub len: u64,
    /// Protection flags (PROT_*)
    pub prot: u32,
    /// Map flags (MAP_*)
    pub flags: u32,
    /// File descriptor
    pub fd: i32,
    /// File offset
    pub offset: u64,
    /// Padding
    pub _pad: u32,
}

/// Sensitive file access event
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SensitiveFileEvent {
    /// Common header
    pub header: EventHeader,
    /// File path
    pub path: [u8; MAX_PATH_LEN],
    /// Access type (read, write, execute)
    pub access_type: u32,
    /// Sensitivity category (0=passwd, 1=shadow, 2=ssh_keys, 3=config, etc.)
    pub sensitivity: u32,
}

// ============================================================================
// Network Events
// ============================================================================

/// Network connection event (connect/accept)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetworkEvent {
    /// Common header
    pub header: EventHeader,
    /// Source IP address (IPv4 or IPv6)
    pub saddr: [u8; 16],
    /// Destination IP address (IPv4 or IPv6)
    pub daddr: [u8; 16],
    /// Source port (host byte order)
    pub sport: u16,
    /// Destination port (host byte order)
    pub dport: u16,
    /// Protocol (IPPROTO_TCP, IPPROTO_UDP)
    pub protocol: u8,
    /// Address family (AF_INET, AF_INET6)
    pub family: u8,
    /// Connection state (for TCP)
    pub state: u8,
    /// Direction (0=outbound, 1=inbound)
    pub direction: u8,
    /// Socket type (SOCK_STREAM, SOCK_DGRAM)
    pub sock_type: u32,
    /// Bytes sent (if available)
    pub bytes_sent: u64,
    /// Bytes received (if available)
    pub bytes_recv: u64,
}

/// Socket bind event
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SocketBindEvent {
    /// Common header
    pub header: EventHeader,
    /// Bind address
    pub addr: [u8; 16],
    /// Bind port
    pub port: u16,
    /// Address family
    pub family: u8,
    /// Protocol
    pub protocol: u8,
    /// Socket type
    pub sock_type: u32,
    /// Backlog (for listen)
    pub backlog: u32,
}

/// TCP state change event
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TcpStateEvent {
    /// Common header
    pub header: EventHeader,
    /// Source address
    pub saddr: [u8; 16],
    /// Destination address
    pub daddr: [u8; 16],
    /// Source port
    pub sport: u16,
    /// Destination port
    pub dport: u16,
    /// Old TCP state
    pub old_state: u8,
    /// New TCP state
    pub new_state: u8,
    /// Address family
    pub family: u8,
    /// Padding
    pub _pad: u8,
}

/// XDP packet event (for deep packet inspection)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct XdpPacketEvent {
    /// Event type
    pub event_type: u32,
    /// Interface index
    pub ifindex: u32,
    /// Packet length
    pub pkt_len: u32,
    /// Captured length
    pub cap_len: u32,
    /// Timestamp
    pub timestamp_ns: u64,
    /// Source MAC
    pub src_mac: [u8; 6],
    /// Destination MAC
    pub dst_mac: [u8; 6],
    /// Ethernet type
    pub eth_type: u16,
    /// IP protocol
    pub ip_proto: u8,
    /// Padding
    pub _pad: u8,
    /// Source IP
    pub saddr: [u8; 16],
    /// Destination IP
    pub daddr: [u8; 16],
    /// Source port
    pub sport: u16,
    /// Destination port
    pub dport: u16,
    /// TCP flags (if TCP)
    pub tcp_flags: u8,
    /// Padding
    pub _pad2: [u8; 3],
    /// Payload hash (for quick comparison)
    pub payload_hash: u64,
}

/// DNS query event (captured from UDP port 53)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsEvent {
    /// Common header
    pub header: EventHeader,
    /// DNS query name
    pub query: [u8; MAX_PATH_LEN],
    /// Query length
    pub query_len: u32,
    /// Query type (A=1, AAAA=28, etc)
    pub query_type: u16,
    /// Query class
    pub query_class: u16,
    /// DNS server address
    pub dns_server: [u8; 16],
    /// Response (for DnsResponse events)
    pub response: [u8; 64],
    /// Response length
    pub response_len: u32,
    /// Transaction ID
    pub txn_id: u16,
    /// Flags
    pub flags: u16,
}

// ============================================================================
// Security Events
// ============================================================================

/// Privilege escalation event (commit_creds detection)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PrivilegeEvent {
    /// Common header
    pub header: EventHeader,
    /// Old UID
    pub old_uid: u32,
    /// New UID
    pub new_uid: u32,
    /// Old EUID
    pub old_euid: u32,
    /// New EUID
    pub new_euid: u32,
    /// Old capabilities (effective)
    pub old_cap_effective: u64,
    /// New capabilities (effective)
    pub new_cap_effective: u64,
    /// Old capabilities (permitted)
    pub old_cap_permitted: u64,
    /// New capabilities (permitted)
    pub new_cap_permitted: u64,
    /// Escalation type (0=setuid, 1=setcap, 2=kernel_exploit)
    pub escalation_type: u32,
    /// Padding
    pub _pad: u32,
}

/// Capability use event
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CapabilityEvent {
    /// Common header
    pub header: EventHeader,
    /// Capability number (CAP_*)
    pub cap: u32,
    /// Target audit type
    pub audit: u32,
    /// Return value (0=allowed, -EPERM=denied)
    pub ret: i32,
    /// Padding
    pub _pad: u32,
}

// ============================================================================
// Syscall Events
// ============================================================================

/// Mount syscall event
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MountEvent {
    /// Common header
    pub header: EventHeader,
    /// Source (device path)
    pub source: [u8; MAX_PATH_LEN],
    /// Target (mount point)
    pub target: [u8; MAX_PATH_LEN],
    /// Filesystem type
    pub fstype: [u8; 64],
    /// Mount flags
    pub flags: u64,
}

/// Kill syscall event
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KillEvent {
    /// Common header (sender)
    pub header: EventHeader,
    /// Target PID
    pub target_pid: i32,
    /// Signal number
    pub signal: i32,
    /// Target process name
    pub target_comm: [u8; MAX_COMM_LEN],
    /// Return value
    pub ret: i32,
    /// Padding
    pub _pad: u32,
}

/// memfd_create syscall event (fileless malware detection)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MemfdEvent {
    /// Common header
    pub header: EventHeader,
    /// Name argument
    pub name: [u8; MAX_COMM_LEN],
    /// Flags
    pub flags: u32,
    /// Returned fd
    pub fd: i32,
}

// ============================================================================
// LSM Hook Events
// ============================================================================

/// LSM bprm_check_security event (process execution authorization)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LsmBprmEvent {
    /// Common header
    pub header: EventHeader,
    /// Executable path
    pub filename: [u8; MAX_PATH_LEN],
    /// Interpreter path (for scripts)
    pub interpreter: [u8; MAX_PATH_LEN],
    /// Return value (0=allowed, negative=denied)
    pub ret: i32,
    /// Is setuid/setgid?
    pub is_suid: u8,
    /// Is privileged (uid 0)?
    pub is_priv: u8,
    /// Padding
    pub _pad: [u8; 2],
}

/// LSM socket operation event
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LsmSocketEvent {
    /// Common header
    pub header: EventHeader,
    /// Address
    pub addr: [u8; 16],
    /// Port
    pub port: u16,
    /// Family
    pub family: u8,
    /// Protocol
    pub protocol: u8,
    /// Socket type
    pub sock_type: u32,
    /// Return value
    pub ret: i32,
    /// Operation type (0=connect, 1=bind)
    pub op: u32,
}

/// LSM task_kill event (signal authorization)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LsmTaskKillEvent {
    /// Common header (sender)
    pub header: EventHeader,
    /// Target PID
    pub target_pid: u32,
    /// Signal
    pub signal: i32,
    /// Permission type
    pub perm: u32,
    /// Return value
    pub ret: i32,
    /// Target command
    pub target_comm: [u8; MAX_COMM_LEN],
}

// ============================================================================
// Container Events
// ============================================================================

/// Container context
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ContainerContext {
    /// Container ID (first 12 chars of docker ID or similar)
    pub container_id: [u8; MAX_CONTAINER_ID_LEN],
    /// cgroup path
    pub cgroup_path: [u8; MAX_CGROUP_PATH_LEN],
    /// cgroup ID
    pub cgroup_id: u64,
    /// Mount namespace ID
    pub mnt_ns: u32,
    /// PID namespace ID
    pub pid_ns: u32,
    /// Net namespace ID
    pub net_ns: u32,
    /// User namespace ID
    pub user_ns: u32,
    /// Is this a container? (vs host)
    pub is_container: u8,
    /// Container runtime (0=unknown, 1=docker, 2=containerd, 3=crio, 4=podman)
    pub runtime: u8,
    /// Padding
    pub _pad: [u8; 2],
}

/// Namespace change event (container escape detection)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NamespaceEvent {
    /// Common header
    pub header: EventHeader,
    /// Namespace type (CLONE_NEWNS, CLONE_NEWPID, etc.)
    pub ns_type: u32,
    /// Old namespace ID
    pub old_ns: u32,
    /// New namespace ID
    pub new_ns: u32,
    /// Flags
    pub flags: u32,
    /// Is this potentially a container escape?
    pub is_escape: u8,
    /// Padding
    pub _pad: [u8; 7],
}

/// Cgroup change event
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CgroupEvent {
    /// Common header
    pub header: EventHeader,
    /// Old cgroup path
    pub old_path: [u8; MAX_CGROUP_PATH_LEN],
    /// New cgroup path
    pub new_path: [u8; MAX_CGROUP_PATH_LEN],
    /// Old cgroup ID
    pub old_id: u64,
    /// New cgroup ID
    pub new_id: u64,
}

// ============================================================================
// Kernel Module Events
// ============================================================================

/// Kernel module load event
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ModuleEvent {
    /// Common header
    pub header: EventHeader,
    /// Module name
    pub name: [u8; MAX_COMM_LEN],
    /// Module path (if loaded from file)
    pub path: [u8; MAX_PATH_LEN],
    /// Module flags
    pub flags: u32,
    /// Is signed?
    pub is_signed: u8,
    /// Padding
    pub _pad: [u8; 3],
}

// ============================================================================
// Syscall Evasion Events
// ============================================================================

/// Syscall evasion detection event
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SyscallEvasionEvent {
    /// Common header
    pub header: EventHeader,
    /// Syscall number
    pub syscall_nr: u32,
    /// Evasion type (160-166 maps to SyscallEvasion* variants)
    pub evasion_type: u32,
    /// Return address of syscall (for detecting direct syscalls)
    pub return_addr: u64,
    /// Start address of the memory region containing the syscall
    pub region_start: u64,
    /// Size of the memory region
    pub region_size: u64,
    /// Memory protection flags
    pub mem_prot: u32,
    /// Memory flags (anonymous, shared, etc.)
    pub mem_flags: u32,
    /// File descriptor (for memfd_create, execveat)
    pub fd: i32,
    /// Confidence level (0-100)
    pub confidence: u8,
    /// Padding
    pub _pad: [u8; 3],
    /// Target PID (for ptrace operations)
    pub target_pid: u32,
    /// Syscall argument 1
    pub arg1: u64,
    /// Syscall argument 2
    pub arg2: u64,
    /// Syscall argument 3
    pub arg3: u64,
    /// Path or name associated with the event
    pub path: [u8; MAX_PATH_LEN],
}

/// Event for tracking syscalls from anonymous memory regions
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SyscallFromAnonEvent {
    /// Common header
    pub header: EventHeader,
    /// Syscall number
    pub syscall_nr: u32,
    /// Return address (instruction pointer)
    pub ip: u64,
    /// Stack pointer
    pub sp: u64,
    /// VMA start address
    pub vma_start: u64,
    /// VMA end address
    pub vma_end: u64,
    /// VMA flags (VM_READ, VM_WRITE, VM_EXEC, etc.)
    pub vma_flags: u64,
    /// VMA is anonymous (no file backing)
    pub is_anonymous: u8,
    /// VMA is private
    pub is_private: u8,
    /// Padding
    pub _pad: [u8; 6],
}

/// Event for memfd_create + execveat detection (fileless execution)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FilelessExecEvent {
    /// Common header
    pub header: EventHeader,
    /// memfd name
    pub memfd_name: [u8; MAX_COMM_LEN],
    /// memfd flags
    pub memfd_flags: u32,
    /// Created file descriptor
    pub fd: i32,
    /// Whether execveat was called with this fd
    pub exec_attempted: u8,
    /// Flags for execveat (AT_EMPTY_PATH, etc.)
    pub exec_flags: u32,
    /// Padding
    pub _pad: [u8; 3],
    /// Written bytes to memfd before exec
    pub bytes_written: u64,
}

// ============================================================================
// Configuration Structures
// ============================================================================

/// Configuration for filtering events
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EbpfConfig {
    /// Master enable flag
    pub enabled: u8,
    /// Enable process monitoring
    pub process_enabled: u8,
    /// Enable file monitoring
    pub file_enabled: u8,
    /// Enable network monitoring
    pub network_enabled: u8,
    /// Enable security monitoring
    pub security_enabled: u8,
    /// Enable container awareness
    pub container_enabled: u8,
    /// Enable LSM hooks (requires BPF LSM)
    pub lsm_enabled: u8,
    /// Enable XDP (requires XDP support)
    pub xdp_enabled: u8,
    /// UID to filter (0 = monitor all)
    pub filter_uid: u32,
    /// Only monitor containers?
    pub containers_only: u8,
    /// Monitor sensitive files?
    pub sensitive_files_enabled: u8,
    /// Filter low PIDs (kernel threads, early system processes)
    pub filter_low_pids: u8,
    /// Padding
    pub _pad: [u8; 1],
}

/// Sensitive file patterns for monitoring
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SensitiveFilePath {
    /// Path pattern
    pub path: [u8; MAX_PATH_LEN],
    /// Sensitivity level (0-3)
    pub level: u8,
    /// Is prefix match? (vs exact)
    pub is_prefix: u8,
    /// Padding
    pub _pad: [u8; 2],
}

// ============================================================================
// Production eBPF Statistics and Rate Limiting
// ============================================================================

/// Statistics counters for eBPF program monitoring
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct EbpfStats {
    /// Total events generated
    pub events_generated: u64,
    /// Events dropped due to full ring buffer
    pub events_dropped_full: u64,
    /// Events dropped due to rate limiting
    pub events_rate_limited: u64,
    /// Map lookup failures
    pub map_lookup_failures: u64,
    /// Probe read failures
    pub probe_read_failures: u64,
}

/// Rate limit entry for per-PID rate limiting
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RateLimitEntry {
    /// Event count in current window
    pub count: u32,
    /// Window start timestamp (nanoseconds)
    pub window_start: u64,
}

/// Host namespace IDs for container escape detection
#[repr(C)]
#[derive(Clone, Copy)]
pub struct HostNamespaceIds {
    /// Mount namespace ID
    pub mnt_ns: u32,
    /// PID namespace ID
    pub pid_ns: u32,
    /// Network namespace ID
    pub net_ns: u32,
    /// User namespace ID
    pub user_ns: u32,
    /// Whether IDs have been initialized
    pub initialized: u8,
    /// Padding
    pub _pad: [u8; 3],
}

/// Syscall context for entry/exit correlation
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SyscallContextData {
    /// Syscall number
    pub syscall_nr: u32,
    /// Argument 0
    pub arg0: u64,
    /// Argument 1
    pub arg1: u64,
    /// Argument 2
    pub arg2: u64,
    /// Argument 3
    pub arg3: u64,
    /// Timestamp when syscall was entered
    pub timestamp_ns: u64,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Helper to read event type from raw bytes
#[inline]
pub fn get_event_type(data: &[u8]) -> Option<EventType> {
    if data.len() < 4 {
        return None;
    }
    let event_type = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
    EventType::from_u32(event_type)
}

/// Helper to convert byte array to string (stops at null or end)
#[inline]
pub fn bytes_to_str(bytes: &[u8]) -> &str {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    core::str::from_utf8(&bytes[..len]).unwrap_or("")
}

// TCP state constants
pub const TCP_ESTABLISHED: u8 = 1;
pub const TCP_SYN_SENT: u8 = 2;
pub const TCP_SYN_RECV: u8 = 3;
pub const TCP_FIN_WAIT1: u8 = 4;
pub const TCP_FIN_WAIT2: u8 = 5;
pub const TCP_TIME_WAIT: u8 = 6;
pub const TCP_CLOSE: u8 = 7;
pub const TCP_CLOSE_WAIT: u8 = 8;
pub const TCP_LAST_ACK: u8 = 9;
pub const TCP_LISTEN: u8 = 10;
pub const TCP_CLOSING: u8 = 11;

// Sensitivity levels for files
pub const SENSITIVITY_PASSWD: u32 = 0;
pub const SENSITIVITY_SHADOW: u32 = 1;
pub const SENSITIVITY_SSH_KEYS: u32 = 2;
pub const SENSITIVITY_CONFIG: u32 = 3;
pub const SENSITIVITY_CREDS: u32 = 4;
pub const SENSITIVITY_CRYPTO: u32 = 5;

// Namespace type constants
pub const CLONE_NEWNS: u32 = 0x00020000;
pub const CLONE_NEWUTS: u32 = 0x04000000;
pub const CLONE_NEWIPC: u32 = 0x08000000;
pub const CLONE_NEWUSER: u32 = 0x10000000;
pub const CLONE_NEWPID: u32 = 0x20000000;
pub const CLONE_NEWNET: u32 = 0x40000000;
pub const CLONE_NEWCGROUP: u32 = 0x02000000;

// Container runtime types
pub const RUNTIME_UNKNOWN: u8 = 0;
pub const RUNTIME_DOCKER: u8 = 1;
pub const RUNTIME_CONTAINERD: u8 = 2;
pub const RUNTIME_CRIO: u8 = 3;
pub const RUNTIME_PODMAN: u8 = 4;

// Security-relevant syscall numbers (x86_64)
pub const SYS_MMAP: u32 = 9;
pub const SYS_MPROTECT: u32 = 10;
pub const SYS_PTRACE: u32 = 101;
pub const SYS_PROCESS_VM_READV: u32 = 310;
pub const SYS_PROCESS_VM_WRITEV: u32 = 311;
pub const SYS_MEMFD_CREATE: u32 = 319;
pub const SYS_EXECVEAT: u32 = 322;
pub const SYS_SECCOMP: u32 = 317;
pub const SYS_PRCTL: u32 = 157;
pub const SYS_CLONE: u32 = 56;
pub const SYS_CLONE3: u32 = 435;
pub const SYS_FORK: u32 = 57;
pub const SYS_VFORK: u32 = 58;
pub const SYS_EXECVE: u32 = 59;
pub const SYS_OPEN: u32 = 2;
pub const SYS_OPENAT: u32 = 257;
pub const SYS_WRITE: u32 = 1;
pub const SYS_PWRITE64: u32 = 18;

// execveat flags
pub const AT_EMPTY_PATH: u32 = 0x1000;

// Memory protection flags
pub const PROT_NONE: u32 = 0x0;
pub const PROT_READ: u32 = 0x1;
pub const PROT_WRITE: u32 = 0x2;
pub const PROT_EXEC: u32 = 0x4;

// VMA flags
pub const VM_READ: u64 = 0x00000001;
pub const VM_WRITE: u64 = 0x00000002;
pub const VM_EXEC: u64 = 0x00000004;
pub const VM_SHARED: u64 = 0x00000008;
pub const VM_MAYREAD: u64 = 0x00000010;
pub const VM_MAYWRITE: u64 = 0x00000020;
pub const VM_MAYEXEC: u64 = 0x00000040;

// Ptrace request types
pub const PTRACE_TRACEME: u32 = 0;
pub const PTRACE_PEEKTEXT: u32 = 1;
pub const PTRACE_PEEKDATA: u32 = 2;
pub const PTRACE_POKETEXT: u32 = 4;
pub const PTRACE_POKEDATA: u32 = 5;
pub const PTRACE_ATTACH: u32 = 16;
pub const PTRACE_DETACH: u32 = 17;
pub const PTRACE_SEIZE: u32 = 0x4206;
pub const PTRACE_GETREGS: u32 = 12;
pub const PTRACE_SETREGS: u32 = 13;

// Evasion type discriminators (matching EventType variants)
pub const EVASION_DIRECT_SYSCALL: u32 = 160;
pub const EVASION_ANONYMOUS_MMAP: u32 = 161;
pub const EVASION_SECCOMP_BYPASS: u32 = 162;
pub const EVASION_PTRACE_INJECT: u32 = 163;
pub const EVASION_MEMFD_EXEC: u32 = 164;
pub const EVASION_PROC_MEM_WRITE: u32 = 165;
pub const EVASION_LD_PRELOAD: u32 = 166;

// LLM event type discriminators
pub const LLM_EVENT_TYPE_SSL_WRITE: u32 = 1;
pub const LLM_EVENT_TYPE_SSL_READ: u32 = 2;

// ============================================================================
// LLM Events
// ============================================================================

/// LLM API request event captured via SSL_write interception
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LlmRequestEvent {
    /// Event type (SSL_WRITE or SSL_READ)
    pub event_type: u32,
    /// Process ID
    pub pid: u32,
    /// Thread ID
    pub tid: u32,
    /// Kernel timestamp in nanoseconds
    pub timestamp_ns: u64,
    /// Socket file descriptor
    pub fd: i32,
    /// Actual data length (before truncation)
    pub data_len: u32,
    /// Process command name
    pub comm: [u8; 16],
    /// Request body (JSON, truncated to 4KB)
    pub data: [u8; LLM_DATA_MAX_LEN],
}

#[cfg(feature = "user")]
impl core::fmt::Debug for LlmRequestEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let comm_str = bytes_to_str(&self.comm);
        let data_len_capped = core::cmp::min(self.data_len as usize, LLM_DATA_MAX_LEN);
        let data_str =
            core::str::from_utf8(&self.data[..data_len_capped]).unwrap_or("<invalid UTF-8>");

        f.debug_struct("LlmRequestEvent")
            .field("event_type", &self.event_type)
            .field("pid", &self.pid)
            .field("tid", &self.tid)
            .field("timestamp_ns", &self.timestamp_ns)
            .field("fd", &self.fd)
            .field("data_len", &self.data_len)
            .field("comm", &comm_str)
            .field("data", &data_str)
            .finish()
    }
}

// ============================================================================
// Pod Implementations for Aya (userspace only)
// ============================================================================
// Pod (Plain Old Data) trait is required for types used in BPF maps with aya.
// These are marked unsafe because we guarantee the types are:
// - #[repr(C)] for stable layout
// - Copy
// - Contain no padding that could leak data
// - Have no pointer types

#[cfg(feature = "user")]
mod pod_impls {
    use super::*;

    // SAFETY: All types below are #[repr(C)], Copy, and have no pointers
    unsafe impl Pod for EventHeader {}
    unsafe impl Pod for ProcessExecEvent {}
    unsafe impl Pod for ProcessExitEvent {}
    unsafe impl Pod for ProcessForkEvent {}
    unsafe impl Pod for PtraceEvent {}
    unsafe impl Pod for FileEvent {}
    unsafe impl Pod for FileRenameEvent {}
    unsafe impl Pod for MmapEvent {}
    unsafe impl Pod for SensitiveFileEvent {}
    unsafe impl Pod for NetworkEvent {}
    unsafe impl Pod for SocketBindEvent {}
    unsafe impl Pod for TcpStateEvent {}
    unsafe impl Pod for XdpPacketEvent {}
    unsafe impl Pod for DnsEvent {}
    unsafe impl Pod for PrivilegeEvent {}
    unsafe impl Pod for CapabilityEvent {}
    unsafe impl Pod for MountEvent {}
    unsafe impl Pod for KillEvent {}
    unsafe impl Pod for MemfdEvent {}
    unsafe impl Pod for LsmBprmEvent {}
    unsafe impl Pod for LsmSocketEvent {}
    unsafe impl Pod for LsmTaskKillEvent {}
    unsafe impl Pod for ContainerContext {}
    unsafe impl Pod for NamespaceEvent {}
    unsafe impl Pod for CgroupEvent {}
    unsafe impl Pod for ModuleEvent {}
    unsafe impl Pod for EbpfConfig {}
    unsafe impl Pod for SensitiveFilePath {}
    unsafe impl Pod for SyscallEvasionEvent {}
    unsafe impl Pod for SyscallFromAnonEvent {}
    unsafe impl Pod for FilelessExecEvent {}
    unsafe impl Pod for EbpfStats {}
    unsafe impl Pod for RateLimitEntry {}
    unsafe impl Pod for HostNamespaceIds {}
    unsafe impl Pod for SyscallContextData {}
    unsafe impl Pod for LlmRequestEvent {}
}
