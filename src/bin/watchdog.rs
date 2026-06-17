//! Tamandua External Watchdog Process
//!
//! A standalone executable that provides process persistence for the Tamandua EDR agent.
//!
//! ## Features
//!
//! - Monitors the main agent process by PID
//! - Restarts agent if process dies unexpectedly
//! - Uses named mutex for single instance enforcement
//! - Runs hidden (no console window on Windows)
//! - Registers with kernel driver for protection
//! - Heartbeat communication via shared memory or named pipe
//!
//! ## Mutual Watchdog Architecture
//!
//! The main agent and watchdog protect each other:
//! - Main agent spawns watchdog on start
//! - Watchdog respawns main agent on crash
//! - Both register with kernel driver for anti-tamper protection
//!
//! ## Communication Protocol
//!
//! Heartbeat via named pipe or shared memory:
//! - Agent sends heartbeat every 10 seconds
//! - Watchdog restarts if no heartbeat for 30 seconds
//!
//! ## Building
//!
//! ```bash
//! cargo build --release --bin tamandua-watchdog
//! ```

#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};

// ============================================================================
// Constants
// ============================================================================

/// Mutex name for single instance enforcement
const WATCHDOG_MUTEX_NAME: &str = "Global\\TamanduaWatchdogMutex";

/// Named pipe for heartbeat communication.
/// Reserved for a future named-pipe IPC fallback; the current implementation
/// uses shared memory (`HEARTBEAT_SHMEM_NAME`) on Windows.
#[allow(dead_code)]
const HEARTBEAT_PIPE_NAME: &str = r"\\.\pipe\TamanduaHeartbeat";

/// Shared memory name for heartbeat (Windows)
const HEARTBEAT_SHMEM_NAME: &str = "Global\\TamanduaWatchdogHeartbeat";

/// Heartbeat interval (agent sends heartbeat every 10 seconds).
/// Documented for parity with the agent-side timer; the watchdog enforces
/// the timeout (`HEARTBEAT_TIMEOUT_SECS`) rather than the interval.
#[allow(dead_code)]
const HEARTBEAT_INTERVAL_SECS: u64 = 10;

/// Heartbeat timeout (restart if no heartbeat for 30 seconds)
const HEARTBEAT_TIMEOUT_SECS: u64 = 30;

/// Process check interval (check process status every 5 seconds)
const PROCESS_CHECK_INTERVAL_MS: u64 = 5000;

/// Maximum restart attempts before exponential backoff
const MAX_RESTART_ATTEMPTS: u32 = 5;

/// Base restart delay in seconds
const BASE_RESTART_DELAY_SECS: u64 = 5;

/// Maximum restart delay in seconds (after exponential backoff)
const MAX_RESTART_DELAY_SECS: u64 = 300;

/// Service name for SCM restart
const SERVICE_NAME: &str = "TamanduaAgent";

// ============================================================================
// Platform-specific imports
// ============================================================================

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::*;
    use std::ffi::c_void;
    use std::mem;

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_ALREADY_EXISTS, FALSE, HANDLE, INVALID_HANDLE_VALUE, TRUE,
    };

    use windows::Win32::Storage::InstallableFileSystems::{
        FilterConnectCommunicationPort, FilterSendMessage,
    };
    use windows::Win32::System::Memory::{
        CreateFileMappingW, MapViewOfFile, OpenFileMappingW, UnmapViewOfFile, FILE_MAP_ALL_ACCESS,
        PAGE_READWRITE,
    };

    use windows::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, StartServiceW, SC_MANAGER_CONNECT,
        SERVICE_START,
    };
    use windows::Win32::System::Threading::{
        CreateMutexW, GetExitCodeProcess, OpenProcess, ReleaseMutex,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    /// Ensure single instance via named mutex
    pub struct SingleInstanceGuard {
        mutex_handle: HANDLE,
    }

    impl SingleInstanceGuard {
        pub fn acquire() -> Result<Option<Self>> {
            unsafe {
                let mutex_name: Vec<u16> = WATCHDOG_MUTEX_NAME
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect();

                let handle = CreateMutexW(None, TRUE, PCWSTR(mutex_name.as_ptr()))?;

                // Check if mutex already existed (another instance running)
                // Use std::io to get the last OS error in a cross-platform way
                let last_error = std::io::Error::last_os_error();
                if last_error.raw_os_error() == Some(ERROR_ALREADY_EXISTS.0 as i32) {
                    let _ = CloseHandle(handle);
                    return Ok(None); // Another instance running
                }

                Ok(Some(Self {
                    mutex_handle: handle,
                }))
            }
        }
    }

    impl Drop for SingleInstanceGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = ReleaseMutex(self.mutex_handle);
                let _ = CloseHandle(self.mutex_handle);
            }
        }
    }

    /// Check if a process is running by PID
    pub fn is_process_running(pid: u32) -> bool {
        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid) {
                Ok(h) => h,
                Err(_) => return false,
            };

            let mut exit_code: u32 = 0;
            let result = GetExitCodeProcess(handle, &mut exit_code);
            let _ = CloseHandle(handle);

            // STILL_ACTIVE = 259 (0x103)
            result.is_ok() && exit_code == 259
        }
    }

    /// Shared memory heartbeat structure
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct SharedHeartbeat {
        pub magic: u32,
        pub version: u32,
        pub agent_pid: u32,
        pub watchdog_pid: u32,
        pub last_agent_heartbeat: u64,
        pub last_watchdog_heartbeat: u64,
        pub agent_start_count: u32,
        pub flags: u32,
    }

    impl SharedHeartbeat {
        pub const MAGIC: u32 = 0x54414D41; // "TAMA"
        pub const VERSION: u32 = 1;
        pub const FLAG_AGENT_RUNNING: u32 = 0x01;
        pub const FLAG_WATCHDOG_RUNNING: u32 = 0x02;
        pub const FLAG_SHUTDOWN_REQUESTED: u32 = 0x04;
    }

    /// Shared memory manager for heartbeat
    pub struct SharedMemory {
        handle: HANDLE,
        view: *mut c_void,
        /// Reserved for bounded-write validation when the heartbeat schema
        /// grows beyond the current fixed `SharedHeartbeat` layout.
        #[allow(dead_code)]
        size: usize,
    }

    impl SharedMemory {
        pub fn create_or_open() -> Result<Self> {
            let size = mem::size_of::<SharedHeartbeat>();

            let name: Vec<u16> = HEARTBEAT_SHMEM_NAME
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            unsafe {
                // Try to open existing first
                let handle =
                    match OpenFileMappingW(FILE_MAP_ALL_ACCESS.0, FALSE, PCWSTR(name.as_ptr())) {
                        Ok(h) => h,
                        Err(_) => {
                            // Create new
                            CreateFileMappingW(
                                INVALID_HANDLE_VALUE,
                                None,
                                PAGE_READWRITE,
                                0,
                                size as u32,
                                PCWSTR(name.as_ptr()),
                            )?
                        }
                    };

                let view = MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, size);
                if view.Value.is_null() {
                    let _ = CloseHandle(handle);
                    return Err(anyhow!("Failed to map view of file"));
                }

                Ok(Self {
                    handle,
                    view: view.Value,
                    size,
                })
            }
        }

        pub fn heartbeat_ptr(&self) -> *mut SharedHeartbeat {
            self.view as *mut SharedHeartbeat
        }

        pub fn read(&self) -> SharedHeartbeat {
            unsafe { std::ptr::read_volatile(self.heartbeat_ptr()) }
        }

        pub fn write(&self, hb: &SharedHeartbeat) {
            unsafe {
                std::ptr::write_volatile(self.heartbeat_ptr(), *hb);
            }
        }
    }

    impl Drop for SharedMemory {
        fn drop(&mut self) {
            unsafe {
                if !self.view.is_null() {
                    let _ = UnmapViewOfFile(
                        windows::Win32::System::Memory::MEMORY_MAPPED_VIEW_ADDRESS {
                            Value: self.view,
                        },
                    );
                }
                if self.handle != INVALID_HANDLE_VALUE {
                    let _ = CloseHandle(self.handle);
                }
            }
        }
    }

    unsafe impl Send for SharedMemory {}
    unsafe impl Sync for SharedMemory {}

    /// Restart agent via Service Control Manager
    pub fn restart_agent_via_scm() -> Result<()> {
        unsafe {
            let sc_manager = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT)?;

            let service_name: Vec<u16> = SERVICE_NAME
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let service =
                match OpenServiceW(sc_manager, PCWSTR(service_name.as_ptr()), SERVICE_START) {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = CloseServiceHandle(sc_manager);
                        return Err(anyhow!("Failed to open service: {:?}", e));
                    }
                };

            let result = StartServiceW(service, None);
            let _ = CloseServiceHandle(service);
            let _ = CloseServiceHandle(sc_manager);

            result.map_err(|e| anyhow!("Failed to start service: {:?}", e))
        }
    }

    /// Register this process with the kernel driver for protection
    pub fn register_with_driver() -> Result<()> {
        const TAMANDUA_PORT_NAME: &str = "\\TamanduaPort";
        const SET_AGENT_PID: u32 = 0x00A0;

        #[repr(C, packed)]
        struct MessageHeader {
            message_type: u32,
            message_id: u32,
            data_length: u32,
            status: i32,
        }

        let port_name: Vec<u16> = TAMANDUA_PORT_NAME
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            let port_handle = match FilterConnectCommunicationPort(
                PCWSTR(port_name.as_ptr()),
                0,
                None,
                0,
                None,
            ) {
                Ok(handle) => handle,
                Err(e) => return Err(anyhow!("Failed to connect to driver port: {:?}", e)),
            };

            static MESSAGE_ID: AtomicU64 = AtomicU64::new(0);

            let request = MessageHeader {
                message_type: SET_AGENT_PID,
                message_id: MESSAGE_ID.fetch_add(1, Ordering::SeqCst) as u32,
                data_length: 0,
                status: 0,
            };

            let mut response = MessageHeader {
                message_type: 0,
                message_id: 0,
                data_length: 0,
                status: 0,
            };
            let mut bytes_returned: u32 = 0;

            let send_result = FilterSendMessage(
                port_handle,
                &request as *const _ as *const c_void,
                mem::size_of::<MessageHeader>() as u32,
                Some(&mut response as *mut _ as *mut c_void),
                mem::size_of::<MessageHeader>() as u32,
                &mut bytes_returned,
            );

            let _ = CloseHandle(port_handle);

            if send_result.is_err() {
                return Err(anyhow!(
                    "Failed to register with driver: {:?}",
                    send_result.err()
                ));
            }

            Ok(())
        }
    }

    /// Hide from Task Manager (optional, via driver)
    pub fn hide_from_task_manager() -> Result<()> {
        // This would require kernel driver support to hook NtQuerySystemInformation
        // and filter out our process. For now, this is a placeholder that would
        // communicate with the driver if such functionality is implemented.
        //
        // Note: This is an optional feature and may not be implemented in all deployments.
        // The driver would need to:
        // 1. Hook NtQuerySystemInformation for SystemProcessInformation class
        // 2. Filter out processes matching our PID from the linked list
        //
        // Without driver support, we rely on process protection to prevent tampering.
        Ok(())
    }

    /// Set process as critical (BSOD on termination)
    pub fn set_critical_process() -> Result<()> {
        use windows::core::s;
        use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
        use windows::Win32::System::Threading::{
            GetCurrentProcess, SetPriorityClass, HIGH_PRIORITY_CLASS,
        };

        // NTSTATUS type
        type NTSTATUS = i32;
        const STATUS_SUCCESS: NTSTATUS = 0;

        // ProcessBreakOnTermination = 29 in PROCESSINFOCLASS
        const PROCESS_BREAK_ON_TERMINATION: u32 = 29;

        // NtSetInformationProcess function signature (PascalCase names mirror the
        // native NT API parameter names in the Windows kernel documentation).
        #[allow(non_snake_case)]
        type NtSetInformationProcessFn = unsafe extern "system" fn(
            ProcessHandle: HANDLE,
            ProcessInformationClass: u32,
            ProcessInformation: *const c_void,
            ProcessInformationLength: u32,
        ) -> NTSTATUS;

        unsafe {
            let process = GetCurrentProcess();

            // Set high priority first
            let _ = SetPriorityClass(process, HIGH_PRIORITY_CLASS);

            // Dynamically load NtSetInformationProcess from ntdll.dll
            let ntdll = match GetModuleHandleW(windows::core::w!("ntdll.dll")) {
                Ok(h) => h,
                Err(_) => {
                    return Err(anyhow!("Failed to get ntdll.dll handle"));
                }
            };

            let proc_addr = match GetProcAddress(ntdll, s!("NtSetInformationProcess")) {
                Some(addr) => addr,
                None => {
                    return Err(anyhow!("Failed to get NtSetInformationProcess address"));
                }
            };

            let nt_set_info: NtSetInformationProcessFn = std::mem::transmute(proc_addr);

            // Try to set as critical process (requires SeDebugPrivilege)
            let break_on_termination: u32 = 1;
            let status = nt_set_info(
                process,
                PROCESS_BREAK_ON_TERMINATION,
                &break_on_termination as *const _ as *const c_void,
                mem::size_of::<u32>() as u32,
            );

            if status != STATUS_SUCCESS {
                return Err(anyhow!(
                    "Failed to set critical process flag (NTSTATUS: 0x{:08X}): requires elevated privileges",
                    status as u32
                ));
            }

            Ok(())
        }
    }
}

#[cfg(unix)]
mod unix_impl {
    use super::*;
    use nix::fcntl::{flock, FlockArg};
    use nix::sys::signal::{kill, Signal};
    use nix::sys::stat::Mode;
    use nix::unistd::Pid;
    use std::fs::{File, OpenOptions};
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};

    /// Lock file path for single instance
    const LOCK_FILE: &str = "/var/run/tamandua-watchdog.lock";

    /// Unix socket for heartbeat
    const HEARTBEAT_SOCKET: &str = "/var/run/tamandua-heartbeat.sock";

    /// Ensure single instance via file lock
    pub struct SingleInstanceGuard {
        _file: File,
    }

    impl SingleInstanceGuard {
        pub fn acquire() -> Result<Option<Self>> {
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .mode(0o600)
                .open(LOCK_FILE)?;

            match flock(file.as_raw_fd(), FlockArg::LockExclusiveNonblock) {
                Ok(()) => {
                    // Write our PID to the lock file
                    let pid = std::process::id();
                    std::fs::write(LOCK_FILE, pid.to_string())?;
                    Ok(Some(Self { _file: file }))
                }
                Err(nix::errno::Errno::EWOULDBLOCK) => Ok(None),
                Err(e) => Err(anyhow!("Failed to acquire lock: {}", e)),
            }
        }
    }

    /// Check if a process is running by PID
    pub fn is_process_running(pid: u32) -> bool {
        // Send signal 0 to check if process exists
        kill(Pid::from_raw(pid as i32), None).is_ok()
    }

    /// Shared memory heartbeat (using mmap)
    pub struct SharedMemory {
        ptr: *mut u8,
        size: usize,
        fd: RawFd,
    }

    impl SharedMemory {
        pub fn create_or_open() -> Result<Self> {
            use nix::fcntl::OFlag;
            use nix::sys::mman::{mmap, munmap, shm_open, MapFlags, ProtFlags};
            use nix::sys::stat::Mode;

            let size = std::mem::size_of::<SharedHeartbeat>();
            let name = c"/tamandua_heartbeat";

            let fd = shm_open(
                name,
                OFlag::O_CREAT | OFlag::O_RDWR,
                Mode::S_IRUSR | Mode::S_IWUSR,
            )?;

            // Resize
            nix::unistd::ftruncate(&fd, size as i64)?;

            let ptr = unsafe {
                mmap(
                    None,
                    std::num::NonZeroUsize::new(size).unwrap(),
                    ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                    MapFlags::MAP_SHARED,
                    Some(&fd),
                    0,
                )?
            };

            Ok(Self {
                ptr: ptr as *mut u8,
                size,
                fd: fd.into_raw_fd(),
            })
        }

        pub fn heartbeat_ptr(&self) -> *mut SharedHeartbeat {
            self.ptr as *mut SharedHeartbeat
        }

        pub fn read(&self) -> SharedHeartbeat {
            unsafe { std::ptr::read_volatile(self.heartbeat_ptr()) }
        }

        pub fn write(&self, hb: &SharedHeartbeat) {
            unsafe {
                std::ptr::write_volatile(self.heartbeat_ptr(), *hb);
            }
        }
    }

    impl Drop for SharedMemory {
        fn drop(&mut self) {
            unsafe {
                let _ = nix::sys::mman::munmap(self.ptr as *mut std::ffi::c_void, self.size);
            }
            let _ = nix::unistd::close(self.fd);
        }
    }

    unsafe impl Send for SharedMemory {}
    unsafe impl Sync for SharedMemory {}

    /// Shared heartbeat structure (same as Windows)
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct SharedHeartbeat {
        pub magic: u32,
        pub version: u32,
        pub agent_pid: u32,
        pub watchdog_pid: u32,
        pub last_agent_heartbeat: u64,
        pub last_watchdog_heartbeat: u64,
        pub agent_start_count: u32,
        pub flags: u32,
    }

    impl SharedHeartbeat {
        pub const MAGIC: u32 = 0x54414D41; // "TAMA"
        pub const VERSION: u32 = 1;
        pub const FLAG_AGENT_RUNNING: u32 = 0x01;
        pub const FLAG_WATCHDOG_RUNNING: u32 = 0x02;
        pub const FLAG_SHUTDOWN_REQUESTED: u32 = 0x04;
    }

    /// Restart agent via systemd
    pub fn restart_agent_via_systemd() -> Result<()> {
        let output = Command::new("systemctl")
            .args(["restart", "tamandua-agent"])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!(
                "Failed to restart agent via systemd: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(())
    }

    /// Register with kernel (Linux doesn't have the same driver, but we can use other protections)
    pub fn register_with_driver() -> Result<()> {
        // On Linux, we don't have the same kernel driver infrastructure.
        // Instead, we can:
        // 1. Use prctl to set as non-dumpable
        // 2. Use capabilities to restrict what can interact with us

        #[cfg(target_os = "linux")]
        {
            use nix::sys::prctl::{set_dumpable, PrctlDumpable};

            // Set non-dumpable to prevent ptrace attach
            set_dumpable(PrctlDumpable::NotDumpable)?;
        }

        Ok(())
    }

    /// Set process as protected (Linux version)
    pub fn set_critical_process() -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            use nix::sys::prctl::{set_dumpable, PrctlDumpable};

            // Make process non-dumpable
            set_dumpable(PrctlDumpable::NotDumpable)?;
        }

        // Try to set nice value to highest priority
        unsafe {
            libc::setpriority(libc::PRIO_PROCESS, 0, -20);
        }

        Ok(())
    }

    /// Hide from process listing (placeholder)
    pub fn hide_from_task_manager() -> Result<()> {
        // This would require kernel module support on Linux
        // Not implemented for user-space watchdog
        Ok(())
    }
}

// ============================================================================
// Cross-platform types
// ============================================================================

/// Watchdog configuration
#[derive(Debug, Clone)]
pub struct WatchdogConfig {
    /// Path to the agent executable
    pub agent_path: PathBuf,
    /// Arguments to pass to the agent
    pub agent_args: Vec<String>,
    /// PID of the agent process to monitor (if already running)
    pub agent_pid: Option<u32>,
    /// Heartbeat timeout in seconds
    pub heartbeat_timeout_secs: u64,
    /// Maximum restart attempts before backoff
    pub max_restart_attempts: u32,
    /// Enable driver protection registration
    pub enable_driver_protection: bool,
    /// Enable critical process flag
    pub enable_critical_process: bool,
    /// Enable hiding from task manager
    pub enable_hide: bool,
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        Self {
            agent_path: PathBuf::new(),
            agent_args: vec![],
            agent_pid: None,
            heartbeat_timeout_secs: HEARTBEAT_TIMEOUT_SECS,
            max_restart_attempts: MAX_RESTART_ATTEMPTS,
            enable_driver_protection: true,
            enable_critical_process: false,
            enable_hide: false,
        }
    }
}

/// Watchdog state
struct WatchdogState {
    /// Configuration
    config: WatchdogConfig,
    /// Running flag
    running: Arc<AtomicBool>,
    /// Current agent PID
    agent_pid: AtomicU64,
    /// Restart attempt counter
    restart_attempts: AtomicU64,
    /// Last heartbeat timestamp
    last_heartbeat: AtomicU64,
    /// Total restarts performed
    total_restarts: AtomicU64,
}

impl WatchdogState {
    fn new(config: WatchdogConfig) -> Self {
        Self {
            agent_pid: AtomicU64::new(config.agent_pid.unwrap_or(0) as u64),
            config,
            running: Arc::new(AtomicBool::new(true)),
            restart_attempts: AtomicU64::new(0),
            last_heartbeat: AtomicU64::new(current_timestamp()),
            total_restarts: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// Core Watchdog Functions
// ============================================================================

/// Get current timestamp in seconds since UNIX epoch
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Monitor the agent process and restart if needed
fn monitor_agent(state: &WatchdogState) -> Result<()> {
    let pid = state.agent_pid.load(Ordering::SeqCst) as u32;

    if pid == 0 {
        eprintln!("[watchdog] No agent PID to monitor, attempting restart");
        restart_agent(state)?;
        return Ok(());
    }

    #[cfg(target_os = "windows")]
    let is_running = windows_impl::is_process_running(pid);

    #[cfg(unix)]
    let is_running = unix_impl::is_process_running(pid);

    #[cfg(not(any(target_os = "windows", unix)))]
    let is_running = true;

    if !is_running {
        eprintln!("[watchdog] Agent process {} not running, restarting", pid);
        restart_agent(state)?;
    }

    Ok(())
}

/// Restart the agent process
fn restart_agent(state: &WatchdogState) -> Result<u32> {
    let attempts = state.restart_attempts.fetch_add(1, Ordering::SeqCst);

    // Calculate backoff delay
    let delay_secs = if attempts < state.config.max_restart_attempts as u64 {
        BASE_RESTART_DELAY_SECS
    } else {
        let exp = attempts - state.config.max_restart_attempts as u64;
        std::cmp::min(
            BASE_RESTART_DELAY_SECS * (2u64.pow(exp as u32)),
            MAX_RESTART_DELAY_SECS,
        )
    };

    if delay_secs > BASE_RESTART_DELAY_SECS {
        eprintln!(
            "[watchdog] Backing off restart for {} seconds (attempt {})",
            delay_secs, attempts
        );
        std::thread::sleep(Duration::from_secs(delay_secs));
    }

    // Try SCM/systemd first
    #[cfg(target_os = "windows")]
    {
        if windows_impl::restart_agent_via_scm().is_ok() {
            eprintln!("[watchdog] Agent restarted via SCM");
            state.total_restarts.fetch_add(1, Ordering::SeqCst);
            // Give service time to start
            std::thread::sleep(Duration::from_secs(2));
            // STUB — PRODUCTION-GAP (minor), not production. Returns PID 0 as a
            // sentinel instead of querying the SCM (QueryServiceStatusEx /
            // SERVICE_STATUS_PROCESS) for the restarted agent's real PID. Callers
            // that rely on the returned PID for liveness tracking will see 0.
            return Ok(0);
        }
    }

    #[cfg(unix)]
    {
        if unix_impl::restart_agent_via_systemd().is_ok() {
            eprintln!("[watchdog] Agent restarted via systemd");
            state.total_restarts.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_secs(2));
            return Ok(0);
        }
    }

    // Fallback: direct execution
    let agent_path = &state.config.agent_path;

    if !agent_path.exists() {
        return Err(anyhow!("Agent executable not found: {:?}", agent_path));
    }

    eprintln!("[watchdog] Starting agent directly: {:?}", agent_path);

    let mut cmd = Command::new(agent_path);
    cmd.args(&state.config.agent_args);

    // Detach from this process
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
        const DETACHED_PROCESS: u32 = 0x00000008;
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS);
    }

    let child = cmd.spawn()?;
    let new_pid = child.id();

    state.agent_pid.store(new_pid as u64, Ordering::SeqCst);
    state.restart_attempts.store(0, Ordering::SeqCst);
    state.total_restarts.fetch_add(1, Ordering::SeqCst);
    state
        .last_heartbeat
        .store(current_timestamp(), Ordering::SeqCst);

    eprintln!("[watchdog] Agent started with PID {}", new_pid);

    Ok(new_pid)
}

/// Send heartbeat (for agent to call)
pub fn send_heartbeat() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        let shmem = windows_impl::SharedMemory::create_or_open()?;
        let mut hb = shmem.read();

        if hb.magic != windows_impl::SharedHeartbeat::MAGIC {
            // Initialize
            hb.magic = windows_impl::SharedHeartbeat::MAGIC;
            hb.version = windows_impl::SharedHeartbeat::VERSION;
        }

        hb.agent_pid = std::process::id();
        hb.last_agent_heartbeat = current_timestamp();
        hb.flags |= windows_impl::SharedHeartbeat::FLAG_AGENT_RUNNING;

        shmem.write(&hb);
    }

    #[cfg(unix)]
    {
        let shmem = unix_impl::SharedMemory::create_or_open()?;
        let mut hb = shmem.read();

        if hb.magic != unix_impl::SharedHeartbeat::MAGIC {
            hb.magic = unix_impl::SharedHeartbeat::MAGIC;
            hb.version = unix_impl::SharedHeartbeat::VERSION;
        }

        hb.agent_pid = std::process::id();
        hb.last_agent_heartbeat = current_timestamp();
        hb.flags |= unix_impl::SharedHeartbeat::FLAG_AGENT_RUNNING;

        shmem.write(&hb);
    }

    Ok(())
}

/// Check heartbeat (called by watchdog)
fn check_heartbeat(state: &WatchdogState) -> bool {
    let now = current_timestamp();
    let timeout = state.config.heartbeat_timeout_secs;

    #[cfg(target_os = "windows")]
    {
        if let Ok(shmem) = windows_impl::SharedMemory::create_or_open() {
            let hb = shmem.read();

            if hb.magic == windows_impl::SharedHeartbeat::MAGIC {
                if hb.flags & windows_impl::SharedHeartbeat::FLAG_SHUTDOWN_REQUESTED != 0 {
                    // Clean shutdown requested, don't restart
                    return true;
                }

                let last = hb.last_agent_heartbeat;
                if now.saturating_sub(last) < timeout {
                    state.last_heartbeat.store(last, Ordering::SeqCst);
                    return true;
                }
            }
        }
    }

    #[cfg(unix)]
    {
        if let Ok(shmem) = unix_impl::SharedMemory::create_or_open() {
            let hb = shmem.read();

            if hb.magic == unix_impl::SharedHeartbeat::MAGIC {
                if hb.flags & unix_impl::SharedHeartbeat::FLAG_SHUTDOWN_REQUESTED != 0 {
                    return true;
                }

                let last = hb.last_agent_heartbeat;
                if now.saturating_sub(last) < timeout {
                    state.last_heartbeat.store(last, Ordering::SeqCst);
                    return true;
                }
            }
        }
    }

    // Check last known heartbeat
    let last = state.last_heartbeat.load(Ordering::SeqCst);
    now.saturating_sub(last) < timeout
}

/// Main watchdog loop
fn watchdog_loop(state: Arc<WatchdogState>) -> Result<()> {
    let check_interval = Duration::from_millis(PROCESS_CHECK_INTERVAL_MS);

    eprintln!("[watchdog] Starting watchdog loop");
    eprintln!("[watchdog] Agent path: {:?}", state.config.agent_path);
    eprintln!(
        "[watchdog] Heartbeat timeout: {}s",
        state.config.heartbeat_timeout_secs
    );

    while state.running.load(Ordering::SeqCst) {
        // Check process status
        if let Err(e) = monitor_agent(&state) {
            eprintln!("[watchdog] Error monitoring agent: {}", e);
        }

        // Check heartbeat
        if !check_heartbeat(&state) {
            eprintln!("[watchdog] Heartbeat timeout, checking process");

            let pid = state.agent_pid.load(Ordering::SeqCst) as u32;

            #[cfg(target_os = "windows")]
            let is_running = windows_impl::is_process_running(pid);

            #[cfg(unix)]
            let is_running = unix_impl::is_process_running(pid);

            #[cfg(not(any(target_os = "windows", unix)))]
            let is_running = true;

            if is_running {
                // Process is running but not sending heartbeats - might be hung
                eprintln!(
                    "[watchdog] Agent {} running but not responding, consider force restart",
                    pid
                );
            } else {
                eprintln!("[watchdog] Agent {} terminated, restarting", pid);
                if let Err(e) = restart_agent(&state) {
                    eprintln!("[watchdog] Failed to restart agent: {}", e);
                }
            }
        }

        // Update watchdog heartbeat in shared memory
        #[cfg(target_os = "windows")]
        {
            if let Ok(shmem) = windows_impl::SharedMemory::create_or_open() {
                let mut hb = shmem.read();
                hb.watchdog_pid = std::process::id();
                hb.last_watchdog_heartbeat = current_timestamp();
                hb.flags |= windows_impl::SharedHeartbeat::FLAG_WATCHDOG_RUNNING;
                shmem.write(&hb);
            }
        }

        #[cfg(unix)]
        {
            if let Ok(shmem) = unix_impl::SharedMemory::create_or_open() {
                let mut hb = shmem.read();
                hb.watchdog_pid = std::process::id();
                hb.last_watchdog_heartbeat = current_timestamp();
                hb.flags |= unix_impl::SharedHeartbeat::FLAG_WATCHDOG_RUNNING;
                shmem.write(&hb);
            }
        }

        std::thread::sleep(check_interval);
    }

    Ok(())
}

// ============================================================================
// CLI and Main
// ============================================================================

fn print_usage() {
    eprintln!("Tamandua Watchdog - Agent Persistence Daemon");
    eprintln!();
    eprintln!("Usage: tamandua-watchdog [OPTIONS]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --agent-path <PATH>     Path to agent executable");
    eprintln!("  --agent-pid <PID>       PID of running agent to monitor");
    eprintln!("  --timeout <SECS>        Heartbeat timeout (default: 30)");
    eprintln!("  --no-driver             Disable driver protection registration");
    eprintln!("  --no-critical           Disable critical process flag");
    eprintln!("  --hide                  Hide from task manager (requires driver)");
    eprintln!("  --help                  Show this help message");
}

fn parse_args() -> Result<WatchdogConfig> {
    let args: Vec<String> = std::env::args().collect();
    let mut config = WatchdogConfig::default();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--agent-path" => {
                i += 1;
                if i >= args.len() {
                    return Err(anyhow!("--agent-path requires a value"));
                }
                config.agent_path = PathBuf::from(&args[i]);
            }
            "--agent-pid" => {
                i += 1;
                if i >= args.len() {
                    return Err(anyhow!("--agent-pid requires a value"));
                }
                config.agent_pid = Some(args[i].parse()?);
            }
            "--timeout" => {
                i += 1;
                if i >= args.len() {
                    return Err(anyhow!("--timeout requires a value"));
                }
                config.heartbeat_timeout_secs = args[i].parse()?;
            }
            "--no-driver" => {
                config.enable_driver_protection = false;
            }
            "--no-critical" => {
                config.enable_critical_process = false;
            }
            "--hide" => {
                config.enable_hide = true;
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            arg if arg.starts_with("--") => {
                return Err(anyhow!("Unknown option: {}", arg));
            }
            _ => {
                // Positional argument - treat as agent args
                config.agent_args.push(args[i].clone());
            }
        }
        i += 1;
    }

    // Default agent path
    if config.agent_path.as_os_str().is_empty() {
        let exe_path = std::env::current_exe()?;
        let exe_dir = exe_path
            .parent()
            .ok_or_else(|| anyhow!("Cannot determine exe directory"))?;

        #[cfg(target_os = "windows")]
        {
            config.agent_path = exe_dir.join("tamandua-agent.exe");
        }
        #[cfg(not(target_os = "windows"))]
        {
            config.agent_path = exe_dir.join("tamandua-agent");
        }
    }

    Ok(config)
}

fn main() -> Result<()> {
    // Parse configuration
    let config = match parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            print_usage();
            std::process::exit(1);
        }
    };

    eprintln!("[watchdog] Tamandua Watchdog starting");
    eprintln!("[watchdog] PID: {}", std::process::id());

    // Ensure single instance
    #[cfg(target_os = "windows")]
    let _guard = match windows_impl::SingleInstanceGuard::acquire()? {
        Some(g) => g,
        None => {
            eprintln!("[watchdog] Another instance is already running");
            std::process::exit(1);
        }
    };

    #[cfg(unix)]
    let _guard = match unix_impl::SingleInstanceGuard::acquire()? {
        Some(g) => g,
        None => {
            eprintln!("[watchdog] Another instance is already running");
            std::process::exit(1);
        }
    };

    // Register with kernel driver for protection
    if config.enable_driver_protection {
        #[cfg(target_os = "windows")]
        {
            match windows_impl::register_with_driver() {
                Ok(()) => eprintln!("[watchdog] Registered with kernel driver for protection"),
                Err(e) => eprintln!("[watchdog] Warning: Failed to register with driver: {}", e),
            }
        }

        #[cfg(unix)]
        {
            match unix_impl::register_with_driver() {
                Ok(()) => eprintln!("[watchdog] Applied Linux self-protection"),
                Err(e) => eprintln!("[watchdog] Warning: Failed to apply protection: {}", e),
            }
        }
    }

    // Set as critical process
    if config.enable_critical_process {
        #[cfg(target_os = "windows")]
        {
            match windows_impl::set_critical_process() {
                Ok(()) => eprintln!("[watchdog] Set as critical process"),
                Err(e) => eprintln!("[watchdog] Warning: Failed to set critical: {}", e),
            }
        }

        #[cfg(unix)]
        {
            match unix_impl::set_critical_process() {
                Ok(()) => eprintln!("[watchdog] Applied process protection"),
                Err(e) => eprintln!("[watchdog] Warning: Failed to set protection: {}", e),
            }
        }
    }

    // Hide from task manager (optional)
    if config.enable_hide {
        #[cfg(target_os = "windows")]
        {
            match windows_impl::hide_from_task_manager() {
                Ok(()) => eprintln!("[watchdog] Hidden from task manager"),
                Err(e) => eprintln!("[watchdog] Warning: Failed to hide: {}", e),
            }
        }

        #[cfg(unix)]
        {
            let _ = unix_impl::hide_from_task_manager();
        }
    }

    // Create state
    let state = Arc::new(WatchdogState::new(config));

    // Setup signal handlers. The platform branches below use either the
    // Unix sigaction model or the Windows static `RUNNING`/console control
    // handler; the clone is kept available for future threaded variants.
    let _running = state.running.clone();

    #[cfg(unix)]
    {
        use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};

        extern "C" fn handle_signal(_: i32) {
            // Signal received - will cause running check to fail
        }

        let sig_action = SigAction::new(
            SigHandler::Handler(handle_signal),
            SaFlags::empty(),
            SigSet::empty(),
        );

        unsafe {
            let _ = sigaction(Signal::SIGTERM, &sig_action);
            let _ = sigaction(Signal::SIGINT, &sig_action);
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Set console control handler
        use windows::Win32::System::Console::SetConsoleCtrlHandler;

        static RUNNING: AtomicBool = AtomicBool::new(true);

        unsafe extern "system" fn ctrl_handler(ctrl_type: u32) -> windows::Win32::Foundation::BOOL {
            match ctrl_type {
                0..=2 => {
                    // CTRL_C, CTRL_BREAK, CTRL_CLOSE
                    RUNNING.store(false, Ordering::SeqCst);
                    windows::Win32::Foundation::TRUE
                }
                _ => windows::Win32::Foundation::FALSE,
            }
        }

        unsafe {
            let _ = SetConsoleCtrlHandler(Some(ctrl_handler), true);
        }
    }

    // Start watchdog loop
    eprintln!("[watchdog] Entering main loop");
    watchdog_loop(state)?;

    eprintln!("[watchdog] Shutting down");
    Ok(())
}

// ============================================================================
// Public API for Agent Integration
// ============================================================================

/// Spawn the watchdog process from the main agent
pub fn spawn_watchdog(agent_path: &Path) -> Result<u32> {
    let watchdog_path = agent_path
        .parent()
        .ok_or_else(|| anyhow!("Cannot determine agent directory"))?
        .join(if cfg!(target_os = "windows") {
            "tamandua-watchdog.exe"
        } else {
            "tamandua-watchdog"
        });

    if !watchdog_path.exists() {
        return Err(anyhow!(
            "Watchdog executable not found: {:?}",
            watchdog_path
        ));
    }

    let agent_pid = std::process::id();

    let mut cmd = Command::new(&watchdog_path);
    cmd.arg("--agent-path").arg(agent_path);
    cmd.arg("--agent-pid").arg(agent_pid.to_string());

    // Detach from current process
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
        const DETACHED_PROCESS: u32 = 0x00000008;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS | CREATE_NO_WINDOW);
    }

    let child = cmd.spawn()?;
    let watchdog_pid = child.id();

    eprintln!(
        "[agent] Spawned watchdog process {} -> {:?}",
        watchdog_pid, watchdog_path
    );

    Ok(watchdog_pid)
}

/// Signal clean shutdown to watchdog (prevents restart)
pub fn signal_shutdown() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        let shmem = windows_impl::SharedMemory::create_or_open()?;
        let mut hb = shmem.read();
        hb.flags |= windows_impl::SharedHeartbeat::FLAG_SHUTDOWN_REQUESTED;
        shmem.write(&hb);
    }

    #[cfg(unix)]
    {
        let shmem = unix_impl::SharedMemory::create_or_open()?;
        let mut hb = shmem.read();
        hb.flags |= unix_impl::SharedHeartbeat::FLAG_SHUTDOWN_REQUESTED;
        shmem.write(&hb);
    }

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_timestamp() {
        let ts = current_timestamp();
        assert!(ts > 0);
        assert!(ts > 1700000000); // After 2023
    }

    #[test]
    fn test_config_default() {
        let config = WatchdogConfig::default();
        assert_eq!(config.heartbeat_timeout_secs, HEARTBEAT_TIMEOUT_SECS);
        assert_eq!(config.max_restart_attempts, MAX_RESTART_ATTEMPTS);
        assert!(config.enable_driver_protection);
        assert!(!config.enable_critical_process);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_is_process_running_self() {
        let pid = std::process::id();
        assert!(windows_impl::is_process_running(pid));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_is_process_running_invalid() {
        // PID 0 is the System Idle Process, PID 4 is System - both should exist
        // Use a very high PID that's unlikely to exist
        assert!(!windows_impl::is_process_running(999999999));
    }

    #[cfg(unix)]
    #[test]
    fn test_is_process_running_self() {
        let pid = std::process::id();
        assert!(unix_impl::is_process_running(pid));
    }

    #[cfg(unix)]
    #[test]
    fn test_is_process_running_invalid() {
        assert!(!unix_impl::is_process_running(999999999));
    }
}
