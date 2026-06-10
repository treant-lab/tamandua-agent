//! Tamandua Kernel Driver Communication
//!
//! This module provides communication with the Tamandua kernel driver.
//! The driver provides:
//! - High-performance telemetry via shared memory ring buffer
//! - Agent protection (prevents termination)
//! - File protection
//! - Network isolation
//! - LSASS protection

// Driver IOCTL codes, shared-memory layout constants, and protection-policy
// flag tables are kept exhaustive so changes to the kernel driver remain
// machine-checkable from userspace. Unused entries are deliberate reserved
// surface.
#![allow(dead_code)]

pub mod ring_buffer;
pub mod scan_port;

use anyhow::{anyhow, Result};
use std::ffi::c_void;
use std::mem;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::Arc;
use tracing::{debug, info, warn};

#[cfg(target_os = "windows")]
use windows::core::PCWSTR;
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
#[cfg(target_os = "windows")]
use windows::Win32::Storage::InstallableFileSystems::{
    FilterConnectCommunicationPort, FilterSendMessage,
};

/// Driver port name
const TAMANDUA_PORT_NAME: &str = "\\TamanduaPort";

/// Lab feature level compiled into the current bundled driver.
///
/// Keep this in sync with `apps/tamandua_driver/src/driver.h` and the driver
/// Makefile default. It is surfaced in agent health so the backend can show
/// what Windows kernel feature set is expected on the endpoint.
pub const LAB_LEVEL: u32 = 14;

pub fn lab_feature_level() -> &'static str {
    match LAB_LEVEL {
        0..=14 => "core_callbacks",
        15..=150 => "core_callbacks_experimental",
        151..=157 => "advanced_callbacks",
        158..=160 => "network_controls",
        161..=170 => "self_protection_basic",
        171 => "driver_protection",
        172.. => "callback_guard",
    }
}

/// Command types (must match driver)
mod commands {
    pub const REGISTER_AGENT: u32 = 0x0001;
    // pub const UNREGISTER_AGENT: u32 = 0x0002; // Not in header
    pub const HEARTBEAT: u32 = 0x0003;
    pub const CONFIG_GET: u32 = 0x0010; // Not in header but likely reserved
    pub const CONFIG_SET: u32 = 0x0011; // Not in header but likely reserved

    // Rules
    pub const RULE_ADD: u32 = 0x0010;
    pub const RULE_REMOVE: u32 = 0x0011;
    pub const RULE_CLEAR: u32 = 0x0012;

    // Process
    pub const PROCESS_BLOCK: u32 = 0x0020;
    pub const PROCESS_UNBLOCK: u32 = 0x0021;
    pub const PROCESS_KILL: u32 = 0x0022;

    // File
    pub const FILE_PROTECT: u32 = 0x0030;
    pub const FILE_UNPROTECT: u32 = 0x0031;

    // Network
    pub const NETWORK_ISOLATE: u32 = 0x0040;
    pub const NETWORK_RESTORE: u32 = 0x0041;

    // Stats
    pub const STATUS_GET: u32 = 0x0050;
    pub const STATS_GET: u32 = 0x0051;
    pub const STATS_RESET: u32 = 0x0052;
    pub const CAPABILITIES_GET: u32 = 0x0062;

    // Legacy / Aliases (kept for compatibility with existing code calling them)
    pub const PROTECT_PROCESS: u32 = 0x0030; // ERROR: This was overlapping with FILE_PROTECT in older agent code
                                             // We will rely on mapped constants now

    // WFP Specific (0x00B0 range in driver header)
    pub const ENABLE_ISOLATION: u32 = 0x00B0;
    pub const DISABLE_ISOLATION: u32 = 0x00B1;
    pub const BLOCK_PROCESS_NET: u32 = 0x00B2;
    pub const UNBLOCK_PROCESS_NET: u32 = 0x00B3;
    pub const ADD_IP_BLOCK: u32 = 0x00B4;
    pub const REMOVE_IP_BLOCK: u32 = 0x00B5;
    pub const GET_NET_STATS: u32 = 0x00B6;

    // Anti-tamper
    pub const SET_AGENT_PID: u32 = 0x00A0;
    pub const SET_CLEAN_SHUTDOWN: u32 = 0x00A1;
    pub const GET_ANTITAMPER_STATS: u32 = 0x00A2;

    // Restart protection (0x00C0 range)
    // Uses PsSetCreateProcessNotifyRoutineEx to detect agent termination
    pub const REGISTER_RESTART_PROTECTION: u32 = 0x00C0;
    pub const UNREGISTER_RESTART_PROTECTION: u32 = 0x00C1;
    pub const SET_RESTART_ENABLED: u32 = 0x00C2;
    pub const GET_RESTART_STATUS: u32 = 0x00C3;
}

/// Response types
mod responses {
    pub const SUCCESS: u32 = 0x8000;
    pub const ERROR: u32 = 0x8001;
    pub const DATA: u32 = 0x8002;
}

/// Agent registration flags
pub mod agent_flags {
    pub const AUTO_RESTART: u32 = 0x00000001;
    pub const PROTECTED: u32 = 0x00000002;
    pub const ELEVATED: u32 = 0x00000004;
}

/// Process protection flags
pub mod protect_flags {
    pub const NO_TERMINATE: u32 = 0x00000001;
    pub const NO_INJECT: u32 = 0x00000002;
    pub const NO_MEMORY_ACCESS: u32 = 0x00000004;
    pub const NO_HANDLE_DUP: u32 = 0x00000008;
    pub const FULL: u32 = 0x0000000F;
}

/// File protection flags
pub mod file_protect_flags {
    pub const NO_DELETE: u32 = 0x00000001;
    pub const NO_MODIFY: u32 = 0x00000002;
    pub const NO_RENAME: u32 = 0x00000004;
    pub const FULL: u32 = 0x00000007;
}

/// Restart protection flags
pub mod restart_flags {
    /// Restart agent via Service Control Manager (recommended)
    pub const RESTART_VIA_SCM: u32 = 0x00000001;
    /// Restart agent via direct process creation (fallback)
    pub const RESTART_DIRECT: u32 = 0x00000002;
    /// Restart agent via recovery helper process
    pub const RESTART_VIA_HELPER: u32 = 0x00000004;
    /// Only restart on unexpected termination (not clean shutdown)
    pub const RESTART_ON_CRASH_ONLY: u32 = 0x00000008;
    /// Default: SCM restart on crash only
    pub const DEFAULT: u32 = RESTART_VIA_SCM | RESTART_ON_CRASH_ONLY;
}

/// Event types (from kernel)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum EventType {
    ProcessCreate = 0x0001,
    ProcessExit = 0x0002,
    ThreadCreate = 0x0003,
    ThreadExit = 0x0004,
    ImageLoad = 0x0005,
    FileCreate = 0x0010,
    FileRead = 0x0011,
    FileWrite = 0x0012,
    FileDelete = 0x0013,
    FileRename = 0x0014,
    FileSetAttributes = 0x0015,
    FileClose = 0x0016,
    RegCreateKey = 0x0020,
    RegOpenKey = 0x0021,
    RegDeleteKey = 0x0022,
    RegSetValue = 0x0023,
    RegDeleteValue = 0x0024,
    RegQueryKey = 0x0025,
    RegQueryValue = 0x0026,
    NetConnect = 0x0030,
    NetDisconnect = 0x0031,
    NetListen = 0x0032,
    NetAccept = 0x0033,
    NetSend = 0x0034,
    NetReceive = 0x0035,
    DnsQuery = 0x0036,
    HandleCreate = 0x0040,
    HandleDuplicate = 0x0041,
    HandleClose = 0x0042,
    // Image load detection events (from image load callback)
    ImageLoadDetail = 0x0090,
    DllHijack = 0x0091,
    ReflectiveLoad = 0x0092,
    UnsignedDll = 0x0093,
    AlertRansomware = 0x0100,
    AlertInjection = 0x0101,
    AlertCredential = 0x0102,
    AlertPersistence = 0x0103,
    AlertEvasion = 0x0104,
    AlertLateral = 0x0105,
    Unknown = 0xFFFF,
}

impl From<u16> for EventType {
    fn from(value: u16) -> Self {
        match value {
            0x0001 => EventType::ProcessCreate,
            0x0002 => EventType::ProcessExit,
            0x0003 => EventType::ThreadCreate,
            0x0004 => EventType::ThreadExit,
            0x0005 => EventType::ImageLoad,
            0x0010 => EventType::FileCreate,
            0x0011 => EventType::FileRead,
            0x0012 => EventType::FileWrite,
            0x0013 => EventType::FileDelete,
            0x0014 => EventType::FileRename,
            0x0015 => EventType::FileSetAttributes,
            0x0016 => EventType::FileClose,
            0x0020 => EventType::RegCreateKey,
            0x0021 => EventType::RegOpenKey,
            0x0022 => EventType::RegDeleteKey,
            0x0023 => EventType::RegSetValue,
            0x0024 => EventType::RegDeleteValue,
            0x0025 => EventType::RegQueryKey,
            0x0026 => EventType::RegQueryValue,
            0x0030 => EventType::NetConnect,
            0x0031 => EventType::NetDisconnect,
            0x0032 => EventType::NetListen,
            0x0033 => EventType::NetAccept,
            0x0034 => EventType::NetSend,
            0x0035 => EventType::NetReceive,
            0x0036 => EventType::DnsQuery,
            0x0040 => EventType::HandleCreate,
            0x0041 => EventType::HandleDuplicate,
            0x0042 => EventType::HandleClose,
            0x0090 => EventType::ImageLoadDetail,
            0x0091 => EventType::DllHijack,
            0x0092 => EventType::ReflectiveLoad,
            0x0093 => EventType::UnsignedDll,
            0x0100 => EventType::AlertRansomware,
            0x0101 => EventType::AlertInjection,
            0x0102 => EventType::AlertCredential,
            0x0103 => EventType::AlertPersistence,
            0x0104 => EventType::AlertEvasion,
            0x0105 => EventType::AlertLateral,
            _ => EventType::Unknown,
        }
    }
}

/// Message header (must match driver)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct MessageHeader {
    message_type: u32,
    message_id: u32,
    data_length: u32,
    status: i32,
}

/// Register agent request
#[repr(C, packed)]
struct RegisterAgentRequest {
    header: MessageHeader,
    flags: u32,
    image_path: [u16; 260],
    command_line: [u16; 512],
}

/// Heartbeat request
#[repr(C, packed)]
struct HeartbeatRequest {
    header: MessageHeader,
    uptime: u32,
    events_processed: u32,
}

/// Ring buffer header (shared memory)
#[repr(C)]
struct RingBufferHeader {
    write_index: std::sync::atomic::AtomicI32,
    read_index: std::sync::atomic::AtomicI32,
    buffer_size: u32,
    version: u32,
    total_events_written: std::sync::atomic::AtomicI64,
    total_events_dropped: std::sync::atomic::AtomicI64,
    total_bytes_written: std::sync::atomic::AtomicI64,
    overflow_count: std::sync::atomic::AtomicI64,
    sequence_number: std::sync::atomic::AtomicI32,
    flags: std::sync::atomic::AtomicU32,
    reserved: [u32; 4],
}

/// Telemetry event header
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct TelemetryEventHeader {
    pub event_type: u16,
    pub event_size: u16,
    pub sequence_number: u32,
    pub timestamp: i64,
    pub process_id: u32,
    pub thread_id: u32,
    pub session_id: u32,
    pub flags: u32,
}

/// Raw telemetry event from kernel
#[derive(Debug, Clone)]
pub struct RawKernelEvent {
    pub header: TelemetryEventHeader,
    pub data: Vec<u8>,
}

// ========================================================================
// Graceful Degradation (CrowdStrike Lesson)
//
// If the kernel driver fails, crashes, or becomes unreachable, the agent
// must NOT crash. Instead, it falls back to usermode-only monitoring and
// periodically retries the driver connection.
//
// This prevents the agent from being a single point of failure tied to
// a potentially buggy kernel component.
// ========================================================================

/// Driver safety state (mirrors kernel safety module)
#[derive(Debug, Clone)]
pub struct DriverSafetyState {
    /// Driver is in safe mode (boot loop detected, minimal functionality)
    pub safe_mode: bool,
    /// Circuit breaker tripped (too many errors, degraded mode)
    pub circuit_broken: bool,
    /// Consecutive crash count from boot loop detection
    pub crash_count: u32,
    /// Last time we successfully communicated with the driver
    pub last_successful_comm: Option<std::time::Instant>,
    /// Number of consecutive communication failures
    pub consecutive_failures: u32,
    /// Whether we have fallen back to usermode-only monitoring
    pub usermode_fallback: bool,
}

impl Default for DriverSafetyState {
    fn default() -> Self {
        Self {
            safe_mode: false,
            circuit_broken: false,
            crash_count: 0,
            last_successful_comm: None,
            consecutive_failures: 0,
            usermode_fallback: false,
        }
    }
}

/// Restart protection status from the kernel driver
#[derive(Debug, Clone, Default)]
pub struct RestartProtectionStatus {
    /// Whether restart protection is registered with the driver
    pub registered: bool,
    /// Whether restart on termination is currently enabled
    pub enabled: bool,
    /// Number of times the agent has been restarted by the driver
    pub restart_count: u32,
    /// Timestamp of the last driver-initiated restart (0 if never)
    pub last_restart_time: u64,
    /// Whether a clean shutdown has been signaled (restart won't occur)
    pub clean_shutdown_signaled: bool,
}

/// Driver capability flags reported by TAMANDUA_CMD_GET_CAPABILITIES.
pub mod capability_flags {
    pub const FILE_MONITORING: u32 = 0x00000001;
    pub const PROCESS_MONITORING: u32 = 0x00000002;
    pub const THREAD_MONITORING: u32 = 0x00000004;
    pub const IMAGE_MONITORING: u32 = 0x00000008;
    pub const REGISTRY_MONITORING: u32 = 0x00000010;
    pub const OBJECT_MONITORING: u32 = 0x00000020;
    pub const TELEMETRY_RING: u32 = 0x00000040;
    pub const COMM_PORT: u32 = 0x00000080;
    pub const NETWORK_CONTROL: u32 = 0x00000100;
    pub const ANTITAMPER: u32 = 0x00000200;
    pub const RANSOMWARE: u32 = 0x00000400;
    pub const SYSCALL_MONITORING: u32 = 0x00000800;
    pub const ETW_AMSI_MONITORING: u32 = 0x00001000;
    pub const PREEXEC_SCAN: u32 = 0x00002000;
    pub const SELF_PROTECTION: u32 = 0x00004000;
    pub const CALLBACK_GUARD: u32 = 0x00008000;
}

/// Driver health/readiness flags reported by TAMANDUA_CMD_GET_CAPABILITIES.
pub mod health_flags {
    pub const DRIVER_LOADED: u32 = 0x00000001;
    pub const COMM_PORT_READY: u32 = 0x00000002;
    pub const TELEMETRY_READY: u32 = 0x00000004;
    pub const CALLBACKS_READY: u32 = 0x00000008;
}

/// Read-only driver capability and readiness report.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DriverCapabilityReport {
    pub protocol_version: u32,
    pub driver_version_major: u32,
    pub driver_version_minor: u32,
    pub driver_version_patch: u32,
    pub lab_level: u32,
    pub capability_flags: u32,
    pub active_flags: u32,
    pub health_flags: u32,
}

impl DriverCapabilityReport {
    pub fn has_capability(&self, flag: u32) -> bool {
        self.capability_flags & flag != 0
    }

    pub fn is_active(&self, flag: u32) -> bool {
        self.active_flags & flag != 0
    }

    pub fn has_health(&self, flag: u32) -> bool {
        self.health_flags & flag != 0
    }

    pub fn version_string(&self) -> String {
        format!(
            "{}.{}.{}",
            self.driver_version_major, self.driver_version_minor, self.driver_version_patch
        )
    }

    pub fn readiness_warnings(&self) -> Vec<&'static str> {
        let mut warnings = Vec::new();

        if !self.has_health(health_flags::DRIVER_LOADED) {
            warnings.push("driver_not_loaded");
        }
        if self.has_capability(capability_flags::COMM_PORT)
            && !self.has_health(health_flags::COMM_PORT_READY)
        {
            warnings.push("comm_port_not_ready");
        }
        if self.has_capability(capability_flags::TELEMETRY_RING)
            && !self.has_health(health_flags::TELEMETRY_READY)
        {
            warnings.push("telemetry_not_ready");
        }
        if self.has_capability(capability_flags::OBJECT_MONITORING)
            && !self.is_active(capability_flags::OBJECT_MONITORING)
        {
            warnings.push("object_monitoring_inactive");
        }

        warnings
    }
}

/// Maximum consecutive failures before falling back to usermode-only
const MAX_CONSECUTIVE_FAILURES: u32 = 5;

/// How often to retry reconnecting to the driver (seconds)
const DRIVER_RECONNECT_INTERVAL_SEC: u64 = 30;

/// NTSTATUS code indicating driver is in degraded mode
const STATUS_DEVICE_NOT_READY: i32 = 0xC00000A3_u32 as i32;

/// Driver connection handle
pub struct DriverConnection {
    #[cfg(target_os = "windows")]
    port_handle: HANDLE,
    connected: AtomicBool,
    message_id: std::sync::atomic::AtomicU32,
    telemetry_buffer: AtomicPtr<c_void>,
    telemetry_size: std::sync::atomic::AtomicUsize,
    /// Safety state tracking for graceful degradation
    safety_state: std::sync::Mutex<DriverSafetyState>,
}

impl DriverConnection {
    /// Create a new driver connection (not connected yet)
    pub fn new() -> Self {
        Self {
            #[cfg(target_os = "windows")]
            port_handle: HANDLE(INVALID_HANDLE_VALUE.0),
            connected: AtomicBool::new(false),
            message_id: std::sync::atomic::AtomicU32::new(1),
            telemetry_buffer: AtomicPtr::new(ptr::null_mut()),
            telemetry_size: std::sync::atomic::AtomicUsize::new(0),
            safety_state: std::sync::Mutex::new(DriverSafetyState::default()),
        }
    }

    /// Record a successful communication with the driver
    fn record_success(&self) {
        if let Ok(mut state) = self.safety_state.lock() {
            state.last_successful_comm = Some(std::time::Instant::now());
            state.consecutive_failures = 0;
            if state.usermode_fallback {
                info!("Driver communication restored - exiting usermode fallback");
                state.usermode_fallback = false;
            }
        }
    }

    /// Record a failed communication with the driver
    fn record_failure(&self, error: &str) {
        if let Ok(mut state) = self.safety_state.lock() {
            state.consecutive_failures += 1;
            warn!(
                "Driver communication failure #{}: {}",
                state.consecutive_failures, error
            );

            if state.consecutive_failures >= MAX_CONSECUTIVE_FAILURES && !state.usermode_fallback {
                warn!(
                    "Driver communication failed {} consecutive times - \
                     falling back to usermode-only monitoring. \
                     Will retry every {} seconds.",
                    state.consecutive_failures, DRIVER_RECONNECT_INTERVAL_SEC
                );
                state.usermode_fallback = true;
            }
        }
    }

    /// Check if we should skip driver operations (in usermode fallback)
    pub fn is_usermode_fallback(&self) -> bool {
        self.safety_state
            .lock()
            .map(|s| s.usermode_fallback)
            .unwrap_or(false)
    }

    /// Get a copy of the current safety state
    pub fn get_safety_state(&self) -> DriverSafetyState {
        self.safety_state
            .lock()
            .map(|s| s.clone())
            .unwrap_or_default()
    }

    /// Connect to the driver.
    ///
    /// Graceful degradation: if connection fails, the agent logs a warning
    /// and enters usermode-only fallback mode. It does NOT crash.
    /// Periodic reconnection attempts are handled by the heartbeat task.
    #[cfg(target_os = "windows")]
    pub fn connect(&mut self) -> Result<()> {
        if self.connected.load(Ordering::SeqCst) {
            return Ok(());
        }

        let port_name: Vec<u16> = TAMANDUA_PORT_NAME
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            let result =
                FilterConnectCommunicationPort(PCWSTR(port_name.as_ptr()), 0, None, 0, None);

            match result {
                Ok(handle) => {
                    self.port_handle = handle;
                }
                Err(e) => {
                    self.record_failure(&format!("connect failed: {:?}", e));
                    return Err(anyhow!("Failed to connect to driver: {:?}", e));
                }
            }
        }

        self.connected.store(true, Ordering::SeqCst);
        self.record_success();
        info!("Connected to Tamandua kernel driver");

        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn connect(&mut self) -> Result<()> {
        Err(anyhow!("Driver communication only supported on Windows"))
    }

    /// Attempt to reconnect to the driver after a failure.
    /// Returns Ok(true) if reconnected, Ok(false) if still disconnected.
    /// Never returns Err -- all failures are logged and tracked gracefully.
    #[cfg(target_os = "windows")]
    pub fn try_reconnect(&mut self) -> Result<bool> {
        if self.connected.load(Ordering::SeqCst) {
            return Ok(true);
        }

        debug!("Attempting to reconnect to kernel driver...");

        match self.connect() {
            Ok(()) => {
                info!("Successfully reconnected to kernel driver");
                Ok(true)
            }
            Err(e) => {
                debug!("Driver reconnection failed (will retry): {}", e);
                Ok(false)
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn try_reconnect(&mut self) -> Result<bool> {
        Ok(false)
    }

    /// Check if connected to driver
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    /// Register this agent with the driver
    #[cfg(target_os = "windows")]
    pub fn register_agent(
        &self,
        image_path: &str,
        command_line: Option<&str>,
        auto_restart: bool,
        protected: bool,
    ) -> Result<()> {
        if !self.is_connected() {
            return Err(anyhow!("Not connected to driver"));
        }

        let mut request = RegisterAgentRequest {
            header: MessageHeader {
                message_type: commands::REGISTER_AGENT,
                message_id: self.next_message_id(),
                data_length: (mem::size_of::<RegisterAgentRequest>()
                    - mem::size_of::<MessageHeader>()) as u32,
                status: 0,
            },
            flags: 0,
            image_path: [0u16; 260],
            command_line: [0u16; 512],
        };

        // Set flags
        if auto_restart {
            request.flags |= agent_flags::AUTO_RESTART;
        }
        if protected {
            request.flags |= agent_flags::PROTECTED;
        }

        // Copy image path (use raw pointer for packed struct)
        let path_utf16: Vec<u16> = image_path.encode_utf16().collect();
        let copy_len = path_utf16.len().min(259);
        unsafe {
            let dst = ptr::addr_of_mut!(request.image_path) as *mut u16;
            ptr::copy_nonoverlapping(path_utf16.as_ptr(), dst, copy_len);
        }

        // Copy command line (use raw pointer for packed struct)
        if let Some(cmd) = command_line {
            let cmd_utf16: Vec<u16> = cmd.encode_utf16().collect();
            let copy_len = cmd_utf16.len().min(511);
            unsafe {
                let dst = ptr::addr_of_mut!(request.command_line) as *mut u16;
                ptr::copy_nonoverlapping(cmd_utf16.as_ptr(), dst, copy_len);
            }
        }

        let mut response = MessageHeader {
            message_type: 0,
            message_id: 0,
            data_length: 0,
            status: 0,
        };
        let mut bytes_returned: u32 = 0;

        unsafe {
            let result = FilterSendMessage(
                self.port_handle,
                &request as *const _ as *const c_void,
                mem::size_of::<RegisterAgentRequest>() as u32,
                Some(&mut response as *mut _ as *mut c_void),
                mem::size_of::<MessageHeader>() as u32,
                &mut bytes_returned,
            );

            if result.is_err() {
                return Err(anyhow!("Failed to register agent: {:?}", result.err()));
            }

            // Read status safely from potentially unaligned field
            let status = ptr::read_unaligned(ptr::addr_of!(response.status));
            if status != 0 {
                return Err(anyhow!("Driver returned error: 0x{:08X}", status));
            }
        }

        info!(
            "Agent registered with driver (auto_restart={}, protected={})",
            auto_restart, protected
        );
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn register_agent(
        &self,
        _image_path: &str,
        _command_line: Option<&str>,
        _auto_restart: bool,
        _protected: bool,
    ) -> Result<()> {
        Err(anyhow!("Driver communication only supported on Windows"))
    }

    /// Send heartbeat to driver
    #[cfg(target_os = "windows")]
    pub fn heartbeat(&self, uptime: u32, events_processed: u32) -> Result<()> {
        if !self.is_connected() {
            return Ok(()); // Silent fail if not connected
        }

        let request = HeartbeatRequest {
            header: MessageHeader {
                message_type: commands::HEARTBEAT,
                message_id: self.next_message_id(),
                data_length: (mem::size_of::<HeartbeatRequest>() - mem::size_of::<MessageHeader>())
                    as u32,
                status: 0,
            },
            uptime,
            events_processed,
        };

        let mut response = MessageHeader {
            message_type: 0,
            message_id: 0,
            data_length: 0,
            status: 0,
        };
        let mut bytes_returned: u32 = 0;

        unsafe {
            let _ = FilterSendMessage(
                self.port_handle,
                &request as *const _ as *const c_void,
                mem::size_of::<HeartbeatRequest>() as u32,
                Some(&mut response as *mut _ as *mut c_void),
                mem::size_of::<MessageHeader>() as u32,
                &mut bytes_returned,
            );
        }

        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn heartbeat(&self, _uptime: u32, _events_processed: u32) -> Result<()> {
        Ok(())
    }

    /// Terminate a malicious process
    #[cfg(target_os = "windows")]
    pub fn kill_process(&self, pid: u32) -> Result<()> {
        if !self.is_connected() {
            return Err(anyhow!("Not connected to driver"));
        }

        let request = MessageHeader {
            message_type: commands::PROCESS_KILL,
            message_id: self.next_message_id(),
            data_length: mem::size_of::<u32>() as u32,
            status: 0,
        };

        let mut response = MessageHeader {
            message_type: 0,
            message_id: 0,
            data_length: 0,
            status: 0,
        };
        let mut bytes_returned: u32 = 0;

        unsafe {
            // Send [Header][PID]
            let payload = pid;
            let mut buffer =
                Vec::with_capacity(mem::size_of::<MessageHeader>() + mem::size_of::<u32>());
            buffer.extend_from_slice(std::slice::from_raw_parts(
                &request as *const _ as *const u8,
                mem::size_of::<MessageHeader>(),
            ));
            buffer.extend_from_slice(&payload.to_le_bytes());

            let result = FilterSendMessage(
                self.port_handle,
                buffer.as_ptr() as *const c_void,
                buffer.len() as u32,
                Some(&mut response as *mut _ as *mut c_void),
                mem::size_of::<MessageHeader>() as u32,
                &mut bytes_returned,
            );

            if result.is_err() {
                return Err(anyhow!("Failed to kill process: {:?}", result.err()));
            }
        }

        // Check response status
        let status = unsafe { ptr::read_unaligned(ptr::addr_of!(response.status)) };
        if status != 0 {
            return Err(anyhow!(
                "Driver failed to kill process {}: 0x{:08X}",
                pid,
                status
            ));
        }

        info!("Process {} killed via driver", pid);
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn kill_process(&self, _pid: u32) -> Result<()> {
        Err(anyhow!("Driver communication only supported on Windows"))
    }

    /// Protect a process
    #[cfg(target_os = "windows")]
    pub fn protect_process(&self, pid: u32, flags: u32) -> Result<()> {
        if !self.is_connected() {
            return Err(anyhow!("Not connected to driver"));
        }

        #[repr(C, packed)]
        struct ProtectProcessRequest {
            header: MessageHeader,
            process_id: u32,
            protection_flags: u32,
        }

        let request = ProtectProcessRequest {
            header: MessageHeader {
                message_type: commands::PROTECT_PROCESS,
                message_id: self.next_message_id(),
                data_length: 8,
                status: 0,
            },
            process_id: pid,
            protection_flags: flags,
        };

        let mut response = MessageHeader {
            message_type: 0,
            message_id: 0,
            data_length: 0,
            status: 0,
        };
        let mut bytes_returned: u32 = 0;

        unsafe {
            let result = FilterSendMessage(
                self.port_handle,
                &request as *const _ as *const c_void,
                mem::size_of::<ProtectProcessRequest>() as u32,
                Some(&mut response as *mut _ as *mut c_void),
                mem::size_of::<MessageHeader>() as u32,
                &mut bytes_returned,
            );

            if result.is_err() {
                return Err(anyhow!("Failed to protect process: {:?}", result.err()));
            }
        }

        debug!("Process {} protected with flags 0x{:08X}", pid, flags);
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn protect_process(&self, _pid: u32, _flags: u32) -> Result<()> {
        Err(anyhow!("Driver communication only supported on Windows"))
    }

    /// Enable network isolation
    #[cfg(target_os = "windows")]
    pub fn isolate_network(&self, isolate_all: bool, allowed_ips: &[u32]) -> Result<()> {
        if !self.is_connected() {
            return Err(anyhow!("Not connected to driver"));
        }

        #[repr(C, packed)]
        struct IsolateNetworkRequest {
            header: MessageHeader,
            isolate_all: u32,
            address_count: u32,
            allowed_addresses: [u32; 16],
            allowed_ports: [u16; 16],
        }

        let mut request = IsolateNetworkRequest {
            header: MessageHeader {
                message_type: commands::NETWORK_ISOLATE,
                message_id: self.next_message_id(),
                data_length: (mem::size_of::<IsolateNetworkRequest>()
                    - mem::size_of::<MessageHeader>()) as u32,
                status: 0,
            },
            isolate_all: if isolate_all { 1 } else { 0 },
            address_count: allowed_ips.len().min(16) as u32,
            allowed_addresses: [0u32; 16],
            allowed_ports: [0u16; 16],
        };

        // Copy allowed IPs
        for (i, &ip) in allowed_ips.iter().take(16).enumerate() {
            request.allowed_addresses[i] = ip;
        }

        let mut response = MessageHeader {
            message_type: 0,
            message_id: 0,
            data_length: 0,
            status: 0,
        };
        let mut bytes_returned: u32 = 0;

        unsafe {
            let result = FilterSendMessage(
                self.port_handle,
                &request as *const _ as *const c_void,
                mem::size_of::<IsolateNetworkRequest>() as u32,
                Some(&mut response as *mut _ as *mut c_void),
                mem::size_of::<MessageHeader>() as u32,
                &mut bytes_returned,
            );

            if result.is_err() {
                return Err(anyhow!("Failed to isolate network: {:?}", result.err()));
            }
        }

        info!("Network isolation enabled (isolate_all={})", isolate_all);
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn isolate_network(&self, _isolate_all: bool, _allowed_ips: &[u32]) -> Result<()> {
        Err(anyhow!("Driver communication only supported on Windows"))
    }

    /// Restore network connectivity
    #[cfg(target_os = "windows")]
    pub fn restore_network(&self) -> Result<()> {
        if !self.is_connected() {
            return Err(anyhow!("Not connected to driver"));
        }

        let request = MessageHeader {
            message_type: commands::NETWORK_RESTORE,
            message_id: self.next_message_id(),
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

        unsafe {
            let result = FilterSendMessage(
                self.port_handle,
                &request as *const _ as *const c_void,
                mem::size_of::<MessageHeader>() as u32,
                Some(&mut response as *mut _ as *mut c_void),
                mem::size_of::<MessageHeader>() as u32,
                &mut bytes_returned,
            );

            if result.is_err() {
                return Err(anyhow!("Failed to restore network: {:?}", result.err()));
            }
        }

        info!("Network isolation disabled");
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn restore_network(&self) -> Result<()> {
        Err(anyhow!("Driver communication only supported on Windows"))
    }

    // ========================================================================
    // Anti-tamper commands
    // ========================================================================

    /// Register this process's PID with the kernel driver's anti-tamper watchdog.
    /// The driver validates that the calling process is the Tamandua agent binary
    /// before accepting the PID. Once registered, the kernel watchdog timer will
    /// check every 5 seconds that the agent is still running and trigger a restart
    /// via SCM if it is unexpectedly terminated.
    #[cfg(target_os = "windows")]
    pub fn register_agent_pid(&self) -> Result<()> {
        if !self.is_connected() {
            return Err(anyhow!("Not connected to driver"));
        }

        let request = MessageHeader {
            message_type: commands::SET_AGENT_PID,
            message_id: self.next_message_id(),
            data_length: 0, // PID is derived from caller in kernel
            status: 0,
        };

        let mut response = MessageHeader {
            message_type: 0,
            message_id: 0,
            data_length: 0,
            status: 0,
        };
        let mut bytes_returned: u32 = 0;

        unsafe {
            let result = FilterSendMessage(
                self.port_handle,
                &request as *const _ as *const c_void,
                mem::size_of::<MessageHeader>() as u32,
                Some(&mut response as *mut _ as *mut c_void),
                mem::size_of::<MessageHeader>() as u32,
                &mut bytes_returned,
            );

            if result.is_err() {
                return Err(anyhow!("Failed to register agent PID: {:?}", result.err()));
            }
        }

        info!("Agent PID registered with kernel anti-tamper watchdog");
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn register_agent_pid(&self) -> Result<()> {
        // Anti-tamper watchdog is Windows-only (kernel driver)
        Ok(())
    }

    /// Signal the kernel driver that the agent is performing a planned shutdown.
    /// When set, the watchdog timer will NOT attempt an automatic restart.
    /// Call this before updates or administrative shutdowns.
    #[cfg(target_os = "windows")]
    pub fn signal_clean_shutdown(&self) -> Result<()> {
        if !self.is_connected() {
            return Err(anyhow!("Not connected to driver"));
        }

        #[repr(C, packed)]
        struct CleanShutdownRequest {
            header: MessageHeader,
            clean_shutdown: u32,
        }

        let request = CleanShutdownRequest {
            header: MessageHeader {
                message_type: commands::SET_CLEAN_SHUTDOWN,
                message_id: self.next_message_id(),
                data_length: mem::size_of::<u32>() as u32,
                status: 0,
            },
            clean_shutdown: 1, // TRUE
        };

        let mut response = MessageHeader {
            message_type: 0,
            message_id: 0,
            data_length: 0,
            status: 0,
        };
        let mut bytes_returned: u32 = 0;

        unsafe {
            let result = FilterSendMessage(
                self.port_handle,
                &request as *const _ as *const c_void,
                mem::size_of::<CleanShutdownRequest>() as u32,
                Some(&mut response as *mut _ as *mut c_void),
                mem::size_of::<MessageHeader>() as u32,
                &mut bytes_returned,
            );

            if result.is_err() {
                return Err(anyhow!(
                    "Failed to signal clean shutdown: {:?}",
                    result.err()
                ));
            }
        }

        info!("Clean shutdown signaled to kernel anti-tamper watchdog");
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn signal_clean_shutdown(&self) -> Result<()> {
        Ok(())
    }

    // ========================================================================
    // Restart Protection Commands
    //
    // These commands allow the agent to register for automatic restart when
    // the process is terminated unexpectedly. The kernel driver uses
    // PsSetCreateProcessNotifyRoutineEx to detect process exit and can either:
    //
    // 1. Signal SCM to restart the service (preferred on Windows)
    // 2. Spawn the agent directly via ZwCreateUserProcess (fallback)
    // 3. Signal a recovery helper process to restart the agent
    //
    // This provides resilience against attacks that kill the agent process.
    // ========================================================================

    /// Register the agent process for automatic restart protection.
    ///
    /// The driver will use PsSetCreateProcessNotifyRoutineEx to detect when
    /// the agent process terminates. If termination was not preceded by a
    /// clean shutdown signal, the driver will restart the agent.
    ///
    /// # Arguments
    /// * `agent_path` - Full path to the agent executable
    /// * `service_name` - Service name for SCM restart (e.g., "TamanduaAgent")
    /// * `flags` - Restart flags from `restart_flags` module
    ///
    /// # Kernel-Mode Implementation
    /// The driver maintains a structure with:
    /// - Agent PID (from caller via PsGetCurrentProcessId)
    /// - Agent path (for direct restart)
    /// - Service name (for SCM restart)
    /// - Clean shutdown flag (set via signal_clean_shutdown)
    #[cfg(target_os = "windows")]
    pub fn register_restart_protection(
        &self,
        agent_path: &std::path::Path,
        service_name: &str,
        flags: u32,
    ) -> Result<()> {
        if !self.is_connected() {
            return Err(anyhow!("Not connected to driver"));
        }

        #[repr(C, packed)]
        struct RestartProtectionRequest {
            header: MessageHeader,
            flags: u32,
            service_name: [u16; 64],
            agent_path: [u16; 260],
        }

        let mut request = RestartProtectionRequest {
            header: MessageHeader {
                message_type: commands::REGISTER_RESTART_PROTECTION,
                message_id: self.next_message_id(),
                data_length: (mem::size_of::<RestartProtectionRequest>()
                    - mem::size_of::<MessageHeader>()) as u32,
                status: 0,
            },
            flags,
            service_name: [0u16; 64],
            agent_path: [0u16; 260],
        };

        // Copy service name
        let svc_utf16: Vec<u16> = service_name.encode_utf16().collect();
        let svc_len = svc_utf16.len().min(63);
        unsafe {
            let dst = ptr::addr_of_mut!(request.service_name) as *mut u16;
            ptr::copy_nonoverlapping(svc_utf16.as_ptr(), dst, svc_len);
        }

        // Copy agent path
        let path_str = agent_path.to_string_lossy();
        let path_utf16: Vec<u16> = path_str.encode_utf16().collect();
        let path_len = path_utf16.len().min(259);
        unsafe {
            let dst = ptr::addr_of_mut!(request.agent_path) as *mut u16;
            ptr::copy_nonoverlapping(path_utf16.as_ptr(), dst, path_len);
        }

        let mut response = MessageHeader {
            message_type: 0,
            message_id: 0,
            data_length: 0,
            status: 0,
        };
        let mut bytes_returned: u32 = 0;

        unsafe {
            let result = FilterSendMessage(
                self.port_handle,
                &request as *const _ as *const c_void,
                mem::size_of::<RestartProtectionRequest>() as u32,
                Some(&mut response as *mut _ as *mut c_void),
                mem::size_of::<MessageHeader>() as u32,
                &mut bytes_returned,
            );

            if result.is_err() {
                return Err(anyhow!(
                    "Failed to register restart protection: {:?}",
                    result.err()
                ));
            }

            let status = ptr::read_unaligned(ptr::addr_of!(response.status));
            if status != 0 {
                return Err(anyhow!(
                    "Driver rejected restart protection registration: 0x{:08X}",
                    status
                ));
            }
        }

        info!(
            path = %agent_path.display(),
            service = service_name,
            flags = format!("0x{:08X}", flags),
            "Restart protection registered with kernel driver"
        );
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn register_restart_protection(
        &self,
        _agent_path: &std::path::Path,
        _service_name: &str,
        _flags: u32,
    ) -> Result<()> {
        // Restart protection is Windows-only (kernel driver)
        Ok(())
    }

    /// Unregister from restart protection.
    ///
    /// Call this when the agent is being uninstalled or when restart
    /// protection is no longer needed.
    #[cfg(target_os = "windows")]
    pub fn unregister_restart_protection(&self) -> Result<()> {
        if !self.is_connected() {
            return Err(anyhow!("Not connected to driver"));
        }

        let request = MessageHeader {
            message_type: commands::UNREGISTER_RESTART_PROTECTION,
            message_id: self.next_message_id(),
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

        unsafe {
            let result = FilterSendMessage(
                self.port_handle,
                &request as *const _ as *const c_void,
                mem::size_of::<MessageHeader>() as u32,
                Some(&mut response as *mut _ as *mut c_void),
                mem::size_of::<MessageHeader>() as u32,
                &mut bytes_returned,
            );

            if result.is_err() {
                return Err(anyhow!(
                    "Failed to unregister restart protection: {:?}",
                    result.err()
                ));
            }
        }

        info!("Restart protection unregistered from kernel driver");
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn unregister_restart_protection(&self) -> Result<()> {
        Ok(())
    }

    /// Enable or disable restart on termination.
    ///
    /// This allows temporarily disabling restart (e.g., during updates)
    /// without fully unregistering.
    #[cfg(target_os = "windows")]
    pub fn set_restart_enabled(&self, enabled: bool) -> Result<()> {
        if !self.is_connected() {
            return Err(anyhow!("Not connected to driver"));
        }

        #[repr(C, packed)]
        struct SetRestartEnabledRequest {
            header: MessageHeader,
            enabled: u32,
        }

        let request = SetRestartEnabledRequest {
            header: MessageHeader {
                message_type: commands::SET_RESTART_ENABLED,
                message_id: self.next_message_id(),
                data_length: mem::size_of::<u32>() as u32,
                status: 0,
            },
            enabled: if enabled { 1 } else { 0 },
        };

        let mut response = MessageHeader {
            message_type: 0,
            message_id: 0,
            data_length: 0,
            status: 0,
        };
        let mut bytes_returned: u32 = 0;

        unsafe {
            let result = FilterSendMessage(
                self.port_handle,
                &request as *const _ as *const c_void,
                mem::size_of::<SetRestartEnabledRequest>() as u32,
                Some(&mut response as *mut _ as *mut c_void),
                mem::size_of::<MessageHeader>() as u32,
                &mut bytes_returned,
            );

            if result.is_err() {
                return Err(anyhow!("Failed to set restart enabled: {:?}", result.err()));
            }
        }

        info!(
            enabled = enabled,
            "Restart protection enabled state updated"
        );
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    pub fn set_restart_enabled(&self, _enabled: bool) -> Result<()> {
        Ok(())
    }

    /// Get the current restart protection status from the driver.
    #[cfg(target_os = "windows")]
    pub fn get_restart_status(&self) -> Result<RestartProtectionStatus> {
        if !self.is_connected() {
            return Err(anyhow!("Not connected to driver"));
        }

        let request = MessageHeader {
            message_type: commands::GET_RESTART_STATUS,
            message_id: self.next_message_id(),
            data_length: 0,
            status: 0,
        };

        #[repr(C, packed)]
        struct RestartStatusResponse {
            header: MessageHeader,
            registered: u32,
            enabled: u32,
            restart_count: u32,
            last_restart_time: u64,
            clean_shutdown_signaled: u32,
        }

        let mut response = RestartStatusResponse {
            header: MessageHeader {
                message_type: 0,
                message_id: 0,
                data_length: 0,
                status: 0,
            },
            registered: 0,
            enabled: 0,
            restart_count: 0,
            last_restart_time: 0,
            clean_shutdown_signaled: 0,
        };
        let mut bytes_returned: u32 = 0;

        unsafe {
            let result = FilterSendMessage(
                self.port_handle,
                &request as *const _ as *const c_void,
                mem::size_of::<MessageHeader>() as u32,
                Some(&mut response as *mut _ as *mut c_void),
                mem::size_of::<RestartStatusResponse>() as u32,
                &mut bytes_returned,
            );

            if result.is_err() {
                return Err(anyhow!("Failed to get restart status: {:?}", result.err()));
            }

            Ok(RestartProtectionStatus {
                registered: ptr::read_unaligned(ptr::addr_of!(response.registered)) != 0,
                enabled: ptr::read_unaligned(ptr::addr_of!(response.enabled)) != 0,
                restart_count: ptr::read_unaligned(ptr::addr_of!(response.restart_count)),
                last_restart_time: ptr::read_unaligned(ptr::addr_of!(response.last_restart_time)),
                clean_shutdown_signaled: ptr::read_unaligned(ptr::addr_of!(
                    response.clean_shutdown_signaled
                )) != 0,
            })
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn get_restart_status(&self) -> Result<RestartProtectionStatus> {
        Ok(RestartProtectionStatus::default())
    }

    /// Get the current driver capability/readiness report.
    #[cfg(target_os = "windows")]
    pub fn get_capabilities(&self) -> Result<DriverCapabilityReport> {
        if !self.is_connected() {
            return Err(anyhow!("Not connected to driver"));
        }

        let request = MessageHeader {
            message_type: commands::CAPABILITIES_GET,
            message_id: self.next_message_id(),
            data_length: 0,
            status: 0,
        };

        #[repr(C, packed)]
        struct CapabilitiesResponse {
            header: MessageHeader,
            protocol_version: u32,
            driver_version_major: u32,
            driver_version_minor: u32,
            driver_version_patch: u32,
            lab_level: u32,
            capability_flags: u32,
            active_flags: u32,
            health_flags: u32,
            reserved: [u32; 8],
        }

        let mut response = CapabilitiesResponse {
            header: MessageHeader {
                message_type: 0,
                message_id: 0,
                data_length: 0,
                status: 0,
            },
            protocol_version: 0,
            driver_version_major: 0,
            driver_version_minor: 0,
            driver_version_patch: 0,
            lab_level: 0,
            capability_flags: 0,
            active_flags: 0,
            health_flags: 0,
            reserved: [0; 8],
        };
        let mut bytes_returned: u32 = 0;

        unsafe {
            let result = FilterSendMessage(
                self.port_handle,
                &request as *const _ as *const c_void,
                mem::size_of::<MessageHeader>() as u32,
                Some(&mut response as *mut _ as *mut c_void),
                mem::size_of::<CapabilitiesResponse>() as u32,
                &mut bytes_returned,
            );

            if result.is_err() {
                return Err(anyhow!(
                    "Failed to get driver capabilities: {:?}",
                    result.err()
                ));
            }

            let status = ptr::read_unaligned(ptr::addr_of!(response.header.status));
            if status != 0 {
                return Err(anyhow!(
                    "Driver rejected capability query: 0x{:08X}",
                    status
                ));
            }

            Ok(DriverCapabilityReport {
                protocol_version: ptr::read_unaligned(ptr::addr_of!(response.protocol_version)),
                driver_version_major: ptr::read_unaligned(ptr::addr_of!(
                    response.driver_version_major
                )),
                driver_version_minor: ptr::read_unaligned(ptr::addr_of!(
                    response.driver_version_minor
                )),
                driver_version_patch: ptr::read_unaligned(ptr::addr_of!(
                    response.driver_version_patch
                )),
                lab_level: ptr::read_unaligned(ptr::addr_of!(response.lab_level)),
                capability_flags: ptr::read_unaligned(ptr::addr_of!(response.capability_flags)),
                active_flags: ptr::read_unaligned(ptr::addr_of!(response.active_flags)),
                health_flags: ptr::read_unaligned(ptr::addr_of!(response.health_flags)),
            })
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn get_capabilities(&self) -> Result<DriverCapabilityReport> {
        Ok(DriverCapabilityReport::default())
    }

    /// Get next message ID
    fn next_message_id(&self) -> u32 {
        self.message_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Disconnect from driver
    #[cfg(target_os = "windows")]
    pub fn disconnect(&mut self) {
        if self.connected.load(Ordering::SeqCst) {
            unsafe {
                let _ = CloseHandle(self.port_handle);
            }
            self.port_handle = HANDLE(INVALID_HANDLE_VALUE.0);
            self.connected.store(false, Ordering::SeqCst);
            info!("Disconnected from Tamandua kernel driver");
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn disconnect(&mut self) {
        self.connected.store(false, Ordering::SeqCst);
    }
}

impl Drop for DriverConnection {
    fn drop(&mut self) {
        self.disconnect();
    }
}

impl Default for DriverConnection {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if the driver is loaded
#[cfg(target_os = "windows")]
pub fn is_driver_loaded() -> bool {
    use windows::Win32::Storage::InstallableFileSystems::FilterConnectCommunicationPort;

    let port_name: Vec<u16> = TAMANDUA_PORT_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let result = FilterConnectCommunicationPort(PCWSTR(port_name.as_ptr()), 0, None, 0, None);

        if let Ok(handle) = result {
            let _ = CloseHandle(handle);
            return true;
        }
    }

    false
}

#[cfg(not(target_os = "windows"))]
pub fn is_driver_loaded() -> bool {
    false
}

// ========================================================================
// Image Load Detection Event Parsing
//
// Structures and helpers for parsing image load detection events from the
// kernel driver's telemetry ring buffer. These correspond to the
// TAMANDUA_IMAGE_LOAD_DETAIL_EVENT structure defined in driver.h.
// ========================================================================

/// Classification of an image load detection from the kernel driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageLoadDetectionKind {
    /// Normal image load (no suspicious indicators).
    Normal,
    /// Reflective DLL injection -- image loaded from memory with no file backing (T1620).
    ReflectiveLoad,
    /// DLL search order hijacking -- known target DLL loaded from non-standard path (T1574).
    DllHijack,
    /// Unsigned DLL loaded into a signed / protected process (T1055.001).
    UnsignedInSigned,
}

/// Parsed image load event from the kernel driver.
#[derive(Debug, Clone)]
pub struct ImageLoadEvent {
    /// Process ID that loaded the image.
    pub process_id: u32,
    /// Base address where the image was loaded (as u64 for serialization).
    pub image_base: u64,
    /// Size of the loaded image in bytes.
    pub image_size: u64,
    /// SE_SIGNING_LEVEL_* value from the kernel.
    pub signature_level: u32,
    /// SE_IMAGE_SIGNATURE_TYPE value from the kernel.
    pub signature_type: u32,
    /// Full NT device path of the loaded image (empty for reflective loads).
    pub image_path: String,
    /// Detection classification.
    pub detection_kind: ImageLoadDetectionKind,
}

impl ImageLoadEvent {
    /// Parse an ImageLoadEvent from a raw kernel event's data buffer.
    ///
    /// The data layout matches the C structure TAMANDUA_IMAGE_LOAD_DETAIL_EVENT:
    ///   - ULONG  ProcessId           (4 bytes)
    ///   - padding                    (4 bytes, x64 alignment)
    ///   - PVOID  ImageBase            (pointer-sized: 8 bytes on x64)
    ///   - SIZE_T ImageSize            (pointer-sized: 8 bytes on x64)
    ///   - ULONG  ImageSignatureLevel  (4 bytes)
    ///   - ULONG  ImageSignatureType   (4 bytes)
    ///   - WCHAR  ImagePath[520]       (1040 bytes)
    ///   - BOOLEAN IsReflective        (1 byte)
    ///   - BOOLEAN IsDllHijack         (1 byte)
    ///   - BOOLEAN IsUnsignedInSigned  (1 byte)
    ///
    /// Total minimum size on x64: 4 + 4 padding + 8 + 8 + 4 + 4 + 1040 + 3 = 1075 bytes
    pub fn from_raw(data: &[u8]) -> Option<Self> {
        // Minimum size check (x64 layout).
        if data.len() < 1075 {
            debug!("Image load event too small: {} bytes", data.len());
            return None;
        }

        let process_id = u32::from_le_bytes(data[0..4].try_into().ok()?);
        let image_base = u64::from_le_bytes(data[8..16].try_into().ok()?);
        let image_size = u64::from_le_bytes(data[16..24].try_into().ok()?);
        let signature_level = u32::from_le_bytes(data[24..28].try_into().ok()?);
        let signature_type = u32::from_le_bytes(data[28..32].try_into().ok()?);

        // ImagePath is WCHAR[520] starting at offset 32, length 1040 bytes.
        let path_bytes = &data[32..1072];
        let path_u16: Vec<u16> = path_bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .take_while(|&c| c != 0)
            .collect();
        let image_path = String::from_utf16_lossy(&path_u16);

        // Boolean flags at offsets 1072, 1073, 1074.
        let is_reflective = data[1072] != 0;
        let is_dll_hijack = data[1073] != 0;
        let is_unsigned_in_signed = data[1074] != 0;

        let detection_kind = if is_reflective {
            ImageLoadDetectionKind::ReflectiveLoad
        } else if is_dll_hijack {
            ImageLoadDetectionKind::DllHijack
        } else if is_unsigned_in_signed {
            ImageLoadDetectionKind::UnsignedInSigned
        } else {
            ImageLoadDetectionKind::Normal
        };

        Some(Self {
            process_id,
            image_base,
            image_size,
            signature_level,
            signature_type,
            image_path,
            detection_kind,
        })
    }

    /// Return the MITRE ATT&CK technique ID for this detection.
    pub fn mitre_technique(&self) -> Option<&'static str> {
        match self.detection_kind {
            ImageLoadDetectionKind::ReflectiveLoad => Some("T1620"),
            ImageLoadDetectionKind::DllHijack => Some("T1574.001"),
            ImageLoadDetectionKind::UnsignedInSigned => Some("T1055.001"),
            ImageLoadDetectionKind::Normal => None,
        }
    }

    /// Return a human-readable description of the detection.
    pub fn detection_description(&self) -> &'static str {
        match self.detection_kind {
            ImageLoadDetectionKind::ReflectiveLoad => {
                "Reflective DLL injection: image loaded from memory with no file backing"
            }
            ImageLoadDetectionKind::DllHijack => {
                "DLL search order hijacking: known target DLL loaded from non-standard path"
            }
            ImageLoadDetectionKind::UnsignedInSigned => {
                "Unsigned DLL loaded into a signed or protected process"
            }
            ImageLoadDetectionKind::Normal => "Normal image load",
        }
    }
}

/// Spawn heartbeat task
pub fn spawn_heartbeat_task(
    connection: Arc<std::sync::Mutex<DriverConnection>>,
    interval_secs: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let start = std::time::Instant::now();
        let mut events_processed: u32 = 0;

        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;

            let uptime = start.elapsed().as_secs() as u32;

            if let Ok(conn) = connection.lock() {
                if let Err(e) = conn.heartbeat(uptime, events_processed) {
                    warn!("Heartbeat failed: {}", e);
                }
            }

            events_processed = events_processed.wrapping_add(1);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_report_interprets_flags() {
        let report = DriverCapabilityReport {
            protocol_version: 1,
            driver_version_major: 1,
            driver_version_minor: 2,
            driver_version_patch: 3,
            lab_level: 14,
            capability_flags: capability_flags::COMM_PORT
                | capability_flags::TELEMETRY_RING
                | capability_flags::OBJECT_MONITORING,
            active_flags: capability_flags::COMM_PORT | capability_flags::OBJECT_MONITORING,
            health_flags: health_flags::DRIVER_LOADED
                | health_flags::COMM_PORT_READY
                | health_flags::CALLBACKS_READY,
        };

        assert_eq!(report.version_string(), "1.2.3");
        assert!(report.has_capability(capability_flags::TELEMETRY_RING));
        assert!(report.is_active(capability_flags::OBJECT_MONITORING));
        assert!(report.has_health(health_flags::DRIVER_LOADED));
        assert_eq!(report.readiness_warnings(), vec!["telemetry_not_ready"]);
    }

    #[test]
    fn capability_report_warns_when_driver_not_loaded() {
        let report = DriverCapabilityReport {
            capability_flags: capability_flags::COMM_PORT,
            ..Default::default()
        };

        assert_eq!(
            report.readiness_warnings(),
            vec!["driver_not_loaded", "comm_port_not_ready"]
        );
    }
}
