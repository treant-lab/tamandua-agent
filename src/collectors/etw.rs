//! Windows ETW (Event Tracing for Windows) Collector
//!
//! Provides kernel-level visibility into system events:
//! - Process creation/termination
//! - File operations
//! - Network connections
//! - Registry modifications
//! - Image/DLL loading
//! - PowerShell script blocks
//! - AMSI scan events
//! - Security audit events
//! - Sysmon events (if installed)
//! - Code integrity violations (unsigned/tampered drivers)
//! - LDAP client activity (reconnaissance, credential access)
//! - Task Scheduler activity (persistence)
//! - WMI activity (lateral movement, persistence)
//!
//! Supports Windows 7 through Windows 11 with automatic API detection
//! and fallback to polling-based monitoring on systems where ETW is unavailable.
//!
//! Hardening features:
//! - Ring buffer for event burst absorption (configurable capacity)
//! - ETW session recovery with exponential backoff
//! - ETW tamper detection (session termination, provider disabling, EtwEventWrite patching)
//! - Per-provider event rate tracking and auto-throttling
//! - Keyword-level filtering to reduce usermode event delivery overhead
//!
//! MITRE ATT&CK Coverage:
//! - T1059 (Command and Scripting Interpreter)
//! - T1055 (Process Injection)
//! - T1106 (Native API)
//! - T1547 (Boot or Logon Autostart Execution)
//! - T1562 (Impair Defenses)
//! - T1014 (Rootkit) via CodeIntegrity provider
//! - T1553 (Subvert Trust Controls) via CodeIntegrity provider
//! - T1087 (Account Discovery) via LDAP Client provider
//! - T1018 (Remote System Discovery) via LDAP Client provider
//! - T1053.005 (Scheduled Task) via Task Scheduler provider
//! - T1047 (WMI Execution) via WMI Activity provider
//! - T1546.003 (WMI Event Subscription) via WMI Activity provider

#![cfg(target_os = "windows")]
// This file documents the full ETW provider GUID / keyword / event-ID reference
// table used by the collector. Many constants are intentionally kept as a
// machine-checked reference even when no current subscription consumes them
// (provider GUIDs we may opt into based on runtime capability detection,
// PowerShell/AMSI keyword bitmasks, Security event IDs, etc.). Dead-code
// suppression applies file-wide for this reason.
#![allow(dead_code, unused_variables)]

use super::win_compat::{self, etw as etw_api, SystemCapabilities};
use super::{
    Detection, DetectionType, DnsEvent, EventPayload, EventType, FileEvent, NetworkEvent,
    ProcessEvent, RegistryEvent, ScriptEvent, ScriptType, Severity, TelemetryEvent,
};
use crate::config::AgentConfig;
use anyhow::{anyhow, Result};
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::ProcessStatus::K32GetProcessImageFileNameW;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

/// Known ETW Provider GUIDs
mod providers {
    use windows::core::GUID;

    /// Microsoft-Windows-Kernel-Process
    pub const KERNEL_PROCESS: GUID = GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);

    /// Microsoft-Windows-Kernel-File
    pub const KERNEL_FILE: GUID = GUID::from_u128(0xedd08927_9cc4_4e65_b970_c2560fb5c289);

    /// Microsoft-Windows-Kernel-Network
    pub const KERNEL_NETWORK: GUID = GUID::from_u128(0x7dd42a49_5329_4832_8dfd_43d979153a88);

    /// Microsoft-Windows-Kernel-Registry
    pub const KERNEL_REGISTRY: GUID = GUID::from_u128(0x70eb4f03_c1de_4f73_a051_33d13d5413bd);

    /// Microsoft-Windows-DNS-Client
    pub const DNS_CLIENT: GUID = GUID::from_u128(0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d);

    /// Microsoft-Windows-PowerShell
    pub const POWERSHELL: GUID = GUID::from_u128(0xa0c1853b_5c40_4b15_8766_3cf1c58f985a);

    /// Microsoft-Antimalware-Scan-Interface (AMSI)
    pub const AMSI: GUID = GUID::from_u128(0x2a576b87_09a7_520e_c21a_4942f0271d67);

    /// Microsoft-Windows-Security-Auditing
    pub const SECURITY_AUDITING: GUID = GUID::from_u128(0x54849625_5478_4994_a5ba_3e3b0328c30d);

    /// Microsoft-Windows-Sysmon (if installed)
    pub const SYSMON: GUID = GUID::from_u128(0x5770385f_c22a_43e0_bf4c_06f5698ffbd9);

    /// Microsoft-Windows-Kernel-Audit-API-Calls
    pub const KERNEL_AUDIT_API: GUID = GUID::from_u128(0xe02a841c_75a3_4fa7_afc8_ae09cf9b7f23);

    /// Microsoft-Windows-Threat-Intelligence
    pub const THREAT_INTELLIGENCE: GUID = GUID::from_u128(0xf4e1897c_bb5d_5668_f1d8_040f4d8dd344);

    /// Microsoft-Windows-WMI-Activity
    pub const WMI_ACTIVITY: GUID = GUID::from_u128(0x1418ef04_b0b4_4623_bf7e_d74ab47bbdaa);

    /// Microsoft-Windows-TaskScheduler
    pub const TASK_SCHEDULER: GUID = GUID::from_u128(0xde7b24ea_73c8_4a09_985d_5bdadcfa9017);

    /// Microsoft-Windows-Services
    pub const SERVICES: GUID = GUID::from_u128(0x0063715b_eeda_4007_9429_ad526f62696e);

    /// Microsoft-Windows-RPC
    pub const RPC: GUID = GUID::from_u128(0x6ad52b32_d609_4be9_ae07_ce8dae937e39);

    /// Microsoft-Windows-CodeIntegrity
    /// Detects unsigned/tampered driver loads, failed CI checks
    /// MITRE: T1014 (Rootkit), T1553 (Subvert Trust Controls)
    pub const CODE_INTEGRITY: GUID = GUID::from_u128(0x4ee76bd8_3cf4_44a0_a0ac_3937643db0a2);

    /// Microsoft-Windows-LDAP-Client
    /// Detects LDAP reconnaissance, credential access via LDAP queries
    /// MITRE: T1087 (Account Discovery), T1018 (Remote System Discovery)
    pub const LDAP_CLIENT: GUID = GUID::from_u128(0x099614a5_5dd7_4788_8bc9_e29f43db28fc);
}

/// ETW Session name
const SESSION_NAME: &str = "TamanduaEDR";

/// PowerShell provider keywords
mod powershell_keywords {
    pub const RUNSPACE: u64 = 0x1;
    pub const PIPELINE: u64 = 0x2;
    pub const PROTOCOL: u64 = 0x4;
    pub const TRANSPORT: u64 = 0x8;
    pub const HOST: u64 = 0x10;
    pub const CMDLETS: u64 = 0x20;
    pub const SERIALIZER: u64 = 0x40;
    pub const SESSION: u64 = 0x80;
    pub const MANAGED_PLUGIN: u64 = 0x100;
    /// Script block logging
    pub const EXECUTE_RUNSPACE: u64 = 0x1;
}

/// AMSI provider keywords
mod amsi_keywords {
    pub const AMSI_UAC: u64 = 0x0000000000000001;
    pub const AMSI_AUDIT: u64 = 0x8000000000000000;
}

/// Security Auditing event IDs
mod security_event_ids {
    pub const LOGON_SUCCESS: u16 = 4624;
    pub const LOGON_FAILURE: u16 = 4625;
    pub const LOGOFF: u16 = 4634;
    pub const ACCOUNT_LOGON: u16 = 4648;
    pub const PROCESS_CREATED: u16 = 4688;
    pub const PROCESS_TERMINATED: u16 = 4689;
    pub const SERVICE_INSTALLED: u16 = 4697;
    pub const PRIVILEGED_SERVICE: u16 = 4673;
    pub const SENSITIVE_PRIVILEGE: u16 = 4672;
    pub const OBJECT_ACCESS: u16 = 4663;
    pub const HANDLE_MANIPULATION: u16 = 4656;
    pub const SCHEDULED_TASK_CREATED: u16 = 4698;
    pub const SCHEDULED_TASK_DELETED: u16 = 4699;
    pub const SCHEDULED_TASK_ENABLED: u16 = 4700;
    pub const SCHEDULED_TASK_DISABLED: u16 = 4701;
    pub const SCHEDULED_TASK_UPDATED: u16 = 4702;
    pub const FIREWALL_RULE_ADDED: u16 = 4946;
    pub const FIREWALL_RULE_MODIFIED: u16 = 4947;
    pub const FIREWALL_RULE_DELETED: u16 = 4948;
    pub const GROUP_MEMBERSHIP_ENUM: u16 = 4799;
    pub const PASS_THE_HASH: u16 = 4624; // Check for NTLM logon type 9
    pub const KERBEROASTING: u16 = 4769; // TGS request
    pub const GOLDEN_TICKET: u16 = 4768; // TGT request anomaly
    pub const DCSYNC: u16 = 4662; // DS-Replication-Get-Changes
}

/// PowerShell event IDs
mod powershell_event_ids {
    pub const SCRIPT_BLOCK_LOGGING: u16 = 4104;
    pub const SCRIPT_BLOCK_LOGGING_START: u16 = 4105;
    pub const SCRIPT_BLOCK_LOGGING_STOP: u16 = 4106;
    pub const ENGINE_STATE: u16 = 400;
    pub const COMMAND_LIFECYCLE: u16 = 4103;
    pub const PIPELINE_EXECUTION: u16 = 800;
    pub const PROVIDER_LIFECYCLE: u16 = 600;
}

/// Kernel event IDs
mod event_ids {
    pub const PROCESS_START: u16 = 1;
    pub const PROCESS_END: u16 = 2;
    pub const THREAD_START: u16 = 3;
    pub const THREAD_END: u16 = 4;
    pub const IMAGE_LOAD: u16 = 5;
    pub const IMAGE_UNLOAD: u16 = 6;

    pub const FILE_READ: u16 = 10; // FileIo/Read - used for credential theft detection
    pub const FILE_CLOSE: u16 = 11; // FileIo/Close
    pub const FILE_CREATE: u16 = 12;
    pub const FILE_DELETE: u16 = 13;
    pub const FILE_RENAME: u16 = 14;
    pub const FILE_WRITE: u16 = 15;
    pub const FILE_SET_INFO: u16 = 16;

    pub const REG_CREATE_KEY: u16 = 1;
    pub const REG_DELETE_KEY: u16 = 2;
    pub const REG_SET_VALUE: u16 = 3;
    pub const REG_DELETE_VALUE: u16 = 4;
    pub const REG_QUERY_VALUE: u16 = 5;
    pub const REG_OPEN_KEY: u16 = 6;
    pub const REG_CLOSE_KEY: u16 = 7;

    pub const TCP_IP_SEND: u16 = 10;
    pub const TCP_IP_RECV: u16 = 11;
    pub const TCP_CONNECT: u16 = 12;
    pub const TCP_DISCONNECT: u16 = 13;
    pub const TCP_ACCEPT: u16 = 14;
    pub const TCP_RECONNECT: u16 = 16;
    pub const UDP_SEND: u16 = 17;
    pub const UDP_RECV: u16 = 18;

    // AMSI event IDs
    pub const AMSI_SCAN: u16 = 1101;

    // Code Integrity event IDs
    pub const CI_DRIVER_LOAD_BLOCKED: u16 = 3033;
    pub const CI_UNSIGNED_DRIVER: u16 = 3034;
    pub const CI_CODE_INTEGRITY_CHECK_FAILED: u16 = 3023;
    pub const CI_IMAGE_VERIFICATION_FAILED: u16 = 3076;
    pub const CI_POLICY_VIOLATION: u16 = 3077;

    // LDAP Client event IDs
    pub const LDAP_SEARCH_REQUEST: u16 = 30;
    pub const LDAP_BIND_REQUEST: u16 = 31;
    pub const LDAP_MODIFY_REQUEST: u16 = 32;
    pub const LDAP_ADD_REQUEST: u16 = 33;
    pub const LDAP_DELETE_REQUEST: u16 = 34;

    // Sysmon event IDs
    pub const SYSMON_PROCESS_CREATE: u16 = 1;
    pub const SYSMON_FILE_CREATE_TIME: u16 = 2;
    pub const SYSMON_NETWORK_CONNECT: u16 = 3;
    pub const SYSMON_SERVICE_STATE_CHANGE: u16 = 4;
    pub const SYSMON_PROCESS_TERMINATE: u16 = 5;
    pub const SYSMON_DRIVER_LOAD: u16 = 6;
    pub const SYSMON_IMAGE_LOAD: u16 = 7;
    pub const SYSMON_CREATE_REMOTE_THREAD: u16 = 8;
    pub const SYSMON_RAW_ACCESS_READ: u16 = 9;
    pub const SYSMON_PROCESS_ACCESS: u16 = 10;
    pub const SYSMON_FILE_CREATE: u16 = 11;
    pub const SYSMON_REGISTRY_EVENT: u16 = 12;
    pub const SYSMON_REGISTRY_SET_VALUE: u16 = 13;
    pub const SYSMON_REGISTRY_RENAME: u16 = 14;
    pub const SYSMON_FILE_CREATE_STREAM_HASH: u16 = 15;
    pub const SYSMON_PIPE_CREATED: u16 = 17;
    pub const SYSMON_PIPE_CONNECTED: u16 = 18;
    pub const SYSMON_WMI_FILTER: u16 = 19;
    pub const SYSMON_WMI_CONSUMER: u16 = 20;
    pub const SYSMON_WMI_BINDING: u16 = 21;
    pub const SYSMON_DNS_QUERY: u16 = 22;
    pub const SYSMON_FILE_DELETE: u16 = 23;
    pub const SYSMON_CLIPBOARD_CHANGE: u16 = 24;
    pub const SYSMON_PROCESS_TAMPERING: u16 = 25;
    pub const SYSMON_FILE_DELETE_DETECTED: u16 = 26;
}

/// ETW EVENT_TRACE_PROPERTIES structure
#[repr(C)]
struct EventTraceProperties {
    wnode: WnodeHeader,
    buffer_size: u32,
    minimum_buffers: u32,
    maximum_buffers: u32,
    maximum_file_size: u32,
    log_file_mode: u32,
    flush_timer: u32,
    enable_flags: u32,
    age_limit: i32,
    number_of_buffers: u32,
    free_buffers: u32,
    events_lost: u32,
    buffers_written: u32,
    log_buffers_lost: u32,
    real_time_buffers_lost: u32,
    logger_thread_id: *mut c_void,
    log_file_name_offset: u32,
    logger_name_offset: u32,
    _padding: [u8; 1024], // Extra space for session name and log file name
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct WnodeHeader {
    buffer_size: u32,
    provider_id: u32,
    historical_context: u64,
    timestamp: i64,
    guid: [u8; 16],
    client_context: u32,
    flags: u32,
}

/// EVENT_TRACE_LOGFILEW structure for OpenTraceW
#[repr(C)]
struct EventTraceLogfileW {
    log_file_name: *mut u16,
    logger_name: *mut u16,
    current_time: i64,
    buffers_read: u32,
    log_file_mode: u32,
    current_event: EventTrace,
    logfile_header: TraceLogfileHeader,
    buffer_callback: Option<unsafe extern "system" fn(*mut EventTraceLogfileW) -> u32>,
    buffer_size: u32,
    filled: u32,
    events_lost: u32,
    event_record_callback: Option<unsafe extern "system" fn(*mut EventRecord)>,
    is_kernel_trace: u32,
    context: *mut c_void,
}

/// Minimal EVENT_TRACE structure (legacy, unused but required)
#[repr(C)]
#[derive(Clone, Copy)]
struct EventTrace {
    header: EventTraceHeader,
    instance_id: u32,
    parent_instance_id: u32,
    parent_guid: [u8; 16],
    mof_data: *mut c_void,
    mof_length: u32,
    client_context: u32,
}

impl Default for EventTrace {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct EventTraceHeader {
    size: u16,
    header_type: u8,
    marker_flags: u8,
    class_type: u8,
    class_level: u8,
    class_version: u16,
    thread_id: u32,
    process_id: u32,
    timestamp: i64,
    guid: [u8; 16],
    kernel_time: u32,
    user_time: u32,
}

/// Minimal TRACE_LOGFILE_HEADER (unused but required)
#[repr(C)]
#[derive(Clone, Copy)]
struct TraceLogfileHeader {
    buffer_size: u32,
    version: u32,
    provider_version: u32,
    number_of_processors: u32,
    end_time: i64,
    timer_resolution: u32,
    maximum_file_size: u32,
    log_file_mode: u32,
    buffers_written: u32,
    start_buffers: u32,
    pointer_size: u32,
    events_lost: u32,
    cpu_speed_in_mhz: u32,
    logger_name: *mut u16,
    log_file_name: *mut u16,
    time_zone: [u8; 176], // TIME_ZONE_INFORMATION
    boot_time: i64,
    perf_freq: i64,
    start_time: i64,
    reserved_flags: u32,
    buffers_lost: u32,
}

impl Default for TraceLogfileHeader {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

/// EVENT_RECORD structure (Windows Vista+)
#[repr(C)]
struct EventRecord {
    event_header: EventHeader,
    buffer_context: EtwBufferContext,
    extended_data_count: u16,
    user_data_length: u16,
    extended_data: *mut c_void,
    user_data: *mut c_void,
    user_context: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct EventHeader {
    size: u16,
    header_type: u16,
    flags: u16,
    event_property: u16,
    thread_id: u32,
    process_id: u32,
    timestamp: i64,
    provider_id: [u8; 16], // GUID
    event_descriptor: EventDescriptor,
    kernel_time: u32,
    user_time: u32,
    activity_id: [u8; 16], // GUID
}

#[repr(C)]
#[derive(Clone, Copy)]
struct EventDescriptor {
    id: u16,
    version: u8,
    channel: u8,
    level: u8,
    opcode: u8,
    task: u16,
    keyword: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct EtwBufferContext {
    processor_number: u8,
    alignment: u8,
    logger_id: u16,
}

/// Processing mode flags
const PROCESS_TRACE_MODE_REAL_TIME: u32 = 0x00000100;
const PROCESS_TRACE_MODE_EVENT_RECORD: u32 = 0x10000000;

/// Default ring buffer capacity (events)
const DEFAULT_RING_BUFFER_CAPACITY: usize = 100_000;

/// Default health check interval (seconds)
const DEFAULT_HEALTH_CHECK_INTERVAL_SECS: u64 = 30;

/// Default per-provider event rate limit (events/sec)
const DEFAULT_PROVIDER_RATE_LIMIT: u64 = 10_000;

/// Maximum session restart backoff (milliseconds)
const MAX_RESTART_BACKOFF_MS: u64 = 60_000;

/// Base restart delay (milliseconds)
const BASE_RESTART_DELAY_MS: u64 = 5_000;

// ============================================================================
// Ring Buffer for Event Bursts
// ============================================================================

/// Bounded ring buffer that absorbs event bursts without dropping silently.
/// When full, the oldest event is evicted and the drop counter incremented.
struct EtwRingBuffer {
    buffer: VecDeque<TelemetryEvent>,
    capacity: usize,
    dropped_count: AtomicU64,
    total_pushed: AtomicU64,
}

impl EtwRingBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            buffer: VecDeque::with_capacity(std::cmp::min(capacity, 1024)), // pre-alloc up to 1K
            capacity,
            dropped_count: AtomicU64::new(0),
            total_pushed: AtomicU64::new(0),
        }
    }

    /// Push an event into the ring buffer.  Returns `true` if accepted
    /// without eviction, `false` if the oldest event was dropped.
    fn push(&mut self, event: TelemetryEvent) -> bool {
        self.total_pushed.fetch_add(1, Ordering::Relaxed);
        if self.buffer.len() >= self.capacity {
            self.dropped_count.fetch_add(1, Ordering::Relaxed);
            self.buffer.pop_front();
            self.buffer.push_back(event);
            false
        } else {
            self.buffer.push_back(event);
            true
        }
    }

    /// Drain up to `max` events from the front of the buffer.
    fn drain_batch(&mut self, max: usize) -> Vec<TelemetryEvent> {
        let count = std::cmp::min(max, self.buffer.len());
        self.buffer.drain(..count).collect()
    }

    /// Number of events currently buffered.
    fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Total events dropped due to ring buffer overflow.
    fn dropped(&self) -> u64 {
        self.dropped_count.load(Ordering::Relaxed)
    }

    /// Total events pushed (including dropped).
    fn total(&self) -> u64 {
        self.total_pushed.load(Ordering::Relaxed)
    }
}

// ============================================================================
// Per-Provider Event Rate Tracking
// ============================================================================

/// Tracks event rates per provider for throttling under high load.
struct ProviderRateTracker {
    /// Map from provider name to (window_start, event_count_in_window)
    rates: HashMap<String, (Instant, u64)>,
    /// Maximum events per second per provider before throttling
    rate_limit: u64,
    /// Window duration for rate measurement
    window: Duration,
    /// Total events throttled
    throttled_count: AtomicU64,
}

impl ProviderRateTracker {
    fn new(rate_limit: u64) -> Self {
        Self {
            rates: HashMap::new(),
            rate_limit,
            window: Duration::from_secs(1),
            throttled_count: AtomicU64::new(0),
        }
    }

    /// Record an event from a provider.  Returns `true` if the event should
    /// be processed, `false` if the provider has exceeded its rate limit.
    fn should_process(&mut self, provider_name: &str) -> bool {
        let now = Instant::now();
        let entry = self
            .rates
            .entry(provider_name.to_string())
            .or_insert((now, 0));

        if now.duration_since(entry.0) >= self.window {
            // Reset window
            *entry = (now, 1);
            true
        } else {
            entry.1 += 1;
            if entry.1 > self.rate_limit {
                self.throttled_count.fetch_add(1, Ordering::Relaxed);
                false
            } else {
                true
            }
        }
    }

    fn throttled(&self) -> u64 {
        self.throttled_count.load(Ordering::Relaxed)
    }
}

// ============================================================================
// ETW Session Health and Tamper Detection
// ============================================================================

/// Snapshot of EtwEventWrite prologue bytes for tamper detection.
struct EtwFunctionBaseline {
    /// First 16 bytes of ntdll!EtwEventWrite at baseline time
    etw_event_write_bytes: Option<[u8; 16]>,
    /// Address of ntdll!EtwEventWrite
    etw_event_write_addr: usize,
    /// Timestamp when baseline was captured
    baseline_time: Instant,
}

impl EtwFunctionBaseline {
    /// Capture baseline of EtwEventWrite prologue bytes.
    fn capture() -> Self {
        let mut baseline = Self {
            etw_event_write_bytes: None,
            etw_event_write_addr: 0,
            baseline_time: Instant::now(),
        };

        unsafe {
            // Load ntdll and find EtwEventWrite
            let ntdll = windows::Win32::System::LibraryLoader::GetModuleHandleW(
                &windows::core::HSTRING::from("ntdll.dll"),
            );
            if let Ok(module) = ntdll {
                let proc_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
                    module,
                    windows::core::PCSTR::from_raw(b"EtwEventWrite\0".as_ptr()),
                );
                if let Some(addr) = proc_addr {
                    let func_ptr = addr as *const u8;
                    baseline.etw_event_write_addr = func_ptr as usize;
                    let mut bytes = [0u8; 16];
                    std::ptr::copy_nonoverlapping(func_ptr, bytes.as_mut_ptr(), 16);
                    baseline.etw_event_write_bytes = Some(bytes);
                    debug!(
                        addr = format!("0x{:x}", func_ptr as usize),
                        "EtwEventWrite baseline captured"
                    );
                }
            }
        }

        baseline
    }

    /// Check if EtwEventWrite has been patched since baseline.
    /// Returns `true` if tampering is detected.
    fn is_tampered(&self) -> bool {
        let Some(baseline_bytes) = &self.etw_event_write_bytes else {
            return false; // No baseline available
        };

        if self.etw_event_write_addr == 0 {
            return false;
        }

        unsafe {
            let func_ptr = self.etw_event_write_addr as *const u8;
            let mut current_bytes = [0u8; 16];
            // Read current bytes - use SEH-safe copy
            let current_bytes_ref = &mut current_bytes;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                std::ptr::copy_nonoverlapping(func_ptr, current_bytes_ref.as_mut_ptr(), 16);
                *current_bytes_ref
            }));

            match result {
                Ok(current) => {
                    if current != *baseline_bytes {
                        // Check for common NOP patterns (0x90, 0xC3 = ret)
                        let is_nop_patch = current[0] == 0xC3 // ret at start
                            || (current[0] == 0x33 && current[1] == 0xC0 && current[2] == 0xC3) // xor eax,eax; ret
                            || current[0] == 0x90; // nop

                        if is_nop_patch {
                            warn!(
                                "ETW TAMPER DETECTED: EtwEventWrite patched with NOP/RET pattern"
                            );
                        } else {
                            warn!("ETW TAMPER DETECTED: EtwEventWrite prologue bytes changed");
                        }
                        return true;
                    }
                    false
                }
                Err(_) => {
                    warn!("ETW tamper check: failed to read EtwEventWrite memory");
                    false
                }
            }
        }
    }
}

/// Shared state for session health monitoring, ring buffer, and rate tracking.
struct EtwSessionHealth {
    /// Ring buffer for burst absorption
    ring_buffer: Mutex<EtwRingBuffer>,
    /// Per-provider rate tracker
    rate_tracker: Mutex<ProviderRateTracker>,
    /// EtwEventWrite function baseline for tamper detection
    function_baseline: EtwFunctionBaseline,
    /// Consecutive session failure count
    consecutive_failures: AtomicU64,
    /// Whether the session is currently healthy
    session_healthy: AtomicBool,
    /// Last health check time
    last_health_check: Mutex<Instant>,
    /// Health check interval
    health_check_interval: Duration,
    /// Whether tamper detection is enabled
    tamper_detection_enabled: bool,
    /// Statistics: events received from ETW
    events_received: AtomicU64,
    /// Statistics: events dropped by ring buffer
    events_dropped_ring: AtomicU64,
    /// Statistics: events throttled by rate limiter
    events_throttled: AtomicU64,
}

/// TDH (Trace Data Helper) structures for proper event parsing
mod tdh {
    use super::*;
    use std::sync::OnceLock;
    use windows::core::HSTRING;
    use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

    static TDH_API: OnceLock<Option<TdhApi>> = OnceLock::new();

    pub struct TdhApi {
        pub get_event_information: TdhGetEventInformationFn,
        pub get_property: TdhGetPropertyFn,
        pub get_property_size: TdhGetPropertySizeFn,
    }

    type TdhGetEventInformationFn = unsafe extern "system" fn(
        event: *const EventRecord,
        tmap_info_count: u32,
        tmap_info: *const c_void,
        buffer: *mut c_void,
        buffer_size: *mut u32,
    ) -> u32;

    type TdhGetPropertyFn = unsafe extern "system" fn(
        event: *const EventRecord,
        tmap_info_count: u32,
        tmap_info: *const c_void,
        property_data_count: u32,
        property_data: *const PropertyDataDescriptor,
        buffer_size: u32,
        buffer: *mut u8,
    ) -> u32;

    type TdhGetPropertySizeFn = unsafe extern "system" fn(
        event: *const EventRecord,
        tmap_info_count: u32,
        tmap_info: *const c_void,
        property_data_count: u32,
        property_data: *const PropertyDataDescriptor,
        property_size: *mut u32,
    ) -> u32;

    #[repr(C)]
    pub struct PropertyDataDescriptor {
        pub property_name: u64, // Pointer to property name or array index
        pub array_index: u32,
        pub reserved: u32,
    }

    #[repr(C)]
    pub struct TraceEventInfo {
        pub provider_guid: [u8; 16],
        pub event_guid: [u8; 16],
        pub event_descriptor: EventDescriptor,
        pub decode_source: u32,
        pub provider_name_offset: u32,
        pub level_name_offset: u32,
        pub channel_name_offset: u32,
        pub keywords_name_offset: u32,
        pub task_name_offset: u32,
        pub opcode_name_offset: u32,
        pub event_message_offset: u32,
        pub provider_message_offset: u32,
        pub binary_xml_offset: u32,
        pub binary_xml_size: u32,
        pub activity_id_name_offset: u32,
        pub related_activity_id_name_offset: u32,
        pub property_count: u32,
        pub top_level_property_count: u32,
        pub flags: u32,
        // Followed by EVENT_PROPERTY_INFO array
    }

    #[repr(C)]
    pub struct EventPropertyInfo {
        pub flags: u32,
        pub name_offset: u32,
        pub non_struct_type: PropertyType,
        pub count_or_count_index: u16,
        pub length_or_length_index: u16,
        pub reserved: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct PropertyType {
        pub in_type: u16,
        pub out_type: u16,
        pub map_name_offset: u32,
    }

    /// TDH in types
    pub const TDH_INTYPE_UNICODESTRING: u16 = 1;
    pub const TDH_INTYPE_ANSISTRING: u16 = 2;
    pub const TDH_INTYPE_INT32: u16 = 7;
    pub const TDH_INTYPE_UINT32: u16 = 8;
    pub const TDH_INTYPE_INT64: u16 = 9;
    pub const TDH_INTYPE_UINT64: u16 = 10;
    pub const TDH_INTYPE_POINTER: u16 = 13;
    pub const TDH_INTYPE_GUID: u16 = 14;
    pub const TDH_INTYPE_FILETIME: u16 = 17;
    pub const TDH_INTYPE_SID: u16 = 19;

    pub fn get_tdh_api() -> Option<&'static TdhApi> {
        TDH_API
            .get_or_init(|| unsafe {
                let module = LoadLibraryW(&HSTRING::from("tdh.dll")).ok()?;

                let get_event_information = GetProcAddress(
                    module,
                    windows::core::PCSTR::from_raw(b"TdhGetEventInformation\0".as_ptr()),
                )?;
                let get_property = GetProcAddress(
                    module,
                    windows::core::PCSTR::from_raw(b"TdhGetProperty\0".as_ptr()),
                )?;
                let get_property_size = GetProcAddress(
                    module,
                    windows::core::PCSTR::from_raw(b"TdhGetPropertySize\0".as_ptr()),
                )?;

                Some(TdhApi {
                    get_event_information: std::mem::transmute(get_event_information),
                    get_property: std::mem::transmute(get_property),
                    get_property_size: std::mem::transmute(get_property_size),
                })
            })
            .as_ref()
    }

    /// Get a string property from an ETW event
    pub fn get_string_property(record: &EventRecord, property_name: &str) -> Option<String> {
        let api = get_tdh_api()?;

        let property_name_wide: Vec<u16> = property_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let descriptor = PropertyDataDescriptor {
            property_name: property_name_wide.as_ptr() as u64,
            array_index: u32::MAX, // ULONG_MAX for non-array
            reserved: 0,
        };

        // Get property size
        let mut property_size: u32 = 0;
        let status = unsafe {
            (api.get_property_size)(
                record,
                0,
                std::ptr::null(),
                1,
                &descriptor,
                &mut property_size,
            )
        };

        if status != 0 || property_size == 0 {
            return None;
        }

        // Get property value
        let mut buffer = vec![0u8; property_size as usize];
        let status = unsafe {
            (api.get_property)(
                record,
                0,
                std::ptr::null(),
                1,
                &descriptor,
                property_size,
                buffer.as_mut_ptr(),
            )
        };

        if status != 0 {
            return None;
        }

        // Convert from UTF-16
        if buffer.len() >= 2 {
            let chars: Vec<u16> = buffer
                .chunks(2)
                .filter_map(|chunk| {
                    if chunk.len() == 2 {
                        Some(u16::from_le_bytes([chunk[0], chunk[1]]))
                    } else {
                        None
                    }
                })
                .take_while(|&c| c != 0)
                .collect();
            Some(String::from_utf16_lossy(&chars))
        } else {
            None
        }
    }

    /// Get a u32 property from an ETW event
    pub fn get_u32_property(record: &EventRecord, property_name: &str) -> Option<u32> {
        let api = get_tdh_api()?;

        let property_name_wide: Vec<u16> = property_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let descriptor = PropertyDataDescriptor {
            property_name: property_name_wide.as_ptr() as u64,
            array_index: u32::MAX,
            reserved: 0,
        };

        let mut buffer = [0u8; 4];
        let status = unsafe {
            (api.get_property)(
                record,
                0,
                std::ptr::null(),
                1,
                &descriptor,
                4,
                buffer.as_mut_ptr(),
            )
        };

        if status == 0 {
            Some(u32::from_le_bytes(buffer))
        } else {
            None
        }
    }

    /// Get a u64 property from an ETW event
    pub fn get_u64_property(record: &EventRecord, property_name: &str) -> Option<u64> {
        let api = get_tdh_api()?;

        let property_name_wide: Vec<u16> = property_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let descriptor = PropertyDataDescriptor {
            property_name: property_name_wide.as_ptr() as u64,
            array_index: u32::MAX,
            reserved: 0,
        };

        let mut buffer = [0u8; 8];
        let status = unsafe {
            (api.get_property)(
                record,
                0,
                std::ptr::null(),
                1,
                &descriptor,
                8,
                buffer.as_mut_ptr(),
            )
        };

        if status == 0 {
            Some(u64::from_le_bytes(buffer))
        } else {
            None
        }
    }

    /// Get binary property from an ETW event
    pub fn get_binary_property(record: &EventRecord, property_name: &str) -> Option<Vec<u8>> {
        let api = get_tdh_api()?;

        let property_name_wide: Vec<u16> = property_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let descriptor = PropertyDataDescriptor {
            property_name: property_name_wide.as_ptr() as u64,
            array_index: u32::MAX,
            reserved: 0,
        };

        let mut property_size: u32 = 0;
        let status = unsafe {
            (api.get_property_size)(
                record,
                0,
                std::ptr::null(),
                1,
                &descriptor,
                &mut property_size,
            )
        };

        if status != 0 || property_size == 0 {
            return None;
        }

        let mut buffer = vec![0u8; property_size as usize];
        let status = unsafe {
            (api.get_property)(
                record,
                0,
                std::ptr::null(),
                1,
                &descriptor,
                property_size,
                buffer.as_mut_ptr(),
            )
        };

        if status == 0 {
            Some(buffer)
        } else {
            None
        }
    }
}

/// Global context for ETW callback (unfortunately required due to C callback limitations)
static ETW_CONTEXT: std::sync::OnceLock<EtwCallbackContext> = std::sync::OnceLock::new();

/// Global session health state for tamper detection and recovery
static ETW_SESSION_HEALTH: std::sync::OnceLock<EtwSessionHealth> = std::sync::OnceLock::new();

struct EtwCallbackContext {
    tx: std::sync::Mutex<Option<mpsc::Sender<TelemetryEvent>>>,
    running: Arc<AtomicBool>,
    event_count: AtomicU64,
    script_block_cache: RwLock<HashMap<String, ScriptBlockReassembler>>,
    process_name_cache: RwLock<HashMap<u32, String>>,
}

/// Reassembles fragmented PowerShell script blocks
#[derive(Debug, Clone)]
struct ScriptBlockReassembler {
    script_block_id: String,
    message_number: u32,
    message_total: u32,
    fragments: Vec<String>,
    path: Option<String>,
    timestamp: u64,
}

impl ScriptBlockReassembler {
    fn new(script_block_id: String, message_total: u32, path: Option<String>) -> Self {
        Self {
            script_block_id,
            message_number: 0,
            message_total,
            fragments: Vec::with_capacity(message_total as usize),
            path,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        }
    }

    fn add_fragment(&mut self, message_number: u32, script_block_text: String) -> bool {
        self.message_number = message_number;
        self.fragments.push(script_block_text);
        self.fragments.len() as u32 >= self.message_total
    }

    fn get_complete_script(&self) -> String {
        self.fragments.join("")
    }
}

/// ETW collector with version-adaptive implementation, session recovery,
/// tamper detection, ring buffer, and per-provider rate tracking.
pub struct EtwCollector {
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    capabilities: SystemCapabilities,
    running: Arc<AtomicBool>,
    /// ETW-specific configuration
    etw_config: EtwConfig,
}

/// ETW collector configuration (extracted from AgentConfig or defaults)
#[derive(Debug, Clone)]
pub struct EtwConfig {
    /// Session name for the ETW trace
    pub session_name: String,
    /// Ring buffer capacity (number of events)
    pub ring_buffer_size: usize,
    /// Enable ETW session tamper detection
    pub tamper_detection: bool,
    /// Health check interval in seconds
    pub health_check_interval_secs: u64,
    /// Per-provider rate limit (events/sec)
    pub provider_rate_limit: u64,
    /// Per-provider enable/disable flags
    pub provider_config: EtwProviderConfig,
    /// Performance profile
    pub profile: crate::config::PerformanceProfile,
}

impl Default for EtwConfig {
    fn default() -> Self {
        Self {
            session_name: SESSION_NAME.to_string(),
            ring_buffer_size: DEFAULT_RING_BUFFER_CAPACITY,
            tamper_detection: true,
            health_check_interval_secs: DEFAULT_HEALTH_CHECK_INTERVAL_SECS,
            provider_rate_limit: DEFAULT_PROVIDER_RATE_LIMIT,
            provider_config: EtwProviderConfig::default(),
            profile: crate::config::PerformanceProfile::Balanced,
        }
    }
}

/// Per-provider enable/disable configuration
#[derive(Debug, Clone)]
pub struct EtwProviderConfig {
    pub kernel_process: bool,
    pub kernel_file: bool,
    pub kernel_network: bool,
    pub kernel_registry: bool,
    pub dns_client: bool,
    pub powershell: bool,
    pub amsi: bool,
    pub security_auditing: bool,
    pub sysmon: bool,
    pub threat_intelligence: bool,
    pub kernel_audit_api: bool,
    pub wmi_activity: bool,
    pub task_scheduler: bool,
    pub services: bool,
    pub code_integrity: bool,
    pub ldap_client: bool,
}

impl Default for EtwProviderConfig {
    fn default() -> Self {
        Self {
            kernel_process: true,
            kernel_file: true,
            kernel_network: true,
            kernel_registry: true,
            dns_client: true,
            powershell: true,
            amsi: true,
            security_auditing: true,
            sysmon: true,
            threat_intelligence: true,
            kernel_audit_api: true,
            wmi_activity: true,
            task_scheduler: true,
            services: true,
            code_integrity: true,
            ldap_client: true,
        }
    }
}

impl EtwConfig {
    /// Build EtwConfig from AgentConfig, reading the `collectors.etw` sub-section
    /// and falling back to sensible defaults for anything missing.
    pub fn from_agent_config(config: &AgentConfig) -> Self {
        let etw_cfg = &config.collectors.etw;

        Self {
            session_name: etw_cfg.session_name.clone(),
            ring_buffer_size: etw_cfg.ring_buffer_size,
            tamper_detection: etw_cfg.tamper_detection,
            health_check_interval_secs: etw_cfg.health_check_interval_secs,
            provider_rate_limit: etw_cfg.provider_rate_limit,
            profile: config.performance_profile,
            provider_config: EtwProviderConfig {
                kernel_process: etw_cfg.providers.kernel_process,
                kernel_file: etw_cfg.providers.kernel_file,
                kernel_network: etw_cfg.providers.kernel_network,
                kernel_registry: etw_cfg.providers.kernel_registry,
                dns_client: etw_cfg.providers.dns_client,
                powershell: etw_cfg.providers.powershell,
                amsi: etw_cfg.providers.amsi,
                security_auditing: etw_cfg.providers.security_auditing,
                sysmon: etw_cfg.providers.sysmon,
                threat_intelligence: etw_cfg.providers.threat_intelligence,
                kernel_audit_api: etw_cfg.providers.kernel_audit_api,
                wmi_activity: etw_cfg.providers.wmi_activity,
                task_scheduler: etw_cfg.providers.task_scheduler,
                services: etw_cfg.providers.services,
                code_integrity: etw_cfg.providers.code_integrity,
                ldap_client: etw_cfg.providers.ldap_client,
            },
        }
    }
}

/// Monitoring mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitoringMode {
    /// Full ETW with kernel providers (requires elevation)
    EtwKernel,
    /// ETW with user-mode providers only
    EtwUserMode,
    /// Polling-based fallback
    Polling,
}

/// Provider configuration
struct ProviderConfig {
    guid: windows::core::GUID,
    name: &'static str,
    requires_kernel: bool,
    keywords: u64,
    level: u8,
}

impl EtwCollector {
    /// Create a new ETW collector with automatic capability detection,
    /// ring buffer, session recovery, and tamper detection.
    pub fn new(config: &AgentConfig) -> Result<Self> {
        let (tx, rx) = mpsc::channel(10000); // Larger buffer for high-volume ETW
        let capabilities = SystemCapabilities::detect();
        let running = Arc::new(AtomicBool::new(true));
        let etw_config = EtwConfig::from_agent_config(config);

        // Log capabilities
        win_compat::log_capabilities();

        // Initialize session health state (ring buffer, rate tracker, tamper detection)
        let _ = ETW_SESSION_HEALTH.get_or_init(|| {
            let baseline = if etw_config.tamper_detection {
                info!("Capturing EtwEventWrite baseline for tamper detection");
                EtwFunctionBaseline::capture()
            } else {
                EtwFunctionBaseline {
                    etw_event_write_bytes: None,
                    etw_event_write_addr: 0,
                    baseline_time: Instant::now(),
                }
            };

            EtwSessionHealth {
                ring_buffer: Mutex::new(EtwRingBuffer::new(etw_config.ring_buffer_size)),
                rate_tracker: Mutex::new(ProviderRateTracker::new(etw_config.provider_rate_limit)),
                function_baseline: baseline,
                consecutive_failures: AtomicU64::new(0),
                session_healthy: AtomicBool::new(true),
                last_health_check: Mutex::new(Instant::now()),
                health_check_interval: Duration::from_secs(etw_config.health_check_interval_secs),
                tamper_detection_enabled: etw_config.tamper_detection,
                events_received: AtomicU64::new(0),
                events_dropped_ring: AtomicU64::new(0),
                events_throttled: AtomicU64::new(0),
            }
        });

        info!(
            ring_buffer_size = etw_config.ring_buffer_size,
            tamper_detection = etw_config.tamper_detection,
            health_check_interval = etw_config.health_check_interval_secs,
            provider_rate_limit = etw_config.provider_rate_limit,
            "ETW session health infrastructure initialized"
        );

        // Determine monitoring mode
        let mode = Self::determine_mode(&capabilities);
        info!(
            mode = ?mode,
            version = %capabilities.version,
            "ETW collector initializing"
        );

        // Start the appropriate monitoring method with session recovery
        let tx_clone = tx.clone();
        let config_clone = config.clone();
        let running_clone = running.clone();
        let caps_clone = capabilities.clone();

        // Extra clones for potential fallback
        let tx_fallback = tx.clone();
        let config_fallback = config.clone();
        let running_fallback = running.clone();

        std::thread::spawn(move || {
            let result = match mode {
                MonitoringMode::EtwKernel => Self::run_etw_session_with_recovery(
                    tx_clone,
                    config_clone,
                    running_clone,
                    caps_clone,
                    true,
                ),
                MonitoringMode::EtwUserMode => Self::run_etw_session_with_recovery(
                    tx_clone,
                    config_clone,
                    running_clone,
                    caps_clone,
                    false,
                ),
                MonitoringMode::Polling => {
                    Self::run_polling_fallback(tx_clone, config_clone, running_clone)
                }
            };

            if let Err(e) = result {
                error!(error = %e, "ETW collector error, falling back to polling");
                // Try polling as last resort
                let _ = Self::run_polling_fallback(tx_fallback, config_fallback, running_fallback);
            }
        });

        // Start health check thread (tamper detection + session monitoring)
        if etw_config.tamper_detection {
            let health_running = running.clone();
            let health_tx = tx.clone();
            let health_interval = Duration::from_secs(etw_config.health_check_interval_secs);
            std::thread::spawn(move || {
                Self::run_health_check_loop(health_running, health_tx, health_interval);
            });
        }

        Ok(Self {
            config: config.clone(),
            event_rx: rx,
            capabilities,
            running,
            etw_config,
        })
    }

    /// Session recovery wrapper: restarts ETW session on failure with
    /// exponential backoff (5s, 10s, 20s, 40s, max 60s).
    fn run_etw_session_with_recovery(
        tx: mpsc::Sender<TelemetryEvent>,
        config: AgentConfig,
        running: Arc<AtomicBool>,
        caps: SystemCapabilities,
        kernel_mode: bool,
    ) -> Result<()> {
        let mut consecutive_failures: u32 = 0;

        while running.load(Ordering::SeqCst) {
            let result = Self::run_etw_session(
                tx.clone(),
                config.clone(),
                running.clone(),
                caps.clone(),
                kernel_mode,
            );

            if !running.load(Ordering::SeqCst) {
                // Graceful shutdown, not a failure
                break;
            }

            match result {
                Ok(()) => {
                    // Session ended normally (shutdown)
                    break;
                }
                Err(e) => {
                    consecutive_failures += 1;

                    // Update global health state
                    if let Some(health) = ETW_SESSION_HEALTH.get() {
                        health
                            .consecutive_failures
                            .store(consecutive_failures as u64, Ordering::Relaxed);
                        health.session_healthy.store(false, Ordering::Relaxed);
                    }

                    if consecutive_failures >= 3 {
                        warn!(
                            failures = consecutive_failures,
                            error = %e,
                            "ETW session failed repeatedly, attempting restart with backoff"
                        );

                        // Exponential backoff: 5s, 10s, 20s, 40s, max 60s
                        let delay_ms = std::cmp::min(
                            BASE_RESTART_DELAY_MS
                                * (1u64 << std::cmp::min(consecutive_failures - 3, 4)),
                            MAX_RESTART_BACKOFF_MS,
                        );

                        info!(delay_ms = delay_ms, "Waiting before ETW session restart");
                        std::thread::sleep(Duration::from_millis(delay_ms));
                    } else {
                        warn!(
                            failures = consecutive_failures,
                            error = %e,
                            "ETW session error, retrying"
                        );
                        std::thread::sleep(Duration::from_secs(1));
                    }

                    // Emit a tamper/recovery event so the backend knows
                    let alert_event = TelemetryEvent::new(
                        EventType::ETWTamper,
                        Severity::High,
                        EventPayload::Custom(serde_json::json!({
                            "event_type": "etw_session_recovery",
                            "consecutive_failures": consecutive_failures,
                            "error": format!("{}", e),
                            "action": "restart_attempted",
                            "timestamp": chrono::Utc::now().timestamp_millis(),
                        })),
                    );
                    let _ = tx.try_send(alert_event);
                }
            }
        }

        Ok(())
    }

    /// Periodic health check loop: verifies ETW session integrity,
    /// checks for EtwEventWrite patching, and emits tamper alerts.
    fn run_health_check_loop(
        running: Arc<AtomicBool>,
        tx: mpsc::Sender<TelemetryEvent>,
        interval: Duration,
    ) {
        info!(
            interval_secs = interval.as_secs(),
            "ETW health check thread started"
        );

        while running.load(Ordering::SeqCst) {
            std::thread::sleep(interval);

            if !running.load(Ordering::SeqCst) {
                break;
            }

            let Some(health) = ETW_SESSION_HEALTH.get() else {
                continue;
            };

            // 1. Check EtwEventWrite for patching (NOP/RET patterns)
            if health.tamper_detection_enabled && health.function_baseline.is_tampered() {
                error!("ETW tamper detection: EtwEventWrite has been patched!");

                let tamper_event = TelemetryEvent::new(
                    EventType::ETWTamper,
                    Severity::Critical,
                    EventPayload::Custom(serde_json::json!({
                        "event_type": "etw_function_tamper",
                        "function": "ntdll!EtwEventWrite",
                        "description": "EtwEventWrite prologue bytes have been modified - ETW blinding attack detected",
                        "mitre_technique": "T1562.006",
                        "mitre_tactic": "Defense Evasion",
                        "address": format!("0x{:x}", health.function_baseline.etw_event_write_addr),
                        "timestamp": chrono::Utc::now().timestamp_millis(),
                    })),
                );
                let _ = tx.try_send(tamper_event);
            }

            // 2. Check if session is healthy by querying trace status
            if let Some(api) = etw_api::get_etw_api() {
                let session_ok = Self::query_session_health(api);
                let was_healthy = health.session_healthy.load(Ordering::Relaxed);

                if !session_ok && was_healthy {
                    warn!("ETW session health check: session appears to be terminated or disabled");
                    health.session_healthy.store(false, Ordering::Relaxed);

                    let tamper_event = TelemetryEvent::new(
                        EventType::ETWTamper,
                        Severity::Critical,
                        EventPayload::Custom(serde_json::json!({
                            "event_type": "etw_session_terminated",
                            "session_name": SESSION_NAME,
                            "description": "ETW trace session was terminated externally - possible EDR blinding attack",
                            "mitre_technique": "T1562.006",
                            "mitre_tactic": "Defense Evasion",
                            "timestamp": chrono::Utc::now().timestamp_millis(),
                        })),
                    );
                    let _ = tx.try_send(tamper_event);
                } else if session_ok && !was_healthy {
                    info!("ETW session health restored");
                    health.session_healthy.store(true, Ordering::Relaxed);
                    health.consecutive_failures.store(0, Ordering::Relaxed);
                }
            }

            // 3. Log statistics periodically
            let received = health.events_received.load(Ordering::Relaxed);
            let dropped = if let Ok(rb) = health.ring_buffer.lock() {
                rb.dropped()
            } else {
                0
            };
            let throttled = if let Ok(rt) = health.rate_tracker.lock() {
                rt.throttled()
            } else {
                0
            };

            if received > 0 {
                debug!(
                    events_received = received,
                    events_dropped = dropped,
                    events_throttled = throttled,
                    session_healthy = health.session_healthy.load(Ordering::Relaxed),
                    "ETW health check statistics"
                );
            }
        }

        info!("ETW health check thread stopped");
    }

    /// Query the ETW session status using ControlTrace(QUERY).
    /// Returns `true` if the session is still active.
    fn query_session_health(api: &etw_api::EtwApi) -> bool {
        let mut properties = Self::create_trace_properties();

        let session_name_wide: Vec<u16> = SESSION_NAME
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let name_offset = std::mem::offset_of!(EventTraceProperties, _padding);
        unsafe {
            let props_ptr = &mut properties as *mut EventTraceProperties as *mut u8;
            std::ptr::copy_nonoverlapping(
                session_name_wide.as_ptr() as *const u8,
                props_ptr.add(name_offset),
                session_name_wide.len() * 2,
            );
        }
        properties.logger_name_offset = name_offset as u32;

        let result = unsafe {
            (api.control_trace)(
                0,
                session_name_wide.as_ptr(),
                &mut properties as *mut _ as *mut c_void,
                etw_api::EVENT_TRACE_CONTROL_QUERY,
            )
        };

        result == etw_api::ERROR_SUCCESS
    }

    /// Determine the best monitoring mode for the current system
    fn determine_mode(caps: &SystemCapabilities) -> MonitoringMode {
        if caps.has_etw && caps.is_elevated {
            MonitoringMode::EtwKernel
        } else if caps.has_etw {
            MonitoringMode::EtwUserMode
        } else {
            MonitoringMode::Polling
        }
    }

    /// Get all provider configurations with keyword-level filtering for
    /// performance optimization.
    fn get_provider_configs(kernel_mode: bool, config: &EtwConfig) -> Vec<ProviderConfig> {
        let mut providers = Vec::new();
        let p_cfg = &config.provider_config;

        // Kernel providers (require elevation)
        if p_cfg.kernel_process {
            // Include Thread events (0x20) only in Aggressive mode
            // Thread events are extremely high volume and cause 10-20% CPU usage
            let keywords = if config.profile == crate::config::PerformanceProfile::Aggressive {
                0x70 // Process (0x10) | Thread (0x20) | Image (0x40)
            } else {
                0x50 // Process (0x10) | Image (0x40)
            };

            providers.push(ProviderConfig {
                guid: providers::KERNEL_PROCESS,
                name: "Kernel-Process",
                requires_kernel: true,
                // Keywords: Process, Thread, Image load/unload
                keywords,
                level: etw_api::TRACE_LEVEL_INFORMATION,
            });
        }

        if p_cfg.kernel_file {
            providers.push(ProviderConfig {
                guid: providers::KERNEL_FILE,
                name: "Kernel-File",
                requires_kernel: true,
                // Keywords: FileIO create/delete/rename/write
                keywords: 0x40, // WINEVENT_KEYWORD_FILE_IO
                level: etw_api::TRACE_LEVEL_INFORMATION,
            });
        }

        if p_cfg.kernel_network {
            providers.push(ProviderConfig {
                guid: providers::KERNEL_NETWORK,
                name: "Kernel-Network",
                requires_kernel: true,
                // Keywords: TCP/IP connect, accept, send, recv
                keywords: 0x80, // WINEVENT_KEYWORD_NETWORK_IO
                level: etw_api::TRACE_LEVEL_INFORMATION,
            });
        }

        if p_cfg.kernel_registry {
            providers.push(ProviderConfig {
                guid: providers::KERNEL_REGISTRY,
                name: "Kernel-Registry",
                requires_kernel: true,
                // Keywords: Registry create, set value, delete
                keywords: 0x20, // WINEVENT_KEYWORD_REGISTRY
                level: etw_api::TRACE_LEVEL_INFORMATION,
            });
        }

        // User-mode providers (don't require elevation for basic use)
        if p_cfg.dns_client {
            providers.push(ProviderConfig {
                guid: providers::DNS_CLIENT,
                name: "DNS-Client",
                requires_kernel: false,
                keywords: 0xFFFFFFFFFFFFFFFF,
                level: etw_api::TRACE_LEVEL_INFORMATION,
            });
        }

        if p_cfg.powershell {
            providers.push(ProviderConfig {
                guid: providers::POWERSHELL,
                name: "PowerShell",
                requires_kernel: false,
                // Keywords: all - needed for script block logging (event 4104)
                keywords: 0xFFFFFFFFFFFFFFFF,
                level: etw_api::TRACE_LEVEL_VERBOSE,
            });
        }

        if p_cfg.amsi {
            providers.push(ProviderConfig {
                guid: providers::AMSI,
                name: "AMSI",
                requires_kernel: false,
                keywords: 0xFFFFFFFFFFFFFFFF,
                level: etw_api::TRACE_LEVEL_INFORMATION,
            });
        }

        if p_cfg.sysmon {
            providers.push(ProviderConfig {
                guid: providers::SYSMON,
                name: "Sysmon",
                requires_kernel: false,
                keywords: 0xFFFFFFFFFFFFFFFF,
                level: etw_api::TRACE_LEVEL_VERBOSE,
            });
        }

        if p_cfg.wmi_activity {
            providers.push(ProviderConfig {
                guid: providers::WMI_ACTIVITY,
                name: "WMI-Activity",
                requires_kernel: false,
                keywords: 0xFFFFFFFFFFFFFFFF,
                level: etw_api::TRACE_LEVEL_INFORMATION,
            });
        }

        if p_cfg.task_scheduler {
            providers.push(ProviderConfig {
                guid: providers::TASK_SCHEDULER,
                name: "TaskScheduler",
                requires_kernel: false,
                keywords: 0xFFFFFFFFFFFFFFFF,
                level: etw_api::TRACE_LEVEL_INFORMATION,
            });
        }

        if p_cfg.services {
            providers.push(ProviderConfig {
                guid: providers::SERVICES,
                name: "Services",
                requires_kernel: false,
                keywords: 0xFFFFFFFFFFFFFFFF,
                level: etw_api::TRACE_LEVEL_INFORMATION,
            });
        }

        if p_cfg.code_integrity {
            providers.push(ProviderConfig {
                guid: providers::CODE_INTEGRITY,
                name: "CodeIntegrity",
                requires_kernel: false, // Available without elevation, but some events need it
                keywords: 0xFFFFFFFFFFFFFFFF,
                level: etw_api::TRACE_LEVEL_WARNING, // Only warnings and above for CI
            });
        }

        if p_cfg.ldap_client {
            providers.push(ProviderConfig {
                guid: providers::LDAP_CLIENT,
                name: "LDAP-Client",
                requires_kernel: false,
                keywords: 0xFFFFFFFFFFFFFFFF,
                level: etw_api::TRACE_LEVEL_INFORMATION,
            });
        }

        // Add security auditing provider only in kernel mode (requires SYSTEM privileges)
        if kernel_mode {
            if p_cfg.security_auditing {
                providers.push(ProviderConfig {
                    guid: providers::SECURITY_AUDITING,
                    name: "Security-Auditing",
                    requires_kernel: true,
                    // Keywords: Logon/Logoff, Process, Privilege, Object Access, Policy Change
                    keywords: 0x8020000000000000 | 0x0010000000000000 | 0x0000000000000010,
                    level: etw_api::TRACE_LEVEL_INFORMATION,
                });
            }

            if p_cfg.threat_intelligence {
                providers.push(ProviderConfig {
                    guid: providers::THREAT_INTELLIGENCE,
                    name: "Threat-Intelligence",
                    requires_kernel: true,
                    keywords: 0xFFFFFFFFFFFFFFFF,
                    level: etw_api::TRACE_LEVEL_VERBOSE,
                });
            }

            if p_cfg.kernel_audit_api {
                providers.push(ProviderConfig {
                    guid: providers::KERNEL_AUDIT_API,
                    name: "Kernel-Audit-API",
                    requires_kernel: true,
                    keywords: 0xFFFFFFFFFFFFFFFF,
                    level: etw_api::TRACE_LEVEL_INFORMATION,
                });
            }
        }

        providers
    }

    /// Run ETW real-time session (Windows 7+)
    fn run_etw_session(
        tx: mpsc::Sender<TelemetryEvent>,
        config: AgentConfig,
        running: Arc<AtomicBool>,
        caps: SystemCapabilities,
        kernel_mode: bool,
    ) -> Result<()> {
        let api = etw_api::get_etw_api().ok_or_else(|| anyhow!("ETW API not available"))?;

        info!(
            kernel_mode = kernel_mode,
            has_ex2 = caps.has_etw_ex2,
            "Starting ETW real-time session"
        );

        // Create session properties
        let mut properties = Self::create_trace_properties();
        let mut session_handle: u64 = 0;

        // Session name as wide string
        let session_name_wide: Vec<u16> = SESSION_NAME
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        // Copy session name to properties structure
        let name_offset = std::mem::offset_of!(EventTraceProperties, _padding);
        unsafe {
            let props_ptr = &mut properties as *mut EventTraceProperties as *mut u8;
            std::ptr::copy_nonoverlapping(
                session_name_wide.as_ptr() as *const u8,
                props_ptr.add(name_offset),
                session_name_wide.len() * 2,
            );
        }
        properties.logger_name_offset = name_offset as u32;

        // Try to start the trace session
        let result = unsafe {
            (api.start_trace)(
                &mut session_handle,
                session_name_wide.as_ptr(),
                &mut properties as *mut _ as *mut c_void,
            )
        };

        match result {
            etw_api::ERROR_SUCCESS => {
                info!(handle = session_handle, "ETW session created");
            }
            etw_api::ERROR_ALREADY_EXISTS => {
                info!("ETW session already exists, stopping and recreating");
                // Stop existing session
                unsafe {
                    (api.control_trace)(
                        0,
                        session_name_wide.as_ptr(),
                        &mut properties as *mut _ as *mut c_void,
                        etw_api::EVENT_TRACE_CONTROL_STOP,
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
                // Retry start
                properties = Self::create_trace_properties();
                properties.logger_name_offset = name_offset as u32;
                unsafe {
                    let props_ptr = &mut properties as *mut EventTraceProperties as *mut u8;
                    std::ptr::copy_nonoverlapping(
                        session_name_wide.as_ptr() as *const u8,
                        props_ptr.add(name_offset),
                        session_name_wide.len() * 2,
                    );
                }
                let retry_result = unsafe {
                    (api.start_trace)(
                        &mut session_handle,
                        session_name_wide.as_ptr(),
                        &mut properties as *mut _ as *mut c_void,
                    )
                };
                if retry_result != etw_api::ERROR_SUCCESS {
                    return Err(anyhow!(
                        "Failed to start ETW session after stop: {}",
                        retry_result
                    ));
                }
                info!(handle = session_handle, "ETW session created after stop");
            }
            etw_api::ERROR_ACCESS_DENIED => {
                warn!("ETW access denied - elevation required for kernel providers");
                return Err(anyhow!("ETW access denied"));
            }
            _ => {
                return Err(anyhow!("StartTrace failed: {}", result));
            }
        }

        // Create ETW config from agent config for provider flags
        let etw_config = EtwConfig::from_agent_config(&config);

        // Enable providers based on mode and capabilities
        Self::enable_providers(api, session_handle, &caps, kernel_mode, &etw_config);

        // Start consumer in separate thread
        let tx_clone = tx.clone();
        let running_clone = running.clone();
        let session_name_clone = session_name_wide.clone();

        let consumer_handle = std::thread::spawn(move || {
            Self::consume_etw_events(tx_clone, running_clone, session_name_clone)
        });

        // Keep session alive
        while running.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_secs(1));

            // Log statistics periodically
            if let Some(ctx) = ETW_CONTEXT.get() {
                let count = ctx.event_count.load(Ordering::Relaxed);
                if count > 0 && count % 10000 == 0 {
                    debug!(events_processed = count, "ETW event processing statistics");
                }
            }
        }

        // Stop session
        info!("Stopping ETW session");
        unsafe {
            (api.control_trace)(
                session_handle,
                session_name_wide.as_ptr(),
                &mut properties as *mut _ as *mut c_void,
                etw_api::EVENT_TRACE_CONTROL_STOP,
            );
        }

        // Wait for consumer
        let _ = consumer_handle.join();

        Ok(())
    }

    /// Create ETW trace properties structure
    fn create_trace_properties() -> EventTraceProperties {
        let total_size = std::mem::size_of::<EventTraceProperties>();

        EventTraceProperties {
            wnode: WnodeHeader {
                buffer_size: total_size as u32,
                provider_id: 0,
                historical_context: 0,
                timestamp: 0,
                guid: [0; 16],
                client_context: 1, // QPC timestamp
                flags: etw_api::WNODE_FLAG_TRACED_GUID,
            },
            buffer_size: 64, // 64 KB buffers
            minimum_buffers: 8,
            maximum_buffers: 128,
            maximum_file_size: 0,
            log_file_mode: etw_api::EVENT_TRACE_REAL_TIME_MODE
                | etw_api::EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING,
            flush_timer: 1,
            enable_flags: 0,
            age_limit: 0,
            number_of_buffers: 0,
            free_buffers: 0,
            events_lost: 0,
            buffers_written: 0,
            log_buffers_lost: 0,
            real_time_buffers_lost: 0,
            logger_thread_id: std::ptr::null_mut(),
            log_file_name_offset: 0,
            logger_name_offset: 0,
            _padding: [0; 1024],
        }
    }

    /// Enable ETW providers based on capabilities
    fn enable_providers(
        api: &etw_api::EtwApi,
        session_handle: u64,
        caps: &SystemCapabilities,
        kernel_mode: bool,
        config: &EtwConfig,
    ) {
        let provider_configs = Self::get_provider_configs(kernel_mode, config);

        for config in provider_configs {
            // Skip kernel providers if not in kernel mode
            if config.requires_kernel && !kernel_mode {
                debug!(provider = %config.name, "Skipping kernel provider (user-mode only)");
                continue;
            }

            let result = if caps.has_etw_ex2 {
                // Use EnableTraceEx2 (Windows 8+)
                if let Some(enable_ex2) = api.enable_trace_ex2 {
                    unsafe {
                        enable_ex2(
                            session_handle,
                            &config.guid as *const _ as *const c_void,
                            etw_api::EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            config.level,
                            config.keywords,
                            0,
                            0,
                            std::ptr::null(),
                        )
                    }
                } else {
                    etw_api::ERROR_ACCESS_DENIED
                }
            } else {
                // Use legacy EnableTrace (Windows 7)
                unsafe {
                    (api.enable_trace)(
                        1, // Enable
                        config.keywords as u32,
                        config.level as u32,
                        &config.guid as *const _ as *const c_void,
                        session_handle,
                    )
                }
            };

            if result == etw_api::ERROR_SUCCESS {
                info!(provider = %config.name, "ETW provider enabled");
            } else if result == etw_api::ERROR_ACCESS_DENIED {
                debug!(provider = %config.name, "Provider requires elevation");
            } else {
                debug!(provider = %config.name, error = result, "Failed to enable provider");
            }
        }
    }

    /// Consume ETW events via OpenTrace/ProcessTrace
    fn consume_etw_events(
        tx: mpsc::Sender<TelemetryEvent>,
        running: Arc<AtomicBool>,
        mut session_name: Vec<u16>,
    ) -> Result<()> {
        let api = etw_api::get_etw_api().ok_or_else(|| anyhow!("ETW API not available"))?;

        info!("Starting real-time ETW event consumption");

        // Initialize global callback context
        let _ = ETW_CONTEXT.set(EtwCallbackContext {
            tx: std::sync::Mutex::new(Some(tx)),
            running: running.clone(),
            event_count: AtomicU64::new(0),
            script_block_cache: RwLock::new(HashMap::new()),
            process_name_cache: RwLock::new(HashMap::new()),
        });

        // Create logfile structure for real-time consumption
        let mut logfile = unsafe { std::mem::zeroed::<EventTraceLogfileW>() };
        logfile.logger_name = session_name.as_mut_ptr();
        logfile.log_file_mode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.event_record_callback = Some(etw_event_callback);

        // Open the trace session
        let trace_handle = unsafe { (api.open_trace)(&mut logfile as *mut _ as *mut c_void) };

        // INVALID_PROCESSTRACE_HANDLE is 0xFFFFFFFFFFFFFFFF on 64-bit
        if trace_handle == u64::MAX {
            let error = unsafe { windows::Win32::Foundation::GetLastError() };
            return Err(anyhow!("OpenTrace failed: {:?}", error));
        }

        info!(handle = trace_handle, "ETW trace opened for consumption");

        // ProcessTrace runs until the session is closed or an error occurs
        // It blocks, so we run it and check our running flag in the callback
        let handles = [trace_handle];
        let result =
            unsafe { (api.process_trace)(handles.as_ptr(), 1, std::ptr::null(), std::ptr::null()) };

        // Clean up
        unsafe { (api.close_trace)(trace_handle) };

        // Clear the callback context
        if let Some(ctx) = ETW_CONTEXT.get() {
            if let Ok(mut guard) = ctx.tx.lock() {
                *guard = None;
            }
        }

        if result != etw_api::ERROR_SUCCESS && result != 1223 {
            // 1223 = ERROR_CANCELLED
            warn!(error = result, "ProcessTrace ended with error");
        }

        info!("ETW event consumption stopped");
        Ok(())
    }
}

/// ETW event callback - called for each ETW event
/// This is a C callback, so we need to be careful with panics and use the global context
unsafe extern "system" fn etw_event_callback(event_record: *mut EventRecord) {
    if event_record.is_null() {
        return;
    }

    let record = &*event_record;
    let header = &record.event_header;

    // Check if we should stop
    if let Some(ctx) = ETW_CONTEXT.get() {
        if !ctx.running.load(Ordering::SeqCst) {
            return;
        }

        // Get the tx channel
        let tx = match ctx.tx.lock() {
            Ok(guard) => match guard.as_ref() {
                Some(tx) => tx.clone(),
                None => return,
            },
            Err(_) => return,
        };

        // Increment event counter
        ctx.event_count.fetch_add(1, Ordering::Relaxed);

        // Update session health statistics
        if let Some(health) = ETW_SESSION_HEALTH.get() {
            health.events_received.fetch_add(1, Ordering::Relaxed);
        }

        // Parse the event based on provider and event ID
        if let Some(event) = parse_etw_event(record, ctx) {
            // Apply per-provider rate limiting
            let provider_name = identify_provider_name(&record.event_header.provider_id);
            if let Some(health) = ETW_SESSION_HEALTH.get() {
                if let Ok(mut tracker) = health.rate_tracker.lock() {
                    if !tracker.should_process(provider_name) {
                        health.events_throttled.fetch_add(1, Ordering::Relaxed);
                        return; // Rate limited - drop this event
                    }
                }

                // Push into ring buffer (absorb bursts)
                if let Ok(mut rb) = health.ring_buffer.lock() {
                    if !rb.push(event.clone()) {
                        health.events_dropped_ring.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }

            // Send event to collector channel (non-blocking)
            let _ = tx.try_send(event);
        }
    }
}

/// Identify provider name from GUID bytes for rate tracking.
fn identify_provider_name(provider_id: &[u8; 16]) -> &'static str {
    let guid = windows::core::GUID::from_u128(u128::from_le_bytes(*provider_id));

    if guid == providers::KERNEL_PROCESS {
        "Kernel-Process"
    } else if guid == providers::KERNEL_FILE {
        "Kernel-File"
    } else if guid == providers::KERNEL_NETWORK {
        "Kernel-Network"
    } else if guid == providers::KERNEL_REGISTRY {
        "Kernel-Registry"
    } else if guid == providers::DNS_CLIENT {
        "DNS-Client"
    } else if guid == providers::POWERSHELL {
        "PowerShell"
    } else if guid == providers::AMSI {
        "AMSI"
    } else if guid == providers::SECURITY_AUDITING {
        "Security-Auditing"
    } else if guid == providers::SYSMON {
        "Sysmon"
    } else if guid == providers::THREAT_INTELLIGENCE {
        "Threat-Intelligence"
    } else if guid == providers::WMI_ACTIVITY {
        "WMI-Activity"
    } else if guid == providers::TASK_SCHEDULER {
        "TaskScheduler"
    } else if guid == providers::CODE_INTEGRITY {
        "CodeIntegrity"
    } else if guid == providers::LDAP_CLIENT {
        "LDAP-Client"
    } else if guid == providers::SERVICES {
        "Services"
    } else if guid == providers::KERNEL_AUDIT_API {
        "Kernel-Audit-API"
    } else {
        "Unknown"
    }
}

/// Parse an ETW event record into a TelemetryEvent
fn parse_etw_event(record: &EventRecord, ctx: &EtwCallbackContext) -> Option<TelemetryEvent> {
    let header = &record.event_header;
    let event_id = header.event_descriptor.id;
    let provider_id = header.provider_id;

    // Convert provider GUID to comparable format
    let provider_guid = windows::core::GUID::from_u128(u128::from_le_bytes([
        provider_id[0],
        provider_id[1],
        provider_id[2],
        provider_id[3],
        provider_id[4],
        provider_id[5],
        provider_id[6],
        provider_id[7],
        provider_id[8],
        provider_id[9],
        provider_id[10],
        provider_id[11],
        provider_id[12],
        provider_id[13],
        provider_id[14],
        provider_id[15],
    ]));

    // Route to appropriate parser based on provider
    if provider_guid == providers::KERNEL_PROCESS {
        parse_process_event(record, event_id, ctx)
    } else if provider_guid == providers::KERNEL_FILE {
        parse_file_event(record, event_id, ctx)
    } else if provider_guid == providers::KERNEL_NETWORK {
        parse_network_event(record, event_id, ctx)
    } else if provider_guid == providers::KERNEL_REGISTRY {
        parse_registry_event(record, event_id, ctx)
    } else if provider_guid == providers::DNS_CLIENT {
        parse_dns_event(record, event_id)
    } else if provider_guid == providers::POWERSHELL {
        parse_powershell_event(record, event_id, ctx)
    } else if provider_guid == providers::AMSI {
        parse_amsi_etw_event(record, event_id)
    } else if provider_guid == providers::SECURITY_AUDITING {
        parse_security_auditing_event(record, event_id)
    } else if provider_guid == providers::SYSMON {
        parse_sysmon_event(record, event_id)
    } else if provider_guid == providers::THREAT_INTELLIGENCE {
        parse_threat_intelligence_event(record, event_id)
    } else if provider_guid == providers::WMI_ACTIVITY {
        parse_wmi_activity_event(record, event_id)
    } else if provider_guid == providers::TASK_SCHEDULER {
        parse_task_scheduler_event(record, event_id)
    } else if provider_guid == providers::CODE_INTEGRITY {
        parse_code_integrity_event(record, event_id)
    } else if provider_guid == providers::LDAP_CLIENT {
        parse_ldap_client_event(record, event_id)
    } else {
        None
    }
}

/// Parse kernel process events
fn parse_process_event(
    record: &EventRecord,
    event_id: u16,
    ctx: &EtwCallbackContext,
) -> Option<TelemetryEvent> {
    let header = &record.event_header;

    match event_id {
        event_ids::PROCESS_START | event_ids::PROCESS_END => {
            let is_start = event_id == event_ids::PROCESS_START;
            let pid = header.process_id;

            // Update process cache
            if is_start {
                let image_file_name = tdh::get_string_property(record, "ImageFileName")
                    .or_else(|| get_process_path_by_pid(pid));
                if let Some(path) = &image_file_name {
                    let name = std::path::Path::new(path)
                        .file_name()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_else(|| format!("PID:{}", pid));

                    if let Ok(mut cache) = ctx.process_name_cache.write() {
                        cache.insert(pid, name);
                    }
                }
            } else {
                // Process end - remove from cache
                // Note: We might want to delay removal slightly if we expect lingering events,
                // but for now, simple removal is better than memory leak.
                if let Ok(mut cache) = ctx.process_name_cache.write() {
                    cache.remove(&pid);
                }
            }

            // Try to get additional info from TDH
            let image_file_name = tdh::get_string_property(record, "ImageFileName")
                .or_else(|| get_process_path_by_pid(pid));
            let command_line = tdh::get_string_property(record, "CommandLine");
            let parent_id = tdh::get_u32_property(record, "ParentId");

            let path = image_file_name.unwrap_or_default();
            let name = std::path::Path::new(&path)
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| format!("PID:{}", pid));

            let ppid = parent_id.unwrap_or(header.thread_id);

            Some(TelemetryEvent::new(
                if is_start {
                    EventType::ProcessCreate
                } else {
                    EventType::ProcessTerminate
                },
                if is_start {
                    Severity::Info
                } else {
                    Severity::Low
                },
                EventPayload::Process(ProcessEvent {
                    pid,
                    ppid,
                    name: name.clone(),
                    path,
                    cmdline: command_line.unwrap_or_default(),
                    user: String::new(),
                    sha256: Vec::new(),
                    entropy: 0.0,
                    is_elevated: false,
                    parent_name: None,
                    parent_path: None,
                    is_signed: false,
                    signer: None,
                    start_time: chrono::Utc::now().timestamp_millis() as u64,
                    cpu_usage: 0.0,
                    memory_bytes: 0,
                    company_name: None,
                    file_description: None,
                    product_name: None,
                    file_version: None,
                    environment: None,
                }),
            ))
        }
        event_ids::IMAGE_LOAD => {
            let pid = header.process_id;
            let image_name = tdh::get_string_property(record, "FileName")
                .or_else(|| tdh::get_string_property(record, "ImageName"));
            let image_base = tdh::get_u64_property(record, "ImageBase");
            let image_size = tdh::get_u64_property(record, "ImageSize");

            Some(TelemetryEvent::new(
                EventType::ModuleLoad,
                Severity::Info,
                EventPayload::Custom(serde_json::json!({
                    "event_type": "image_load",
                    "process_id": pid,
                    "image_name": image_name,
                    "image_base": format!("0x{:x}", image_base.unwrap_or(0)),
                    "image_size": image_size,
                    "timestamp": chrono::Utc::now().timestamp_millis(),
                })),
            ))
        }
        event_ids::THREAD_START => {
            let pid = header.process_id;
            let thread_id = header.thread_id;
            let start_address = tdh::get_u64_property(record, "StartAddr")
                .or_else(|| tdh::get_u64_property(record, "Win32StartAddr"));

            // Remote thread creation detection
            let target_pid = tdh::get_u32_property(record, "ProcessId");
            let is_remote = target_pid.map(|t| t != pid).unwrap_or(false);

            if is_remote {
                Some(TelemetryEvent::new(
                    EventType::ProcessInject,
                    Severity::High,
                    EventPayload::Custom(serde_json::json!({
                        "event_type": "remote_thread_creation",
                        "source_pid": pid,
                        "target_pid": target_pid,
                        "thread_id": thread_id,
                        "start_address": format!("0x{:x}", start_address.unwrap_or(0)),
                        "timestamp": chrono::Utc::now().timestamp_millis(),
                    })),
                ))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Check if a file read operation targets a Windows credential file.
/// Returns a CredentialTheft event if the file matches known credential paths.
/// This enables detection of browser credential theft (T1555.003), SSH key theft (T1552.004),
/// SAM database access (T1003.002), and other credential access attacks on Windows.
fn check_windows_credential_file_read(
    path: &str,
    pid: u32,
    ctx: &EtwCallbackContext,
) -> Option<TelemetryEvent> {
    use super::credential_theft::CredentialAttackType;
    use super::{CredentialTheftEvent, Detection, DetectionType};

    let path_lower = path.to_lowercase();

    // Windows credential file patterns with their attack types
    // Format: (pattern, attack_type, target_description)
    let windows_credential_patterns: &[(&str, CredentialAttackType, &str)] = &[
        // SAM/SECURITY/SYSTEM hives (T1003.002)
        (
            r"\windows\system32\config\sam",
            CredentialAttackType::SamAccess,
            "SAM Database",
        ),
        (
            r"\windows\system32\config\security",
            CredentialAttackType::SamAccess,
            "SECURITY Hive",
        ),
        (
            r"\windows\system32\config\system",
            CredentialAttackType::SamAccess,
            "SYSTEM Hive",
        ),
        // NTDS.dit (T1003.003)
        (
            r"\windows\ntds\ntds.dit",
            CredentialAttackType::NtdsAccess,
            "Active Directory Database",
        ),
        (
            r"\windows\ntds\ntds.jfm",
            CredentialAttackType::NtdsAccess,
            "NTDS Journal",
        ),
        // Chrome credentials (T1555.003)
        (
            r"\google\chrome\user data\default\login data",
            CredentialAttackType::BrowserCredentials,
            "Chrome Login Data",
        ),
        (
            r"\google\chrome\user data\default\cookies",
            CredentialAttackType::BrowserCredentials,
            "Chrome Cookies",
        ),
        (
            r"\google\chrome\user data\default\web data",
            CredentialAttackType::BrowserCredentials,
            "Chrome Web Data",
        ),
        (
            r"\google\chrome\user data\local state",
            CredentialAttackType::BrowserCredentials,
            "Chrome Local State",
        ),
        // Edge credentials
        (
            r"\microsoft\edge\user data\default\login data",
            CredentialAttackType::BrowserCredentials,
            "Edge Login Data",
        ),
        (
            r"\microsoft\edge\user data\default\cookies",
            CredentialAttackType::BrowserCredentials,
            "Edge Cookies",
        ),
        // Firefox credentials
        (
            r"\mozilla\firefox\profiles",
            CredentialAttackType::BrowserCredentials,
            "Firefox Profile",
        ),
        (
            r"\logins.json",
            CredentialAttackType::BrowserCredentials,
            "Firefox Logins",
        ),
        (
            r"\key4.db",
            CredentialAttackType::BrowserCredentials,
            "Firefox Key DB",
        ),
        (
            r"\cookies.sqlite",
            CredentialAttackType::BrowserCredentials,
            "Firefox Cookies",
        ),
        // Brave credentials
        (
            r"\bravesoftware\brave-browser\user data\default\login data",
            CredentialAttackType::BrowserCredentials,
            "Brave Login Data",
        ),
        // Windows Credential Manager (T1555.004)
        (
            r"\microsoft\credentials",
            CredentialAttackType::CredentialVault,
            "Windows Credentials",
        ),
        (
            r"\microsoft\vault",
            CredentialAttackType::CredentialVault,
            "Windows Vault",
        ),
        // SSH keys (T1552.004)
        (
            r"\.ssh\id_rsa",
            CredentialAttackType::SshKeyTheft,
            "SSH Private Key (RSA)",
        ),
        (
            r"\.ssh\id_ed25519",
            CredentialAttackType::SshKeyTheft,
            "SSH Private Key (Ed25519)",
        ),
        (
            r"\.ssh\id_ecdsa",
            CredentialAttackType::SshKeyTheft,
            "SSH Private Key (ECDSA)",
        ),
        // PuTTY sessions (T1552.004)
        (
            r"\.ppk",
            CredentialAttackType::SshKeyTheft,
            "PuTTY Private Key",
        ),
        // Password managers
        (
            r".kdbx",
            CredentialAttackType::PasswordManager,
            "KeePass Database",
        ),
        // RDP credentials
        (
            r".rdp",
            CredentialAttackType::RdpCredentials,
            "RDP Credentials File",
        ),
        // FileZilla/WinSCP
        (
            r"\filezilla\recentservers.xml",
            CredentialAttackType::CredentialFile,
            "FileZilla Servers",
        ),
        (
            r"\filezilla\sitemanager.xml",
            CredentialAttackType::CredentialFile,
            "FileZilla Sites",
        ),
        (
            r"\winscp.ini",
            CredentialAttackType::CredentialFile,
            "WinSCP Config",
        ),
        // Cloud credentials
        (
            r"\.aws\credentials",
            CredentialAttackType::CredentialFile,
            "AWS Credentials",
        ),
        (
            r"\.azure\accesstokens.json",
            CredentialAttackType::CredentialFile,
            "Azure Access Tokens",
        ),
        // Git credentials
        (
            r"\.git-credentials",
            CredentialAttackType::CredentialFile,
            "Git Credentials",
        ),
        // Crypto wallet extensions (T1528)
        (
            r"\metamask\",
            CredentialAttackType::BrowserCredentials,
            "MetaMask Wallet",
        ),
        (
            r"\phantom\",
            CredentialAttackType::BrowserCredentials,
            "Phantom Wallet",
        ),
        (
            r"\solflare\",
            CredentialAttackType::BrowserCredentials,
            "Solflare Wallet",
        ),
        (
            r"\backpack\",
            CredentialAttackType::BrowserCredentials,
            "Backpack Wallet",
        ),
    ];

    for (pattern, attack_type, target_name) in windows_credential_patterns {
        if path_lower.contains(pattern) {
            // Get process name from cache or lookup
            let process_name = if let Ok(cache) = ctx.process_name_cache.read() {
                if let Some(name) = cache.get(&pid) {
                    name.clone()
                } else {
                    drop(cache);
                    get_process_name_by_pid(pid).unwrap_or_else(|| format!("PID:{}", pid))
                }
            } else {
                get_process_name_by_pid(pid).unwrap_or_else(|| format!("PID:{}", pid))
            };

            // Skip legitimate system processes and browsers
            let process_lower = process_name.to_lowercase();
            let legitimate_processes = [
                "system",
                "lsass.exe",
                "services.exe",
                "svchost.exe",
                "csrss.exe",
                "smss.exe",
                "wininit.exe",
                "winlogon.exe",
                "dwm.exe",
                "searchindexer.exe",
                "msmpeng.exe",
                "mssense.exe",
                "chrome.exe",
                "firefox.exe",
                "msedge.exe",
                "brave.exe",
                "code.exe",
                "explorer.exe",
            ];
            if legitimate_processes.iter().any(|p| process_lower == *p) {
                return None;
            }

            warn!(
                pid = pid,
                process = %process_name,
                path = %path,
                attack_type = %attack_type.as_str(),
                "Windows credential file read detected via ETW"
            );

            let process_path = get_process_path_by_pid(pid).unwrap_or_default();
            let username = std::env::var("USERNAME").unwrap_or_else(|_| "UNKNOWN".to_string());

            let mut event = TelemetryEvent::new(
                EventType::CredentialTheft,
                attack_type.severity(),
                EventPayload::CredentialTheft(CredentialTheftEvent {
                    attack_type: attack_type.as_str().to_string(),
                    mitre_technique: attack_type.mitre_technique().to_string(),
                    target: target_name.to_string(),
                    process_name: process_name.clone(),
                    pid,
                    process_path,
                    process_cmdline: String::new(),
                    username,
                    blocked: false,
                    details: format!(
                        "Process '{}' (PID: {}) read credential file: {}",
                        process_name, pid, path
                    ),
                }),
            );

            event.add_detection(Detection {
                detection_type: DetectionType::CredentialTheft,
                rule_name: format!("etw_credential_file_read_{}", attack_type.as_str()),
                confidence: 0.85,
                description: format!(
                    "{}: {} accessed by {} (PID: {})",
                    attack_type.description(),
                    target_name,
                    process_name,
                    pid
                ),
                mitre_tactics: attack_type.mitre_tactics(),
                mitre_techniques: vec![attack_type.mitre_technique().to_string()],
            });

            return Some(event);
        }
    }

    None
}

/// Parse kernel file events
fn parse_file_event(
    record: &EventRecord,
    event_id: u16,
    ctx: &EtwCallbackContext,
) -> Option<TelemetryEvent> {
    let header = &record.event_header;
    let pid = header.process_id;

    // For FILE_READ events, only process credential file reads to avoid noise
    if event_id == event_ids::FILE_READ {
        let file_path = tdh::get_string_property(record, "FileName")
            .or_else(|| tdh::get_string_property(record, "OpenPath"));

        if let Some(path) = file_path {
            if let Some(cred_event) = check_windows_credential_file_read(&path, pid, ctx) {
                return Some(cred_event);
            }
        }
        return None; // Skip non-credential file reads
    }

    let operation = match event_id {
        event_ids::FILE_CREATE => "create",
        event_ids::FILE_DELETE => "delete",
        event_ids::FILE_RENAME => "rename",
        event_ids::FILE_WRITE => "modify",
        event_ids::FILE_SET_INFO => "set_info",
        event_ids::FILE_CLOSE => return None, // Skip close events
        _ => return None,
    };

    // Get file path from TDH
    let file_path = tdh::get_string_property(record, "FileName")
        .or_else(|| tdh::get_string_property(record, "OpenPath"));

    // Resolve process name from cache first
    let process_name = if let Ok(cache) = ctx.process_name_cache.read() {
        if let Some(name) = cache.get(&pid) {
            name.clone()
        } else {
            // Drop read lock to acquire write lock if needed
            drop(cache);
            let name = get_process_name_by_pid(pid).unwrap_or_default();
            if !name.is_empty() {
                if let Ok(mut write_cache) = ctx.process_name_cache.write() {
                    write_cache.insert(pid, name.clone());
                }
            }
            name
        }
    } else {
        get_process_name_by_pid(pid).unwrap_or_default()
    };

    Some(TelemetryEvent::new(
        match event_id {
            event_ids::FILE_CREATE => EventType::FileCreate,
            event_ids::FILE_DELETE => EventType::FileDelete,
            event_ids::FILE_RENAME => EventType::FileRename,
            event_ids::FILE_WRITE | event_ids::FILE_SET_INFO => EventType::FileModify,
            _ => EventType::FileModify,
        },
        Severity::Info,
        EventPayload::File(FileEvent {
            path: file_path.unwrap_or_default(),
            old_path: if event_id == event_ids::FILE_RENAME {
                tdh::get_string_property(record, "OldFileName")
            } else {
                None
            },
            operation: operation.to_string(),
            pid,
            process_name,
            sha256: Vec::new(),
            size: tdh::get_u64_property(record, "FileSize").unwrap_or(0),
            entropy: 0.0,
            file_type: String::new(),
        }),
    ))
}

/// Parse kernel network events
fn parse_network_event(
    record: &EventRecord,
    event_id: u16,
    ctx: &EtwCallbackContext,
) -> Option<TelemetryEvent> {
    let header = &record.event_header;
    let pid = header.process_id;

    let (event_type_str, direction) = match event_id {
        event_ids::TCP_CONNECT => ("connect", "outbound"),
        event_ids::TCP_ACCEPT => ("accept", "inbound"),
        event_ids::TCP_DISCONNECT => ("disconnect", "none"),
        event_ids::TCP_RECONNECT => ("reconnect", "outbound"),
        event_ids::TCP_IP_SEND => ("send", "outbound"),
        event_ids::TCP_IP_RECV => ("recv", "inbound"),
        event_ids::UDP_SEND => ("send", "outbound"),
        event_ids::UDP_RECV => ("recv", "inbound"),
        _ => return None,
    };

    // Parse IP addresses and ports from TDH
    let local_addr = tdh::get_binary_property(record, "LocalAddr")
        .map(|b| parse_ip_address(&b))
        .flatten(); // or and_then(|x| x)
    let remote_addr = tdh::get_binary_property(record, "RemoteAddr")
        .or_else(|| tdh::get_binary_property(record, "daddr"))
        .map(|b| parse_ip_address(&b))
        .flatten();
    let local_port = tdh::get_u32_property(record, "LocalPort")
        .or_else(|| tdh::get_u32_property(record, "sport"))
        .map(|p| p as u16);
    let remote_port = tdh::get_u32_property(record, "RemotePort")
        .or_else(|| tdh::get_u32_property(record, "dport"))
        .map(|p| p as u16);

    let protocol = if event_id >= event_ids::UDP_SEND {
        "udp"
    } else {
        "tcp"
    };

    // Resolve process name from cache
    let process_name = if let Ok(cache) = ctx.process_name_cache.read() {
        if let Some(name) = cache.get(&pid) {
            name.clone()
        } else {
            drop(cache);
            let name = get_process_name_by_pid(pid).unwrap_or_default();
            if !name.is_empty() {
                if let Ok(mut write_cache) = ctx.process_name_cache.write() {
                    write_cache.insert(pid, name.clone());
                }
            }
            name
        }
    } else {
        get_process_name_by_pid(pid).unwrap_or_default()
    };

    // Get transfer size if available (for Send/Recv events)
    let size = tdh::get_u32_property(record, "size")
        .or_else(|| tdh::get_u32_property(record, "dsize")) // Attempt dsize as fallback
        .unwrap_or(0) as u64;

    let (bytes_sent, bytes_received) = match event_type_str {
        "send" => (size, 0),
        "recv" => (0, size),
        _ => (0, 0),
    };

    Some(TelemetryEvent::new(
        EventType::NetworkConnect,
        Severity::Info,
        EventPayload::Network(NetworkEvent {
            protocol: protocol.to_string(),
            local_ip: local_addr.unwrap_or_default(),
            local_port: local_port.unwrap_or(0),
            remote_ip: remote_addr.unwrap_or_default(),
            remote_port: remote_port.unwrap_or(0),
            direction: direction.to_string(),
            pid,
            process_name,
            bytes_sent,
            bytes_received,
            ..Default::default()
        }),
    ))
}

/// Parse IP address from binary format
fn parse_ip_address(data: &[u8]) -> Option<String> {
    if data.len() >= 4 {
        // IPv4
        Some(format!("{}.{}.{}.{}", data[0], data[1], data[2], data[3]))
    } else if data.len() >= 16 {
        // IPv6
        let segments: Vec<String> = (0..8)
            .map(|i| format!("{:x}", u16::from_be_bytes([data[i * 2], data[i * 2 + 1]])))
            .collect();
        Some(segments.join(":"))
    } else {
        None
    }
}

/// Parse kernel registry events
fn parse_registry_event(
    record: &EventRecord,
    event_id: u16,
    ctx: &EtwCallbackContext,
) -> Option<TelemetryEvent> {
    let header = &record.event_header;
    let pid = header.process_id;

    let operation = match event_id {
        event_ids::REG_CREATE_KEY => "create_key",
        event_ids::REG_DELETE_KEY => "delete_key",
        event_ids::REG_SET_VALUE => "set_value",
        event_ids::REG_DELETE_VALUE => "delete_value",
        _ => return None,
    };

    // Parse registry path and value from TDH
    let key_path = tdh::get_string_property(record, "KeyName")
        .or_else(|| tdh::get_string_property(record, "RelativeName"));
    let value_name = tdh::get_string_property(record, "ValueName");

    // Resolve process name from cache
    let process_name = if let Ok(cache) = ctx.process_name_cache.read() {
        if let Some(name) = cache.get(&pid) {
            name.clone()
        } else {
            drop(cache);
            let name = get_process_name_by_pid(pid).unwrap_or_default();
            if !name.is_empty() {
                if let Ok(mut write_cache) = ctx.process_name_cache.write() {
                    write_cache.insert(pid, name.clone());
                }
            }
            name
        }
    } else {
        get_process_name_by_pid(pid).unwrap_or_default()
    };

    Some(TelemetryEvent::new(
        match event_id {
            event_ids::REG_CREATE_KEY => EventType::RegistryCreate,
            event_ids::REG_DELETE_KEY | event_ids::REG_DELETE_VALUE => EventType::RegistryDelete,
            event_ids::REG_SET_VALUE => EventType::RegistrySetValue,
            _ => EventType::RegistrySetValue,
        },
        Severity::Info,
        EventPayload::Registry(RegistryEvent {
            process_name,
            pid,
            key_path: key_path.unwrap_or_default(),
            value_name: value_name,
            value_data: tdh::get_string_property(record, "DataValue"),
            operation: operation.to_string(),
        }),
    ))
}

/// Parse DNS client events
fn parse_dns_event(record: &EventRecord, _event_id: u16) -> Option<TelemetryEvent> {
    let header = &record.event_header;
    let pid = header.process_id;

    // Parse DNS query from TDH
    let query_name = tdh::get_string_property(record, "QueryName")
        .or_else(|| tdh::get_string_property(record, "QueryOptions"));
    let query_type = tdh::get_u32_property(record, "QueryType")
        .map(|t| dns_type_to_string(t as u16))
        .unwrap_or_else(|| "A".to_string());
    let query_results = tdh::get_string_property(record, "QueryResults");

    Some(TelemetryEvent::new(
        EventType::DnsQuery,
        Severity::Info,
        EventPayload::Dns(DnsEvent {
            pid,
            process_name: get_process_name_by_pid(pid).unwrap_or_default(),
            query: query_name.unwrap_or_default(),
            query_type,
            responses: query_results
                .map(|r| r.split(';').map(|s| s.to_string()).collect())
                .unwrap_or_default(),
        }),
    ))
}

/// Convert DNS type number to string
fn dns_type_to_string(qtype: u16) -> String {
    match qtype {
        1 => "A".to_string(),
        2 => "NS".to_string(),
        5 => "CNAME".to_string(),
        6 => "SOA".to_string(),
        12 => "PTR".to_string(),
        15 => "MX".to_string(),
        16 => "TXT".to_string(),
        28 => "AAAA".to_string(),
        33 => "SRV".to_string(),
        255 => "ANY".to_string(),
        _ => format!("TYPE{}", qtype),
    }
}

/// Parse PowerShell ETW events (script block logging)
fn parse_powershell_event(
    record: &EventRecord,
    event_id: u16,
    ctx: &EtwCallbackContext,
) -> Option<TelemetryEvent> {
    let header = &record.event_header;
    let pid = header.process_id;

    match event_id {
        powershell_event_ids::SCRIPT_BLOCK_LOGGING => {
            // Script block events can be fragmented across multiple events
            let script_block_text = tdh::get_string_property(record, "ScriptBlockText")?;
            let script_block_id = tdh::get_string_property(record, "ScriptBlockId")
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            let message_number = tdh::get_u32_property(record, "MessageNumber").unwrap_or(1);
            let message_total = tdh::get_u32_property(record, "MessageTotal").unwrap_or(1);
            let path = tdh::get_string_property(record, "Path");

            // Handle fragmented script blocks
            if message_total > 1 {
                let mut cache = ctx.script_block_cache.write().ok()?;

                let reassembler = cache.entry(script_block_id.clone()).or_insert_with(|| {
                    ScriptBlockReassembler::new(
                        script_block_id.clone(),
                        message_total,
                        path.clone(),
                    )
                });

                if reassembler.add_fragment(message_number, script_block_text) {
                    // All fragments received, emit complete event
                    let complete_script = reassembler.get_complete_script();
                    let script_path = reassembler.path.clone();
                    cache.remove(&script_block_id);

                    return create_powershell_event(pid, &complete_script, script_path);
                }
                return None;
            }

            // Single message script block
            create_powershell_event(pid, &script_block_text, path)
        }
        powershell_event_ids::ENGINE_STATE => {
            let engine_state = tdh::get_string_property(record, "NewEngineState");
            let host_name = tdh::get_string_property(record, "HostName");

            Some(TelemetryEvent::new(
                EventType::ScriptExecution,
                Severity::Info,
                EventPayload::Custom(serde_json::json!({
                    "event_type": "powershell_engine_state",
                    "process_id": pid,
                    "engine_state": engine_state,
                    "host_name": host_name,
                    "timestamp": chrono::Utc::now().timestamp_millis(),
                })),
            ))
        }
        powershell_event_ids::COMMAND_LIFECYCLE => {
            let command_name = tdh::get_string_property(record, "CommandName");
            let command_type = tdh::get_string_property(record, "CommandType");
            let user = tdh::get_string_property(record, "UserId");

            Some(TelemetryEvent::new(
                EventType::ScriptExecution,
                Severity::Info,
                EventPayload::Custom(serde_json::json!({
                    "event_type": "powershell_command",
                    "process_id": pid,
                    "command_name": command_name,
                    "command_type": command_type,
                    "user": user,
                    "timestamp": chrono::Utc::now().timestamp_millis(),
                })),
            ))
        }
        _ => None,
    }
}

/// Create PowerShell script block event with threat detection
fn create_powershell_event(
    pid: u32,
    script_content: &str,
    path: Option<String>,
) -> Option<TelemetryEvent> {
    // Detect suspicious patterns
    let (severity, detections) = analyze_powershell_script(script_content);
    let suspicious_patterns: Vec<String> = detections.iter().map(|d| d.rule_name.clone()).collect();

    let process_name = get_process_name_by_pid(pid).unwrap_or_else(|| "powershell.exe".to_string());
    let process_path = get_process_path_by_pid(pid).unwrap_or_default();

    // Calculate risk score before moving severity
    let risk_score = severity_to_risk_score(&severity);

    let mut event = TelemetryEvent::new(
        EventType::ScriptBlock,
        severity,
        EventPayload::Script(ScriptEvent {
            pid,
            ppid: 0,
            process_name,
            process_path,
            script_type: ScriptType::PowerShell,
            cmdline: String::new(),
            content: Some(if script_content.len() > 10000 {
                format!("{}...[truncated]", &script_content[..10000])
            } else {
                script_content.to_string()
            }),
            deobfuscated_content: None,
            script_path: path,
            user: String::new(),
            is_elevated: false,
            obfuscation_techniques: Vec::new(),
            suspicious_patterns,
            attack_tools: Vec::new(),
            risk_score,
        }),
    );

    for detection in detections {
        event.add_detection(detection);
    }

    Some(event)
}

/// Convert severity to risk score
fn severity_to_risk_score(severity: &Severity) -> f32 {
    match severity {
        Severity::Critical => 1.0,
        Severity::High => 0.8,
        Severity::Medium => 0.5,
        Severity::Low => 0.3,
        Severity::Info => 0.1,
    }
}

/// Analyze PowerShell script for suspicious patterns
fn analyze_powershell_script(content: &str) -> (Severity, Vec<Detection>) {
    let content_lower = content.to_lowercase();
    let mut detections = Vec::new();
    let mut max_severity = Severity::Info;

    // High severity patterns
    let high_severity_patterns = [
        ("downloadstring", "T1105", "Download and execute code"),
        ("downloadfile", "T1105", "Download file"),
        ("invoke-expression", "T1059.001", "Dynamic code execution"),
        ("iex", "T1059.001", "Dynamic code execution (alias)"),
        ("invoke-mimikatz", "T1003", "Credential dumping tool"),
        ("invoke-kerberoast", "T1558.003", "Kerberoasting attack"),
        ("invoke-dcsync", "T1003.006", "DCSync attack"),
        ("invoke-wmiexec", "T1047", "WMI execution"),
        ("invoke-psremoting", "T1021.006", "PowerShell remoting"),
        ("set-mppreference", "T1562.001", "Disable security tools"),
        (
            "add-mppreference -exclusion",
            "T1562.001",
            "Add AV exclusion",
        ),
        ("virtualalloc", "T1055", "Memory allocation (injection)"),
        ("createthread", "T1055", "Thread creation (injection)"),
        (
            "[system.reflection.assembly]::load",
            "T1620",
            "Reflective loading",
        ),
        ("frombase64string", "T1140", "Base64 decoding"),
        (
            "new-object system.net.webclient",
            "T1071",
            "Web client creation",
        ),
        ("hidden", "T1564.003", "Hidden window"),
        ("-nop", "T1059.001", "No profile execution"),
        ("-bypass", "T1059.001", "Execution policy bypass"),
        ("amsiutils", "T1562.001", "AMSI bypass attempt"),
        ("amsiscanbuffer", "T1562.001", "AMSI bypass attempt"),
    ];

    // Medium severity patterns
    let medium_severity_patterns = [
        ("system.net.sockets", "T1095", "Network socket usage"),
        ("invoke-command", "T1059.001", "Remote command execution"),
        ("enter-pssession", "T1021.006", "Remote session"),
        ("new-pssession", "T1021.006", "Remote session creation"),
        ("get-credential", "T1056.002", "Credential prompt"),
        ("convertto-securestring", "T1140", "Secure string creation"),
        ("export-clixml", "T1003", "Credential export"),
        ("winrm", "T1021.006", "Windows Remote Management"),
        ("test-connection", "T1018", "Network discovery"),
        ("get-adcomputer", "T1018", "AD computer enumeration"),
        ("get-aduser", "T1087.002", "AD user enumeration"),
        ("get-adgroup", "T1069.002", "AD group enumeration"),
        ("get-process", "T1057", "Process discovery"),
        ("get-service", "T1007", "Service discovery"),
        ("netstat", "T1049", "Network connection discovery"),
        ("reg query", "T1012", "Registry query"),
        ("schtasks", "T1053.005", "Scheduled task"),
        ("wmic", "T1047", "WMI execution"),
    ];

    for (pattern, technique, description) in high_severity_patterns.iter() {
        if content_lower.contains(pattern) {
            max_severity = Severity::High;
            detections.push(Detection {
                detection_type: DetectionType::ScriptThreat,
                rule_name: format!(
                    "POWERSHELL_SUSPICIOUS_{}",
                    pattern.to_uppercase().replace("-", "_")
                ),
                confidence: 0.85,
                description: description.to_string(),
                mitre_tactics: vec!["Execution".to_string()],
                mitre_techniques: vec![technique.to_string()],
            });
        }
    }

    for (pattern, technique, description) in medium_severity_patterns.iter() {
        if content_lower.contains(pattern) && max_severity != Severity::High {
            max_severity = Severity::Medium;
            detections.push(Detection {
                detection_type: DetectionType::Behavioral,
                rule_name: format!("POWERSHELL_{}", pattern.to_uppercase().replace("-", "_")),
                confidence: 0.65,
                description: description.to_string(),
                mitre_tactics: vec!["Discovery".to_string()],
                mitre_techniques: vec![technique.to_string()],
            });
        }
    }

    // Check for encoded command
    if content_lower.contains("-encodedcommand") || content_lower.contains("-enc ") {
        if max_severity != Severity::High {
            max_severity = Severity::Medium;
        }
        detections.push(Detection {
            detection_type: DetectionType::ScriptThreat,
            rule_name: "POWERSHELL_ENCODED_COMMAND".to_string(),
            confidence: 0.7,
            description: "Encoded PowerShell command detected".to_string(),
            mitre_tactics: vec!["Defense Evasion".to_string()],
            mitre_techniques: vec!["T1027".to_string()],
        });
    }

    // Check for high entropy (possible obfuscation)
    let entropy = calculate_entropy(content);
    if entropy > 5.5 {
        if max_severity == Severity::Info {
            max_severity = Severity::Low;
        }
        detections.push(Detection {
            detection_type: DetectionType::Entropy,
            rule_name: "POWERSHELL_HIGH_ENTROPY".to_string(),
            confidence: 0.5,
            description: format!(
                "High entropy detected ({:.2}), possible obfuscation",
                entropy
            ),
            mitre_tactics: vec!["Defense Evasion".to_string()],
            mitre_techniques: vec!["T1027".to_string()],
        });
    }

    (max_severity, detections)
}

/// Calculate Shannon entropy of a string
fn calculate_entropy(data: &str) -> f64 {
    let mut freq = [0u32; 256];
    let len = data.len() as f64;

    for byte in data.bytes() {
        freq[byte as usize] += 1;
    }

    freq.iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Parse AMSI ETW events
fn parse_amsi_etw_event(record: &EventRecord, event_id: u16) -> Option<TelemetryEvent> {
    let header = &record.event_header;
    let pid = header.process_id;

    if event_id == event_ids::AMSI_SCAN {
        let app_name = tdh::get_string_property(record, "appname");
        let content_name = tdh::get_string_property(record, "contentname");
        let content_size = tdh::get_u32_property(record, "contentsize");
        let scan_result = tdh::get_u32_property(record, "scanresult");
        let content = tdh::get_binary_property(record, "content");

        let is_malicious = scan_result.map(|r| r >= 0x4000).unwrap_or(false);
        let result_str = match scan_result.unwrap_or(0) {
            0 => "clean",
            1 => "not_detected",
            r if r >= 0x4000 && r <= 0x4fff => "blocked_by_admin",
            r if r >= 0x4000 && r < 32768 => "suspicious",
            32768 => "malware",
            _ => "unknown",
        };

        let mut event = TelemetryEvent::new(
            EventType::ScriptExecution,
            if is_malicious {
                Severity::Critical
            } else {
                Severity::Info
            },
            EventPayload::Custom(serde_json::json!({
                "event_type": "amsi_scan",
                "process_id": pid,
                "app_name": app_name,
                "content_name": content_name,
                "content_size": content_size,
                "scan_result": result_str,
                "is_malicious": is_malicious,
                "timestamp": chrono::Utc::now().timestamp_millis(),
            })),
        );

        if is_malicious {
            event.add_detection(Detection {
                detection_type: DetectionType::Malware,
                rule_name: "AMSI_MALWARE_DETECTED".to_string(),
                confidence: 0.95,
                description: format!(
                    "AMSI detected malicious content: {}",
                    content_name.unwrap_or_default()
                ),
                mitre_tactics: vec!["Execution".to_string()],
                mitre_techniques: vec!["T1059".to_string()],
            });
        }

        Some(event)
    } else {
        None
    }
}

/// Parse Windows Security Auditing events
fn parse_security_auditing_event(record: &EventRecord, event_id: u16) -> Option<TelemetryEvent> {
    let header = &record.event_header;

    match event_id {
        security_event_ids::LOGON_SUCCESS => {
            let logon_type = tdh::get_u32_property(record, "LogonType");
            let target_user = tdh::get_string_property(record, "TargetUserName");
            let target_domain = tdh::get_string_property(record, "TargetDomainName");
            let source_ip = tdh::get_string_property(record, "IpAddress");
            let logon_process = tdh::get_string_property(record, "LogonProcessName");

            let logon_type_str = match logon_type.unwrap_or(0) {
                2 => "Interactive",
                3 => "Network",
                4 => "Batch",
                5 => "Service",
                7 => "Unlock",
                8 => "NetworkCleartext",
                9 => "NewCredentials",
                10 => "RemoteInteractive",
                11 => "CachedInteractive",
                _ => "Unknown",
            };

            // Detect pass-the-hash (logon type 9 with NTLM)
            let is_pth = logon_type == Some(9)
                && logon_process
                    .as_ref()
                    .map(|p| p.to_lowercase().contains("ntlm"))
                    .unwrap_or(false);

            let severity = if is_pth {
                Severity::Critical
            } else {
                Severity::Info
            };

            let mut event = TelemetryEvent::new(
                EventType::AuthLogin,
                severity,
                EventPayload::Custom(serde_json::json!({
                    "event_type": "logon_success",
                    "event_id": 4624,
                    "logon_type": logon_type_str,
                    "target_user": target_user,
                    "target_domain": target_domain,
                    "source_ip": source_ip,
                    "logon_process": logon_process,
                    "timestamp": chrono::Utc::now().timestamp_millis(),
                })),
            );

            if is_pth {
                event.add_detection(Detection {
                    detection_type: DetectionType::CredentialTheft,
                    rule_name: "PASS_THE_HASH_DETECTED".to_string(),
                    confidence: 0.85,
                    description: "Potential pass-the-hash attack detected (NTLM logon type 9)"
                        .to_string(),
                    mitre_tactics: vec![
                        "Credential Access".to_string(),
                        "Lateral Movement".to_string(),
                    ],
                    mitre_techniques: vec!["T1550.002".to_string()],
                });
            }

            Some(event)
        }
        security_event_ids::LOGON_FAILURE => {
            let target_user = tdh::get_string_property(record, "TargetUserName");
            let failure_reason = tdh::get_string_property(record, "FailureReason");
            let source_ip = tdh::get_string_property(record, "IpAddress");

            Some(TelemetryEvent::new(
                EventType::AuthFailed,
                Severity::Low,
                EventPayload::Custom(serde_json::json!({
                    "event_type": "logon_failure",
                    "event_id": 4625,
                    "target_user": target_user,
                    "failure_reason": failure_reason,
                    "source_ip": source_ip,
                    "timestamp": chrono::Utc::now().timestamp_millis(),
                })),
            ))
        }
        security_event_ids::PROCESS_CREATED => {
            let new_process_name = tdh::get_string_property(record, "NewProcessName");
            let command_line = tdh::get_string_property(record, "CommandLine");
            let parent_process = tdh::get_string_property(record, "ParentProcessName");
            let token_elevation = tdh::get_string_property(record, "TokenElevationType");

            Some(TelemetryEvent::new(
                EventType::ProcessCreate,
                Severity::Info,
                EventPayload::Custom(serde_json::json!({
                    "event_type": "security_audit_process_create",
                    "event_id": 4688,
                    "process_name": new_process_name,
                    "command_line": command_line,
                    "parent_process": parent_process,
                    "token_elevation": token_elevation,
                    "timestamp": chrono::Utc::now().timestamp_millis(),
                })),
            ))
        }
        security_event_ids::KERBEROASTING => {
            // TGS request - check for suspicious service ticket requests
            let target_user = tdh::get_string_property(record, "TargetUserName");
            let service_name = tdh::get_string_property(record, "ServiceName");
            let encryption_type = tdh::get_u32_property(record, "TicketEncryptionType");

            // RC4 encryption (0x17 = 23) is often used in Kerberoasting
            let is_suspicious = encryption_type == Some(23);

            let mut event = TelemetryEvent::new(
                EventType::CredentialAccess,
                if is_suspicious {
                    Severity::High
                } else {
                    Severity::Info
                },
                EventPayload::Custom(serde_json::json!({
                    "event_type": "kerberos_tgs_request",
                    "event_id": 4769,
                    "target_user": target_user,
                    "service_name": service_name,
                    "encryption_type": encryption_type,
                    "timestamp": chrono::Utc::now().timestamp_millis(),
                })),
            );

            if is_suspicious {
                event.add_detection(Detection {
                    detection_type: DetectionType::CredentialTheft,
                    rule_name: "KERBEROASTING_DETECTED".to_string(),
                    confidence: 0.75,
                    description: "Potential Kerberoasting attack (RC4 TGS request)".to_string(),
                    mitre_tactics: vec!["Credential Access".to_string()],
                    mitre_techniques: vec!["T1558.003".to_string()],
                });
            }

            Some(event)
        }
        security_event_ids::DCSYNC => {
            // DS-Replication-Get-Changes - DCSync detection
            let subject_user = tdh::get_string_property(record, "SubjectUserName");
            let object_name = tdh::get_string_property(record, "ObjectName");
            let access_mask = tdh::get_string_property(record, "AccessMask");

            // Check for replication rights
            let is_dcsync = access_mask
                .as_ref()
                .map(|m| m.contains("0x100") || m.contains("DS-Replication-Get-Changes"))
                .unwrap_or(false);

            let mut event = TelemetryEvent::new(
                EventType::CredentialAccess,
                if is_dcsync {
                    Severity::Critical
                } else {
                    Severity::Medium
                },
                EventPayload::Custom(serde_json::json!({
                    "event_type": "directory_service_access",
                    "event_id": 4662,
                    "subject_user": subject_user,
                    "object_name": object_name,
                    "access_mask": access_mask,
                    "timestamp": chrono::Utc::now().timestamp_millis(),
                })),
            );

            if is_dcsync {
                event.add_detection(Detection {
                    detection_type: DetectionType::CredentialTheft,
                    rule_name: "DCSYNC_DETECTED".to_string(),
                    confidence: 0.9,
                    description: "DCSync attack detected (DS-Replication-Get-Changes)".to_string(),
                    mitre_tactics: vec!["Credential Access".to_string()],
                    mitre_techniques: vec!["T1003.006".to_string()],
                });
            }

            Some(event)
        }
        security_event_ids::SENSITIVE_PRIVILEGE => {
            let subject_user = tdh::get_string_property(record, "SubjectUserName");
            let privileges = tdh::get_string_property(record, "PrivilegeList");

            let has_debug = privileges
                .as_ref()
                .map(|p| p.contains("SeDebugPrivilege"))
                .unwrap_or(false);

            Some(TelemetryEvent::new(
                EventType::CredentialAccess,
                if has_debug {
                    Severity::High
                } else {
                    Severity::Medium
                },
                EventPayload::Custom(serde_json::json!({
                    "event_type": "sensitive_privilege_use",
                    "event_id": 4672,
                    "subject_user": subject_user,
                    "privileges": privileges,
                    "timestamp": chrono::Utc::now().timestamp_millis(),
                })),
            ))
        }
        _ => None,
    }
}

/// Parse Sysmon events (if Sysmon is installed)
fn parse_sysmon_event(record: &EventRecord, event_id: u16) -> Option<TelemetryEvent> {
    let header = &record.event_header;

    // Sysmon provides richer data than kernel ETW
    match event_id {
        event_ids::SYSMON_PROCESS_CREATE => {
            let image = tdh::get_string_property(record, "Image");
            let command_line = tdh::get_string_property(record, "CommandLine");
            let parent_image = tdh::get_string_property(record, "ParentImage");
            let parent_command_line = tdh::get_string_property(record, "ParentCommandLine");
            let user = tdh::get_string_property(record, "User");
            let integrity_level = tdh::get_string_property(record, "IntegrityLevel");
            let hashes = tdh::get_string_property(record, "Hashes");
            let process_guid = tdh::get_string_property(record, "ProcessGuid");
            let process_id = tdh::get_u32_property(record, "ProcessId");
            let parent_process_id = tdh::get_u32_property(record, "ParentProcessId");

            Some(TelemetryEvent::new(
                EventType::ProcessCreate,
                Severity::Info,
                EventPayload::Custom(serde_json::json!({
                    "source": "sysmon",
                    "event_id": 1,
                    "event_type": "ProcessCreate",
                    "process_id": process_id.unwrap_or(header.process_id),
                    "parent_process_id": parent_process_id,
                    "image": image,
                    "command_line": command_line,
                    "parent_image": parent_image,
                    "parent_command_line": parent_command_line,
                    "user": user,
                    "integrity_level": integrity_level,
                    "hashes": hashes,
                    "process_guid": process_guid,
                    "timestamp": chrono::Utc::now().timestamp_millis(),
                })),
            ))
        }
        event_ids::SYSMON_NETWORK_CONNECT => {
            let image = tdh::get_string_property(record, "Image");
            let user = tdh::get_string_property(record, "User");
            let protocol = tdh::get_string_property(record, "Protocol");
            let source_ip = tdh::get_string_property(record, "SourceIp");
            let source_port = tdh::get_u32_property(record, "SourcePort");
            let dest_ip = tdh::get_string_property(record, "DestinationIp");
            let dest_port = tdh::get_u32_property(record, "DestinationPort");
            let dest_hostname = tdh::get_string_property(record, "DestinationHostname");

            Some(TelemetryEvent::new(
                EventType::NetworkConnect,
                Severity::Info,
                EventPayload::Custom(serde_json::json!({
                    "source": "sysmon",
                    "event_id": 3,
                    "event_type": "NetworkConnect",
                    "process_id": header.process_id,
                    "image": image,
                    "user": user,
                    "protocol": protocol,
                    "source_ip": source_ip,
                    "source_port": source_port,
                    "destination_ip": dest_ip,
                    "destination_port": dest_port,
                    "destination_hostname": dest_hostname,
                    "timestamp": chrono::Utc::now().timestamp_millis(),
                })),
            ))
        }
        event_ids::SYSMON_CREATE_REMOTE_THREAD => {
            let source_image = tdh::get_string_property(record, "SourceImage");
            let target_image = tdh::get_string_property(record, "TargetImage");
            let source_process_id = tdh::get_u32_property(record, "SourceProcessId");
            let target_process_id = tdh::get_u32_property(record, "TargetProcessId");
            let start_address = tdh::get_string_property(record, "StartAddress");
            let start_module = tdh::get_string_property(record, "StartModule");
            let start_function = tdh::get_string_property(record, "StartFunction");

            let mut event = TelemetryEvent::new(
                EventType::ProcessInject,
                Severity::High,
                EventPayload::Custom(serde_json::json!({
                    "source": "sysmon",
                    "event_id": 8,
                    "event_type": "CreateRemoteThread",
                    "source_image": source_image,
                    "target_image": target_image,
                    "source_process_id": source_process_id,
                    "target_process_id": target_process_id,
                    "start_address": start_address,
                    "start_module": start_module,
                    "start_function": start_function,
                    "timestamp": chrono::Utc::now().timestamp_millis(),
                })),
            );

            event.add_detection(Detection {
                detection_type: DetectionType::ProcessHollowing,
                rule_name: "SYSMON_REMOTE_THREAD".to_string(),
                confidence: 0.8,
                description: format!(
                    "Remote thread creation: {} -> {}",
                    source_image.unwrap_or_default(),
                    target_image.unwrap_or_default()
                ),
                mitre_tactics: vec![
                    "Defense Evasion".to_string(),
                    "Privilege Escalation".to_string(),
                ],
                mitre_techniques: vec!["T1055".to_string()],
            });

            Some(event)
        }
        event_ids::SYSMON_PROCESS_ACCESS => {
            let source_image = tdh::get_string_property(record, "SourceImage");
            let target_image = tdh::get_string_property(record, "TargetImage");
            let granted_access = tdh::get_string_property(record, "GrantedAccess");
            let call_trace = tdh::get_string_property(record, "CallTrace");

            // Check for LSASS access
            let target_lower = target_image
                .as_ref()
                .map(|t| t.to_lowercase())
                .unwrap_or_default();
            let is_lsass_access = target_lower.contains("lsass.exe");

            let severity = if is_lsass_access {
                Severity::Critical
            } else {
                Severity::Medium
            };

            let mut event = TelemetryEvent::new(
                EventType::CredentialAccess,
                severity,
                EventPayload::Custom(serde_json::json!({
                    "source": "sysmon",
                    "event_id": 10,
                    "event_type": "ProcessAccess",
                    "source_image": source_image,
                    "target_image": target_image,
                    "granted_access": granted_access,
                    "call_trace": call_trace,
                    "timestamp": chrono::Utc::now().timestamp_millis(),
                })),
            );

            if is_lsass_access {
                event.add_detection(Detection {
                    detection_type: DetectionType::CredentialTheft,
                    rule_name: "LSASS_ACCESS_DETECTED".to_string(),
                    confidence: 0.9,
                    description: format!(
                        "LSASS memory access from: {}",
                        source_image.unwrap_or_default()
                    ),
                    mitre_tactics: vec!["Credential Access".to_string()],
                    mitre_techniques: vec!["T1003.001".to_string()],
                });
            }

            Some(event)
        }
        event_ids::SYSMON_DNS_QUERY => {
            let image = tdh::get_string_property(record, "Image");
            let query_name = tdh::get_string_property(record, "QueryName");
            let query_status = tdh::get_string_property(record, "QueryStatus");
            let query_results = tdh::get_string_property(record, "QueryResults");

            Some(TelemetryEvent::new(
                EventType::DnsQuery,
                Severity::Info,
                EventPayload::Custom(serde_json::json!({
                    "source": "sysmon",
                    "event_id": 22,
                    "event_type": "DNSQuery",
                    "process_id": header.process_id,
                    "image": image,
                    "query_name": query_name,
                    "query_status": query_status,
                    "query_results": query_results,
                    "timestamp": chrono::Utc::now().timestamp_millis(),
                })),
            ))
        }
        event_ids::SYSMON_PROCESS_TAMPERING => {
            let image = tdh::get_string_property(record, "Image");
            let tampering_type = tdh::get_string_property(record, "Type");

            let mut event = TelemetryEvent::new(
                EventType::ProcessHollowing,
                Severity::Critical,
                EventPayload::Custom(serde_json::json!({
                    "source": "sysmon",
                    "event_id": 25,
                    "event_type": "ProcessTampering",
                    "process_id": header.process_id,
                    "image": image,
                    "tampering_type": tampering_type,
                    "timestamp": chrono::Utc::now().timestamp_millis(),
                })),
            );

            event.add_detection(Detection {
                detection_type: DetectionType::ProcessHollowing,
                rule_name: "PROCESS_TAMPERING_DETECTED".to_string(),
                confidence: 0.95,
                description: format!(
                    "Process tampering detected: {} ({})",
                    image.unwrap_or_default(),
                    tampering_type.unwrap_or_default()
                ),
                mitre_tactics: vec!["Defense Evasion".to_string()],
                mitre_techniques: vec!["T1055.012".to_string()],
            });

            Some(event)
        }
        event_ids::SYSMON_WMI_FILTER
        | event_ids::SYSMON_WMI_CONSUMER
        | event_ids::SYSMON_WMI_BINDING => {
            let event_type_str = match event_id {
                event_ids::SYSMON_WMI_FILTER => "WMIFilter",
                event_ids::SYSMON_WMI_CONSUMER => "WMIConsumer",
                event_ids::SYSMON_WMI_BINDING => "WMIBinding",
                _ => "WMI",
            };

            let operation = tdh::get_string_property(record, "Operation");
            let user = tdh::get_string_property(record, "User");
            let name = tdh::get_string_property(record, "Name");
            let destination = tdh::get_string_property(record, "Destination");

            let mut event = TelemetryEvent::new(
                EventType::WmiActivity,
                Severity::High,
                EventPayload::Custom(serde_json::json!({
                    "source": "sysmon",
                    "event_id": event_id,
                    "event_type": event_type_str,
                    "operation": operation,
                    "user": user,
                    "name": name,
                    "destination": destination,
                    "timestamp": chrono::Utc::now().timestamp_millis(),
                })),
            );

            event.add_detection(Detection {
                detection_type: DetectionType::WmiPersistence,
                rule_name: format!("SYSMON_{}", event_type_str.to_uppercase()),
                confidence: 0.8,
                description: format!(
                    "WMI {} detected: {} - {}",
                    event_type_str,
                    operation.unwrap_or_default(),
                    name.unwrap_or_default()
                ),
                mitre_tactics: vec!["Persistence".to_string()],
                mitre_techniques: vec!["T1546.003".to_string()],
            });

            Some(event)
        }
        event_ids::SYSMON_PIPE_CREATED | event_ids::SYSMON_PIPE_CONNECTED => {
            let pipe_name = tdh::get_string_property(record, "PipeName");
            let image = tdh::get_string_property(record, "Image");

            Some(TelemetryEvent::new(
                if event_id == event_ids::SYSMON_PIPE_CREATED {
                    EventType::NamedPipeCreate
                } else {
                    EventType::NamedPipeConnect
                },
                Severity::Info,
                EventPayload::Custom(serde_json::json!({
                    "source": "sysmon",
                    "event_id": event_id,
                    "event_type": if event_id == 17 { "PipeCreated" } else { "PipeConnected" },
                    "process_id": header.process_id,
                    "pipe_name": pipe_name,
                    "image": image,
                    "timestamp": chrono::Utc::now().timestamp_millis(),
                })),
            ))
        }
        event_ids::SYSMON_DRIVER_LOAD => {
            let image_loaded = tdh::get_string_property(record, "ImageLoaded");
            let hashes = tdh::get_string_property(record, "Hashes");
            let signed = tdh::get_string_property(record, "Signed");
            let signature = tdh::get_string_property(record, "Signature");

            let is_unsigned = signed
                .as_ref()
                .map(|s| s.to_lowercase() != "true")
                .unwrap_or(true);

            let mut event = TelemetryEvent::new(
                EventType::DriverLoad,
                if is_unsigned {
                    Severity::High
                } else {
                    Severity::Info
                },
                EventPayload::Custom(serde_json::json!({
                    "source": "sysmon",
                    "event_id": 6,
                    "event_type": "DriverLoaded",
                    "image_loaded": image_loaded,
                    "hashes": hashes,
                    "signed": signed,
                    "signature": signature,
                    "timestamp": chrono::Utc::now().timestamp_millis(),
                })),
            );

            if is_unsigned {
                event.add_detection(Detection {
                    detection_type: DetectionType::DriverThreat,
                    rule_name: "UNSIGNED_DRIVER_LOADED".to_string(),
                    confidence: 0.7,
                    description: format!(
                        "Unsigned driver loaded: {}",
                        image_loaded.unwrap_or_default()
                    ),
                    mitre_tactics: vec![
                        "Persistence".to_string(),
                        "Privilege Escalation".to_string(),
                    ],
                    mitre_techniques: vec!["T1543.003".to_string()],
                });
            }

            Some(event)
        }
        _ => None,
    }
}

/// Parse Threat Intelligence provider events
fn parse_threat_intelligence_event(record: &EventRecord, _event_id: u16) -> Option<TelemetryEvent> {
    let header = &record.event_header;

    // Microsoft Threat Intelligence provider gives deep visibility into
    // suspicious API calls, allocations, etc.
    let calling_process_id = tdh::get_u32_property(record, "CallingProcessId");
    let target_process_id = tdh::get_u32_property(record, "TargetProcessId");
    let operation = tdh::get_string_property(record, "OperationType");

    Some(TelemetryEvent::new(
        EventType::ProcessInject,
        Severity::High,
        EventPayload::Custom(serde_json::json!({
            "source": "threat_intelligence",
            "event_type": "suspicious_api_call",
            "calling_process_id": calling_process_id,
            "target_process_id": target_process_id,
            "operation": operation,
            "timestamp": chrono::Utc::now().timestamp_millis(),
        })),
    ))
}

/// Parse WMI Activity events
fn parse_wmi_activity_event(record: &EventRecord, event_id: u16) -> Option<TelemetryEvent> {
    let header = &record.event_header;

    let operation = tdh::get_string_property(record, "Operation");
    let user = tdh::get_string_property(record, "User");
    let namespace = tdh::get_string_property(record, "Namespace");
    let query = tdh::get_string_property(record, "Query");
    let client_machine = tdh::get_string_property(record, "ClientMachine");

    Some(TelemetryEvent::new(
        EventType::WmiActivity,
        Severity::Medium,
        EventPayload::Custom(serde_json::json!({
            "source": "wmi_activity",
            "event_id": event_id,
            "event_type": "wmi_operation",
            "process_id": header.process_id,
            "operation": operation,
            "user": user,
            "namespace": namespace,
            "query": query,
            "client_machine": client_machine,
            "timestamp": chrono::Utc::now().timestamp_millis(),
        })),
    ))
}

/// Parse Task Scheduler events
fn parse_task_scheduler_event(record: &EventRecord, event_id: u16) -> Option<TelemetryEvent> {
    let task_name = tdh::get_string_property(record, "TaskName");
    let user_name = tdh::get_string_property(record, "UserName");
    let action_name = tdh::get_string_property(record, "ActionName");

    let event_type_str = match event_id {
        100 => "TaskStarted",
        101 => "TaskStartFailed",
        102 => "TaskCompleted",
        106 => "TaskRegistered",
        140 => "TaskUpdated",
        141 => "TaskDeleted",
        _ => "TaskEvent",
    };

    let severity = match event_id {
        106 | 140 => Severity::Medium, // Registration and updates
        _ => Severity::Info,
    };

    Some(TelemetryEvent::new(
        EventType::ScheduledTask,
        severity,
        EventPayload::Custom(serde_json::json!({
            "source": "task_scheduler",
            "event_id": event_id,
            "event_type": event_type_str,
            "task_name": task_name,
            "user_name": user_name,
            "action_name": action_name,
            "timestamp": chrono::Utc::now().timestamp_millis(),
        })),
    ))
}

/// Parse Code Integrity events (unsigned/tampered driver loads)
/// MITRE: T1014 (Rootkit), T1553 (Subvert Trust Controls)
fn parse_code_integrity_event(record: &EventRecord, event_id: u16) -> Option<TelemetryEvent> {
    let header = &record.event_header;

    match event_id {
        event_ids::CI_DRIVER_LOAD_BLOCKED | event_ids::CI_UNSIGNED_DRIVER => {
            // A driver failed code integrity checks or is unsigned
            let file_name = tdh::get_string_property(record, "FileName")
                .or_else(|| tdh::get_string_property(record, "FileObject"))
                .or_else(|| tdh::get_string_property(record, "File Name"));
            let process_name = tdh::get_string_property(record, "ProcessName")
                .or_else(|| get_process_name_by_pid(header.process_id));
            let sha1_hash = tdh::get_string_property(record, "SHA1FlatHash")
                .or_else(|| tdh::get_string_property(record, "SHA1Hash"));
            let issuer_name = tdh::get_string_property(record, "IssuerName")
                .or_else(|| tdh::get_string_property(record, "PublisherName"));
            let status = tdh::get_u32_property(record, "Status");

            let event_type_str = if event_id == event_ids::CI_DRIVER_LOAD_BLOCKED {
                "driver_load_blocked"
            } else {
                "unsigned_driver_detected"
            };

            let mut event = TelemetryEvent::new(
                EventType::DriverLoad,
                Severity::High,
                EventPayload::Custom(serde_json::json!({
                    "source": "code_integrity",
                    "event_id": event_id,
                    "event_type": event_type_str,
                    "file_name": file_name,
                    "process_id": header.process_id,
                    "process_name": process_name,
                    "sha1_hash": sha1_hash,
                    "issuer_name": issuer_name,
                    "status": status,
                    "timestamp": chrono::Utc::now().timestamp_millis(),
                })),
            );

            event.add_detection(Detection {
                detection_type: DetectionType::DriverThreat,
                rule_name: format!("CI_{}", event_type_str.to_uppercase()),
                confidence: 0.85,
                description: format!(
                    "Code Integrity {}: {}",
                    event_type_str.replace('_', " "),
                    file_name.unwrap_or_default()
                ),
                mitre_tactics: vec!["Persistence".to_string(), "Defense Evasion".to_string()],
                mitre_techniques: vec!["T1014".to_string(), "T1553".to_string()],
            });

            Some(event)
        }
        event_ids::CI_IMAGE_VERIFICATION_FAILED | event_ids::CI_POLICY_VIOLATION => {
            // Image hash verification failed or WDAC/CI policy violation
            let file_name = tdh::get_string_property(record, "FileName")
                .or_else(|| tdh::get_string_property(record, "File Name"));
            let process_name = get_process_name_by_pid(header.process_id);
            let requested_signing_level = tdh::get_u32_property(record, "RequestedSigningLevel");
            let validated_signing_level = tdh::get_u32_property(record, "ValidatedSigningLevel");

            let event_type_str = if event_id == event_ids::CI_IMAGE_VERIFICATION_FAILED {
                "image_verification_failed"
            } else {
                "ci_policy_violation"
            };

            let mut event = TelemetryEvent::new(
                EventType::DriverLoad,
                Severity::High,
                EventPayload::Custom(serde_json::json!({
                    "source": "code_integrity",
                    "event_id": event_id,
                    "event_type": event_type_str,
                    "file_name": file_name,
                    "process_id": header.process_id,
                    "process_name": process_name,
                    "requested_signing_level": requested_signing_level,
                    "validated_signing_level": validated_signing_level,
                    "timestamp": chrono::Utc::now().timestamp_millis(),
                })),
            );

            event.add_detection(Detection {
                detection_type: DetectionType::DriverThreat,
                rule_name: format!("CI_{}", event_type_str.to_uppercase()),
                confidence: 0.80,
                description: format!(
                    "Code Integrity {}: {}",
                    event_type_str.replace('_', " "),
                    file_name.unwrap_or_default()
                ),
                mitre_tactics: vec!["Defense Evasion".to_string()],
                mitre_techniques: vec!["T1553".to_string()],
            });

            Some(event)
        }
        event_ids::CI_CODE_INTEGRITY_CHECK_FAILED => {
            let file_name = tdh::get_string_property(record, "FileName")
                .or_else(|| tdh::get_string_property(record, "File Name"));
            let process_name = get_process_name_by_pid(header.process_id);

            Some(TelemetryEvent::new(
                EventType::DriverLoad,
                Severity::Medium,
                EventPayload::Custom(serde_json::json!({
                    "source": "code_integrity",
                    "event_id": event_id,
                    "event_type": "code_integrity_check_failed",
                    "file_name": file_name,
                    "process_id": header.process_id,
                    "process_name": process_name,
                    "timestamp": chrono::Utc::now().timestamp_millis(),
                })),
            ))
        }
        _ => None,
    }
}

/// Parse LDAP Client events (reconnaissance and credential access)
/// MITRE: T1087 (Account Discovery), T1018 (Remote System Discovery)
fn parse_ldap_client_event(record: &EventRecord, event_id: u16) -> Option<TelemetryEvent> {
    let header = &record.event_header;
    let pid = header.process_id;

    match event_id {
        event_ids::LDAP_SEARCH_REQUEST => {
            let search_filter = tdh::get_string_property(record, "SearchFilter")
                .or_else(|| tdh::get_string_property(record, "Filter"));
            let search_base = tdh::get_string_property(record, "DistinguishedName")
                .or_else(|| tdh::get_string_property(record, "SearchBase"))
                .or_else(|| tdh::get_string_property(record, "BaseDN"));
            let search_scope = tdh::get_u32_property(record, "SearchScope");
            let server_name = tdh::get_string_property(record, "ServerName")
                .or_else(|| tdh::get_string_property(record, "HostName"));
            let process_name = get_process_name_by_pid(pid);

            // Detect suspicious LDAP queries (recon patterns)
            let filter_lower = search_filter
                .as_ref()
                .map(|f| f.to_lowercase())
                .unwrap_or_default();

            let is_suspicious = is_suspicious_ldap_query(&filter_lower);
            let severity = if is_suspicious {
                Severity::Medium
            } else {
                Severity::Info
            };

            let mut event = TelemetryEvent::new(
                EventType::AdObjectChange,
                severity,
                EventPayload::Custom(serde_json::json!({
                    "source": "ldap_client",
                    "event_id": event_id,
                    "event_type": "ldap_search",
                    "process_id": pid,
                    "process_name": process_name,
                    "search_filter": search_filter,
                    "search_base": search_base,
                    "search_scope": search_scope,
                    "server_name": server_name,
                    "is_suspicious": is_suspicious,
                    "timestamp": chrono::Utc::now().timestamp_millis(),
                })),
            );

            if is_suspicious {
                let (technique, description) = classify_ldap_recon(&filter_lower);
                event.add_detection(Detection {
                    detection_type: DetectionType::AdThreat,
                    rule_name: "LDAP_SUSPICIOUS_QUERY".to_string(),
                    confidence: 0.70,
                    description,
                    mitre_tactics: vec!["Discovery".to_string()],
                    mitre_techniques: vec![technique],
                });
            }

            Some(event)
        }
        event_ids::LDAP_BIND_REQUEST => {
            let server_name = tdh::get_string_property(record, "ServerName")
                .or_else(|| tdh::get_string_property(record, "HostName"));
            let bind_method = tdh::get_u32_property(record, "BindMethod");
            let process_name = get_process_name_by_pid(pid);

            // Simple bind (method 0x80) is cleartext and suspicious
            let is_simple_bind = bind_method == Some(0x80);

            Some(TelemetryEvent::new(
                EventType::AdObjectChange,
                if is_simple_bind {
                    Severity::Medium
                } else {
                    Severity::Info
                },
                EventPayload::Custom(serde_json::json!({
                    "source": "ldap_client",
                    "event_id": event_id,
                    "event_type": "ldap_bind",
                    "process_id": pid,
                    "process_name": process_name,
                    "server_name": server_name,
                    "bind_method": bind_method,
                    "is_simple_bind": is_simple_bind,
                    "timestamp": chrono::Utc::now().timestamp_millis(),
                })),
            ))
        }
        event_ids::LDAP_MODIFY_REQUEST
        | event_ids::LDAP_ADD_REQUEST
        | event_ids::LDAP_DELETE_REQUEST => {
            let dn = tdh::get_string_property(record, "DistinguishedName")
                .or_else(|| tdh::get_string_property(record, "ObjectDN"));
            let process_name = get_process_name_by_pid(pid);

            let operation = match event_id {
                event_ids::LDAP_MODIFY_REQUEST => "ldap_modify",
                event_ids::LDAP_ADD_REQUEST => "ldap_add",
                event_ids::LDAP_DELETE_REQUEST => "ldap_delete",
                _ => "ldap_operation",
            };

            Some(TelemetryEvent::new(
                EventType::AdObjectChange,
                Severity::Medium,
                EventPayload::Custom(serde_json::json!({
                    "source": "ldap_client",
                    "event_id": event_id,
                    "event_type": operation,
                    "process_id": pid,
                    "process_name": process_name,
                    "distinguished_name": dn,
                    "timestamp": chrono::Utc::now().timestamp_millis(),
                })),
            ))
        }
        _ => None,
    }
}

/// Check if an LDAP search filter indicates reconnaissance activity.
fn is_suspicious_ldap_query(filter_lower: &str) -> bool {
    // Patterns commonly used in AD enumeration tools (BloodHound, SharpHound, ADRecon)
    let recon_patterns = [
        // User enumeration
        "(objectclass=user)",
        "(objectcategory=person)",
        "(samaccounttype=805306368)",
        // Computer enumeration
        "(objectclass=computer)",
        "(objectcategory=computer)",
        "(samaccounttype=805306369)",
        // Group enumeration
        "(objectclass=group)",
        "(objectcategory=group)",
        // Domain admin / privileged group enumeration
        "domain admins",
        "enterprise admins",
        "schema admins",
        "account operators",
        "backup operators",
        "administrators",
        // SPN enumeration (Kerberoasting)
        "(serviceprincipalname=*)",
        // Unconstrained delegation
        "(useraccountcontrol:1.2.840.113556.1.4.803:=524288)",
        // Constrained delegation
        "(msds-allowedtodelegateto=*)",
        // LAPS password query
        "(ms-mcs-admpwd=*)",
        // AdminSDHolder / privileged accounts
        "(admincount=1)",
        // GPO enumeration
        "(objectclass=grouppolicycontainer)",
        // Trust enumeration
        "(objectclass=trusteddomain)",
        // AS-REP roastable accounts
        "(useraccountcontrol:1.2.840.113556.1.4.803:=4194304)",
    ];

    recon_patterns.iter().any(|p| filter_lower.contains(p))
}

/// Classify a suspicious LDAP query into a MITRE technique and description.
fn classify_ldap_recon(filter_lower: &str) -> (String, String) {
    if filter_lower.contains("serviceprincipalname") {
        (
            "T1558.003".to_string(),
            "LDAP SPN enumeration (potential Kerberoasting)".to_string(),
        )
    } else if filter_lower.contains("domain admins")
        || filter_lower.contains("enterprise admins")
        || filter_lower.contains("admincount=1")
    {
        (
            "T1069.002".to_string(),
            "LDAP privileged group/account enumeration".to_string(),
        )
    } else if filter_lower.contains("objectclass=computer")
        || filter_lower.contains("objectcategory=computer")
    {
        (
            "T1018".to_string(),
            "LDAP computer enumeration (remote system discovery)".to_string(),
        )
    } else if filter_lower.contains("objectclass=user")
        || filter_lower.contains("objectcategory=person")
    {
        (
            "T1087.002".to_string(),
            "LDAP user enumeration (domain account discovery)".to_string(),
        )
    } else if filter_lower.contains("objectclass=group")
        || filter_lower.contains("objectcategory=group")
    {
        (
            "T1069.002".to_string(),
            "LDAP group enumeration (domain group discovery)".to_string(),
        )
    } else if filter_lower.contains("ms-mcs-admpwd") {
        (
            "T1003".to_string(),
            "LDAP LAPS password enumeration".to_string(),
        )
    } else if filter_lower.contains("useraccountcontrol") && filter_lower.contains("524288") {
        (
            "T1187".to_string(),
            "LDAP unconstrained delegation enumeration".to_string(),
        )
    } else if filter_lower.contains("useraccountcontrol") && filter_lower.contains("4194304") {
        (
            "T1558.004".to_string(),
            "LDAP AS-REP roastable account enumeration".to_string(),
        )
    } else if filter_lower.contains("trusteddomain") {
        (
            "T1482".to_string(),
            "LDAP domain trust enumeration".to_string(),
        )
    } else if filter_lower.contains("grouppolicycontainer") {
        (
            "T1615".to_string(),
            "LDAP Group Policy enumeration".to_string(),
        )
    } else {
        (
            "T1087".to_string(),
            "Suspicious LDAP query detected".to_string(),
        )
    }
}

/// Helper to get process path by PID
fn get_process_path_by_pid(pid: u32) -> Option<String> {
    if pid == 0 || pid == 4 {
        return None;
    }

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut path_buf = [0u16; 260];
        let len = K32GetProcessImageFileNameW(handle, &mut path_buf);
        let _ = CloseHandle(handle);

        if len > 0 {
            Some(String::from_utf16_lossy(&path_buf[..len as usize]))
        } else {
            None
        }
    }
}

/// Helper to get process name by PID
fn get_process_name_by_pid(pid: u32) -> Option<String> {
    get_process_path_by_pid(pid).map(|path| {
        std::path::Path::new(&path)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| format!("PID:{}", pid))
    })
}

impl EtwCollector {
    /// Polling-based fallback for older systems or non-elevated processes
    fn run_polling_fallback(
        tx: mpsc::Sender<TelemetryEvent>,
        _config: AgentConfig,
        running: Arc<AtomicBool>,
    ) -> Result<()> {
        info!("Using polling-based process monitoring (fallback mode)");

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        let mut known_processes: HashMap<u32, ProcessInfo> = HashMap::new();
        let mut last_scan = std::time::Instant::now();
        let scan_interval = std::time::Duration::from_millis(100);

        // Initial snapshot
        for pid in Self::get_process_list() {
            if let Some(info) = Self::get_process_info(pid) {
                known_processes.insert(pid, info);
            }
        }

        while running.load(Ordering::SeqCst) {
            if last_scan.elapsed() >= scan_interval {
                let current_pids = Self::get_process_list();

                // Detect new processes
                for &pid in &current_pids {
                    if !known_processes.contains_key(&pid) {
                        if let Some(info) = Self::get_process_info(pid) {
                            // Create process event
                            if let Some(event) = Self::create_process_event(&info, true) {
                                let _ = rt.block_on(tx.send(event));
                            }
                            known_processes.insert(pid, info);
                        }
                    }
                }

                // Detect terminated processes
                let terminated: Vec<u32> = known_processes
                    .keys()
                    .filter(|pid| !current_pids.contains(pid))
                    .copied()
                    .collect();

                for pid in terminated {
                    if let Some(info) = known_processes.remove(&pid) {
                        if let Some(event) = Self::create_process_event(&info, false) {
                            let _ = rt.block_on(tx.send(event));
                        }
                    }
                }

                last_scan = std::time::Instant::now();
            }

            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        Ok(())
    }

    /// Get list of running process PIDs
    fn get_process_list() -> HashSet<u32> {
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        let mut pids = HashSet::new();

        unsafe {
            let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(h) => h,
                Err(_) => return pids,
            };

            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    pids.insert(entry.th32ProcessID);
                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
        }

        pids
    }

    /// Get process information
    fn get_process_info(pid: u32) -> Option<ProcessInfo> {
        // Skip system processes
        if pid == 0 || pid == 4 {
            return None;
        }

        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;

            let mut path_buf = [0u16; 260];
            let len = K32GetProcessImageFileNameW(handle, &mut path_buf);
            let _ = CloseHandle(handle);

            if len == 0 {
                return None;
            }

            let path = String::from_utf16_lossy(&path_buf[..len as usize]);
            let name = path.rsplit('\\').next().unwrap_or("").to_string();

            // Get parent PID from toolhelp
            let ppid = Self::get_parent_pid(pid);

            Some(ProcessInfo {
                pid,
                ppid,
                name,
                path,
                cmdline: String::new(), // Would need NtQueryInformationProcess
            })
        }
    }

    /// Get parent process ID
    fn get_parent_pid(pid: u32) -> u32 {
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        unsafe {
            let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(h) => h,
                Err(_) => return 0,
            };

            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            let mut ppid = 0;
            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    if entry.th32ProcessID == pid {
                        ppid = entry.th32ParentProcessID;
                        break;
                    }
                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
            ppid
        }
    }

    /// Create process event from process info
    fn create_process_event(info: &ProcessInfo, is_create: bool) -> Option<TelemetryEvent> {
        // Skip system processes
        if info.name.eq_ignore_ascii_case("System")
            || info.name.eq_ignore_ascii_case("[System Process]")
        {
            return None;
        }

        let event_type = if is_create {
            EventType::ProcessCreate
        } else {
            EventType::ProcessTerminate
        };

        let mut severity = Severity::Info;
        let mut detections = Vec::new();

        // Check for suspicious patterns on creation
        if is_create {
            if let Some(detection) = Self::check_suspicious_process(info) {
                severity = Severity::Medium;
                detections.push(detection);
            }
        }

        let mut event = TelemetryEvent::new(
            event_type,
            severity,
            EventPayload::Process(ProcessEvent {
                pid: info.pid,
                ppid: info.ppid,
                name: info.name.clone(),
                path: info.path.clone(),
                cmdline: info.cmdline.clone(),
                user: String::new(),
                sha256: Vec::new(),
                entropy: 0.0,
                is_elevated: false,
                parent_name: None,
                parent_path: None,
                is_signed: false,
                signer: None,
                start_time: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0),
                cpu_usage: 0.0,
                memory_bytes: 0,
                company_name: None,
                file_description: None,
                product_name: None,
                file_version: None,
                environment: None,
            }),
        );

        for detection in detections {
            event.add_detection(detection);
        }

        Some(event)
    }

    /// Check for suspicious process characteristics
    fn check_suspicious_process(info: &ProcessInfo) -> Option<Detection> {
        let name_lower = info.name.to_lowercase();
        let path_lower = info.path.to_lowercase();

        // LOLBins detection
        let lolbins = [
            "powershell.exe",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
            "regsvr32.exe",
            "rundll32.exe",
            "certutil.exe",
            "bitsadmin.exe",
            "msiexec.exe",
            "wmic.exe",
            "installutil.exe",
        ];

        // Execution from suspicious paths
        let suspicious_paths = [
            "\\temp\\",
            "\\tmp\\",
            "\\appdata\\local\\temp",
            "\\users\\public\\",
            "\\downloads\\",
        ];

        // Check for execution from temp/download locations
        if suspicious_paths.iter().any(|p| path_lower.contains(p)) {
            // Only flag non-standard executables from temp
            if !name_lower.ends_with(".tmp") && !name_lower.starts_with("setup") {
                return Some(Detection {
                    detection_type: DetectionType::Behavioral,
                    rule_name: "TempExecution".to_string(),
                    confidence: 0.4,
                    description: format!("Process execution from suspicious path: {}", info.path),
                    mitre_tactics: vec!["Defense Evasion".to_string()],
                    mitre_techniques: vec!["T1036".to_string()],
                });
            }
        }

        None
    }

    /// Get next event from collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }

    /// Check if collector is running in full ETW mode
    pub fn is_full_etw_mode(&self) -> bool {
        self.capabilities.has_etw && self.capabilities.is_elevated
    }

    /// Get current monitoring mode
    pub fn monitoring_mode(&self) -> MonitoringMode {
        Self::determine_mode(&self.capabilities)
    }

    /// Get comprehensive event statistics including ring buffer
    /// and rate tracker metrics for the agent heartbeat.
    pub fn get_stats(&self) -> EtwStats {
        let event_count = ETW_CONTEXT
            .get()
            .map(|ctx| ctx.event_count.load(Ordering::Relaxed))
            .unwrap_or(0);

        let (
            ring_buffer_len,
            ring_buffer_dropped,
            ring_buffer_total,
            rate_throttled,
            session_healthy,
            consecutive_failures,
        ) = ETW_SESSION_HEALTH
            .get()
            .map(|health| {
                let rb_len = health.ring_buffer.lock().map(|rb| rb.len()).unwrap_or(0);
                let rb_dropped = health
                    .ring_buffer
                    .lock()
                    .map(|rb| rb.dropped())
                    .unwrap_or(0);
                let rb_total = health.ring_buffer.lock().map(|rb| rb.total()).unwrap_or(0);
                let throttled = health
                    .rate_tracker
                    .lock()
                    .map(|rt| rt.throttled())
                    .unwrap_or(0);
                let healthy = health.session_healthy.load(Ordering::Relaxed);
                let failures = health.consecutive_failures.load(Ordering::Relaxed);
                (rb_len, rb_dropped, rb_total, throttled, healthy, failures)
            })
            .unwrap_or((0, 0, 0, 0, true, 0));

        EtwStats {
            events_processed: event_count,
            mode: self.monitoring_mode(),
            is_elevated: self.capabilities.is_elevated,
            ring_buffer_len,
            ring_buffer_dropped,
            ring_buffer_total,
            events_throttled: rate_throttled,
            session_healthy,
            consecutive_failures,
        }
    }
}

/// ETW collector statistics for agent heartbeat and monitoring.
#[derive(Debug, Clone)]
pub struct EtwStats {
    /// Total events processed by the ETW callback
    pub events_processed: u64,
    /// Current monitoring mode
    pub mode: MonitoringMode,
    /// Whether the agent is running elevated
    pub is_elevated: bool,
    /// Current number of events in the ring buffer
    pub ring_buffer_len: usize,
    /// Total events dropped due to ring buffer overflow
    pub ring_buffer_dropped: u64,
    /// Total events pushed to ring buffer (including dropped)
    pub ring_buffer_total: u64,
    /// Total events throttled by per-provider rate limiter
    pub events_throttled: u64,
    /// Whether the ETW session is currently healthy
    pub session_healthy: bool,
    /// Number of consecutive session failures
    pub consecutive_failures: u64,
}

impl Drop for EtwCollector {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

/// Process information structure
#[derive(Debug, Clone)]
struct ProcessInfo {
    pid: u32,
    ppid: u32,
    name: String,
    path: String,
    cmdline: String,
}
