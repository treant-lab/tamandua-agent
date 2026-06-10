//! CLR/.NET Runtime Monitoring Collector
//!
//! Provides deep visibility into .NET/CLR runtime activity via ETW:
//! - Assembly loading (including in-memory/byte array loads)
//! - Method invocations (especially via reflection)
//! - JIT compilation events
//! - Exception tracking
//! - Garbage collection activity
//!
//! This collector is critical for detecting modern .NET-based attacks:
//! - Cobalt Strike's execute-assembly
//! - PowerShell Empire .NET payloads
//! - In-memory .NET malware (Donut, etc.)
//! - Fileless malware using Assembly.Load(byte[])
//!
//! MITRE ATT&CK Coverage:
//! - T1059.001 (PowerShell)
//! - T1620 (Reflective Code Loading)
//! - T1055 (Process Injection via .NET)
//! - T1027 (Obfuscated Files or Information)
//!
//! Reference: https://docs.microsoft.com/en-us/dotnet/framework/performance/clr-etw-providers

#![cfg(target_os = "windows")]
// File maintains a checked reference for CLR/.NET ETW provider keywords,
// event IDs, and enum variants used for in-memory assembly load detection.
// Unused entries are retained as reference material for future subscriptions.
#![allow(dead_code)]

use super::win_compat::{etw as etw_api, SystemCapabilities};
use super::{Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent};
use crate::config::AgentConfig;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use windows::core::GUID;

// ============================================================================
// CLR ETW Provider GUIDs and Constants
// ============================================================================

/// Microsoft-Windows-DotNETRuntime provider GUID
/// This is the primary CLR ETW provider for runtime events
const CLR_RUNTIME_PROVIDER: GUID = GUID::from_u128(0xe13c0d23_ccbc_4e12_931b_d9cc2eee27e4);

/// Microsoft-Windows-DotNETRuntimePrivate provider GUID (requires elevation)
const CLR_RUNTIME_PRIVATE_PROVIDER: GUID = GUID::from_u128(0x763fd754_7086_4dfe_95eb_c01a46faf4ca);

/// Microsoft-Windows-DotNETRuntimeRundown provider GUID (for existing state capture)
const CLR_RUNDOWN_PROVIDER: GUID = GUID::from_u128(0xa669021c_c450_4609_a035_5af59af4df18);

/// CLR ETW Keywords for event filtering
mod clr_keywords {
    /// GC events
    pub const GC: u64 = 0x1;
    /// Garbage collection handle events
    pub const GC_HANDLE: u64 = 0x2;
    /// BulkObject events
    pub const BULK_OBJECT: u64 = 0x4;
    /// Loader events (Assembly, Module, Domain)
    pub const LOADER: u64 = 0x8;
    /// JIT events
    pub const JIT: u64 = 0x10;
    /// NGEN events
    pub const NGEN: u64 = 0x20;
    /// Start-enumeration keyword
    pub const START_ENUMERATION: u64 = 0x40;
    /// End-enumeration keyword
    pub const END_ENUMERATION: u64 = 0x80;
    /// Security events
    pub const SECURITY: u64 = 0x400;
    /// AppDomain resource management
    pub const APP_DOMAIN_RESOURCE_MANAGEMENT: u64 = 0x800;
    /// JIT tracing
    pub const JIT_TRACING: u64 = 0x1000;
    /// Interop events
    pub const INTEROP: u64 = 0x2000;
    /// Contention events
    pub const CONTENTION: u64 = 0x4000;
    /// Exception events
    pub const EXCEPTION: u64 = 0x8000;
    /// Threading events
    pub const THREADING: u64 = 0x10000;
    /// Remoting events
    pub const REMOTING: u64 = 0x20000;
    /// Perftrack events
    pub const PERFTRACK: u64 = 0x20000000;
    /// Stack events
    pub const STACK: u64 = 0x40000000;
    /// Type diagnostic events (Win8+)
    pub const TYPE: u64 = 0x80000000;
    /// Combined keywords for security monitoring
    pub const SECURITY_MONITORING: u64 = LOADER | JIT | EXCEPTION | SECURITY | INTEROP | TYPE;
}

/// CLR ETW Event IDs
mod clr_event_ids {
    // Loader events
    pub const ASSEMBLY_LOAD_START: u16 = 152;
    pub const ASSEMBLY_LOAD_STOP: u16 = 153;
    pub const ASSEMBLY_UNLOAD_START: u16 = 154;
    pub const ASSEMBLY_UNLOAD_STOP: u16 = 155;
    pub const MODULE_LOAD: u16 = 152;
    pub const MODULE_UNLOAD: u16 = 153;
    pub const APP_DOMAIN_LOAD: u16 = 156;
    pub const APP_DOMAIN_UNLOAD: u16 = 157;

    // Method/JIT events
    pub const METHOD_LOAD: u16 = 141;
    pub const METHOD_UNLOAD: u16 = 142;
    pub const METHOD_LOAD_VERBOSE: u16 = 143;
    pub const METHOD_UNLOAD_VERBOSE: u16 = 144;
    pub const METHOD_JITTING_STARTED: u16 = 145;
    pub const METHOD_JIT_INLINING_SUCCEEDED: u16 = 185;
    pub const METHOD_JIT_INLINING_FAILED: u16 = 186;

    // Exception events
    pub const EXCEPTION_THROWN: u16 = 80;
    pub const EXCEPTION_CAUGHT: u16 = 250;
    pub const EXCEPTION_FINALIZE: u16 = 251;
    pub const EXCEPTION_FILTER: u16 = 252;

    // GC events
    pub const GC_START: u16 = 1;
    pub const GC_END: u16 = 2;
    pub const GC_HEAP_STATS: u16 = 4;
    pub const GC_CREATE_SEGMENT: u16 = 5;
    pub const GC_ALLOCATION_TICK: u16 = 10;

    // Type events (for reflection detection)
    pub const TYPE_LOAD_START: u16 = 73;
    pub const TYPE_LOAD_STOP: u16 = 74;

    // Security events
    pub const STRONG_NAME_VERIFICATION_START: u16 = 181;
    pub const STRONG_NAME_VERIFICATION_STOP: u16 = 182;
    pub const AUTHENTICODE_VERIFICATION_START: u16 = 183;
    pub const AUTHENTICODE_VERIFICATION_STOP: u16 = 184;

    // Interop events
    pub const IL_STUB_GENERATED: u16 = 88;
    pub const IL_STUB_CACHE_HIT: u16 = 89;
}

// ============================================================================
// Data Structures for CLR Events
// ============================================================================

/// CLR Assembly Load event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClrAssemblyLoad {
    /// Process ID where assembly was loaded
    pub process_id: u32,
    /// Full assembly name (including version, culture, public key token)
    pub assembly_name: String,
    /// File path of the assembly (None if loaded from memory/byte array)
    pub assembly_path: Option<String>,
    /// Whether this is a dynamic assembly (generated at runtime)
    pub is_dynamic: bool,
    /// Whether this was loaded from a byte array (in-memory)
    pub is_from_byte_array: bool,
    /// AppDomain name where assembly was loaded
    pub app_domain: String,
    /// AppDomain ID
    pub app_domain_id: u64,
    /// CLR version string
    pub clr_version: String,
    /// Assembly flags
    pub assembly_flags: u32,
    /// Module ID
    pub module_id: u64,
    /// Binding ID for correlation
    pub binding_id: u64,
    /// Whether assembly passed strong name verification
    pub strong_name_verified: Option<bool>,
    /// Whether assembly is signed with Authenticode
    pub authenticode_verified: Option<bool>,
    /// Timestamp of the load
    pub timestamp: u64,
    /// Risk score based on heuristics (0-100)
    pub risk_score: u32,
    /// Reasons for the risk score
    pub risk_reasons: Vec<String>,
}

/// CLR Method invocation/JIT event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClrMethodInvoke {
    /// Process ID
    pub process_id: u32,
    /// Fully qualified class name
    pub class_name: String,
    /// Method name
    pub method_name: String,
    /// Method signature (parameters)
    pub method_signature: Option<String>,
    /// Whether invoked via reflection (Type.InvokeMember, MethodInfo.Invoke, etc.)
    pub is_reflection: bool,
    /// Whether this is a suspicious method (based on known dangerous APIs)
    pub is_suspicious: bool,
    /// Module name containing the method
    pub module_name: String,
    /// Whether this is a dynamic method (generated at runtime)
    pub is_dynamic_method: bool,
    /// JIT compilation flags
    pub jit_flags: u32,
    /// Method ID for correlation
    pub method_id: u64,
    /// Timestamp
    pub timestamp: u64,
    /// Risk reasons
    pub risk_reasons: Vec<String>,
}

/// CLR Exception event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClrException {
    /// Process ID
    pub process_id: u32,
    /// Exception type name
    pub exception_type: String,
    /// Exception message
    pub message: String,
    /// Stack trace (if available)
    pub stack_trace: Option<String>,
    /// Whether this is a CLR internal exception
    pub is_clr_exception: bool,
    /// AppDomain where exception occurred
    pub app_domain: String,
    /// Timestamp
    pub timestamp: u64,
}

/// CLR GC event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClrGcEvent {
    /// Process ID
    pub process_id: u32,
    /// GC generation (0, 1, 2)
    pub generation: u32,
    /// GC reason
    pub reason: String,
    /// GC type (background, blocking, etc.)
    pub gc_type: String,
    /// Timestamp
    pub timestamp: u64,
}

// ============================================================================
// Suspicious Pattern Detection
// ============================================================================

/// Known suspicious assembly names/patterns (used by malware)
const SUSPICIOUS_ASSEMBLY_NAMES: &[&str] = &[
    // Common in-memory attack tools
    "SharpHound",
    "Rubeus",
    "Seatbelt",
    "SharpUp",
    "SafetyKatz",
    "SharpDPAPI",
    "SharpWMI",
    "SharpView",
    "PowerSharpPack",
    "Covenant",
    "GhostPack",
    // Obfuscator artifacts
    "ConfuserEx",
    "Dotfuscator",
    "SmartAssembly",
    // Generic suspicious patterns will be checked via regex
];

/// Known suspicious method patterns for reflection-based attacks
const SUSPICIOUS_METHODS: &[(&str, &str)] = &[
    // Process execution
    ("System.Diagnostics.Process", "Start"),
    ("System.Diagnostics.ProcessStartInfo", ".ctor"),
    // PowerShell hosting
    ("System.Management.Automation.PowerShell", "Create"),
    ("System.Management.Automation.PowerShell", "Invoke"),
    (
        "System.Management.Automation.Runspaces.RunspaceFactory",
        "CreateRunspace",
    ),
    // Assembly loading (for nested loads)
    ("System.Reflection.Assembly", "Load"),
    ("System.Reflection.Assembly", "LoadFrom"),
    ("System.Reflection.Assembly", "LoadFile"),
    ("System.Reflection.Assembly", "LoadWithPartialName"),
    (
        "System.Runtime.Loader.AssemblyLoadContext",
        "LoadFromStream",
    ),
    // Reflection for method invocation
    ("System.Reflection.MethodBase", "Invoke"),
    ("System.Reflection.MethodInfo", "Invoke"),
    ("System.Type", "InvokeMember"),
    ("System.Activator", "CreateInstance"),
    // P/Invoke dangerous APIs
    (
        "System.Runtime.InteropServices.Marshal",
        "GetDelegateForFunctionPointer",
    ),
    ("System.Runtime.InteropServices.Marshal", "Copy"),
    ("System.Runtime.InteropServices.Marshal", "ReadByte"),
    ("System.Runtime.InteropServices.Marshal", "WriteByte"),
    // Credential access
    ("System.Security.Cryptography.ProtectedData", "Unprotect"),
    ("System.Net.NetworkCredential", ".ctor"),
    ("System.DirectoryServices.DirectoryEntry", ".ctor"),
    // Code generation
    ("System.Reflection.Emit.DynamicMethod", ".ctor"),
    (
        "System.Reflection.Emit.AssemblyBuilder",
        "DefineDynamicAssembly",
    ),
    ("System.Reflection.Emit.ModuleBuilder", "DefineType"),
    // WMI
    ("System.Management.ManagementObject", "InvokeMethod"),
    ("System.Management.ManagementClass", "InvokeMethod"),
    // COM interop
    ("System.Runtime.InteropServices.Marshal", "GetActiveObject"),
    ("System.Activator", "CreateComInstanceFrom"),
    // Network
    ("System.Net.WebClient", "DownloadString"),
    ("System.Net.WebClient", "DownloadData"),
    ("System.Net.WebClient", "DownloadFile"),
    ("System.Net.HttpWebRequest", "GetResponse"),
    // Registry
    ("Microsoft.Win32.Registry", "SetValue"),
    ("Microsoft.Win32.RegistryKey", "SetValue"),
    // Crypto
    ("System.Security.Cryptography.Aes", "Create"),
    ("System.Security.Cryptography.RSA", "Create"),
];

/// Suspicious temp directory patterns
const SUSPICIOUS_PATHS: &[&str] = &[
    "\\Temp\\",
    "\\tmp\\",
    "\\AppData\\Local\\Temp\\",
    "\\Windows\\Temp\\",
    "\\Users\\Public\\",
    "\\ProgramData\\",
    "\\Downloads\\",
];

// ============================================================================
// ETW Structures for CLR Event Parsing
// ============================================================================

/// Event record from ETW
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
    provider_id: [u8; 16],
    event_descriptor: EventDescriptor,
    kernel_time: u32,
    user_time: u32,
    activity_id: [u8; 16],
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

/// ETW trace session properties
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
    _padding: [u8; 1024],
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

/// Event trace logfile for consumption
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
    time_zone: [u8; 176],
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

/// Processing mode flags
const PROCESS_TRACE_MODE_REAL_TIME: u32 = 0x00000100;
const PROCESS_TRACE_MODE_EVENT_RECORD: u32 = 0x10000000;

// ============================================================================
// TDH Property Extraction (same as etw.rs)
// ============================================================================

mod tdh {
    use super::*;
    use std::sync::OnceLock;
    use windows::core::HSTRING;
    use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

    static TDH_API: OnceLock<Option<TdhApi>> = OnceLock::new();

    pub struct TdhApi {
        pub get_property: TdhGetPropertyFn,
        pub get_property_size: TdhGetPropertySizeFn,
    }

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
        pub property_name: u64,
        pub array_index: u32,
        pub reserved: u32,
    }

    pub fn get_tdh_api() -> Option<&'static TdhApi> {
        TDH_API
            .get_or_init(|| unsafe {
                let module = LoadLibraryW(&HSTRING::from("tdh.dll")).ok()?;

                let get_property = GetProcAddress(
                    module,
                    windows::core::PCSTR::from_raw(b"TdhGetProperty\0".as_ptr()),
                )?;
                let get_property_size = GetProcAddress(
                    module,
                    windows::core::PCSTR::from_raw(b"TdhGetPropertySize\0".as_ptr()),
                )?;

                Some(TdhApi {
                    get_property: std::mem::transmute(get_property),
                    get_property_size: std::mem::transmute(get_property_size),
                })
            })
            .as_ref()
    }

    pub fn get_string_property(record: &EventRecord, property_name: &str) -> Option<String> {
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

        if status != 0 {
            return None;
        }

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
}

// ============================================================================
// Global Callback Context
// ============================================================================

/// Session name for CLR ETW trace
const CLR_SESSION_NAME: &str = "TamanduaCLR";

/// Global context for ETW callback
static CLR_CONTEXT: std::sync::OnceLock<ClrCallbackContext> = std::sync::OnceLock::new();

struct ClrCallbackContext {
    tx: std::sync::Mutex<Option<mpsc::Sender<TelemetryEvent>>>,
    running: Arc<AtomicBool>,
    event_count: AtomicU64,
    /// Cache of recently seen assemblies to avoid duplicates
    assembly_cache: RwLock<HashMap<String, u64>>,
    /// Suspicious method invocation patterns
    suspicious_methods: HashSet<(String, String)>,
}

// ============================================================================
// CLR Collector Implementation
// ============================================================================

/// CLR/.NET Runtime monitoring collector
pub struct ClrCollector {
    #[allow(dead_code)]
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    running: Arc<AtomicBool>,
    #[allow(dead_code)]
    capabilities: SystemCapabilities,
}

impl ClrCollector {
    /// Create a new CLR collector
    pub fn new(config: &AgentConfig) -> Result<Self> {
        let (tx, rx) = mpsc::channel(5000);
        let capabilities = SystemCapabilities::detect();
        let running = Arc::new(AtomicBool::new(true));

        // Check if ETW is available
        if !capabilities.has_etw {
            return Err(anyhow!("ETW not available on this system"));
        }

        info!(
            version = %capabilities.version,
            elevated = capabilities.is_elevated,
            "CLR collector initializing"
        );

        // Build suspicious method set for fast lookup
        let suspicious_methods: HashSet<(String, String)> = SUSPICIOUS_METHODS
            .iter()
            .map(|(class, method)| (class.to_string(), method.to_string()))
            .collect();

        // Start ETW session in background thread
        let tx_clone = tx.clone();
        let running_clone = running.clone();
        let caps_clone = capabilities.clone();

        std::thread::spawn(move || {
            if let Err(e) =
                Self::run_clr_etw_session(tx_clone, running_clone, caps_clone, suspicious_methods)
            {
                error!(error = %e, "CLR ETW session failed");
            }
        });

        Ok(Self {
            config: config.clone(),
            event_rx: rx,
            running,
            capabilities,
        })
    }

    /// Get the next telemetry event
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }

    /// Run the CLR ETW session
    fn run_clr_etw_session(
        tx: mpsc::Sender<TelemetryEvent>,
        running: Arc<AtomicBool>,
        caps: SystemCapabilities,
        suspicious_methods: HashSet<(String, String)>,
    ) -> Result<()> {
        let api = etw_api::get_etw_api().ok_or_else(|| anyhow!("ETW API not available"))?;

        info!(
            elevated = caps.is_elevated,
            has_ex2 = caps.has_etw_ex2,
            "Starting CLR ETW real-time session"
        );

        // Create session properties
        let mut properties = Self::create_trace_properties();
        let mut session_handle: u64 = 0;

        // Session name as wide string
        let session_name_wide: Vec<u16> = CLR_SESSION_NAME
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        // Copy session name to properties
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
                info!(handle = session_handle, "CLR ETW session created");
            }
            etw_api::ERROR_ALREADY_EXISTS => {
                info!("CLR ETW session already exists, stopping and recreating");
                unsafe {
                    (api.control_trace)(
                        0,
                        session_name_wide.as_ptr(),
                        &mut properties as *mut _ as *mut c_void,
                        etw_api::EVENT_TRACE_CONTROL_STOP,
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(100));

                // Retry
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
                        "Failed to start CLR ETW session after stop: {}",
                        retry_result
                    ));
                }
                info!(
                    handle = session_handle,
                    "CLR ETW session created after stop"
                );
            }
            etw_api::ERROR_ACCESS_DENIED => {
                warn!("CLR ETW access denied - elevation may be required for some events");
                return Err(anyhow!("CLR ETW access denied"));
            }
            _ => {
                return Err(anyhow!("StartTrace failed for CLR session: {}", result));
            }
        }

        // Enable CLR runtime provider
        Self::enable_clr_providers(api, session_handle, &caps);

        // Start consumer thread
        let tx_clone = tx.clone();
        let running_clone = running.clone();
        let session_name_clone = session_name_wide.clone();

        let consumer_handle = std::thread::spawn(move || {
            Self::consume_clr_events(
                tx_clone,
                running_clone,
                session_name_clone,
                suspicious_methods,
            )
        });

        // Keep session alive
        while running.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_secs(1));

            if let Some(ctx) = CLR_CONTEXT.get() {
                let count = ctx.event_count.load(Ordering::Relaxed);
                if count > 0 && count % 1000 == 0 {
                    debug!(events_processed = count, "CLR ETW event statistics");
                }
            }
        }

        // Stop session
        info!("Stopping CLR ETW session");
        unsafe {
            (api.control_trace)(
                session_handle,
                session_name_wide.as_ptr(),
                &mut properties as *mut _ as *mut c_void,
                etw_api::EVENT_TRACE_CONTROL_STOP,
            );
        }

        let _ = consumer_handle.join();
        Ok(())
    }

    /// Create trace properties for CLR session
    fn create_trace_properties() -> EventTraceProperties {
        let total_size = std::mem::size_of::<EventTraceProperties>();

        EventTraceProperties {
            wnode: WnodeHeader {
                buffer_size: total_size as u32,
                provider_id: 0,
                historical_context: 0,
                timestamp: 0,
                guid: [0; 16],
                client_context: 1,
                flags: etw_api::WNODE_FLAG_TRACED_GUID,
            },
            buffer_size: 64,
            minimum_buffers: 8,
            maximum_buffers: 64,
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

    /// Enable CLR ETW providers
    fn enable_clr_providers(api: &etw_api::EtwApi, session_handle: u64, caps: &SystemCapabilities) {
        // Keywords for security monitoring
        let keywords = clr_keywords::SECURITY_MONITORING;

        // Enable main CLR runtime provider
        let result = if caps.has_etw_ex2 {
            if let Some(enable_ex2) = api.enable_trace_ex2 {
                unsafe {
                    enable_ex2(
                        session_handle,
                        &CLR_RUNTIME_PROVIDER as *const _ as *const c_void,
                        etw_api::EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                        etw_api::TRACE_LEVEL_VERBOSE,
                        keywords,
                        0,
                        0,
                        std::ptr::null(),
                    )
                }
            } else {
                etw_api::ERROR_ACCESS_DENIED
            }
        } else {
            unsafe {
                (api.enable_trace)(
                    1,
                    keywords as u32,
                    etw_api::TRACE_LEVEL_VERBOSE as u32,
                    &CLR_RUNTIME_PROVIDER as *const _ as *const c_void,
                    session_handle,
                )
            }
        };

        if result == etw_api::ERROR_SUCCESS {
            info!("CLR Runtime ETW provider enabled");
        } else {
            warn!(error = result, "Failed to enable CLR Runtime provider");
        }

        // Try to enable private provider (requires elevation)
        if caps.is_elevated {
            let private_result = if let Some(enable_ex2) = api.enable_trace_ex2 {
                unsafe {
                    enable_ex2(
                        session_handle,
                        &CLR_RUNTIME_PRIVATE_PROVIDER as *const _ as *const c_void,
                        etw_api::EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                        etw_api::TRACE_LEVEL_VERBOSE,
                        keywords,
                        0,
                        0,
                        std::ptr::null(),
                    )
                }
            } else {
                etw_api::ERROR_ACCESS_DENIED
            };

            if private_result == etw_api::ERROR_SUCCESS {
                info!("CLR Runtime Private ETW provider enabled");
            } else {
                debug!(error = private_result, "CLR Private provider not available");
            }
        }
    }

    /// Consume CLR ETW events
    fn consume_clr_events(
        tx: mpsc::Sender<TelemetryEvent>,
        running: Arc<AtomicBool>,
        mut session_name: Vec<u16>,
        suspicious_methods: HashSet<(String, String)>,
    ) -> Result<()> {
        let api = etw_api::get_etw_api().ok_or_else(|| anyhow!("ETW API not available"))?;

        info!("Starting CLR ETW event consumption");

        // Initialize global callback context
        let _ = CLR_CONTEXT.set(ClrCallbackContext {
            tx: std::sync::Mutex::new(Some(tx)),
            running: running.clone(),
            event_count: AtomicU64::new(0),
            assembly_cache: RwLock::new(HashMap::new()),
            suspicious_methods,
        });

        // Create logfile structure for real-time consumption
        let mut logfile = unsafe { std::mem::zeroed::<EventTraceLogfileW>() };
        logfile.logger_name = session_name.as_mut_ptr();
        logfile.log_file_mode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.event_record_callback = Some(clr_event_callback);

        // Open the trace session
        let trace_handle = unsafe { (api.open_trace)(&mut logfile as *mut _ as *mut c_void) };

        if trace_handle == u64::MAX {
            let error = unsafe { windows::Win32::Foundation::GetLastError() };
            return Err(anyhow!("OpenTrace failed for CLR session: {:?}", error));
        }

        info!(handle = trace_handle, "CLR ETW trace opened");

        // Process trace (blocks until session ends)
        let handles = [trace_handle];
        let result =
            unsafe { (api.process_trace)(handles.as_ptr(), 1, std::ptr::null(), std::ptr::null()) };

        // Cleanup
        unsafe { (api.close_trace)(trace_handle) };

        if let Some(ctx) = CLR_CONTEXT.get() {
            if let Ok(mut guard) = ctx.tx.lock() {
                *guard = None;
            }
        }

        if result != etw_api::ERROR_SUCCESS && result != 1223 {
            warn!(error = result, "ProcessTrace ended with error");
        }

        info!("CLR ETW event consumption stopped");
        Ok(())
    }
}

impl Drop for ClrCollector {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

// ============================================================================
// ETW Event Callback and Parsing
// ============================================================================

/// CLR ETW event callback
unsafe extern "system" fn clr_event_callback(event_record: *mut EventRecord) {
    if event_record.is_null() {
        return;
    }

    let record = &*event_record;
    let header = &record.event_header;

    if let Some(ctx) = CLR_CONTEXT.get() {
        if !ctx.running.load(Ordering::SeqCst) {
            return;
        }

        let tx = match ctx.tx.lock() {
            Ok(guard) => match guard.as_ref() {
                Some(tx) => tx.clone(),
                None => return,
            },
            Err(_) => return,
        };

        ctx.event_count.fetch_add(1, Ordering::Relaxed);

        // Check if this is from CLR provider
        let provider_guid = GUID::from_u128(u128::from_le_bytes([
            header.provider_id[0],
            header.provider_id[1],
            header.provider_id[2],
            header.provider_id[3],
            header.provider_id[4],
            header.provider_id[5],
            header.provider_id[6],
            header.provider_id[7],
            header.provider_id[8],
            header.provider_id[9],
            header.provider_id[10],
            header.provider_id[11],
            header.provider_id[12],
            header.provider_id[13],
            header.provider_id[14],
            header.provider_id[15],
        ]));

        if provider_guid == CLR_RUNTIME_PROVIDER || provider_guid == CLR_RUNTIME_PRIVATE_PROVIDER {
            if let Some(event) = parse_clr_event(record, ctx) {
                let _ = tx.try_send(event);
            }
        }
    }
}

/// Parse CLR ETW event into telemetry
fn parse_clr_event(record: &EventRecord, ctx: &ClrCallbackContext) -> Option<TelemetryEvent> {
    let header = &record.event_header;
    let event_id = header.event_descriptor.id;

    match event_id {
        // Assembly load events
        clr_event_ids::ASSEMBLY_LOAD_START | clr_event_ids::ASSEMBLY_LOAD_STOP => {
            parse_assembly_load_event(record, ctx)
        }

        // Method JIT events
        clr_event_ids::METHOD_LOAD
        | clr_event_ids::METHOD_LOAD_VERBOSE
        | clr_event_ids::METHOD_JITTING_STARTED => parse_method_event(record, ctx),

        // Exception events
        clr_event_ids::EXCEPTION_THROWN => parse_exception_event(record),

        // GC events (for memory pressure detection)
        clr_event_ids::GC_START => parse_gc_event(record),

        _ => None,
    }
}

/// Parse assembly load events
fn parse_assembly_load_event(
    record: &EventRecord,
    ctx: &ClrCallbackContext,
) -> Option<TelemetryEvent> {
    let header = &record.event_header;
    let process_id = header.process_id;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // Extract assembly information from TDH
    let assembly_name = tdh::get_string_property(record, "FullyQualifiedAssemblyName")
        .or_else(|| tdh::get_string_property(record, "AssemblyName"))
        .unwrap_or_default();

    // Skip if we've seen this assembly recently (within 1 second)
    if let Ok(cache) = ctx.assembly_cache.read() {
        if let Some(&last_seen) = cache.get(&assembly_name) {
            if timestamp.saturating_sub(last_seen) < 1000 {
                return None;
            }
        }
    }

    // Update cache
    if let Ok(mut cache) = ctx.assembly_cache.write() {
        cache.insert(assembly_name.clone(), timestamp);
        // Prune old entries (keep last 1000)
        if cache.len() > 1000 {
            let oldest: Vec<_> = cache
                .iter()
                .filter(|(_, &ts)| timestamp.saturating_sub(ts) > 60000)
                .map(|(k, _)| k.clone())
                .collect();
            for key in oldest {
                cache.remove(&key);
            }
        }
    }

    let assembly_path = tdh::get_string_property(record, "ModuleNativePath")
        .or_else(|| tdh::get_string_property(record, "ModuleILPath"));

    let app_domain =
        tdh::get_string_property(record, "AppDomainName").unwrap_or_else(|| "Unknown".to_string());
    let app_domain_id = tdh::get_u64_property(record, "AppDomainID").unwrap_or(0);
    let module_id = tdh::get_u64_property(record, "ModuleID").unwrap_or(0);
    let binding_id = tdh::get_u64_property(record, "BindingID").unwrap_or(0);
    let assembly_flags = tdh::get_u32_property(record, "AssemblyFlags").unwrap_or(0);

    // Determine if this is a dynamic/in-memory assembly
    let is_dynamic = (assembly_flags & 0x2) != 0; // ASSEMBLY_DYNAMIC flag
    let is_from_byte_array =
        assembly_path.is_none() || assembly_path.as_ref().map(|p| p.is_empty()).unwrap_or(true);

    // Calculate risk score
    let (risk_score, risk_reasons) = calculate_assembly_risk(
        &assembly_name,
        assembly_path.as_deref(),
        is_dynamic,
        is_from_byte_array,
    );

    // Determine severity based on risk
    let severity = if risk_score >= 80 {
        Severity::Critical
    } else if risk_score >= 60 {
        Severity::High
    } else if risk_score >= 40 {
        Severity::Medium
    } else if risk_score >= 20 {
        Severity::Low
    } else {
        Severity::Info
    };

    let clr_event = ClrAssemblyLoad {
        process_id,
        assembly_name: assembly_name.clone(),
        assembly_path,
        is_dynamic,
        is_from_byte_array,
        app_domain,
        app_domain_id,
        clr_version: get_clr_version(),
        assembly_flags,
        module_id,
        binding_id,
        strong_name_verified: None,
        authenticode_verified: None,
        timestamp,
        risk_score,
        risk_reasons: risk_reasons.clone(),
    };

    let mut event = TelemetryEvent::new(
        EventType::ModuleLoad,
        severity,
        EventPayload::Custom(serde_json::json!({
            "event_type": "clr_assembly_load",
            "clr_event": clr_event,
            "mitre_technique": "T1620",
            "mitre_tactic": "Defense Evasion",
        })),
    );

    // Add detections for suspicious assemblies
    if risk_score >= 40 {
        event.add_detection(Detection {
            detection_type: DetectionType::Behavioral,
            rule_name: "Suspicious CLR Assembly Load".to_string(),
            confidence: (risk_score as f32) / 100.0,
            description: format!(
                "Suspicious .NET assembly loaded: {} (Risk: {}). Reasons: {}",
                assembly_name,
                risk_score,
                risk_reasons.join(", ")
            ),
            mitre_tactics: vec!["Defense Evasion".to_string(), "Execution".to_string()],
            mitre_techniques: vec!["T1620".to_string(), "T1059.001".to_string()],
        });
    }

    Some(event)
}

/// Parse method JIT/load events
fn parse_method_event(record: &EventRecord, ctx: &ClrCallbackContext) -> Option<TelemetryEvent> {
    let header = &record.event_header;
    let process_id = header.process_id;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // Extract method information
    let method_namespace = tdh::get_string_property(record, "MethodNamespace").unwrap_or_default();
    let method_name = tdh::get_string_property(record, "MethodName").unwrap_or_default();
    let method_signature = tdh::get_string_property(record, "MethodSignature");
    let module_name =
        tdh::get_string_property(record, "ModuleILPath").unwrap_or_else(|| "dynamic".to_string());
    let method_id = tdh::get_u64_property(record, "MethodID").unwrap_or(0);
    let jit_flags = tdh::get_u32_property(record, "MethodFlags").unwrap_or(0);

    // Build full class name
    let class_name = method_namespace.clone();

    // Check if this is a suspicious method invocation
    let is_suspicious = ctx
        .suspicious_methods
        .contains(&(class_name.clone(), method_name.clone()));

    // Check for reflection-related methods
    let is_reflection = class_name.contains("System.Reflection")
        || class_name.contains("System.Activator")
        || method_name.contains("Invoke");

    // Check for dynamic method
    let is_dynamic_method = class_name.contains("DynamicMethod")
        || module_name.contains("dynamic")
        || (jit_flags & 0x10) != 0; // JIT_DYNAMIC flag

    // Build risk reasons
    let mut risk_reasons = Vec::new();
    if is_suspicious {
        risk_reasons.push(format!(
            "Known suspicious API: {}.{}",
            class_name, method_name
        ));
    }
    if is_reflection {
        risk_reasons.push("Reflection-based invocation".to_string());
    }
    if is_dynamic_method {
        risk_reasons.push("Dynamic method generation".to_string());
    }

    // Only emit events for interesting methods
    if !is_suspicious && !is_reflection && !is_dynamic_method {
        return None;
    }

    let severity = if is_suspicious && is_reflection {
        Severity::High
    } else if is_suspicious || is_dynamic_method {
        Severity::Medium
    } else {
        Severity::Low
    };

    let clr_method = ClrMethodInvoke {
        process_id,
        class_name: class_name.clone(),
        method_name: method_name.clone(),
        method_signature,
        is_reflection,
        is_suspicious,
        module_name,
        is_dynamic_method,
        jit_flags,
        method_id,
        timestamp,
        risk_reasons: risk_reasons.clone(),
    };

    let mut event = TelemetryEvent::new(
        EventType::ProcessInject, // Using ProcessInject for reflection-based execution
        severity,
        EventPayload::Custom(serde_json::json!({
            "event_type": "clr_method_invoke",
            "clr_event": clr_method,
            "mitre_technique": "T1620",
            "mitre_tactic": "Execution",
        })),
    );

    if is_suspicious {
        event.add_detection(Detection {
            detection_type: DetectionType::Behavioral,
            rule_name: "Suspicious CLR Method Invocation".to_string(),
            confidence: 0.8,
            description: format!(
                "Suspicious .NET method called: {}.{}. {}",
                class_name,
                method_name,
                risk_reasons.join(", ")
            ),
            mitre_tactics: vec!["Execution".to_string(), "Defense Evasion".to_string()],
            mitre_techniques: vec!["T1059.001".to_string(), "T1620".to_string()],
        });
    }

    Some(event)
}

/// Parse exception events
fn parse_exception_event(record: &EventRecord) -> Option<TelemetryEvent> {
    let header = &record.event_header;
    let process_id = header.process_id;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let exception_type =
        tdh::get_string_property(record, "ExceptionType").unwrap_or_else(|| "Unknown".to_string());
    let message = tdh::get_string_property(record, "ExceptionMessage").unwrap_or_default();

    // Check for CLR internal exception (might indicate exploitation attempt)
    let is_clr_exception = exception_type.contains("CLR")
        || exception_type.contains("AccessViolation")
        || exception_type.contains("StackOverflow")
        || exception_type.contains("InvalidProgram");

    // Only report interesting exceptions
    if !is_clr_exception && !exception_type.contains("Security") {
        return None;
    }

    let clr_exception = ClrException {
        process_id,
        exception_type: exception_type.clone(),
        message,
        stack_trace: None,
        is_clr_exception,
        app_domain: "Unknown".to_string(),
        timestamp,
    };

    let severity = if is_clr_exception {
        Severity::High
    } else {
        Severity::Medium
    };

    Some(TelemetryEvent::new(
        EventType::ExploitAttempt,
        severity,
        EventPayload::Custom(serde_json::json!({
            "event_type": "clr_exception",
            "clr_event": clr_exception,
            "mitre_technique": "T1203",
            "mitre_tactic": "Execution",
        })),
    ))
}

/// Parse GC events (for detecting memory-heavy operations like decryption)
fn parse_gc_event(record: &EventRecord) -> Option<TelemetryEvent> {
    let header = &record.event_header;
    let process_id = header.process_id;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let generation = tdh::get_u32_property(record, "Depth").unwrap_or(0);
    let reason = tdh::get_u32_property(record, "Reason").unwrap_or(0);
    let gc_type = tdh::get_u32_property(record, "Type").unwrap_or(0);

    // Only report Gen 2 GCs (might indicate large memory operations)
    if generation < 2 {
        return None;
    }

    let reason_str = match reason {
        0 => "AllocSmall",
        1 => "Induced",
        2 => "LowMemory",
        3 => "Empty",
        4 => "AllocLarge",
        5 => "OutOfSpaceSOH",
        6 => "OutOfSpaceLOH",
        7 => "InducedNotForced",
        _ => "Unknown",
    }
    .to_string();

    let gc_type_str = match gc_type {
        0 => "NonConcurrent",
        1 => "Background",
        2 => "Foreground",
        _ => "Unknown",
    }
    .to_string();

    let clr_gc = ClrGcEvent {
        process_id,
        generation,
        reason: reason_str,
        gc_type: gc_type_str,
        timestamp,
    };

    Some(TelemetryEvent::new(
        EventType::MemoryScan,
        Severity::Info,
        EventPayload::Custom(serde_json::json!({
            "event_type": "clr_gc",
            "clr_event": clr_gc,
        })),
    ))
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Calculate risk score for an assembly
fn calculate_assembly_risk(
    assembly_name: &str,
    assembly_path: Option<&str>,
    is_dynamic: bool,
    is_from_byte_array: bool,
) -> (u32, Vec<String>) {
    let mut score: u32 = 0;
    let mut reasons = Vec::new();

    // In-memory/byte array load is highly suspicious
    if is_from_byte_array {
        score += 50;
        reasons.push("Loaded from byte array (no file path)".to_string());
    }

    // Dynamic assembly is suspicious
    if is_dynamic {
        score += 30;
        reasons.push("Dynamic assembly".to_string());
    }

    // Check for known malicious assembly names
    let assembly_lower = assembly_name.to_lowercase();
    for &suspicious in SUSPICIOUS_ASSEMBLY_NAMES {
        if assembly_lower.contains(&suspicious.to_lowercase()) {
            score += 40;
            reasons.push(format!("Known attack tool: {}", suspicious));
            break;
        }
    }

    // Check for obfuscated names (random-looking characters)
    if looks_obfuscated(assembly_name) {
        score += 20;
        reasons.push("Potentially obfuscated assembly name".to_string());
    }

    // Check for suspicious paths
    if let Some(path) = assembly_path {
        let path_lower = path.to_lowercase();
        for &suspicious_path in SUSPICIOUS_PATHS {
            if path_lower.contains(&suspicious_path.to_lowercase()) {
                score += 15;
                reasons.push(format!("Loaded from suspicious path: {}", suspicious_path));
                break;
            }
        }
    }

    // Cap at 100
    score = score.min(100);

    (score, reasons)
}

/// Check if a name looks obfuscated (high entropy, random chars)
fn looks_obfuscated(name: &str) -> bool {
    // Extract just the assembly name (before comma if versioned)
    let short_name = name.split(',').next().unwrap_or(name);

    // Check for common obfuscation patterns
    // 1. Very short names with mixed case
    if short_name.len() <= 3 {
        return true;
    }

    // 2. Names that are mostly random-looking (high consonant ratio, numbers mixed in)
    let letters: Vec<char> = short_name.chars().filter(|c| c.is_alphabetic()).collect();
    if letters.is_empty() {
        return true;
    }

    let vowels = letters
        .iter()
        .filter(|c| "aeiouAEIOU".contains(**c))
        .count();
    let vowel_ratio = vowels as f32 / letters.len() as f32;

    // Natural English has ~40% vowels, obfuscated names often have much less
    if vowel_ratio < 0.15 && short_name.len() > 5 {
        return true;
    }

    // 3. Contains sequences of digits mixed with letters (like "a1b2c3")
    let has_mixed_digits = short_name.chars().collect::<Vec<_>>().windows(2).any(|w| {
        (w[0].is_alphabetic() && w[1].is_numeric()) || (w[0].is_numeric() && w[1].is_alphabetic())
    });

    if has_mixed_digits && short_name.len() > 8 {
        return true;
    }

    // 4. Contains unusual characters for assembly names
    if short_name.contains('$') || short_name.contains('@') || short_name.contains('#') {
        return true;
    }

    false
}

/// Get CLR version string by querying the Windows Registry.
///
/// Detection strategy:
/// 1. Check for .NET 5+/6+/7+/8+ via the shared host registry key
/// 2. Check for .NET Framework 4.x via the NDP\v4\Full release DWORD
/// 3. Fall back to a generic CLR version string
fn get_clr_version() -> String {
    // Try .NET 5+/Core first (modern runtimes)
    if let Some(version) = get_dotnet_modern_version() {
        return version;
    }

    // Try .NET Framework 4.x via release DWORD
    if let Some(version) = get_dotnet_framework_version() {
        return version;
    }

    // Fallback: indicate architecture but unknown version
    let arch = if cfg!(target_arch = "x86_64") {
        "64-bit"
    } else {
        "32-bit"
    };
    format!("CLR Unknown ({})", arch)
}

/// Query the registry for .NET 5+/6+/7+/8+ (modern .NET) shared host version.
///
/// Checks: HKLM\SOFTWARE\dotnet\Setup\InstalledVersions\{arch}\sharedhost -> "Version"
/// Falls back to running `dotnet --version` if the registry key is not found.
fn get_dotnet_modern_version() -> Option<String> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::*;

    let arch = if cfg!(target_arch = "x86_64") {
        "x64"
    } else if cfg!(target_arch = "x86") {
        "x86"
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x64"
    };

    let subkey = format!(
        "SOFTWARE\\dotnet\\Setup\\InstalledVersions\\{}\\sharedhost\0",
        arch
    );
    let subkey_wide: Vec<u16> = subkey.encode_utf16().collect();

    unsafe {
        let mut key_handle = HKEY::default();
        let result = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey_wide.as_ptr()),
            0,
            KEY_READ,
            &mut key_handle,
        );

        if result.is_err() {
            // Registry key not found; try dotnet CLI as fallback
            return get_dotnet_cli_version();
        }

        // Read the "Version" string value
        let value_name: Vec<u16> = "Version\0".encode_utf16().collect();
        let mut data_type = REG_VALUE_TYPE(0);
        let mut data_size: u32 = 0;

        // First call to get size
        let result = RegQueryValueExW(
            key_handle,
            PCWSTR(value_name.as_ptr()),
            None,
            Some(&mut data_type),
            None,
            Some(&mut data_size),
        );

        if result.is_err() || data_size == 0 {
            let _ = RegCloseKey(key_handle);
            return get_dotnet_cli_version();
        }

        let mut buffer = vec![0u8; data_size as usize];
        let result = RegQueryValueExW(
            key_handle,
            PCWSTR(value_name.as_ptr()),
            None,
            Some(&mut data_type),
            Some(buffer.as_mut_ptr()),
            Some(&mut data_size),
        );

        let _ = RegCloseKey(key_handle);

        if result.is_err() {
            return get_dotnet_cli_version();
        }

        // REG_SZ: decode UTF-16LE string
        if data_type == REG_SZ && buffer.len() >= 2 {
            let chars: Vec<u16> = buffer
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .take_while(|&c| c != 0)
                .collect();
            let version = String::from_utf16_lossy(&chars);
            if !version.is_empty() {
                let arch_label = if cfg!(target_arch = "x86_64") {
                    "64-bit"
                } else {
                    "32-bit"
                };
                return Some(format!(".NET {} ({})", version.trim(), arch_label));
            }
        }
    }

    get_dotnet_cli_version()
}

/// Run `dotnet --version` as a fallback for detecting .NET SDK/runtime version.
fn get_dotnet_cli_version() -> Option<String> {
    let output = std::process::Command::new("dotnet")
        .arg("--version")
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if version.is_empty() {
        return None;
    }

    let arch_label = if cfg!(target_arch = "x86_64") {
        "64-bit"
    } else {
        "32-bit"
    };
    Some(format!(".NET {} ({})", version, arch_label))
}

/// Query the registry for .NET Framework 4.x version via the Release DWORD.
///
/// Reads: HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full -> "Release"
/// Maps the Release value to a human-readable version string.
///
/// Reference: https://learn.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed
fn get_dotnet_framework_version() -> Option<String> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::*;

    let subkey = "SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full\0";
    let subkey_wide: Vec<u16> = subkey.encode_utf16().collect();

    unsafe {
        let mut key_handle = HKEY::default();
        let result = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey_wide.as_ptr()),
            0,
            KEY_READ,
            &mut key_handle,
        );

        if result.is_err() {
            return None;
        }

        // Read the "Release" DWORD value
        let value_name: Vec<u16> = "Release\0".encode_utf16().collect();
        let mut data_type = REG_VALUE_TYPE(0);
        let mut data: u32 = 0;
        let mut data_size: u32 = std::mem::size_of::<u32>() as u32;

        let result = RegQueryValueExW(
            key_handle,
            PCWSTR(value_name.as_ptr()),
            None,
            Some(&mut data_type),
            Some(&mut data as *mut u32 as *mut u8),
            Some(&mut data_size),
        );

        let _ = RegCloseKey(key_handle);

        if result.is_err() {
            return None;
        }

        let release = data;
        let version = map_framework_release_to_version(release);

        let arch_label = if cfg!(target_arch = "x86_64") {
            "64-bit"
        } else {
            "32-bit"
        };
        Some(format!(".NET Framework {} ({})", version, arch_label))
    }
}

/// Map a .NET Framework Release DWORD value to a version string.
///
/// Values sourced from:
/// https://learn.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed#minimum-version
fn map_framework_release_to_version(release: u32) -> &'static str {
    match release {
        // .NET Framework 4.8.1
        r if r >= 533320 => "4.8.1",
        // .NET Framework 4.8
        r if r >= 528040 => "4.8",
        // .NET Framework 4.7.2
        r if r >= 461808 => "4.7.2",
        // .NET Framework 4.7.1
        r if r >= 461308 => "4.7.1",
        // .NET Framework 4.7
        r if r >= 460798 => "4.7",
        // .NET Framework 4.6.2
        r if r >= 394802 => "4.6.2",
        // .NET Framework 4.6.1
        r if r >= 394254 => "4.6.1",
        // .NET Framework 4.6
        r if r >= 393295 => "4.6",
        // .NET Framework 4.5.2
        r if r >= 379893 => "4.5.2",
        // .NET Framework 4.5.1
        r if r >= 378675 => "4.5.1",
        // .NET Framework 4.5
        r if r >= 378389 => "4.5",
        _ => "4.0",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_looks_obfuscated() {
        // Should be detected as obfuscated
        assert!(looks_obfuscated("abc"));
        assert!(looks_obfuscated("xyzpqr")); // Low vowel ratio
        assert!(looks_obfuscated("a1b2c3d4e5"));
        assert!(looks_obfuscated("$MyClass"));

        // Should NOT be detected as obfuscated
        assert!(!looks_obfuscated("System.Collections"));
        assert!(!looks_obfuscated("MyApplication"));
        assert!(!looks_obfuscated("Microsoft.CSharp"));
    }

    #[test]
    fn test_calculate_assembly_risk() {
        // In-memory load should be high risk
        let (score, reasons) = calculate_assembly_risk("SomeAssembly", None, false, true);
        assert!(score >= 50);
        assert!(reasons.iter().any(|r| r.contains("byte array")));

        // Known attack tool should be high risk
        let (score, _) = calculate_assembly_risk(
            "SharpHound, Version=1.0.0.0",
            Some("C:\\Temp\\SharpHound.exe"),
            false,
            false,
        );
        assert!(score >= 40);

        // Normal assembly should be low risk
        let (score, _) = calculate_assembly_risk(
            "System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
            Some("C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\System.Core.dll"),
            false,
            false,
        );
        assert!(score < 20);
    }

    #[test]
    fn test_map_framework_release_to_version() {
        // .NET Framework 4.8.1
        assert_eq!(map_framework_release_to_version(533320), "4.8.1");
        assert_eq!(map_framework_release_to_version(533325), "4.8.1");

        // .NET Framework 4.8
        assert_eq!(map_framework_release_to_version(528040), "4.8");
        assert_eq!(map_framework_release_to_version(528049), "4.8");

        // .NET Framework 4.7.2
        assert_eq!(map_framework_release_to_version(461808), "4.7.2");
        assert_eq!(map_framework_release_to_version(461814), "4.7.2");

        // .NET Framework 4.7.1
        assert_eq!(map_framework_release_to_version(461308), "4.7.1");

        // .NET Framework 4.7
        assert_eq!(map_framework_release_to_version(460798), "4.7");

        // .NET Framework 4.6.2
        assert_eq!(map_framework_release_to_version(394802), "4.6.2");

        // .NET Framework 4.6.1
        assert_eq!(map_framework_release_to_version(394254), "4.6.1");

        // .NET Framework 4.6
        assert_eq!(map_framework_release_to_version(393295), "4.6");

        // .NET Framework 4.5.2
        assert_eq!(map_framework_release_to_version(379893), "4.5.2");

        // .NET Framework 4.5.1
        assert_eq!(map_framework_release_to_version(378675), "4.5.1");

        // .NET Framework 4.5
        assert_eq!(map_framework_release_to_version(378389), "4.5");

        // Unknown/old version
        assert_eq!(map_framework_release_to_version(100000), "4.0");
        assert_eq!(map_framework_release_to_version(0), "4.0");
    }

    // Note: Additional CLR monitor tests are Windows-specific and require ETW access
    // The existing tests above cover core functionality (obfuscation detection, risk scoring, etc.)
    #[test]
    fn test_clr_collector_basics() {
        // This test verifies that the CLR module compiles and basic functions work
        assert!(looks_obfuscated("a1b2c3d4e5"));
        assert!(!looks_obfuscated("System.Core"));
    }
}
