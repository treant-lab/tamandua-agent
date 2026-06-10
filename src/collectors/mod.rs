//! Telemetry collectors for various system events
//!
//! This module provides collectors for monitoring system activity across
//! multiple domains: processes, files, network, registry, and more.

#[cfg(test)]
mod tests;

// ============================================================================
// Core Cross-Platform Collectors
// ============================================================================

pub mod ai_discovery;
pub mod ai_model_loader;
pub mod ai_usage;
pub mod bof_collector;
pub mod cloud;
pub mod credential_theft;
pub mod defense_evasion;
pub mod dns;
pub mod driver_blocklist;
pub mod exploit_mitigation;
pub mod file;
pub mod heavens_gate;
pub mod inference_monitor;
pub mod injection;
pub mod lateral_movement;
pub mod llm_interceptor;
pub mod memory;
pub mod model_format;
pub mod model_scanner;
pub mod named_pipes;
pub mod network;
pub mod network_discovery;
pub mod network_dpi;
pub mod ntdll_write_monitor;
pub mod persistence;
pub mod phantom_dll;
pub mod ppid_spoofing;
pub mod process;
pub mod process_doppelganging;
pub mod process_hollowing;
pub mod ransomware_canary;
pub mod scheduled_tasks;
pub mod script_inspector;
pub mod sleep_masking;
pub mod software_inventory;
pub mod stack_spoofing;
pub mod status;
pub mod usb;

// Container collector is Linux-only (relies on /proc, Docker socket, etc.)
#[cfg(target_os = "linux")]
pub mod container;

// Stub ContainerEvent for non-Linux platforms to allow EventPayload to compile
#[cfg(not(target_os = "linux"))]
pub mod container {
    use serde::{Deserialize, Serialize};

    /// Stub ContainerEvent for non-Linux platforms
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ContainerEvent {
        pub placeholder: String,
    }
}

pub mod browser_protection;
pub mod clipboard;
pub mod firmware;
pub mod input_capture;
pub mod network_anomaly;
pub mod office_email;
pub mod syscall_evasion;

// ad_monitor and identity collectors are Windows-only
#[cfg(target_os = "windows")]
pub mod ad_monitor;
pub mod clipboard_monitor;
pub mod dlp;
pub mod file_journal;
pub mod fim;
pub mod governor_aware_interval;
pub mod health;
#[cfg(target_os = "windows")]
pub mod identity;

// ============================================================================
// Linux-Specific Collectors
// ============================================================================

#[cfg(all(target_os = "linux", feature = "ebpf"))]
#[path = "ebpf/mod.rs"]
pub mod ebpf;

#[cfg(target_os = "linux")]
pub mod linux;

pub mod ebpf_linux;

// Container-escape detection test harness: synthetic BPF ring-buffer payloads
// fed into the exposed parser entry points. Linux-only because it exercises
// types from the `inner` module that only compile on Linux.
#[cfg(all(test, target_os = "linux"))]
mod ebpf_container_escape_tests;

// ============================================================================
// macOS-Specific Collectors
// ============================================================================

/// macOS-specific utilities and helpers
#[cfg(target_os = "macos")]
pub mod macos;

/// macOS Endpoint Security Framework integration
/// Requires: com.apple.developer.endpoint-security.client entitlement
#[cfg(target_os = "macos")]
pub mod endpoint_security;

/// TCC (Transparency, Consent, and Control) monitoring
#[cfg(target_os = "macos")]
pub mod tcc_monitor;

/// XPC service monitoring
#[cfg(target_os = "macos")]
pub mod xpc_monitor;

/// System Extension bridge for receiving file events via XPC
/// This provides an alternative to direct EndpointSecurity integration,
/// allowing the agent to run without root privileges.
#[cfg(target_os = "macos")]
pub mod sysext_bridge;

// Re-export System Extension bridge types for macOS
#[cfg(target_os = "macos")]
pub use sysext_bridge::{FileMonitorEvent, SysExtBridge, SysExtBridgeError, SysExtStats};

// Stub for non-macOS platforms
#[cfg(not(target_os = "macos"))]
pub mod endpoint_security {
    use super::TelemetryEvent;
    use tokio::sync::mpsc;

    #[derive(Debug, Clone, Default)]
    pub struct EndpointSecurityConfig;

    pub struct EndpointSecurityClient;

    impl EndpointSecurityClient {
        pub fn new(
            _config: EndpointSecurityConfig,
            _event_tx: mpsc::Sender<TelemetryEvent>,
        ) -> Result<Self, String> {
            Err("Endpoint Security is only available on macOS".to_string())
        }
        pub fn start(&mut self) -> Result<(), String> {
            Err("Endpoint Security is only available on macOS".to_string())
        }
        pub fn stop(&mut self) {}
        pub fn is_running(&self) -> bool {
            false
        }
    }
}

// ============================================================================
// Windows-Specific Collectors
// ============================================================================

#[cfg(target_os = "windows")]
pub mod registry;

#[cfg(target_os = "windows")]
pub mod etw;

#[cfg(target_os = "windows")]
pub mod amsi;

#[cfg(target_os = "windows")]
pub mod lsass;

#[cfg(target_os = "windows")]
pub mod win_compat;

#[cfg(target_os = "windows")]
pub mod wmi;

#[cfg(target_os = "windows")]
pub mod clr;

// ============================================================================
// Common Types and Re-exports
// ============================================================================

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg(target_os = "windows")]
use crate::integrations;

/// Null collector that never produces events.
/// Used as a placeholder on platforms where certain collectors are not available.
pub struct NullCollector;

impl NullCollector {
    pub fn new() -> Option<Self> {
        None
    }

    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        std::future::pending().await
    }
}

// Re-export commonly used types from submodules for convenience
#[allow(unused_imports)]
pub use defense_evasion::{DefenseEvasionEvent, EvasionType};
#[allow(unused_imports)]
pub use persistence::{PersistenceEvent, PersistenceType};
#[allow(unused_imports)]
pub use process::{CommandLineSpoofingDetector, SpoofingAlert};
// DllSideloadEvent and LolbinExecutionEvent are defined in this module (mod.rs)
#[allow(unused_imports)]
pub use container::ContainerEvent;
#[allow(unused_imports)]
pub use credential_theft::CredentialAttackType;
#[allow(unused_imports)]
pub use fim::{ComplianceFramework, FileCategory, FileIntegrityEvent, IntegrityChangeType};
#[allow(unused_imports)]
pub use lateral_movement::{LateralMovementEvent, LateralMovementType};
#[allow(unused_imports)]
pub use memory::{
    // Adaptive entropy types
    AdaptiveEntropyTracker,
    // Deep memory analysis types
    DeepMemoryScanner,
    DeepScanResult,
    HeapAnomaly,
    HeapAnomalyType,
    InlineHook,
    // Permission transition tracking types
    MemoryRegionState,
    MemoryScanResult,
    MemoryScanner,
    ModuleIntegrityResult,
    ModuleRange,
    PermissionTransitionTracker,
    ShellcodeSignature,
    VadAnomaly,
    VadAnomalyType,
};
#[allow(unused_imports)]
pub use process_hollowing::{
    HollowingAnalysis, HollowingIndicator, InjectionTechnique, ProcessHollowingCollector,
    ProcessHollowingEvent, ProcessImageInfo,
};
#[cfg(target_os = "windows")]
#[allow(unused_imports)]
pub use process_hollowing::{
    HollowingApiMonitor, HollowingDetectorConfig, HollowingSequenceTracker, PebAnomaly,
    PebValidationResult, SuspendedProcessInfo,
};
#[allow(unused_imports)]
pub use scheduled_tasks::ScheduledTaskEvent;
#[allow(unused_imports)]
pub use script_inspector::{ScriptEvent, ScriptType};
#[allow(unused_imports)]
pub use status::{
    CollectorCapabilityStatus, CollectorError, CollectorState, CollectorStatus, PolicyApplyState,
    PolicyStatus,
};
#[allow(unused_imports)]
pub use syscall_evasion::{SyscallEvasionEvent, SyscallEvasionType};

#[allow(unused_imports)]
pub use model_scanner::{
    hash_file, CachedScanResult, ModelScanner, ModelType, ScanCache, ScanResult, ScanStatus, Threat,
};

#[allow(unused_imports)]
pub use ai_model_loader::{
    AIModelLoadEvent, AIModelLoaderCollector, LoadingMethod, ModelInfo, ModelLoadSession,
    ProcessContext,
};

#[allow(unused_imports)]
pub use ntdll_write_monitor::{
    get_tool_signatures,
    // Advanced unhooking detection types
    AdvancedUnhookingEvent,
    CrossProcessUnhookState,
    HookType,
    MemoryOperationType,
    NtdllBaseline,
    NtdllWriteEvent,
    NtdllWriteMonitor,
    NtdllWriteTracker,
    SectionComparisonResult,
    ToolSignature,
    TrackedApiCall,
    UnhookedFunction,
    UnhookingTechnique,
    CRITICAL_FUNCTIONS,
};

#[allow(unused_imports)]
pub use model_format::{detect_model_format, ModelFormat, ModelMetadata};

#[allow(unused_imports)]
pub use bof_collector::{BofCollector, BofCollectorConfig};

#[cfg(target_os = "windows")]
#[allow(unused_imports)]
pub use ppid_spoofing::StartupInfoExTracker;
#[allow(unused_imports)]
pub use ppid_spoofing::{
    PpidSpoofingCollector, PpidSpoofingDetector, PpidSpoofingEvent, ProcessCreationInfo,
    SpoofingDetectionMethod,
};

// Re-export macOS Endpoint Security types when on macOS
#[cfg(target_os = "macos")]
pub use endpoint_security::{EndpointSecurityClient, EndpointSecurityConfig};

#[allow(unused_imports)]
pub use sleep_masking::{SleepMaskingDetector, SleepMaskingEvent, SleepMaskingType};

#[allow(unused_imports)]
pub use stack_spoofing::{scan_all_processes, scan_process, StackSpoofingCollector};

#[allow(unused_imports)]
pub use heavens_gate::{HeavensGateCollector, HeavensGateEvent, HeavensGateTechnique};

#[allow(unused_imports)]
pub use process_doppelganging::{
    DoppelgangingDetectionMethod, DoppelgangingEvent, ProcessDoppelgangingCollector,
    ProcessDoppelgangingEvent,
};

#[allow(unused_imports)]
pub use phantom_dll::{
    scan_all_processes_for_phantom_dlls, scan_process_for_phantom_dlls, PhantomDllCollector,
    PhantomDllConfig, PhantomDllEvent, PhantomIndicator,
};

/// Common event structure for all telemetry data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    /// Unique event identifier
    pub event_id: String,

    /// Event type
    pub event_type: EventType,

    /// Unix timestamp in milliseconds
    pub timestamp: u64,

    /// Event severity
    pub severity: Severity,

    /// Event payload
    pub payload: EventPayload,

    /// Pre-analysis detections
    #[serde(default)]
    pub detections: Vec<Detection>,

    /// Additional metadata
    #[serde(default)]
    pub metadata: std::collections::HashMap<String, String>,
}

/// Event types for all telemetry sources
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    // Process events
    ProcessCreate,
    ProcessTerminate,
    ProcessInject,
    ProcessHollowing,
    // File events
    FileCreate,
    FileModify,
    FileDelete,
    FileRename,
    FileExecute,
    FileExecuteBlocked,
    FileIntegrity,
    // Network events
    NetworkConnect,
    NetworkListen,
    NetworkClose,
    NetworkAnomaly,
    NetworkFingerprint,
    CertificateAnomaly,
    // DNS events
    DnsQuery,
    // LLM events
    LLMRequest,
    // Inference monitoring events
    InferenceRequest,
    InferenceResponse,
    // AI model loading events
    AIModelLoad,
    // Registry events (Windows)
    RegistryCreate,
    RegistrySetValue,
    RegistryDelete,
    // Module events
    ModuleLoad,
    DriverLoad,
    // Authentication events
    AuthLogin,
    AuthLogout,
    AuthFailed,
    // Deception events
    HoneyfileAccess,
    DecoyServiceAccess,
    // Response events
    ResponseAction,
    ForensicCollection,
    // Memory events
    MemoryScan,
    MemoryPermissionChange,
    UnbackedThreadStart,
    // Advanced injection events
    ModuleStomping,
    TransactedHollowing,
    ThreadHijacking,
    ProcessDoppelganging,
    // WMI events (Windows)
    WmiActivity,
    // Named pipe events
    NamedPipeCreate,
    NamedPipeConnect,
    NamedPipeClose,
    // USB events
    UsbConnect,
    UsbDisconnect,
    UsbBlocked,
    // Credential events
    CredentialAccess,
    CredentialTheft,
    BrowserDataAccess,
    // Extension events
    ExtensionInstall,
    // Ransomware events
    RansomwareDetected,
    RansomwareCanaryTriggered,
    // Exploit events
    ExploitAttempt,
    MitigationViolation,
    // Persistence events
    PersistenceInstall,
    PersistenceRemove,
    // Defense evasion events
    DefenseEvasion,
    DllSideload,
    LolbinExecution,
    // EDR blinding / security infrastructure tampering events
    #[serde(rename = "etw_tamper")]
    ETWTamper,
    #[serde(rename = "amsi_bypass")]
    AMSIBypass,
    EventLogTamper,
    CredGuardBypass,
    // Script events
    ScriptExecution,
    ScriptBlock,
    // Lateral movement events
    LateralMovement,
    // Scheduled task events
    ScheduledTask,
    ScheduledTaskCreate,
    ScheduledTaskModify,
    ScheduledTaskDelete,
    ScheduledTaskRun,
    // Cloud/Container events
    CloudMetadataAccess,
    ContainerEscape,
    ContainerActivity,
    KubernetesAnomaly,
    // Clipboard events
    ClipboardAccess,
    // Input capture events
    InputCapture,
    // Firmware events
    FirmwareAnomaly,
    // AD monitoring events
    AdObjectChange,
    AdReplication,
    // Office/Email events
    OfficeDocMacro,
    EmailAttachment,
    EmailPhishing,
    // Software inventory events
    SoftwareInstall,
    SoftwareUninstall,
    SoftwareChange,
    SoftwareInventory,
    // System health events
    SystemHealth,
    // Network discovery events
    NetworkDiscovery,
    // Patch management events
    PatchScan,
    PatchInstall,
    PatchRollback,
    // Antivirus/EDR integration events
    MalwareDetection,
    SecurityToolTamper,
    SecurityCenterChange,
    AntivirusExclusion,
    // Security audit events (GUI/IPC operations)
    SecurityAudit,
    // Stack spoofing detection events
    StackSpoofing,
    // Heaven's Gate (WoW64 abuse) detection events
    HeavensGate,
    // Phantom DLL hollowing detection events
    PhantomDll,
    // Deterministic behavioral risk score export (fenced; off by default)
    #[cfg(feature = "export_risk_score")]
    BehavioralRiskScore,
}

/// Event severity levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Event payload variants
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EventPayload {
    Process(ProcessEvent),
    File(FileEvent),
    Network(NetworkEvent),
    Registry(RegistryEvent),
    Dns(DnsEvent),
    Honeyfile(HoneyfileEvent),
    Wmi(WmiEvent),
    Usb(UsbDeviceEvent),
    BrowserCredential(BrowserCredentialEvent),
    Persistence(PersistenceEvent),
    DefenseEvasion(DefenseEvasionEvent),
    Script(ScriptEvent),
    CredentialTheft(CredentialTheftEvent),
    LateralMovement(LateralMovementEvent),
    ProcessHollowing(ProcessHollowingEvent),
    ScheduledTask(ScheduledTaskEvent),
    Container(ContainerEvent),
    FileIntegrity(FileIntegrityEvent),
    MemoryPermission(MemoryPermissionEvent),
    DllSideload(DllSideloadEvent),
    LolbinExecution(LolbinExecutionEvent),
    SystemHealth(health::SystemHealthEvent),
    EnhancedHealth(crate::health::DetailedHealthMetrics),
    NetworkDiscovery(network_discovery::NetworkDiscoveryEvent),
    /// Windows Defender threat event
    #[cfg(target_os = "windows")]
    DefenderThreat(integrations::DefenderThreatEvent),
    /// LLM API request event
    LLMRequest(llm_interceptor::LLMRequestEvent),
    /// Inference monitoring event (request/response with correlation)
    Inference(inference_monitor::InferenceEvent),
    /// AI model load detection event
    AIModelLoad(ai_model_loader::AIModelLoadEvent),
    /// Generic payload for various events
    Generic(serde_json::Value),
    Custom(serde_json::Value),
    /// Security audit event (driver/agent control operations)
    SecurityAudit(SecurityAuditEvent),
    /// Stack spoofing detection event
    StackSpoofing(StackSpoofingEvent),
    /// Heaven's Gate (WoW64 abuse) detection event
    HeavensGate(heavens_gate::HeavensGateEvent),
    /// Phantom DLL hollowing detection event
    PhantomDll(phantom_dll::PhantomDllEvent),
    /// Deterministic behavioral risk-score snapshot, exported onto the
    /// telemetry stream to pair telemetry with the deterministic score for the
    /// behavioral-sequence ML path. Fenced behind `export_risk_score`; never
    /// emitted unless the feature is compiled in AND runtime export is enabled.
    #[cfg(feature = "export_risk_score")]
    BehavioralRiskScore(crate::analyzers::behavioral::RiskScoreSnapshot),
}

/// Security audit event for tracking administrative/control operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAuditEvent {
    /// Operation performed (e.g., "driver_load", "driver_unload", "agent_stop", "agent_restart")
    pub operation: String,
    /// Whether the operation was successful
    pub success: bool,
    /// Human-readable description
    pub description: String,
    /// Client identifier that initiated the operation
    pub client_id: String,
    /// Client type (e.g., "gui", "cli", "api")
    pub client_type: String,
    /// Additional details
    #[serde(default)]
    pub details: Option<serde_json::Value>,
    /// Error message if operation failed
    #[serde(default)]
    pub error: Option<String>,
}

/// Memory permission change event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryPermissionEvent {
    /// Process ID
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// Process path
    pub process_path: String,
    /// Base address of the memory region
    pub base_address: u64,
    /// Size of the memory region in bytes
    pub region_size: u64,
    /// Previous memory protection flags (raw Windows constant or Linux equivalent)
    pub old_protection: u32,
    /// New memory protection flags
    pub new_protection: u32,
    /// Human-readable old protection string
    pub old_protection_str: String,
    /// Human-readable new protection string
    pub new_protection_str: String,
    /// Memory type: MEM_IMAGE (0x1000000), MEM_MAPPED (0x40000), MEM_PRIVATE (0x20000)
    pub mem_type: u32,
    /// Human-readable memory type string
    pub mem_type_str: String,
    /// Shannon entropy of the region content (0.0-8.0)
    pub entropy: f64,
    /// Transition type classification
    pub transition_type: String,
    /// Whether the thread start address is in an unbacked region (for thread events)
    pub thread_from_unbacked: bool,
    /// Thread ID (for thread start events)
    pub thread_id: Option<u32>,
    /// Thread start address (for thread start events)
    pub thread_start_address: Option<u64>,
}

/// USB device event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDeviceEvent {
    /// Event type (connected, disconnected, blocked)
    pub event_type: String,
    /// Vendor ID
    pub vid: u16,
    /// Product ID
    pub pid: u16,
    /// Device class
    pub device_class: String,
    /// Serial number
    pub serial: Option<String>,
    /// Manufacturer
    pub manufacturer: Option<String>,
    /// Product name
    pub product: Option<String>,
    /// Bus number
    pub bus: u8,
    /// Device address
    pub address: u8,
    /// System device path
    pub device_path: String,
    /// USB speed
    pub speed: Option<String>,
    /// Whether device was blocked
    pub blocked: bool,
    /// Block reason if applicable
    pub block_reason: Option<String>,
}

/// Process event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub path: String,
    pub cmdline: String,
    pub user: String,
    #[serde(with = "hex::serde")]
    pub sha256: Vec<u8>,
    pub entropy: f32,
    pub is_elevated: bool,
    pub parent_name: Option<String>,
    pub parent_path: Option<String>,
    pub is_signed: bool,
    pub signer: Option<String>,
    /// Process start time in milliseconds since UNIX epoch
    #[serde(default)]
    pub start_time: u64,
    /// CPU usage percentage (0.0-100.0)
    #[serde(default)]
    pub cpu_usage: f32,
    /// Private working set in bytes
    #[serde(default)]
    pub memory_bytes: u64,
    /// PE VersionInfo CompanyName (Windows PE files only)
    #[serde(default)]
    pub company_name: Option<String>,
    /// PE VersionInfo FileDescription (Windows PE files only)
    #[serde(default)]
    pub file_description: Option<String>,
    /// PE VersionInfo ProductName (Windows PE files only)
    #[serde(default)]
    pub product_name: Option<String>,
    /// PE VersionInfo FileVersion (Windows PE files only)
    #[serde(default)]
    pub file_version: Option<String>,
    /// Selected environment variables captured at process creation.
    /// Only captures security-relevant variables, not the full environment.
    #[serde(default)]
    pub environment: Option<std::collections::HashMap<String, String>>,
}

/// File event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    pub path: String,
    pub old_path: Option<String>,
    pub operation: String,
    pub pid: u32,
    pub process_name: String,
    #[serde(with = "hex::serde")]
    pub sha256: Vec<u8>,
    pub size: u64,
    pub entropy: f32,
    pub file_type: String,
}

/// Network event data
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub pid: u32,
    pub process_name: String,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub protocol: String,
    pub direction: String,
    /// Connection state reported by the OS when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Bytes sent (0 if not tracked)
    #[serde(default)]
    pub bytes_sent: u64,
    /// Bytes received (0 if not tracked)
    #[serde(default)]
    pub bytes_received: u64,
    /// Best single domain associated with remote_ip from recent DNS cache or packet metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// All recent DNS domains associated with remote_ip.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_candidates: Vec<String>,
    /// True only when encryption is directly observed. Omitted otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_encrypted: Option<bool>,
    /// TLS SNI extracted from traffic when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// Alias for SNI kept for downstream compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_sni: Option<String>,
    /// TLS version extracted from handshake when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_version: Option<String>,
    /// JA3 client TLS fingerprint when packet data is available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ja3: Option<String>,
    /// JA3S server TLS fingerprint when packet data is available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ja3s: Option<String>,
    /// Parsed certificate metadata when it can be extracted from TLS traffic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<serde_json::Value>,
    /// Certificate risk analysis when certificate metadata is available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_risk: Option<serde_json::Value>,
    /// Collector-specific enrichment provenance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrichment: Option<serde_json::Value>,
}

/// Registry event data (Windows)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEvent {
    pub key_path: String,
    pub value_name: Option<String>,
    pub value_data: Option<String>,
    pub operation: String,
    pub pid: u32,
    pub process_name: String,
}

impl NetworkEvent {
    /// Add only enrichment backed by local observations or conservative protocol facts.
    pub fn apply_common_enrichment(&mut self) {
        if self.domain_candidates.is_empty() && !self.remote_ip.is_empty() {
            self.domain_candidates = crate::collectors::dns::lookup_domains_for_ip(&self.remote_ip);
        }

        if self.domain.is_none() && self.domain_candidates.len() == 1 {
            self.domain = self.domain_candidates.first().cloned();
        }

        if self.tls_sni.is_none() {
            self.tls_sni = self.sni.clone();
        }

        if self.enrichment.is_none() {
            let mut enrichment = serde_json::Map::new();
            if !self.domain_candidates.is_empty() {
                enrichment.insert(
                    "domain_source".to_string(),
                    serde_json::Value::String("recent_dns_cache".to_string()),
                );
            }
            if !enrichment.is_empty() {
                self.enrichment = Some(serde_json::Value::Object(enrichment));
            }
        }
    }
}

/// DNS event data
#[derive(Debug, Clone, Deserialize)]
pub struct DnsEvent {
    pub pid: u32,
    pub process_name: String,
    pub query: String,
    pub query_type: String,
    pub responses: Vec<String>,
}

impl Serialize for DnsEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let resolved_ips: Vec<&String> = self
            .responses
            .iter()
            .filter(|answer| answer.parse::<std::net::IpAddr>().is_ok())
            .collect();

        let mut state = serializer.serialize_struct("DnsEvent", 8)?;
        state.serialize_field("pid", &self.pid)?;
        state.serialize_field("process_name", &self.process_name)?;
        state.serialize_field("query", &self.query)?;
        state.serialize_field("domain", &self.query)?;
        state.serialize_field("query_type", &self.query_type)?;
        state.serialize_field("responses", &self.responses)?;
        state.serialize_field("answers", &self.responses)?;
        state.serialize_field("resolved_ips", &resolved_ips)?;
        state.end()
    }
}

/// Honeyfile access event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneyfileEvent {
    pub path: String,
    pub operation: String,
    pub pid: u32,
    pub process_name: String,
    pub process_path: String,
    #[serde(with = "hex::serde")]
    pub process_sha256: Vec<u8>,
}

/// WMI activity event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WmiEvent {
    /// Activity type (subscription_created, query_executed, process_created, etc.)
    pub activity_type: String,
    /// WMI namespace (ROOT\subscription, ROOT\CIMV2, etc.)
    pub namespace: String,
    /// WMI class involved (__EventFilter, __EventConsumer, Win32_Process, etc.)
    pub wmi_class: String,
    /// Object name (filter name, consumer name, query, etc.)
    pub object_name: String,
    /// Object details (query text, script content, command line, etc.)
    pub object_details: Option<String>,
    /// Process ID that initiated the WMI activity
    pub pid: u32,
    /// Process name that initiated the WMI activity
    pub process_name: String,
    /// Process command line
    pub process_cmdline: Option<String>,
    /// Remote host if applicable (for WMIC /node:)
    pub remote_host: Option<String>,
    /// User account
    pub user: String,
    /// Attack pattern name if detected
    pub attack_pattern: Option<String>,
}

/// Detection result from local analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub detection_type: DetectionType,
    pub rule_name: String,
    pub confidence: f32,
    pub description: String,
    #[serde(default)]
    pub mitre_tactics: Vec<String>,
    #[serde(default)]
    pub mitre_techniques: Vec<String>,
}

/// Browser credential access event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserCredentialEvent {
    /// Browser name (Chrome, Firefox, Edge, etc.)
    pub browser: String,
    /// Browser profile path accessed
    pub profile_path: String,
    /// Specific data file accessed (Login Data, cookies.sqlite, etc.)
    pub data_file: String,
    /// Type of data (credentials, cookies, history, extensions)
    pub data_type: String,
    /// Access operation (read, copy, sqlite_query)
    pub operation: String,
    /// Process ID that accessed the data
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// Process path
    pub process_path: String,
    /// Process command line
    pub process_cmdline: String,
    /// Whether the accessor is the browser itself
    pub is_browser_process: bool,
    /// Detected stealer malware family (if any)
    pub stealer_family: Option<String>,
    /// SHA256 of the accessing process
    #[serde(with = "hex::serde")]
    pub process_sha256: Vec<u8>,
}

/// Credential theft detection event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialTheftEvent {
    /// Attack type classification
    pub attack_type: String,
    /// MITRE ATT&CK technique ID
    pub mitre_technique: String,
    /// Target resource (SAM, NTDS.dit, credential file, etc.)
    pub target: String,
    /// Process that attempted the access
    pub process_name: String,
    /// Process ID
    pub pid: u32,
    /// Process path
    pub process_path: String,
    /// Process command line
    pub process_cmdline: String,
    /// User context
    pub username: String,
    /// Whether the access was blocked
    pub blocked: bool,
    /// Additional details about the attack
    pub details: String,
}

/// DLL sideloading detection event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DllSideloadEvent {
    /// Host executable name (e.g., "MpCmdRun.exe")
    pub host_exe: String,
    /// Full path to the host executable
    pub host_path: String,
    /// Name of the sideloaded DLL
    pub dll_name: String,
    /// Full path to the sideloaded DLL
    pub dll_path: String,
    /// Expected installation directory for the host executable
    pub expected_path: String,
    /// Code signer of the host executable (if available)
    pub host_signer: String,
    /// Code signer of the DLL (if available)
    pub dll_signer: String,
    /// Process ID of the host executable
    pub pid: u32,
    /// Whether the host is running from an unexpected location
    pub unexpected_location: bool,
    /// Whether there is a signer mismatch between host and DLL
    pub signer_mismatch: bool,
}

/// LOLBin (living-off-the-land binary) execution event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LolbinExecutionEvent {
    /// Process name of the LOLBin
    pub process_name: String,
    /// Full path to the LOLBin process
    pub process_path: String,
    /// Process ID
    pub pid: u32,
    /// Parent process ID
    pub ppid: u32,
    /// Parent process name
    pub parent_name: String,
    /// Full command line arguments
    pub cmdline: String,
    /// User context
    pub user: String,
    /// Whether the process is elevated (admin)
    pub is_elevated: bool,
    /// Computed risk score (0.0 - 1.0)
    pub risk_score: f32,
    /// Suspicious argument patterns matched
    pub matched_patterns: Vec<String>,
    /// Whether the parent process is anomalous for this LOLBin
    pub parent_anomaly: bool,
    /// MITRE ATT&CK technique ID
    pub mitre_technique: String,
    /// MITRE ATT&CK subtechnique description
    pub mitre_description: String,
    /// Hour of day (0-23) when the LOLBin executed
    pub hour_of_day: u8,
}

/// Detection types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionType {
    Yara,
    Sigma,
    Entropy,
    Behavioral,
    Ioc,
    Honeyfile,
    Ransomware,
    Malware,
    Ml,
    MemoryThreat,
    DriverThreat,
    ThreatIntel,
    WmiPersistence,
    UsbThreat,
    ExploitMitigation,
    BrowserStealer,
    CredentialTheft,
    Persistence,
    DefenseEvasion,
    ScriptThreat,
    LateralMovement,
    ProcessHollowing,
    ModuleStomping,
    TransactedHollowing,
    ThreadHijacking,
    ProcessDoppelganging,
    ScheduledTask,
    ContainerThreat,
    ClipboardCapture,
    InputCapture,
    FirmwareThreat,
    Firmware,
    NetworkAnomaly,
    AdThreat,
    OfficeMacro,
    OfficeEmail,
    FileIntegrity,
    NetworkFingerprint,
    CertificateAnomaly,
    DllSideloading,
    LolbinAbuse,
    LLMRequest,
    AIModelLoad,
    /// Supply-chain compromise behavior from package managers/installers
    SupplyChain,
    /// Command line spoofing detection (MITRE T1564.010)
    CommandLineSpoofing,
    /// Stack spoofing / call stack masking detection (MITRE T1055, T1562.001)
    StackSpoofing,
    /// Heaven's Gate (WoW64 abuse) detection (MITRE T1055, T1106, T1562.001)
    HeavensGate,
    /// Phantom DLL hollowing detection (MITRE T1055.012, T1070.004)
    PhantomDllHollowing,
}

/// Stack spoofing / call stack masking detection event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackSpoofingEvent {
    /// Process ID
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// Process path
    pub process_path: String,
    /// Thread ID where spoofing was detected
    pub thread_id: u32,
    /// Stack spoofing technique detected
    pub technique: String,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// Stack pointer (RSP/ESP) at detection
    pub stack_pointer: u64,
    /// Number of suspicious return addresses found
    pub suspicious_return_count: u32,
    /// Number of frame chain anomalies found
    pub frame_anomaly_count: u32,
    /// First suspicious return address (if any)
    pub first_suspicious_return: Option<u64>,
    /// Description of the first suspicious return issue
    pub first_return_issue: Option<String>,
    /// Frame anomaly types found
    pub anomaly_types: Vec<String>,
    /// Evidence details
    pub evidence: Vec<String>,
    /// MITRE ATT&CK technique ID
    pub mitre_technique: String,
}

impl TelemetryEvent {
    /// Create a new event with auto-generated ID and timestamp
    pub fn new(event_type: EventType, severity: Severity, mut payload: EventPayload) -> Self {
        let mut metadata = std::collections::HashMap::new();

        match &mut payload {
            EventPayload::Network(network) => {
                network.apply_common_enrichment();

                let classification = network
                    .domain
                    .as_deref()
                    .and_then(crate::collectors::ai_usage::classify_domain)
                    .or_else(|| {
                        network
                            .tls_sni
                            .as_deref()
                            .and_then(crate::collectors::ai_usage::classify_domain)
                    })
                    .or_else(|| {
                        network
                            .domain_candidates
                            .iter()
                            .find_map(|domain| crate::collectors::ai_usage::classify_domain(domain))
                    })
                    .or_else(|| {
                        crate::collectors::ai_usage::classify_local_port(
                            &network.remote_ip,
                            network.remote_port,
                        )
                    });

                if let Some(classification) = classification {
                    for (key, value) in crate::collectors::ai_usage::metadata_pairs(classification)
                    {
                        metadata.insert(key.to_string(), value);
                    }
                }
            }
            EventPayload::Dns(dns) => {
                crate::collectors::dns::record_dns_event(dns);

                if let Some(classification) =
                    crate::collectors::ai_usage::classify_domain(&dns.query)
                {
                    for (key, value) in crate::collectors::ai_usage::metadata_pairs(classification)
                    {
                        metadata.insert(key.to_string(), value);
                    }
                }
            }
            _ => {}
        }

        let default_source = match event_type {
            EventType::ProcessCreate | EventType::ProcessTerminate => Some("endpoint_process"),
            EventType::DnsQuery => Some("endpoint_dns"),
            EventType::NetworkConnect | EventType::NetworkListen | EventType::NetworkClose => {
                Some("endpoint_network")
            }
            EventType::FileCreate
            | EventType::FileModify
            | EventType::FileDelete
            | EventType::FileExecute => Some("endpoint_file"),
            EventType::RegistryCreate | EventType::RegistrySetValue | EventType::RegistryDelete => {
                Some("endpoint_registry")
            }
            EventType::ResponseAction => Some("agent_response"),
            _ => None,
        };

        if let Some(source) = default_source {
            metadata
                .entry("source".to_string())
                .or_insert_with(|| source.to_string());
            metadata
                .entry("provider".to_string())
                .or_insert_with(|| "tamandua_agent".to_string());
        }

        Self {
            event_id: Uuid::new_v4().to_string(),
            event_type,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            severity,
            payload,
            detections: Vec::new(),
            metadata,
        }
    }

    /// Add a detection to the event
    pub fn add_detection(&mut self, detection: Detection) {
        self.detections.push(detection);
    }
}
