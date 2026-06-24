//! Agent configuration management

pub mod container;
pub mod credentials;
pub mod exclusions;
pub mod health_check;
pub mod manager;
pub mod rollback;
pub mod signing;
pub mod validator;

// Re-export container detection types for convenience
pub use container::{
    detect_runtime, get_container_info, is_containerized, ContainerInfo, ContainerRuntime,
};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use uuid::Uuid;

/// Performance profile presets controlling collector intervals and resource usage.
///
/// - `Aggressive`: Maximum detection coverage. All collectors enabled with tight
///   intervals. Higher CPU/memory usage (~15-25%). Best for high-value assets.
/// - `Balanced`: Default profile. Good detection with reasonable resource usage
///   (~5-10% CPU). Suitable for most workstations and servers.
/// - `Lightweight`: Minimal footprint (~1-3% CPU). Only core collectors active
///   with relaxed intervals. Disables heavy scanners (memory forensics,
///   process hollowing, DPI, credential theft, etc.). Best for performance-
///   sensitive systems or large fleet deployments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceProfile {
    Aggressive,
    Balanced,
    Lightweight,
}

/// A named Ed25519 public key used for verifying signed configuration updates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSigningKey {
    /// Identifier for key rotation (e.g. "production-2026-01")
    pub key_id: String,
    /// Base64-encoded Ed25519 public key (32 bytes)
    pub public_key: String,
}

/// Agent configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    /// Unique agent identifier
    pub agent_id: String,

    /// Backend server URL
    pub server_url: String,

    /// Organization/tenant identifier assigned during enrollment
    pub organization_id: Option<String>,

    /// Authentication token
    pub auth_token: Option<String>,

    /// Heartbeat interval in seconds
    pub heartbeat_interval_seconds: u32,

    /// Telemetry batch size
    pub batch_size: usize,

    /// Batch timeout in seconds
    pub batch_timeout_seconds: u32,

    /// Reconnection delay in seconds (base for exponential backoff)
    pub reconnect_delay_seconds: u32,

    /// Maximum reconnection attempts (0 = infinite)
    pub max_reconnect_attempts: u32,

    /// Connection timeout in seconds
    pub connection_timeout_seconds: u32,

    /// Enable YARA scanning
    pub yara_enabled: bool,

    /// Enable entropy checking
    pub entropy_check_enabled: bool,

    /// Entropy threshold for suspicious files
    pub entropy_threshold: f32,

    /// Paths to exclude from monitoring
    pub excluded_paths: Vec<String>,

    /// Processes to exclude from monitoring
    pub excluded_processes: Vec<String>,

    /// File patterns to monitor
    pub monitored_file_patterns: Vec<String>,

    /// Enable honeyfile monitoring
    pub honeyfiles_enabled: bool,

    /// Honeyfile paths
    pub honeyfile_paths: Vec<String>,

    /// Transport settings (backup servers, cert pinning)
    #[serde(default)]
    pub transport: TransportConfig,

    /// TLS settings
    pub tls: TlsConfig,

    /// Collector configuration - enables/disables individual collectors
    #[serde(default)]
    pub collectors: CollectorConfig,

    /// Collector performance tuning (intervals, thresholds)
    #[serde(default)]
    pub collector_tuning: CollectorTuning,

    /// Enable local analysis pipeline (behavioral detection, IOC matching)
    #[serde(default = "default_local_analysis")]
    pub local_analysis_enabled: bool,

    /// Maximum size of local event queue for offline operation
    #[serde(default)]
    pub local_queue_size: Option<usize>,

    /// Interval in seconds for the health metrics collector (default: 60)
    #[serde(default = "default_health_interval")]
    pub health_interval_seconds: u32,

    /// Enable ML-based pre-execution scanning (requires onnx feature)
    #[serde(default = "default_ml_enabled")]
    pub ml_scanning_enabled: bool,

    /// ML confidence threshold for malware classification (0.0 - 1.0)
    #[serde(default)]
    pub ml_confidence_threshold: Option<f32>,

    /// Path to the ONNX model file (optional, uses default path if not set)
    #[serde(default)]
    pub ml_model_path: Option<String>,

    /// ML inference timeout in seconds (default: 30)
    #[serde(default = "default_ml_inference_timeout")]
    pub ml_inference_timeout_secs: u64,

    /// Feature-based local ML scanning configuration.
    /// Controls the lightweight PE-feature ML engine that runs independently
    /// of the image-based ONNX scanner.
    #[serde(default)]
    pub ml_local: MLLocalConfig,

    /// Pre-execution blocking configuration (Linux only).
    /// Uses fanotify permission events to intercept and optionally block
    /// file executions based on ML scanning results.
    #[serde(default)]
    pub pre_execution_blocking: PreExecutionBlockingConfig,

    /// Offline detection configuration.
    /// Controls the autonomous local ML + YARA detection pipeline used when
    /// the backend ML service is unreachable.
    #[serde(default)]
    pub offline_detection: OfflineDetectionConfig,

    /// USB device enforcement policy configuration.
    /// Controls allowlist/blocklist rules, enforcement mode, and notification
    /// settings for USB device connections.
    #[serde(default)]
    pub usb_enforcement: UsbEnforcementConfig,

    /// Syscall evasion detection configuration
    #[serde(default)]
    pub syscall_evasion: SyscallEvasionConfig,

    /// Network DPI advanced fingerprinting and behavioral baseline configuration
    #[serde(default)]
    pub network_dpi: NetworkDpiConfig,

    /// Network discovery configuration (SentinelOne Ranger-style).
    /// Passive and active device discovery, fingerprinting, and scan coordination.
    #[serde(default)]
    pub network_discovery: crate::collectors::network_discovery::NetworkDiscoveryConfig,

    /// EDR blinding attack detection configuration (ETW patching, AMSI bypass,
    /// Event Log tampering, Credential Guard bypass).
    #[serde(default)]
    pub edr_blinding: EdrBlindingConfig,

    /// File modification journal for ransomware rollback.
    /// Records file modifications with before-snapshots enabling point-in-time
    /// rollback of changes associated with an attack chain.
    #[serde(default)]
    pub file_journal: FileJournalConfig,

    /// DLP (Data Loss Prevention) content classification and monitoring.
    /// Scans files written to sensitive destinations (USB, cloud sync, network
    /// shares) and clipboard content for PII, credentials, regulated data,
    /// and source code secrets.
    #[serde(default)]
    pub dlp: crate::collectors::dlp::DlpConfig,

    /// Self-update configuration.
    /// Controls automatic update checking, verification, and installation.
    #[serde(default)]
    pub updater: crate::updater::UpdateConfig,

    /// Performance profile: "aggressive", "balanced", or "lightweight".
    /// Controls collector intervals, scan depths, and which heavy collectors
    /// are enabled. After loading, call `apply_performance_profile()` to
    /// override `collector_tuning` and `collectors` based on the profile.
    #[serde(default = "default_performance_profile")]
    pub performance_profile: PerformanceProfile,

    /// Ed25519 public keys used to verify signed configuration updates.
    /// Multiple keys support key rotation -- any matching key_id with a
    /// valid signature passes verification.
    #[serde(default)]
    pub config_signing_keys: Option<Vec<ConfigSigningKey>>,

    /// Whether to enforce config signature verification.
    /// When `true`, unsigned or incorrectly signed configs are rejected.
    /// When `false` (default), verification failures are logged as warnings
    /// but the config is still applied (report-only mode for gradual rollout).
    #[serde(default)]
    pub config_signing_enforce: Option<bool>,

    /// Resource governor configuration.
    /// Enforces hard CPU/memory/disk limits with graduated pressure levels.
    /// Collectors automatically throttle when the governor detects overuse.
    #[serde(default)]
    pub resource_governor: crate::resource_governor::ResourceGovernorConfig,

    /// Event triage configuration.
    /// Agent-side deduplication and sampling to reduce telemetry volume by 80-95%.
    #[serde(default)]
    pub event_triage: crate::event_triage::EventTriageConfig,

    /// Maximum CPU usage percentage the agent should target (0.0-100.0).
    /// When the agent's own CPU usage exceeds this value and adaptive
    /// throttling is enabled, collectors will progressively increase their
    /// sleep intervals. Set to 0 to disable the cap.
    #[serde(default = "default_max_cpu_percent")]
    pub max_cpu_percent: f32,

    /// Multiplier applied to hardcoded sub-loop intervals inside heavy
    /// collectors (injection, defense_evasion, credential_theft,
    /// exploit_mitigation).  The performance profile sets this automatically:
    ///   - Aggressive: 1.0 (keep original intervals)
    ///   - Balanced:   3.0 (e.g. 500ms -> 1.5s, 2s -> 6s)
    ///   - Lightweight: 10.0 (e.g. 500ms -> 5s, 2s -> 20s)
    #[serde(default = "default_sub_loop_interval_multiplier")]
    pub sub_loop_interval_multiplier: f32,

    /// Enable full-scan-only features (heavy sub-tasks that are disabled by
    /// default to conserve resources).  When `false`, the following are
    /// skipped:
    ///   - injection: poolparty_monitor, process_doppelganging, process_hollowing
    ///   - defense_evasion: vm_sandbox_evasion, credential_guard_bypass
    ///   - exploit_mitigation: heap_spray_monitor
    ///   - memory: module_integrity_check, permission_transition_tracking
    ///
    /// Set to `true` in aggressive profile or when triggered by the
    /// "full_scan" command from the server.
    #[serde(default)]
    pub full_scan_features: bool,

    /// TCC (Transparency, Consent, and Control) monitor interval in seconds (macOS only).
    /// Polls the TCC database for permission changes. Default: 30 seconds.
    #[serde(default = "default_tcc_monitor_interval")]
    pub tcc_monitor_interval_seconds: Option<u32>,

    /// XPC service monitor interval in seconds (macOS only).
    /// Scans for new XPC services and connections. Default: 60 seconds.
    #[serde(default = "default_xpc_monitor_interval")]
    pub xpc_monitor_interval_seconds: Option<u32>,

    /// IPC (inter-process communication) configuration for GUI/CLI connectivity.
    #[serde(default)]
    pub ipc: IpcConfig,
}

/// IPC server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IpcConfig {
    /// Enable legacy token-hash authentication for backwards compatibility.
    ///
    /// When `false` (default for production), the server rejects legacy
    /// `Authenticate { token_hash }` messages and requires challenge-response
    /// authentication via `RequestChallenge` + `AuthenticateChallenge`.
    ///
    /// When `true` (recommended for development/migration), both legacy and
    /// challenge-response authentication are accepted. A warning is logged
    /// when legacy auth is used.
    ///
    /// **Security Note**: Legacy auth is vulnerable to replay attacks.
    /// Disable in production once all clients are migrated to challenge-response.
    pub legacy_auth_enabled: bool,
}

impl Default for IpcConfig {
    fn default() -> Self {
        // Default to legacy auth DISABLED for security
        // Set to true during migration period or for development
        Self {
            legacy_auth_enabled: false,
        }
    }
}

fn default_health_interval() -> u32 {
    60
}

fn default_local_analysis() -> bool {
    true
}

fn default_ml_enabled() -> bool {
    true
}

fn default_ml_inference_timeout() -> u64 {
    30
}

fn default_performance_profile() -> PerformanceProfile {
    PerformanceProfile::Balanced
}

fn default_max_cpu_percent() -> f32 {
    15.0
}

fn default_sub_loop_interval_multiplier() -> f32 {
    3.0 // Balanced default
}

fn default_tcc_monitor_interval() -> Option<u32> {
    Some(30)
}

fn default_xpc_monitor_interval() -> Option<u32> {
    Some(60)
}

/// Configuration for individual collectors
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CollectorConfig {
    // Core collectors (enabled by default)
    pub process_enabled: bool,
    pub file_enabled: bool,
    pub network_enabled: bool,
    pub dns_enabled: bool,

    // Advanced detection collectors
    pub injection_enabled: bool,
    pub named_pipes_enabled: bool,
    pub usb_enabled: bool,
    pub ransomware_canary_enabled: bool,
    pub driver_blocklist_enabled: bool,
    pub memory_enabled: bool,
    pub network_dpi_enabled: bool,
    pub network_anomaly_enabled: bool,
    pub cloud_enabled: bool,
    pub exploit_mitigation_enabled: bool,
    pub defense_evasion_enabled: bool,
    pub persistence_enabled: bool,
    pub script_inspector_enabled: bool,
    pub credential_theft_enabled: bool,
    pub lateral_movement_enabled: bool,
    pub container_enabled: bool,
    pub process_hollowing_enabled: bool,
    pub scheduled_tasks_enabled: bool,
    pub firmware_enabled: bool,
    pub clipboard_enabled: bool,
    pub browser_protection_enabled: bool,
    pub input_capture_enabled: bool,
    pub office_email_enabled: bool,
    pub ad_monitor_enabled: bool,
    pub health_enabled: bool,
    pub syscall_evasion_enabled: bool,
    pub software_inventory_enabled: bool,
    pub ai_discovery_enabled: bool,
    pub fim_enabled: bool,
    pub dlp_enabled: bool,
    pub clipboard_dlp_enabled: bool,
    pub network_discovery_enabled: bool,
    /// NTDLL write monitor - detects NTDLL unhooking and syscall evasion
    pub ntdll_write_monitor_enabled: bool,

    // Windows-specific collectors
    #[cfg(target_os = "windows")]
    pub identity_enabled: bool,
    #[cfg(target_os = "windows")]
    pub registry_enabled: bool,
    #[cfg(target_os = "windows")]
    pub etw_enabled: bool,
    #[cfg(target_os = "windows")]
    pub amsi_enabled: bool,
    #[cfg(target_os = "windows")]
    pub lsass_enabled: bool,
    #[cfg(target_os = "windows")]
    pub wmi_enabled: bool,
    #[cfg(target_os = "windows")]
    pub clr_enabled: bool,

    /// ETW collector sub-configuration (Windows-only).
    /// Controls ring buffer, tamper detection, health checks,
    /// per-provider rate limits, and per-provider enable/disable.
    #[cfg(target_os = "windows")]
    #[serde(default)]
    pub etw: EtwCollectorConfig,

    // Linux-specific collectors
    #[cfg(target_os = "linux")]
    pub ebpf_enabled: bool,
    #[cfg(target_os = "linux")]
    pub auditd_enabled: bool,

    // macOS-specific collectors
    #[cfg(target_os = "macos")]
    pub tcc_monitor_enabled: bool,
    #[cfg(target_os = "macos")]
    pub xpc_monitor_enabled: bool,
    #[cfg(target_os = "macos")]
    pub endpoint_security_enabled: bool,
    #[cfg(target_os = "macos")]
    pub sysext_bridge_enabled: bool,
}

/// ETW collector sub-configuration.
/// Nested under `[collectors.etw]` in agent.toml.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EtwCollectorConfig {
    /// Whether the ETW collector is enabled (mirrors `etw_enabled`)
    pub enabled: bool,

    /// ETW session name
    pub session_name: String,

    /// Ring buffer capacity (number of events)
    pub ring_buffer_size: usize,

    /// Enable ETW session tamper detection
    pub tamper_detection: bool,

    /// Health check interval in seconds
    pub health_check_interval_secs: u64,

    /// Per-provider event rate limit (events/sec)
    pub provider_rate_limit: u64,

    /// Per-provider enable/disable
    #[serde(default)]
    pub providers: EtwProviderToggles,
}

impl Default for EtwCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            session_name: "TamanduaEDR".to_string(),
            ring_buffer_size: 100_000,
            tamper_detection: true,
            health_check_interval_secs: 30,
            provider_rate_limit: 10_000,
            providers: EtwProviderToggles::default(),
        }
    }
}

/// Per-provider enable/disable toggles for the ETW collector.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EtwProviderToggles {
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

impl Default for EtwProviderToggles {
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

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            // Core collectors - enabled by default
            process_enabled: true,
            file_enabled: true,
            network_enabled: true,
            dns_enabled: true,

            // Advanced detection collectors - enabled by default
            injection_enabled: true,
            named_pipes_enabled: true,
            usb_enabled: true,
            ransomware_canary_enabled: true,
            driver_blocklist_enabled: true,
            memory_enabled: true,
            network_dpi_enabled: true,
            network_anomaly_enabled: true,
            cloud_enabled: true,
            exploit_mitigation_enabled: true,
            defense_evasion_enabled: true,
            persistence_enabled: true,
            script_inspector_enabled: true,
            credential_theft_enabled: true,
            lateral_movement_enabled: true,
            container_enabled: true,
            process_hollowing_enabled: true,
            scheduled_tasks_enabled: true,
            firmware_enabled: true,
            clipboard_enabled: true,
            browser_protection_enabled: true,
            input_capture_enabled: true,
            office_email_enabled: true,
            ad_monitor_enabled: true,
            health_enabled: true,
            syscall_evasion_enabled: true,
            software_inventory_enabled: true,
            ai_discovery_enabled: true,
            fim_enabled: true,
            dlp_enabled: true,
            clipboard_dlp_enabled: true,
            network_discovery_enabled: false, // Off by default - opt-in feature
            // Advanced Windows memory integrity checks are useful, but they are
            // too expensive for the default posture and baseline benchmarks.
            // Enable them through the aggressive profile or explicit policy.
            ntdll_write_monitor_enabled: false,

            // Windows-specific collectors
            #[cfg(target_os = "windows")]
            identity_enabled: true,
            #[cfg(target_os = "windows")]
            registry_enabled: true,
            #[cfg(target_os = "windows")]
            etw_enabled: true,
            #[cfg(target_os = "windows")]
            amsi_enabled: true,
            #[cfg(target_os = "windows")]
            lsass_enabled: true,
            #[cfg(target_os = "windows")]
            wmi_enabled: true,
            #[cfg(target_os = "windows")]
            clr_enabled: true,
            #[cfg(target_os = "windows")]
            etw: EtwCollectorConfig::default(),

            // Linux-specific collectors
            #[cfg(target_os = "linux")]
            ebpf_enabled: false,
            #[cfg(target_os = "linux")]
            auditd_enabled: false,

            // macOS-specific collectors
            #[cfg(target_os = "macos")]
            tcc_monitor_enabled: true,
            #[cfg(target_os = "macos")]
            xpc_monitor_enabled: true,
            #[cfg(target_os = "macos")]
            endpoint_security_enabled: true,
            #[cfg(target_os = "macos")]
            sysext_bridge_enabled: true,
        }
    }
}

/// Performance tuning configuration for collectors
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CollectorTuning {
    /// Memory forensics scan interval in seconds (default: 30s, matches CrowdStrike)
    #[serde(default = "default_memory_scan_interval")]
    pub memory_scan_interval_secs: u64,

    /// DNS UDP table polling interval in milliseconds (default: 500ms, aggressive)
    #[serde(default = "default_dns_poll_interval")]
    pub dns_poll_interval_ms: u64,

    /// Network connection table polling in milliseconds (default: 1000ms)
    #[serde(default = "default_network_poll_interval")]
    pub network_poll_interval_ms: u64,

    /// Process enumeration interval in seconds (default: 5s)
    #[serde(default = "default_process_scan_interval")]
    pub process_scan_interval_secs: u64,

    /// Enable smart diffing for process scans (default: true)
    #[serde(default = "default_true_bool")]
    pub process_smart_diff_enabled: bool,

    /// Registry polling interval in seconds (default: 2s)
    #[serde(default = "default_registry_poll_interval")]
    pub registry_poll_interval_secs: u64,

    /// Adaptive throttling: enable CPU-based auto-adjustment (default: true)
    #[serde(default = "default_true_bool")]
    pub adaptive_throttling_enabled: bool,

    /// CPU threshold percentage to trigger throttling (default: 25%)
    #[serde(default = "default_cpu_threshold")]
    pub cpu_throttle_threshold: f32,

    /// Skip expensive per-process analysis (SHA256 hash, code signatures, PE
    /// version info, YARA scans).  Automatically enabled in lightweight mode.
    /// Reduces CPU usage significantly at the cost of less rich process telemetry.
    #[serde(default)]
    pub skip_expensive_analysis: bool,

    /// Track memory permission transitions (RW->RX, new RWX allocations).
    /// When enabled, the memory collector snapshots each process's memory layout
    /// and detects protection changes between scan cycles.
    #[serde(default = "default_true_bool")]
    pub track_permission_changes: bool,

    /// Detect unbacked executable memory regions (MEM_PRIVATE + PAGE_EXECUTE*).
    /// Also validates thread start addresses against backed memory to detect
    /// threads launched from injected shellcode.
    #[serde(default = "default_true_bool")]
    pub detect_unbacked_executable: bool,

    /// Shannon entropy threshold for flagging high-entropy executable regions.
    /// Default 7.0 bits/byte. Regions above this are likely encrypted or
    /// compressed shellcode. Set to 0.0 to disable entropy-based detection.
    #[serde(default = "default_entropy_threshold_f64")]
    pub memory_entropy_threshold: f64,

    /// Use adaptive entropy thresholds based on per-process-type baselines
    /// instead of the fixed `memory_entropy_threshold`.  Reduces false
    /// positives from JIT compilers and similar legitimate high-entropy sources.
    #[serde(default = "default_true_bool")]
    pub adaptive_entropy_enabled: bool,
}

fn default_entropy_threshold_f64() -> f64 {
    7.0
}
fn default_memory_scan_interval() -> u64 {
    120
}
fn default_dns_poll_interval() -> u64 {
    2000
}
fn default_network_poll_interval() -> u64 {
    3000
}
fn default_process_scan_interval() -> u64 {
    5
}
fn default_registry_poll_interval() -> u64 {
    10
}
fn default_true_bool() -> bool {
    true
}
fn default_cpu_threshold() -> f32 {
    15.0
}

impl Default for CollectorTuning {
    fn default() -> Self {
        Self {
            memory_scan_interval_secs: 120,
            dns_poll_interval_ms: 2000,
            network_poll_interval_ms: 3000,
            process_scan_interval_secs: 5,
            process_smart_diff_enabled: true,
            registry_poll_interval_secs: 10,
            adaptive_throttling_enabled: true,
            cpu_throttle_threshold: 15.0,
            skip_expensive_analysis: false,
            track_permission_changes: true,
            detect_unbacked_executable: true,
            memory_entropy_threshold: 7.0,
            adaptive_entropy_enabled: true,
        }
    }
}

/// Syscall evasion detection configuration
///
/// Controls the behavior of the syscall evasion collector, which detects
/// HookChain/SysWhispers/Hell's Gate style EDR bypass techniques.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SyscallEvasionConfig {
    /// Whether syscall evasion detection is enabled (master switch)
    pub enabled: bool,

    /// Interval in seconds between IAT integrity checks (default: 30s)
    pub iat_check_interval_secs: u64,

    /// Interval in seconds between memory scans for syscall stubs (default: 60s)
    pub memory_scan_interval_secs: u64,

    /// Enable stack frame validation for suspicious processes (default: true)
    pub stack_validation: bool,

    /// Interval in seconds between NTDLL integrity checks (default: 30s)
    pub ntdll_check_interval_secs: u64,

    /// Enable ETW-based syscall sequence profiling (default: true)
    pub etw_profiling: bool,

    /// Enable Heaven's Gate (WoW64 transition abuse) detection (default: true)
    pub heavens_gate_detection: bool,

    /// Process names to always monitor at high frequency (case-insensitive).
    /// Default includes common LOLBIN targets: powershell, cmd, wscript, etc.
    pub high_risk_processes: Vec<String>,

    /// Anomaly score threshold for syscall sequence profiling (0.0-1.0, default: 0.7)
    pub anomaly_threshold: f32,

    /// Learning period in seconds before behavioral baselining activates (default: 300s)
    pub learning_period_secs: u32,

    /// Enable cross-process ETW function integrity checking (default: true).
    /// Monitors ETW functions (EtwEventWrite, NtTraceEvent, etc.) in ALL processes
    /// for patching that would blind EDR telemetry.
    pub etw_cross_process_integrity_enabled: bool,

    /// Interval in seconds for cross-process ETW integrity checks (default: 30s)
    pub etw_cross_process_interval_secs: u64,
}

impl Default for SyscallEvasionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            iat_check_interval_secs: 30,
            memory_scan_interval_secs: 60,
            stack_validation: true,
            ntdll_check_interval_secs: 30,
            etw_profiling: true,
            heavens_gate_detection: true,
            high_risk_processes: vec![
                "powershell.exe".to_string(),
                "pwsh.exe".to_string(),
                "cmd.exe".to_string(),
                "wscript.exe".to_string(),
                "cscript.exe".to_string(),
                "mshta.exe".to_string(),
                "rundll32.exe".to_string(),
                "regsvr32.exe".to_string(),
                "msiexec.exe".to_string(),
                "certutil.exe".to_string(),
                "bitsadmin.exe".to_string(),
                "wmic.exe".to_string(),
                "msbuild.exe".to_string(),
                "installutil.exe".to_string(),
            ],
            anomaly_threshold: 0.7,
            learning_period_secs: 300,
            etw_cross_process_integrity_enabled: true,
            etw_cross_process_interval_secs: 30,
        }
    }
}

/// Network DPI advanced configuration for JA4/JARM fingerprinting and behavioral baselines
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkDpiConfig {
    /// Enable JA4 TLS fingerprinting (successor to JA3)
    pub ja4_enabled: bool,

    /// Enable JARM active server fingerprinting
    pub jarm_enabled: bool,

    /// Enable certificate analysis (self-signed, short-lived, impersonation)
    pub certificate_analysis_enabled: bool,

    /// Enable HTTP/2 fingerprinting (SETTINGS frame, WINDOW_UPDATE, PRIORITY)
    pub http2_fingerprint_enabled: bool,

    /// Enable per-process network behavioral baselines
    pub behavioral_baseline_enabled: bool,

    /// Learning period in seconds before behavioral anomalies are raised
    /// During this period, baselines are established without generating alerts.
    pub baseline_learning_period_secs: u64,

    /// Minimum number of observations before a process baseline is considered valid
    pub baseline_min_observations: u32,

    /// Anomaly threshold: ratio of new unique destination IPs vs baseline average
    /// e.g., 5.0 means alert if dest IP count exceeds 5x the baseline average
    pub dest_ip_anomaly_ratio: f32,

    /// Anomaly threshold: ratio of bytes sent vs baseline average
    /// e.g., 10.0 means alert if bytes sent exceeds 10x the baseline average
    pub bytes_sent_anomaly_ratio: f32,

    /// Anomaly threshold: ratio of connection frequency vs baseline average
    pub conn_frequency_anomaly_ratio: f32,

    /// Certificate validity minimum days -- certificates valid for fewer days
    /// than this threshold are flagged as suspicious short-lived certificates
    pub cert_min_validity_days: u32,

    /// Additional known-malicious JARM hashes (appended to built-in list)
    pub custom_malicious_jarm_hashes: Vec<String>,

    /// Additional known-malicious JA4 hashes (appended to built-in list)
    pub custom_malicious_ja4_hashes: Vec<String>,

    /// Enable DNS-over-HTTPS detection
    pub doh_detection_enabled: bool,

    /// Enable encrypted payload entropy analysis
    pub entropy_analysis_enabled: bool,

    /// Enable advanced protocol identification (SSH, RDP, QUIC, etc.)
    pub protocol_identification_enabled: bool,

    /// Maximum certificate validity period in days before flagging as suspicious
    /// Certificates valid for longer than this are flagged (default 825 = ~2.25 years)
    pub cert_max_validity_days: u32,

    /// Recently issued certificate threshold in days
    /// Certificates issued less than this many days ago are flagged (default 7)
    pub cert_recently_issued_days: u32,

    /// Entropy threshold for encrypted payload anomaly detection (0.0-8.0)
    /// Payloads with entropy above this on non-TLS ports are flagged
    pub payload_entropy_threshold: f64,

    /// Minimum number of payload samples before entropy analysis triggers
    pub payload_entropy_min_samples: usize,

    /// Beacon detection: minimum coefficient of variation threshold
    /// CV below this indicates highly regular timing (beacon-like)
    pub beacon_cv_threshold: f64,

    /// Beacon detection: minimum data size ratio (response/request)
    /// Beacon C2 typically has small requests and larger responses
    pub beacon_data_size_ratio_threshold: f64,
}

impl Default for NetworkDpiConfig {
    fn default() -> Self {
        Self {
            ja4_enabled: true,
            jarm_enabled: true,
            certificate_analysis_enabled: true,
            http2_fingerprint_enabled: true,
            behavioral_baseline_enabled: true,
            baseline_learning_period_secs: 300,
            baseline_min_observations: 10,
            dest_ip_anomaly_ratio: 5.0,
            bytes_sent_anomaly_ratio: 10.0,
            conn_frequency_anomaly_ratio: 5.0,
            cert_min_validity_days: 7,
            custom_malicious_jarm_hashes: Vec::new(),
            custom_malicious_ja4_hashes: Vec::new(),
            doh_detection_enabled: true,
            entropy_analysis_enabled: true,
            protocol_identification_enabled: true,
            cert_max_validity_days: 825,
            cert_recently_issued_days: 7,
            payload_entropy_threshold: 7.5,
            payload_entropy_min_samples: 5,
            beacon_cv_threshold: 0.30,
            beacon_data_size_ratio_threshold: 3.0,
        }
    }
}

/// EDR blinding attack detection configuration.
///
/// Controls the behavior of deep memory-level monitors that detect attempts
/// to blind the EDR agent by patching ETW, AMSI, killing Event Log threads,
/// or bypassing Credential Guard.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EdrBlindingConfig {
    /// Enable ETW patching detection (T1562.006).
    /// Baselines ntdll ETW function prologues and checks for tampering.
    pub etw_patching_enabled: bool,

    /// Interval in seconds between ETW function prologue checks (default: 15s)
    pub etw_check_interval_secs: u64,

    /// Enable AMSI memory patching detection (T1562.001).
    /// Baselines amsi.dll functions and scans AMSI host processes.
    pub amsi_patching_enabled: bool,

    /// Interval in seconds between AMSI function prologue checks (default: 10s)
    pub amsi_check_interval_secs: u64,

    /// Enable cross-process AMSI checking (reads memory of PowerShell, JScript, etc.)
    pub amsi_cross_process_enabled: bool,

    /// Enable Event Log service integrity monitoring (T1070.001).
    /// Checks for thread termination, .evtx file deletion, channel heartbeats.
    pub event_log_integrity_enabled: bool,

    /// Interval in seconds between Event Log service checks (default: 10s)
    pub event_log_check_interval_secs: u64,

    /// Staleness threshold in seconds for the Security event channel heartbeat.
    /// If Security.evtx hasn't been modified in this many seconds, emit an alert.
    pub event_log_heartbeat_stale_secs: u64,

    /// Minimum thread count drop to trigger a thread-kill alert.
    /// Default 3: a drop of 3+ threads in the Event Log service svchost suggests
    /// a Phantom/Invoke-Phant0m style attack.
    pub event_log_thread_drop_threshold: u32,

    /// Enable Credential Guard bypass detection.
    /// Monitors lsaiso.exe, WDigest downgrade, VBS/DeviceGuard registry keys.
    pub credential_guard_enabled: bool,

    /// Interval in seconds between Credential Guard checks (default: 10s)
    pub credential_guard_check_interval_secs: u64,
}

impl Default for EdrBlindingConfig {
    fn default() -> Self {
        Self {
            etw_patching_enabled: true,
            etw_check_interval_secs: 15,
            amsi_patching_enabled: true,
            amsi_check_interval_secs: 10,
            amsi_cross_process_enabled: true,
            event_log_integrity_enabled: true,
            event_log_check_interval_secs: 10,
            event_log_heartbeat_stale_secs: 300,
            event_log_thread_drop_threshold: 3,
            credential_guard_enabled: true,
            credential_guard_check_interval_secs: 10,
        }
    }
}

/// Configuration for the file modification journal and ransomware rollback.
///
/// The journal records file modifications (write, rename, delete) with
/// before-snapshots, enabling point-in-time rollback of file changes
/// associated with an attack chain. Integrates with Windows VSS for
/// full-volume snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FileJournalConfig {
    /// Master switch for the file journal.
    pub enabled: bool,

    /// Maximum SQLite database size in megabytes (default: 500 MB).
    pub max_db_size_mb: u64,

    /// Maximum total backup file size in megabytes (default: 2048 MB / 2 GB).
    pub max_backup_size_mb: u64,

    /// Retention period in hours for journal entries (default: 72 hours).
    pub retention_hours: u64,

    /// Enable Windows Volume Shadow Copy (VSS) integration.
    pub vss_enabled: bool,

    /// Interval in hours between automatic VSS snapshot creation (default: 4h).
    pub vss_interval_hours: u64,

    /// File extensions to monitor for journaling (without leading dot).
    /// Default includes common document, image, database, and source code types.
    pub monitored_extensions: Vec<String>,
}

impl Default for FileJournalConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_db_size_mb: 500,
            max_backup_size_mb: 2048,
            retention_hours: 72,
            vss_enabled: cfg!(windows),
            vss_interval_hours: 4,
            monitored_extensions: vec![
                "doc".into(),
                "docx".into(),
                "xls".into(),
                "xlsx".into(),
                "ppt".into(),
                "pptx".into(),
                "pdf".into(),
                "jpg".into(),
                "png".into(),
                "txt".into(),
                "csv".into(),
                "db".into(),
                "sql".into(),
                "bak".into(),
            ],
        }
    }
}

/// Configuration for the feature-based local ML engine (`ml_local` module).
///
/// This engine extracts 16 structural features from PE files and runs them
/// through a small ONNX model for fast, offline-capable malware classification.
/// It is complementary to the image-based ONNX scanner (`onnx` feature).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MLLocalConfig {
    /// Master switch for the feature-based ML engine.
    pub enabled: bool,

    /// Path to the ONNX model file. If not set, a platform-specific default
    /// path is used (e.g. `C:\ProgramData\Tamandua\models\malware_features.onnx`).
    pub model_path: String,

    /// Minimum confidence score (0.0 - 1.0) to classify a file as malicious.
    pub confidence_threshold: f32,

    /// Skip files larger than this many megabytes.
    pub max_file_size_mb: u64,

    /// Run the ML engine when a new file is created.
    pub scan_on_create: bool,

    /// Run the ML engine when an existing file is modified.
    pub scan_on_modify: bool,
}

impl Default for MLLocalConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            model_path: String::new(), // empty = use platform default
            confidence_threshold: 0.7,
            max_file_size_mb: 100,
            scan_on_create: true,
            scan_on_modify: true,
        }
    }
}

/// Configuration for fanotify-based pre-execution blocking (Linux only).
///
/// When enabled, the file collector uses `FAN_OPEN_EXEC_PERM` permission events
/// to intercept file executions. Each execution is evaluated by the ONNX ML
/// scanner; files classified as malicious with high confidence are blocked
/// (denied) before the kernel allows the exec to proceed.
///
/// **Requirements:**
/// - Linux only (requires `CAP_SYS_ADMIN` for `FAN_CLASS_PRE_CONTENT`)
/// - The `onnx` feature must be enabled for ML scanning; without it, all
///   executions are allowed (the gate degrades to notification-only mode).
///
/// Nested under `[pre_execution_blocking]` in `agent.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PreExecutionBlockingConfig {
    /// Master switch. When `false`, the file collector uses the normal
    /// `FAN_CLASS_NOTIF` mode and no permission events are generated.
    pub enabled: bool,

    /// Paths that are always allowed without ML scanning. Executables whose
    /// path starts with any entry in this list receive an automatic `FAN_ALLOW`.
    /// Useful for trusted system directories to reduce scanning overhead.
    pub trusted_paths: Vec<String>,

    /// ML confidence threshold (0.0 - 1.0) above which a file is blocked.
    /// Must be high to avoid false-positive denials. Default: 0.85.
    pub block_confidence_threshold: f32,

    /// Maximum time in milliseconds to wait for the ML scan to complete.
    /// If the scan exceeds this timeout the file is allowed (fail-open).
    /// Default: 50ms.
    pub scan_timeout_ms: u64,

    /// Maximum file size in bytes that will be scanned. Files larger than
    /// this are always allowed. Default: 50 MB.
    pub max_scan_file_size: u64,
}

impl Default for PreExecutionBlockingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            trusted_paths: vec![
                "/usr/bin".to_string(),
                "/usr/sbin".to_string(),
                "/usr/lib".to_string(),
                "/usr/lib64".to_string(),
                "/usr/libexec".to_string(),
                "/bin".to_string(),
                "/sbin".to_string(),
                "/lib".to_string(),
                "/lib64".to_string(),
            ],
            block_confidence_threshold: 0.85,
            scan_timeout_ms: 50,
            max_scan_file_size: 50 * 1024 * 1024, // 50 MB
        }
    }
}

/// Which ONNX model to use for local offline ML inference.
///
/// - `Smell`:       The original Malware-SMELL VGG-19 image-based model.
///                   Input: [1, 3, image_size, image_size].
/// - `Transformer`: A standalone ByteTransformer model.
///                   Input: [1, max_length] raw byte values.
/// - `Ensemble`:    A combined ONNX model that runs both SMELL and
///                   ByteTransformer internally and outputs weighted
///                   ensemble probabilities.
///                   Input: [1, max_length] raw byte values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalModelType {
    /// VGG-19 image-based (Malware-SMELL) -- existing default.
    Smell,
    /// ByteTransformer -- byte-level transformer model.
    Transformer,
    /// Combined ONNX model (SMELL + ByteTransformer ensemble).
    Ensemble,
}

impl Default for LocalModelType {
    fn default() -> Self {
        Self::Smell
    }
}

/// Configuration for the autonomous offline detection pipeline.
///
/// When the backend ML service is unreachable the agent falls back to
/// local detection using an ONNX model (Malware-SMELL) and YARA rules.
/// Verdicts produced offline are queued and synchronized when the
/// connection is restored.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OfflineDetectionConfig {
    /// Master switch for offline detection.
    pub enabled: bool,

    /// Path to the local ONNX model file for ML inference.
    /// Platform-specific defaults are used when empty.
    pub onnx_model_path: String,

    /// Directory containing `.yar`/`.yara` rule files for local YARA scanning.
    pub yara_rules_dir: String,

    /// Maximum number of offline verdicts to queue before dropping the oldest.
    pub verdict_queue_max: usize,

    /// Interval (seconds) between backend reachability health checks.
    pub backend_check_interval_secs: u64,

    /// ML confidence threshold above which a file is classified as malicious.
    pub ml_confidence_threshold: f32,

    /// Input image size for the ONNX model (must match training, default 64).
    pub onnx_image_size: usize,

    /// Maximum file size (bytes) that will be submitted to local scanning.
    pub max_file_size: u64,

    /// Which ONNX model to use for local inference.
    ///
    /// - `smell`       (default): Malware-SMELL VGG-19 image-based model.
    /// - `transformer`: ByteTransformer byte-level model.
    /// - `ensemble`:    Combined ONNX model (both models in one graph).
    ///
    /// When set to `transformer` or `ensemble` the agent uses the
    /// `onnx_model_path` for the selected model file.  The `onnx_image_size`
    /// field is only relevant for the `smell` model type.
    pub model_type: LocalModelType,

    /// Maximum input byte length for transformer and ensemble models.
    /// The raw binary is truncated (or zero-padded) to this length before
    /// being fed into the ONNX session.  Only used when `model_type` is
    /// `transformer` or `ensemble`.  Default: 4096.
    pub max_input_length: usize,
}

impl Default for OfflineDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            onnx_model_path: Self::default_model_path(),
            yara_rules_dir: Self::default_rules_dir(),
            verdict_queue_max: 10_000,
            backend_check_interval_secs: 30,
            ml_confidence_threshold: 0.7,
            onnx_image_size: 64,
            max_file_size: 100 * 1024 * 1024, // 100 MB
            model_type: LocalModelType::Smell,
            max_input_length: 4096,
        }
    }
}

impl OfflineDetectionConfig {
    fn default_model_path() -> String {
        #[cfg(target_os = "windows")]
        {
            windows_data_dir()
                .join("models")
                .join("malware_smell.onnx")
                .to_string_lossy()
                .to_string()
        }
        #[cfg(target_os = "linux")]
        {
            "/var/lib/tamandua/models/malware_smell.onnx".to_string()
        }
        #[cfg(target_os = "macos")]
        {
            "/Library/Application Support/Tamandua/models/malware_smell.onnx".to_string()
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            "./models/malware_smell.onnx".to_string()
        }
    }

    fn default_rules_dir() -> String {
        #[cfg(target_os = "windows")]
        {
            windows_data_dir()
                .join("rules")
                .join("yara")
                .to_string_lossy()
                .to_string()
        }
        #[cfg(target_os = "linux")]
        {
            "/var/lib/tamandua/rules/yara".to_string()
        }
        #[cfg(target_os = "macos")]
        {
            "/Library/Application Support/Tamandua/rules/yara".to_string()
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            "./rules/yara".to_string()
        }
    }

    /// Return the default ONNX model path for the given model type.
    pub fn default_model_path_for_type(model_type: LocalModelType) -> String {
        match model_type {
            LocalModelType::Smell => Self::default_model_path(),
            LocalModelType::Transformer => {
                #[cfg(target_os = "windows")]
                {
                    r"C:\ProgramData\Tamandua\models\byte_transformer.onnx".to_string()
                }
                #[cfg(target_os = "linux")]
                {
                    "/var/lib/tamandua/models/byte_transformer.onnx".to_string()
                }
                #[cfg(target_os = "macos")]
                {
                    "/Library/Application Support/Tamandua/models/byte_transformer.onnx".to_string()
                }
                #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
                {
                    "./models/byte_transformer.onnx".to_string()
                }
            }
            LocalModelType::Ensemble => {
                #[cfg(target_os = "windows")]
                {
                    r"C:\ProgramData\Tamandua\models\ensemble.onnx".to_string()
                }
                #[cfg(target_os = "linux")]
                {
                    "/var/lib/tamandua/models/ensemble.onnx".to_string()
                }
                #[cfg(target_os = "macos")]
                {
                    "/Library/Application Support/Tamandua/models/ensemble.onnx".to_string()
                }
                #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
                {
                    "./models/ensemble.onnx".to_string()
                }
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn windows_data_dir() -> std::path::PathBuf {
    if let Some(path) = std::env::var_os("TAMANDUA_DATA_DIR").map(std::path::PathBuf::from) {
        return path;
    }

    std::env::var_os("ProgramData")
        .map(|p| std::path::PathBuf::from(p).join("Tamandua"))
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\ProgramData\Tamandua"))
}

// ============================================================================
// USB Device Enforcement Policy Configuration
// ============================================================================

/// USB enforcement policy mode.
///
/// - `Monitor`:  Log all device events but never block. Useful for audit/shadow
///               deployments where you want to understand the device landscape
///               before enforcing policy.
/// - `Enforce`:  Apply allowlist and blocklist rules. Devices not matching any
///               rule are subject to `default_action`.
/// - `BlockAll`: Block every USB mass storage device unconditionally. HID
///               (keyboards, mice) and Hub devices are always allowed for safety.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsbPolicyMode {
    /// Only log, never block
    Monitor,
    /// Apply allowlist/blocklist rules
    Enforce,
    /// Block ALL USB storage devices (HID/Hub still allowed)
    BlockAll,
}

impl Default for UsbPolicyMode {
    fn default() -> Self {
        Self::Monitor
    }
}

/// Default action for devices that do not match any allowlist or blocklist rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsbDefaultAction {
    /// Allow the device
    Allow,
    /// Block (disable/eject) the device
    Block,
    /// Allow but force read-only mount for mass storage
    AllowReadOnly,
}

impl Default for UsbDefaultAction {
    fn default() -> Self {
        Self::Allow
    }
}

/// A single device matching rule for the USB allowlist or blocklist.
///
/// All fields are optional; a device matches if **every specified** field
/// matches the device. Unset fields are treated as wildcards.
///
/// Examples:
/// - `{ vendor_id = 0x046D }` matches any Logitech device
/// - `{ vendor_id = 0x0781, product_id = 0x5583 }` matches a specific SanDisk model
/// - `{ device_class = 8 }` matches all USB mass storage class devices
/// - `{ serial_number = "ABC123" }` matches one specific device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDeviceRule {
    /// USB Vendor ID (VID). Matched against the device's idVendor.
    #[serde(default)]
    pub vendor_id: Option<u16>,

    /// USB Product ID (PID). Matched against the device's idProduct.
    #[serde(default)]
    pub product_id: Option<u16>,

    /// USB device class code (bDeviceClass). Common values:
    ///   0x03 = HID, 0x08 = Mass Storage, 0x09 = Hub, 0xE0 = Wireless
    #[serde(default)]
    pub device_class: Option<u8>,

    /// Device serial number string (exact match, case-insensitive).
    #[serde(default)]
    pub serial_number: Option<String>,

    /// Human-readable description of this rule (for logging and UI display).
    #[serde(default)]
    pub description: Option<String>,
}

impl UsbDeviceRule {
    /// Test whether a device matches this rule.
    ///
    /// Every **specified** (non-None) field must match; unset fields are wildcards.
    /// Returns `false` if no fields are specified (empty rule matches nothing).
    pub fn matches_device(&self, vid: u16, pid: u16, class_code: u8, serial: Option<&str>) -> bool {
        let any_set = self.vendor_id.is_some()
            || self.product_id.is_some()
            || self.device_class.is_some()
            || self.serial_number.is_some();

        if !any_set {
            return false; // empty rule matches nothing
        }

        if let Some(v) = self.vendor_id {
            if v != vid {
                return false;
            }
        }
        if let Some(p) = self.product_id {
            if p != pid {
                return false;
            }
        }
        if let Some(c) = self.device_class {
            if c != class_code {
                return false;
            }
        }
        if let Some(ref sn) = self.serial_number {
            match serial {
                Some(dev_sn) => {
                    if !dev_sn.eq_ignore_ascii_case(sn) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        true
    }
}

/// USB device enforcement configuration.
///
/// Controls how the USB collector evaluates newly connected devices and whether
/// it actively blocks (disables/ejects) devices that violate policy.
///
/// Nested under `[usb_enforcement]` in `agent.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct UsbEnforcementConfig {
    /// Whether USB enforcement is enabled. When `false`, the USB collector
    /// still monitors connections but skips policy evaluation entirely.
    pub enabled: bool,

    /// Enforcement mode. See [`UsbPolicyMode`] for details.
    pub mode: UsbPolicyMode,

    /// Default action for devices that match neither the allowlist nor the
    /// blocklist. Only effective when `mode` is `Enforce`.
    pub default_action: UsbDefaultAction,

    /// Send an alert to the backend when a device is blocked.
    pub notify_on_block: bool,

    /// Log telemetry events for every USB connection, including allowed
    /// devices. When `false`, only blocked or high-risk connections generate
    /// telemetry events.
    pub log_all_connections: bool,

    /// Device rules that are always allowed, regardless of `default_action`.
    /// Evaluated before the blocklist. First matching rule wins.
    #[serde(default)]
    pub allowlist: Vec<UsbDeviceRule>,

    /// Device rules that are always blocked. Evaluated after the allowlist.
    /// First matching rule wins.
    #[serde(default)]
    pub blocklist: Vec<UsbDeviceRule>,

    /// Device group for this endpoint. Controls which built-in group policy
    /// the `UsbPolicyManager` applies. One of:
    ///   "standard" (default), "it_admin", "developer", "kiosk", "executive"
    #[serde(default = "default_device_group")]
    pub device_group: String,

    /// Poll interval in seconds for USB device enumeration (default: 15).
    #[serde(default = "default_usb_poll_interval")]
    pub poll_interval_secs: u64,
}

fn default_device_group() -> String {
    "standard".to_string()
}

fn default_usb_poll_interval() -> u64 {
    15
}

impl Default for UsbEnforcementConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: UsbPolicyMode::Monitor,
            default_action: UsbDefaultAction::Allow,
            notify_on_block: true,
            log_all_connections: true,
            allowlist: Vec::new(),
            blocklist: Vec::new(),
            device_group: "standard".to_string(),
            poll_interval_secs: 15,
        }
    }
}

/// Transport configuration for failover, certificate pinning, and proxy support
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TransportConfig {
    /// Backup server URLs for failover
    #[serde(default)]
    pub backup_servers: Vec<String>,

    /// Certificate pins (SHA-256 hashes of server certificate DER, base64-encoded).
    /// Supports optional "sha256//" prefix (HPKP format).
    /// Multiple pins allow rotation: any single match is valid.
    ///
    /// Example:
    /// ```toml
    /// cert_pins = [
    ///     "sha256//YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=",
    ///     "sha256//sRHdihwgkaib1P1gN7SkKPuOHmLSkyVEFhGIBi8Aaho=",
    /// ]
    /// ```
    #[serde(default)]
    pub cert_pins: Vec<String>,

    /// Whether to enforce certificate pinning (default: true).
    /// When false, pin mismatches are logged as warnings but the connection
    /// proceeds (report-only mode for gradual rollout).
    #[serde(default = "default_cert_pin_enforce")]
    pub cert_pin_enforce: bool,

    /// HTTP or SOCKS5 proxy URL for environments that require proxied connections.
    /// Supports authentication via embedded credentials.
    ///
    /// Examples:
    /// ```toml
    /// proxy_url = "http://proxy.corp.example.com:8080"
    /// proxy_url = "http://user:password@proxy.corp.example.com:8080"
    /// proxy_url = "socks5://socks-proxy.corp.example.com:1080"
    /// ```
    #[serde(default)]
    pub proxy_url: Option<String>,
}

fn default_cert_pin_enforce() -> bool {
    true
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            backup_servers: vec![],
            cert_pins: vec![],
            cert_pin_enforce: true,
            proxy_url: None,
        }
    }
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsConfig {
    /// Enable mTLS
    pub enabled: bool,

    /// Path to client certificate
    pub cert_path: Option<String>,

    /// Path to client key
    pub key_path: Option<String>,

    /// Path to CA certificate
    pub ca_path: Option<String>,

    /// Skip server certificate verification (DANGEROUS - dev only)
    pub skip_verify: bool,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            agent_id: Uuid::new_v4().to_string(),
            server_url: "wss://agents.tamandua.treantlab.org:8443/socket/agent".to_string(),
            organization_id: None,
            auth_token: None,
            heartbeat_interval_seconds: 30,
            batch_size: 100,
            batch_timeout_seconds: 5,
            reconnect_delay_seconds: 5,
            max_reconnect_attempts: 0, // 0 = infinite
            connection_timeout_seconds: 30,
            yara_enabled: true,
            entropy_check_enabled: true,
            entropy_threshold: 7.5,
            excluded_paths: vec![
                "/proc".to_string(),
                "/sys".to_string(),
                "/dev".to_string(),
                "C:\\Windows\\WinSxS".to_string(),
            ],
            excluded_processes: vec!["tamandua-agent".to_string()],
            monitored_file_patterns: vec![
                "*.exe".to_string(),
                "*.dll".to_string(),
                "*.ps1".to_string(),
                "*.bat".to_string(),
                "*.vbs".to_string(),
                "*.js".to_string(),
                "*.aspx".to_string(),
                "*.asp".to_string(),
                "*.jsp".to_string(),
                "*.php".to_string(),
            ],
            honeyfiles_enabled: true,
            honeyfile_paths: vec![],
            transport: TransportConfig::default(),
            tls: TlsConfig::default(),
            collectors: CollectorConfig::default(),
            collector_tuning: CollectorTuning::default(),
            local_analysis_enabled: true,
            local_queue_size: Some(50_000), // Default 50K events
            health_interval_seconds: 60,
            ml_scanning_enabled: true,
            ml_confidence_threshold: Some(0.7),
            ml_model_path: None,
            ml_inference_timeout_secs: 30,
            ml_local: MLLocalConfig::default(),
            pre_execution_blocking: PreExecutionBlockingConfig::default(),
            offline_detection: OfflineDetectionConfig::default(),
            usb_enforcement: UsbEnforcementConfig::default(),
            syscall_evasion: SyscallEvasionConfig::default(),
            network_dpi: NetworkDpiConfig::default(),
            network_discovery:
                crate::collectors::network_discovery::NetworkDiscoveryConfig::default(),
            edr_blinding: EdrBlindingConfig::default(),
            file_journal: FileJournalConfig::default(),
            dlp: crate::collectors::dlp::DlpConfig::default(),
            updater: crate::updater::UpdateConfig::default(),
            resource_governor: crate::resource_governor::ResourceGovernorConfig::default(),
            event_triage: crate::event_triage::EventTriageConfig::default(),
            performance_profile: PerformanceProfile::Balanced,
            config_signing_keys: None,
            config_signing_enforce: None,
            max_cpu_percent: 15.0,
            sub_loop_interval_multiplier: 3.0,
            full_scan_features: false,
            tcc_monitor_interval_seconds: default_tcc_monitor_interval(),
            xpc_monitor_interval_seconds: default_xpc_monitor_interval(),
            ipc: IpcConfig::default(),
        }
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_path: None,
            key_path: None,
            ca_path: None,
            skip_verify: false,
        }
    }
}

/// Recursively merge `defaults` into `base`. For any key present in `defaults`
/// but missing from `base`, the default value is inserted. For keys present in
/// both where both values are tables, merge recursively. Otherwise the existing
/// value in `base` takes precedence.
fn deep_merge_toml(base: &mut toml::Value, defaults: toml::Value) {
    if let (toml::Value::Table(base_table), toml::Value::Table(default_table)) = (base, defaults) {
        for (key, default_val) in default_table {
            match base_table.get_mut(&key) {
                Some(existing) if existing.is_table() && default_val.is_table() => {
                    // Both are tables -- recurse to merge nested keys
                    deep_merge_toml(existing, default_val);
                }
                Some(_) => {
                    // Key exists and is not a table-table pair -- keep existing value
                }
                None => {
                    // Key missing from base -- insert the default
                    base_table.insert(key, default_val);
                }
            }
        }
    }
}

fn normalize_legacy_auth_token(config: &mut toml::Value) {
    let Some(table) = config.as_table_mut() else {
        return;
    };

    let has_auth_token = table
        .get("auth_token")
        .and_then(|value| value.as_str())
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);

    if has_auth_token {
        return;
    }

    let legacy_jwt = table
        .get("auth")
        .and_then(|value| value.as_table())
        .and_then(|auth| auth.get("jwt"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);

    if let Some(jwt) = legacy_jwt {
        table.insert("auth_token".to_string(), toml::Value::String(jwt));
    }
}

#[cfg(target_os = "windows")]
fn platform_machine_id() -> Option<String> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let crypto = hklm.open_subkey("SOFTWARE\\Microsoft\\Cryptography").ok()?;
    crypto.get_value::<String, _>("MachineGuid").ok()
}

#[cfg(target_os = "linux")]
fn platform_machine_id() -> Option<String> {
    std::fs::read_to_string("/etc/machine-id")
        .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(target_os = "macos")]
fn platform_machine_id() -> Option<String> {
    use std::process::Command;

    let output = Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);

    text.lines().find_map(|line| {
        if line.contains("IOPlatformUUID") {
            line.split('=')
                .nth(1)
                .map(|value| value.trim().trim_matches('"').to_string())
        } else {
            None
        }
    })
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn platform_machine_id() -> Option<String> {
    None
}

impl AgentConfig {
    fn ensure_monitored_file_patterns(&mut self, patterns: &[&str]) {
        for pattern in patterns {
            if !self
                .monitored_file_patterns
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(pattern))
            {
                self.monitored_file_patterns.push((*pattern).to_string());
            }
        }
    }

    /// Platform default configuration path used by an installed agent service.
    pub fn default_config_path() -> std::path::PathBuf {
        #[cfg(target_os = "windows")]
        {
            let data_dir = if let Some(path) =
                std::env::var_os("TAMANDUA_DATA_DIR").map(std::path::PathBuf::from)
            {
                path
            } else if let Some(path) = std::env::var_os("ProgramData")
                .map(|p| std::path::PathBuf::from(p).join("Tamandua"))
                .filter(|path| path.exists() || path.parent().is_some_and(|parent| parent.exists()))
            {
                path
            } else {
                std::env::var_os("SystemDrive")
                    .map(|drive| {
                        std::path::PathBuf::from(format!(
                            r"{}\ProgramData\Tamandua",
                            drive.to_string_lossy()
                        ))
                    })
                    .unwrap_or_else(|| std::path::PathBuf::from(r"C:\ProgramData\Tamandua"))
            };
            return data_dir.join("config").join("agent.toml");
        }

        #[cfg(target_os = "linux")]
        {
            return std::path::PathBuf::from("/etc/tamandua/agent.toml");
        }

        #[cfg(target_os = "macos")]
        {
            return std::path::PathBuf::from(
                "/Library/Application Support/Tamandua/config/agent.toml",
            );
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            std::path::PathBuf::from("config/agent.toml")
        }
    }

    /// Load default config path if present, otherwise return default configuration.
    pub fn load_or_default() -> Result<Self> {
        let installed_path = Self::default_config_path();
        let default_path = if installed_path.exists() {
            installed_path.as_path()
        } else {
            Path::new("config/agent.toml")
        };
        if default_path.exists() {
            Self::from_file(default_path)
        } else {
            Ok(Self::default())
        }
    }

    /// Load configuration from a TOML file with graceful migration for missing fields.
    ///
    /// With `#[serde(default)]` on all config structs, serde will automatically
    /// fill in any missing fields from the `Default` impl. The fallback merge
    /// path handles edge cases where the TOML is structurally valid but serde
    /// still reports missing fields (e.g., unexpected enum variants).
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())?;
        let mut raw_value: toml::Value = toml::from_str(&content)?;
        normalize_legacy_auth_token(&mut raw_value);
        let normalized = toml::to_string(&raw_value)?;

        // With #[serde(default)] on all structs, this should handle missing fields
        // gracefully by pulling values from Default::default().
        match toml::from_str::<Self>(&normalized) {
            Ok(config) => Ok(config),
            Err(e) if e.to_string().contains("missing field") => {
                // Fallback: deep-merge stored config with defaults
                tracing::warn!(
                    "Config file has missing fields ({}), deep-merging with defaults",
                    e
                );

                // Parse into a generic TOML value first
                let mut stored_config = raw_value;
                let default_config = toml::to_string(&Self::default())?;
                let default_value: toml::Value = toml::from_str(&default_config)?;

                // Deep-merge defaults into stored config (stored values take precedence)
                deep_merge_toml(&mut stored_config, default_value);

                // Re-serialize and parse as AgentConfig
                let merged = toml::to_string(&stored_config)?;
                let config: Self = toml::from_str(&merged)?;

                // Save the migrated config back to disk
                tracing::info!("Saving migrated config to {:?}", path.as_ref());
                config.save(path)?;

                Ok(config)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Save configuration to a TOML file
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Save configuration to the default path (config/agent.toml).
    /// Returns Ok if save succeeded, Err otherwise.
    pub fn save_default(&self) -> Result<()> {
        let default_path = Self::default_config_path();
        if let Some(parent) = default_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        self.save(default_path)
    }

    /// Get hostname
    pub fn get_hostname(&self) -> String {
        hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    }

    /// Get OS type
    pub fn get_os_type(&self) -> &'static str {
        #[cfg(target_os = "windows")]
        {
            return "windows";
        }

        #[cfg(target_os = "linux")]
        {
            return "linux";
        }

        #[cfg(target_os = "macos")]
        {
            return "macos";
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            return "unknown";
        }
    }

    /// Get OS version
    pub fn get_os_version(&self) -> String {
        sysinfo::System::os_version().unwrap_or_else(|| "unknown".to_string())
    }

    /// Get a stable, privacy-safe endpoint identity for backend inventory deduplication.
    ///
    /// The raw OS machine identifier never leaves the endpoint. We hash it with a
    /// Tamandua-specific domain separator so server-side inventory can collapse
    /// reinstall/enrollment attempts without exposing the original machine GUID.
    pub fn get_machine_id_hash(&self) -> String {
        let raw = platform_machine_id().unwrap_or_else(|| self.get_hostname());
        let mut hasher = Sha256::new();
        hasher.update(b"tamandua-agent-machine-id-v1");
        hasher.update(raw.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Apply the selected performance profile, overriding `collector_tuning`
    /// intervals and selectively disabling heavy collectors in lightweight mode.
    ///
    /// Call this after loading the config and before starting collectors.
    /// Individual collector enable/disable flags from the config file still
    /// take precedence — if the user explicitly disabled a collector, the
    /// profile won't re-enable it.
    pub fn apply_performance_profile(&mut self) {
        #[cfg(target_os = "windows")]
        self.ensure_monitored_file_patterns(&["*.aspx", "*.asp", "*.jsp", "*.php"]);

        let offline_detection_requested = self.offline_detection.enabled;

        match self.performance_profile {
            PerformanceProfile::Aggressive => {
                // Sub-loop multiplier: keep original intervals
                self.sub_loop_interval_multiplier = 1.0;
                // Enable full scan features for maximum detection
                self.full_scan_features = true;

                // Maximum detection via core collectors + ETW + key detectors.
                // ETW alone covers most attack techniques (injection, credential
                // access, lateral movement, defense evasion) through Windows event
                // tracing, so specialized polling collectors that duplicate ETW
                // coverage are disabled to keep CPU under ~15-20%.
                self.collector_tuning.process_scan_interval_secs = 3;
                self.collector_tuning.memory_scan_interval_secs = 60;
                self.collector_tuning.dns_poll_interval_ms = 1000;
                self.collector_tuning.network_poll_interval_ms = 2000;
                self.collector_tuning.registry_poll_interval_secs = 5;
                self.collector_tuning.cpu_throttle_threshold = 25.0;
                self.collector_tuning.adaptive_throttling_enabled = true;
                self.collector_tuning.skip_expensive_analysis = true;
                self.max_cpu_percent = 20.0;

                // ---- Disable heavy multi-thread collectors ----
                #[cfg(target_os = "windows")]
                {
                    self.collectors.wmi_enabled = false; // 3 threads, COM
                    self.collectors.clr_enabled = false; // 2 threads, profiler
                }

                // Injection (6 concurrent sub-loops — biggest CPU hog)
                self.collectors.injection_enabled = false;

                // Deep memory scanning (ReadProcessMemory across all procs)
                self.collectors.memory_enabled = false;
                self.collectors.process_hollowing_enabled = false;
                self.collectors.ntdll_write_monitor_enabled = true;

                // Network deep inspection
                self.collectors.network_dpi_enabled = false;
                self.collectors.network_anomaly_enabled = false;

                // Heavy kernel-call collectors (handle enum, ntdll scan)
                self.collectors.credential_theft_enabled = false;
                self.collectors.lateral_movement_enabled = false;
                self.collectors.syscall_evasion_enabled = false;
                self.collectors.defense_evasion_enabled = false;
                self.collectors.exploit_mitigation_enabled = false;

                // Widen syscall evasion intervals even if re-enabled manually
                self.syscall_evasion.iat_check_interval_secs = 60;
                self.syscall_evasion.memory_scan_interval_secs = 120;

                // Multi-thread polling collectors
                self.collectors.scheduled_tasks_enabled = false; // 2 threads
                self.collectors.named_pipes_enabled = false;
                self.collectors.driver_blocklist_enabled = false;
                self.collectors.browser_protection_enabled = false;
                self.collectors.script_inspector_enabled = false;

                // Windows-specific heavy collectors (ETW stays)
                #[cfg(target_os = "windows")]
                {
                    self.collectors.lsass_enabled = false; // handle monitoring
                    self.collectors.ad_monitor_enabled = false; // AD polling
                }

                // Polling collectors with low unique detection value
                self.collectors.firmware_enabled = false;
                self.collectors.clipboard_enabled = false;
                self.collectors.input_capture_enabled = false;
                self.collectors.office_email_enabled = false;
                self.collectors.cloud_enabled = false;
                self.collectors.container_enabled = false;

                // Newly added collectors (DLP, AI discovery, etc.)
                self.collectors.dlp_enabled = false;
                self.collectors.clipboard_dlp_enabled = false;
                self.collectors.ai_discovery_enabled = false;
                self.collectors.software_inventory_enabled = false;
                #[cfg(not(feature = "onnx"))]
                {
                    self.offline_detection.enabled = false;
                }
                #[cfg(feature = "onnx")]
                {
                    self.offline_detection.enabled = offline_detection_requested
                        && std::path::Path::new(&self.offline_detection.onnx_model_path).exists();
                }
                #[cfg(target_os = "windows")]
                {
                    self.collectors.identity_enabled = false;
                }

                // Active: process(3s), file, network(2s), dns(1s),
                // registry(5s), usb, ransomware_canary, health,
                // etw (event-driven), amsi, persistence, fim

                tracing::info!(
                    profile = "aggressive",
                    process_interval = 3,
                    dns_interval = 1000,
                    max_cpu = 20.0,
                    "Performance profile applied: maximum detection via ETW + core + key detectors"
                );
            }
            PerformanceProfile::Balanced => {
                // Sub-loop multiplier: 3x slower sub-loops
                self.sub_loop_interval_multiplier = 3.0;
                // Full scan features disabled in balanced mode
                self.full_scan_features = false;

                // Moderate intervals, skip per-event expensive analysis,
                // keep only core + key detection collectors.
                self.collector_tuning.process_scan_interval_secs = 5;
                self.collector_tuning.memory_scan_interval_secs = 120;
                self.collector_tuning.dns_poll_interval_ms = 2000;
                self.collector_tuning.network_poll_interval_ms = 3000;
                self.collector_tuning.registry_poll_interval_secs = 10;
                self.collector_tuning.cpu_throttle_threshold = 15.0;
                self.collector_tuning.adaptive_throttling_enabled = true;
                self.collector_tuning.skip_expensive_analysis = true;
                self.max_cpu_percent = 15.0;

                // ---- Disable ALL heavy collectors ----
                // Each spawns 1-3 OS threads with tight polling loops.

                // Deep memory scanning
                self.collectors.memory_enabled = false;
                self.collectors.process_hollowing_enabled = false;

                // Network deep inspection
                self.collectors.network_dpi_enabled = false;
                self.collectors.network_anomaly_enabled = false;

                // Credential / lateral / evasion (handle enum, ntdll scan)
                self.collectors.credential_theft_enabled = false;
                self.collectors.lateral_movement_enabled = false;
                self.collectors.ntdll_write_monitor_enabled = false;
                self.collectors.syscall_evasion_enabled = false;
                self.collectors.defense_evasion_enabled = false;
                self.collectors.exploit_mitigation_enabled = false;

                // Widen syscall evasion intervals even if re-enabled manually
                self.syscall_evasion.iat_check_interval_secs = 120;
                self.syscall_evasion.memory_scan_interval_secs = 300;
                self.syscall_evasion.stack_validation = false;
                self.syscall_evasion.etw_profiling = false;

                // Multi-loop collectors (injection=6, scheduled_tasks=2)
                self.collectors.injection_enabled = false;
                self.collectors.scheduled_tasks_enabled = false;

                // Named pipes / driver blocklist (polling)
                self.collectors.named_pipes_enabled = false;
                self.collectors.driver_blocklist_enabled = false;

                // Script inspector
                self.collectors.script_inspector_enabled = false;

                // Browser / firmware / clipboard / input / office / cloud
                self.collectors.browser_protection_enabled = false;
                self.collectors.firmware_enabled = false;
                self.collectors.clipboard_enabled = false;
                self.collectors.input_capture_enabled = false;
                self.collectors.office_email_enabled = false;
                self.collectors.cloud_enabled = false;
                self.collectors.container_enabled = false;

                // Newly added collectors (DLP, AI discovery, etc.)
                self.collectors.dlp_enabled = false;
                self.collectors.clipboard_dlp_enabled = false;
                self.collectors.ai_discovery_enabled = false;
                self.collectors.software_inventory_enabled = false;
                #[cfg(not(feature = "onnx"))]
                {
                    self.offline_detection.enabled = false;
                }
                #[cfg(feature = "onnx")]
                {
                    self.offline_detection.enabled = offline_detection_requested
                        && std::path::Path::new(&self.offline_detection.onnx_model_path).exists();
                }
                #[cfg(target_os = "windows")]
                {
                    self.collectors.identity_enabled = false;
                }

                // Windows-specific heavy collectors
                #[cfg(target_os = "windows")]
                {
                    self.collectors.wmi_enabled = false;
                    self.collectors.clr_enabled = false;
                    self.collectors.amsi_enabled = false;
                    self.collectors.lsass_enabled = false;
                    self.collectors.ad_monitor_enabled = false;
                }

                // Linux eBPF
                #[cfg(target_os = "linux")]
                {
                    self.collectors.ebpf_enabled = false;
                    self.collectors.auditd_enabled = false;
                }

                // Active in balanced (over lightweight):
                //   process(5s), file, network(3s), dns(2s), registry(10s),
                //   usb, ransomware_canary, health, persistence, fim,
                //   etw (event-driven Windows telemetry)

                tracing::info!(
                    profile = "balanced",
                    process_interval = 5,
                    dns_interval = 2000,
                    max_cpu = 15.0,
                    "Performance profile applied: core + detection collectors, expensive analysis skipped"
                );
            }
            PerformanceProfile::Lightweight => {
                // Sub-loop multiplier: 10x slower sub-loops
                self.sub_loop_interval_multiplier = 10.0;
                // Full scan features disabled in lightweight mode
                self.full_scan_features = false;

                // Core EDR visibility must remain near-realtime even in the
                // lightweight profile. Keep advanced collectors off, but do
                // not let process/network latency drift into minutes during
                // benchmark or incident-response workflows.
                self.collector_tuning.process_scan_interval_secs = 5;
                self.collector_tuning.memory_scan_interval_secs = 300;
                self.collector_tuning.dns_poll_interval_ms = 5000;
                self.collector_tuning.network_poll_interval_ms = 5000;
                self.collector_tuning.registry_poll_interval_secs = 30;
                self.collector_tuning.cpu_throttle_threshold = 10.0;
                self.collector_tuning.adaptive_throttling_enabled = true;
                self.collector_tuning.skip_expensive_analysis = true;
                self.max_cpu_percent = 15.0;

                // ---- Disable ALL heavy/polling collectors ----
                // Each of these spawns background loops at 100ms-2s intervals,
                // contributing significantly to CPU usage even when idle.

                // Memory & deep scanning (30s loops, ReadProcessMemory calls)
                self.collectors.memory_enabled = false;
                self.collectors.process_hollowing_enabled = false;

                // Network deep inspection (1s loops, packet capture)
                self.collectors.network_dpi_enabled = false;
                self.collectors.network_anomaly_enabled = false;

                // Credential / lateral (500ms-2s loops, handle enumeration)
                self.collectors.credential_theft_enabled = false;
                self.collectors.lateral_movement_enabled = false;

                // Evasion detection (2s loops, ntdll scanning)
                self.collectors.defense_evasion_enabled = false;
                self.collectors.exploit_mitigation_enabled = false;
                self.collectors.syscall_evasion_enabled = false;

                // Disable all syscall evasion sub-features if re-enabled manually
                self.syscall_evasion.enabled = false;
                self.syscall_evasion.stack_validation = false;
                self.syscall_evasion.etw_profiling = false;
                self.syscall_evasion.heavens_gate_detection = false;

                // Injection detection (6 sub-loops at 500ms-2s each!)
                self.collectors.injection_enabled = false;

                // Scheduled tasks (3 sub-loops at 500ms each)
                self.collectors.scheduled_tasks_enabled = false;

                // NTDLL write monitor has several Windows sub-loops and is too
                // noisy for baseline/lab liveness. It is re-enabled by balanced
                // or explicit collector policy.
                self.collectors.ntdll_write_monitor_enabled = false;

                // Named pipes (2s polling)
                self.collectors.named_pipes_enabled = false;

                // Driver blocklist (1-2s polling)
                self.collectors.driver_blocklist_enabled = false;

                // Persistence (30-60s polling)
                self.collectors.persistence_enabled = false;

                // Script inspection
                self.collectors.script_inspector_enabled = false;

                // Cloud / container
                self.collectors.cloud_enabled = false;
                self.collectors.container_enabled = false;

                // Input / clipboard / browser (500ms-2s loops)
                self.collectors.firmware_enabled = false;
                self.collectors.clipboard_enabled = false;
                self.collectors.browser_protection_enabled = false;
                self.collectors.input_capture_enabled = false;
                self.collectors.office_email_enabled = false;
                self.collectors.ad_monitor_enabled = false;

                // Newly added collectors — heavy init and/or polling
                self.collectors.dlp_enabled = false;
                self.collectors.clipboard_dlp_enabled = false;
                self.collectors.ai_discovery_enabled = false;
                self.collectors.software_inventory_enabled = false;
                self.collectors.fim_enabled = false;
                // File telemetry is required for web shell/dropper visibility.
                // In lightweight mode the file watcher is scoped to C:\Windows\Temp,
                // avoiding the high-volume user/profile paths.
                self.collectors.file_enabled = true;
                self.collectors.ransomware_canary_enabled = false;
                self.collectors.usb_enabled = false;
                #[cfg(target_os = "windows")]
                {
                    self.collectors.identity_enabled = false;
                    // Registry Run keys are a core persistence signal; keep the
                    // Windows registry collector on with the slower 30s interval.
                    self.collectors.registry_enabled = true;
                }

                // Disable local ML model loading — ONNX and feature engine
                // init are CPU-intensive even if never used at runtime
                self.ml_local.enabled = false;

                // Windows process creation must be event-driven even in the
                // lightweight profile. Keep the broad ETW surface disabled, but
                // retain the kernel process provider so short-lived Atomic/CALDERA
                // processes are observable without enabling the heavy collectors.
                #[cfg(target_os = "windows")]
                {
                    self.collectors.etw_enabled = true;
                    self.collectors.etw.enabled = true;
                    self.collectors.etw.ring_buffer_size = 16_384;
                    self.collectors.etw.provider_rate_limit = 1_000;
                    self.collectors.etw.tamper_detection = false;
                    self.collectors.etw.providers.kernel_process = true;
                    self.collectors.etw.providers.kernel_file = false;
                    self.collectors.etw.providers.kernel_network = false;
                    self.collectors.etw.providers.kernel_registry = false;
                    // DNS is low-volume and feeds the DNS monitoring, DoH/DoT
                    // bypass, and domain correlation views. Keep it on even in
                    // lightweight mode so endpoint DNS visibility does not go
                    // dark while heavier ETW providers remain disabled.
                    self.collectors.etw.providers.dns_client = true;
                    self.collectors.etw.providers.powershell = false;
                    self.collectors.etw.providers.amsi = false;
                    self.collectors.etw.providers.security_auditing = false;
                    self.collectors.etw.providers.sysmon = false;
                    self.collectors.etw.providers.threat_intelligence = false;
                    self.collectors.etw.providers.kernel_audit_api = false;
                    self.collectors.etw.providers.wmi_activity = false;
                    self.collectors.etw.providers.task_scheduler = false;
                    self.collectors.etw.providers.services = false;
                    self.collectors.etw.providers.code_integrity = false;
                    self.collectors.etw.providers.ldap_client = false;
                    self.collectors.amsi_enabled = false;
                    self.collectors.lsass_enabled = false;
                    self.collectors.wmi_enabled = false;
                    self.collectors.clr_enabled = false;
                }

                // Linux eBPF (event-driven but still overhead)
                #[cfg(target_os = "linux")]
                {
                    self.collectors.ebpf_enabled = false;
                    self.collectors.auditd_enabled = false;
                }

                // Disable File Journal (Ransomware Rollback) - Heavy I/O
                self.file_journal.enabled = false;

                // Keep the image-based ONNX offline detector available when a
                // local model is staged. It is invoked only for file-content
                // events and avoids the always-on cost of the feature-based
                // ml_local engine, which remains disabled in lightweight mode.
                #[cfg(not(feature = "onnx"))]
                {
                    self.offline_detection.enabled = false;
                }
                #[cfg(feature = "onnx")]
                {
                    self.offline_detection.enabled = offline_detection_requested
                        && std::path::Path::new(&self.offline_detection.onnx_model_path).exists();
                }

                // Disable USB Enforcement - Polling overhead
                self.usb_enforcement.enabled = false;

                // In lightweight mode, only these remain active:
                //   - process (5s)    - core visibility
                //   - file            - scoped C:\Windows\Temp file telemetry
                //   - network (5s)    - connection tracking
                //   - dns (5s)        - DNS monitoring
                //   - registry (30s)  - Run key/persistence telemetry
                //   - etw process     - short-lived Windows process starts
                //   - health (60s)    - agent health metrics

                tracing::info!(
                    profile = "lightweight",
                    process_interval = 5,
                    dns_interval = 5000,
                    network_interval = 5000,
                    max_cpu = 15.0,
                    "Performance profile applied: low-overhead core EDR visibility"
                );
            }
        }

        self.apply_collector_runtime_policy();
    }

    /// Keep nested subsystem switches aligned with the authoritative collector
    /// toggles. This prevents expensive engines from staying active because a
    /// nested config block defaulted to `enabled = true` after the top-level
    /// collector was disabled by profile or fleet policy.
    pub fn apply_collector_runtime_policy(&mut self) {
        if !self.collectors.network_dpi_enabled {
            self.network_dpi.ja4_enabled = false;
            self.network_dpi.jarm_enabled = false;
            self.network_dpi.certificate_analysis_enabled = false;
            self.network_dpi.http2_fingerprint_enabled = false;
            self.network_dpi.behavioral_baseline_enabled = false;
            self.network_dpi.doh_detection_enabled = false;
            self.network_dpi.entropy_analysis_enabled = false;
            self.network_dpi.protocol_identification_enabled = false;
        }

        if !self.collectors.syscall_evasion_enabled {
            self.syscall_evasion.enabled = false;
            self.syscall_evasion.stack_validation = false;
            self.syscall_evasion.etw_profiling = false;
            self.syscall_evasion.heavens_gate_detection = false;
            self.syscall_evasion.etw_cross_process_integrity_enabled = false;
        }

        if !self.collectors.dlp_enabled {
            self.dlp.enabled = false;
            self.dlp.monitor_usb_writes = false;
            self.dlp.monitor_network_shares = false;
            self.dlp.monitor_cloud_sync = false;
        }
        if !self.collectors.clipboard_dlp_enabled {
            self.dlp.monitor_clipboard = false;
        }

        if !self.collectors.usb_enabled {
            self.usb_enforcement.enabled = false;
        }

        if !self.collectors.file_enabled {
            self.ml_local.enabled = false;
            self.ml_local.scan_on_create = false;
            self.ml_local.scan_on_modify = false;
            self.file_journal.enabled = false;
        }

        self.apply_compiled_feature_policy();

        #[cfg(target_os = "windows")]
        {
            self.collectors.etw.enabled = self.collectors.etw_enabled;
            if !self.collectors.etw_enabled {
                self.collectors.etw.tamper_detection = false;
                self.collectors.etw.providers.kernel_process = false;
                self.collectors.etw.providers.kernel_file = false;
                self.collectors.etw.providers.kernel_network = false;
                self.collectors.etw.providers.kernel_registry = false;
                self.collectors.etw.providers.dns_client = false;
                self.collectors.etw.providers.powershell = false;
                self.collectors.etw.providers.amsi = false;
                self.collectors.etw.providers.security_auditing = false;
                self.collectors.etw.providers.sysmon = false;
                self.collectors.etw.providers.threat_intelligence = false;
                self.collectors.etw.providers.kernel_audit_api = false;
                self.collectors.etw.providers.wmi_activity = false;
                self.collectors.etw.providers.task_scheduler = false;
                self.collectors.etw.providers.services = false;
                self.collectors.etw.providers.code_integrity = false;
                self.collectors.etw.providers.ldap_client = false;
                self.edr_blinding.etw_patching_enabled = false;
                self.edr_blinding.event_log_integrity_enabled = false;
            }

            if !self.collectors.amsi_enabled {
                self.edr_blinding.amsi_patching_enabled = false;
                self.edr_blinding.amsi_cross_process_enabled = false;
            }

            if !self.collectors.credential_theft_enabled {
                self.edr_blinding.credential_guard_enabled = false;
            }
        }
    }

    /// Align config-visible local ML switches with the features compiled into
    /// this binary. Fleet config can request ONNX/local ML, but the running
    /// binary is authoritative about whether those engines can actually load.
    pub fn apply_compiled_feature_policy(&mut self) {
        #[cfg(not(feature = "onnx"))]
        {
            if self.ml_scanning_enabled
                || self.pre_execution_blocking.enabled
                || self.offline_detection.enabled
            {
                tracing::warn!(
                    "ONNX feature not compiled; disabling ONNX ML scanning and pre-execution ML"
                );
            }
            self.ml_scanning_enabled = false;
            self.pre_execution_blocking.enabled = false;
        }

        #[cfg(not(feature = "ml-local"))]
        {
            if self.ml_local.enabled || self.ml_local.scan_on_create || self.ml_local.scan_on_modify
            {
                tracing::warn!("ml-local feature not compiled; disabling feature-based local ML");
            }
            self.ml_local.enabled = false;
            self.ml_local.scan_on_create = false;
            self.ml_local.scan_on_modify = false;
        }

        #[cfg(all(not(feature = "onnx"), not(feature = "yara")))]
        {
            if self.offline_detection.enabled {
                tracing::warn!(
                    "Neither ONNX nor YARA features are compiled; disabling offline detection"
                );
            }
            self.offline_detection.enabled = false;
        }
    }
}

// ============================================================================
// FIM Policies Handler
// ============================================================================

/// Handle FIM policies update from server
pub async fn handle_fim_policies_update(payload: &serde_json::Value) -> anyhow::Result<()> {
    use crate::collectors::fim::FimPolicy;

    let policies: Vec<FimPolicy> = serde_json::from_value(
        payload
            .get("policies")
            .cloned()
            .unwrap_or(serde_json::json!([])),
    )?;

    tracing::info!(count = policies.len(), "Received FIM policies update");

    // Store policies to config file
    let policies_path = get_fim_policies_path();
    let content = serde_json::to_string_pretty(&policies)?;

    if let Some(parent) = policies_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(&policies_path, content)?;

    tracing::debug!(path = %policies_path.display(), "FIM policies saved");

    // Notify FIM collector to reload policies (via watch channel if available)
    // This will be picked up on next collector iteration

    Ok(())
}

/// Get the path for FIM policies storage
fn get_fim_policies_path() -> std::path::PathBuf {
    #[cfg(target_os = "windows")]
    return std::path::PathBuf::from("C:\\ProgramData\\Tamandua\\fim_policies.json");

    #[cfg(not(target_os = "windows"))]
    return std::path::PathBuf::from("/var/lib/tamandua/fim_policies.json");
}

#[cfg(test)]
mod performance_profile_tests {
    use super::{AgentConfig, PerformanceProfile};

    fn config_for(profile: PerformanceProfile) -> AgentConfig {
        let mut config = AgentConfig::default();
        config.performance_profile = profile;
        config.apply_performance_profile();
        config
    }

    #[test]
    fn aggressive_profile_keeps_core_visibility_and_full_scan_features() {
        let config = config_for(PerformanceProfile::Aggressive);

        assert_eq!(config.max_cpu_percent, 20.0);
        assert_eq!(config.sub_loop_interval_multiplier, 1.0);
        assert!(config.full_scan_features);
        assert_eq!(config.collector_tuning.process_scan_interval_secs, 3);
        assert_eq!(config.collector_tuning.dns_poll_interval_ms, 1000);
        assert!(config.collectors.process_enabled);
        assert!(config.collectors.file_enabled);
        assert!(config.collectors.network_enabled);
        assert!(config.collectors.dns_enabled);
        assert!(config.collectors.ransomware_canary_enabled);
        assert!(config.collectors.persistence_enabled);
        assert!(!config.collectors.injection_enabled);
        assert!(!config.collectors.memory_enabled);
        assert!(!config.collectors.network_dpi_enabled);
        assert!(!config.network_dpi.behavioral_baseline_enabled);
        assert!(!config.network_dpi.protocol_identification_enabled);
        assert!(!config.offline_detection.enabled);
    }

    #[test]
    fn balanced_profile_keeps_core_detectors_with_bounded_overhead() {
        let config = config_for(PerformanceProfile::Balanced);

        assert_eq!(config.max_cpu_percent, 15.0);
        assert_eq!(config.sub_loop_interval_multiplier, 3.0);
        assert!(!config.full_scan_features);
        assert_eq!(config.collector_tuning.process_scan_interval_secs, 5);
        assert_eq!(config.collector_tuning.network_poll_interval_ms, 3000);
        assert!(config.collectors.process_enabled);
        assert!(config.collectors.file_enabled);
        assert!(config.collectors.network_enabled);
        assert!(config.collectors.dns_enabled);
        assert!(config.collectors.ransomware_canary_enabled);
        assert!(config.collectors.persistence_enabled);
        assert!(!config.collectors.injection_enabled);
        assert!(!config.collectors.memory_enabled);
        assert!(!config.collectors.credential_theft_enabled);
        assert!(!config.collectors.lateral_movement_enabled);
        assert!(!config.collectors.syscall_evasion_enabled);
        assert!(!config.syscall_evasion.enabled);
        assert!(!config.syscall_evasion.etw_cross_process_integrity_enabled);
        assert!(!config.collectors.dlp_enabled);
        assert!(!config.dlp.enabled);
        assert!(!config.dlp.monitor_clipboard);
        assert!(!config.offline_detection.enabled);
    }

    #[test]
    fn lightweight_profile_disables_heavy_collectors_and_local_heavy_analysis() {
        let config = config_for(PerformanceProfile::Lightweight);

        assert_eq!(config.max_cpu_percent, 15.0);
        assert_eq!(config.sub_loop_interval_multiplier, 10.0);
        assert!(!config.full_scan_features);
        assert_eq!(config.collector_tuning.process_scan_interval_secs, 5);
        assert_eq!(config.collector_tuning.dns_poll_interval_ms, 5000);
        assert_eq!(config.collector_tuning.network_poll_interval_ms, 5000);
        assert!(config.collectors.process_enabled);
        assert!(config.collectors.file_enabled);
        assert!(config.collectors.network_enabled);
        assert!(config.collectors.dns_enabled);
        assert!(!config.collectors.ransomware_canary_enabled);
        assert!(!config.collectors.memory_enabled);
        assert!(!config.collectors.process_hollowing_enabled);
        assert!(!config.collectors.network_dpi_enabled);
        assert!(!config.network_dpi.ja4_enabled);
        assert!(!config.network_dpi.entropy_analysis_enabled);
        assert!(!config.collectors.persistence_enabled);
        assert!(!config.collectors.fim_enabled);
        assert!(!config.collectors.usb_enabled);
        assert!(!config.usb_enforcement.enabled);
        assert!(!config.ml_local.enabled);
        assert!(!config.offline_detection.enabled);
        assert!(!config.file_journal.enabled);
        assert!(config.collectors.etw.providers.dns_client);
    }

    #[test]
    fn profile_resource_budget_is_monotonic() {
        let aggressive = config_for(PerformanceProfile::Aggressive);
        let balanced = config_for(PerformanceProfile::Balanced);
        let lightweight = config_for(PerformanceProfile::Lightweight);

        assert!(aggressive.max_cpu_percent > balanced.max_cpu_percent);
        assert!(balanced.max_cpu_percent >= lightweight.max_cpu_percent);
        assert!(
            aggressive.collector_tuning.process_scan_interval_secs
                < balanced.collector_tuning.process_scan_interval_secs
        );
        assert!(
            balanced.collector_tuning.process_scan_interval_secs
                <= lightweight.collector_tuning.process_scan_interval_secs
        );
    }

    #[test]
    fn collector_runtime_policy_makes_top_level_toggles_authoritative() {
        let mut config = AgentConfig::default();
        config.collectors.network_dpi_enabled = false;
        config.collectors.syscall_evasion_enabled = false;
        config.collectors.dlp_enabled = false;
        config.collectors.clipboard_dlp_enabled = false;
        config.collectors.usb_enabled = false;
        config.collectors.file_enabled = false;
        #[cfg(target_os = "windows")]
        {
            config.collectors.etw_enabled = false;
            config.collectors.amsi_enabled = false;
            config.collectors.credential_theft_enabled = false;
        }

        config.apply_collector_runtime_policy();

        assert!(!config.network_dpi.protocol_identification_enabled);
        assert!(!config.network_dpi.behavioral_baseline_enabled);
        assert!(!config.syscall_evasion.enabled);
        assert!(!config.syscall_evasion.etw_cross_process_integrity_enabled);
        assert!(!config.dlp.enabled);
        assert!(!config.dlp.monitor_clipboard);
        assert!(!config.usb_enforcement.enabled);
        assert!(!config.ml_local.enabled);
        assert!(!config.ml_local.scan_on_create);
        assert!(!config.file_journal.enabled);

        #[cfg(target_os = "windows")]
        {
            assert!(!config.collectors.etw.enabled);
            assert!(!config.collectors.etw.providers.kernel_process);
            assert!(!config.edr_blinding.etw_patching_enabled);
            assert!(!config.edr_blinding.amsi_patching_enabled);
            assert!(!config.edr_blinding.credential_guard_enabled);
        }
    }

    #[test]
    fn compiled_feature_policy_makes_binary_capabilities_authoritative() {
        let mut config = AgentConfig::default();
        config.ml_scanning_enabled = true;
        config.ml_local.enabled = true;
        config.ml_local.scan_on_create = true;
        config.ml_local.scan_on_modify = true;
        config.pre_execution_blocking.enabled = true;
        config.offline_detection.enabled = true;

        config.apply_compiled_feature_policy();

        #[cfg(not(feature = "onnx"))]
        {
            assert!(!config.ml_scanning_enabled);
            assert!(!config.pre_execution_blocking.enabled);
        }

        #[cfg(not(feature = "ml-local"))]
        {
            assert!(!config.ml_local.enabled);
            assert!(!config.ml_local.scan_on_create);
            assert!(!config.ml_local.scan_on_modify);
        }

        #[cfg(all(not(feature = "onnx"), not(feature = "yara")))]
        {
            assert!(!config.offline_detection.enabled);
        }
    }
}
