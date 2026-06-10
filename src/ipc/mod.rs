//! Inter-Process Communication between Service and GUI
//!
//! This module provides secure IPC between the privileged service and unprivileged GUI.
//! - Windows: Named pipes with ACLs
//! - Linux/macOS: Unix domain sockets with filesystem permissions
//!
//! Protocol features:
//! - MessagePack serialization for efficiency
//! - Length-prefixed framing
//! - Authentication via shared secret
//! - Request/response and push notification patterns

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub mod acl;
mod auth;
pub mod client;
mod event_store;
mod protocol;
pub mod server;

#[cfg(test)]
mod tests;

pub use auth::{AuthChallenge, AuthState, ChallengeResponse, IpcAuthenticator};
pub use client::IpcClient;
pub use protocol::{MessageCodec, MessageFrame};
pub use server::IpcServer;

/// Maximum message size (16 MB)
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// IPC pipe name for Windows
#[cfg(windows)]
pub const PIPE_NAME: &str = r"\\.\pipe\tamandua-agent";

/// IPC socket path for macOS
#[cfg(target_os = "macos")]
pub const SOCKET_PATH: &str = "/Library/Application Support/Tamandua/agent.sock";

/// IPC socket path for Linux
#[cfg(all(unix, not(target_os = "macos")))]
pub const SOCKET_PATH: &str = "/var/run/tamandua/agent.sock";

/// Messages exchanged between service and GUI
///
/// Note: Using default (externally tagged) serialization for MessagePack compatibility.
/// Internally tagged enums (`#[serde(tag = "type")]`) don't work correctly with rmp_serde.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcMessage {
    // ==================== GUI -> Service ====================
    /// Request current agent status
    GetStatus,

    /// Request detailed agent metrics
    GetMetrics,

    /// Request recent alerts
    GetAlerts {
        since: Option<DateTime<Utc>>,
        limit: Option<usize>,
    },

    /// Request log entries
    GetLogs {
        since: Option<DateTime<Utc>>,
        level: Option<String>,
        limit: Option<usize>,
    },

    /// Start on-demand file/directory scan
    StartScan {
        path: PathBuf,
        recursive: bool,
        scan_archives: bool,
    },

    /// Cancel ongoing scan
    CancelScan { scan_id: String },

    /// Update agent configuration
    UpdateConfig { config: AgentConfigUpdate },

    /// Execute response action
    ExecuteAction { action: ResponseAction },

    /// Block an IP address locally.
    #[serde(rename = "block_ip")]
    BlockIp {
        ip: String,
        reason: Option<String>,
        direction: Option<String>,
    },

    /// Unblock an IP address locally.
    #[serde(rename = "unblock_ip")]
    UnblockIp {
        ip: String,
        reason: Option<String>,
        direction: Option<String>,
    },

    /// Block a domain locally.
    #[serde(rename = "block_domain")]
    BlockDomain {
        domain: String,
        reason: Option<String>,
    },

    /// Unblock a domain locally.
    #[serde(rename = "unblock_domain")]
    UnblockDomain {
        domain: String,
        reason: Option<String>,
    },

    /// List locally blocked IP addresses.
    #[serde(rename = "list_blocked_ips")]
    ListBlockedIps,

    /// List locally blocked domains.
    #[serde(rename = "list_blocked_domains")]
    ListBlockedDomains,

    /// Isolate the host network locally.
    #[serde(rename = "isolate_network")]
    IsolateNetwork { allowed_ips: Option<Vec<String>> },

    /// Restore the host network after isolation.
    #[serde(rename = "restore_network")]
    RestoreNetwork,

    /// Request quarantined files list
    GetQuarantinedFiles,

    /// Restore file from quarantine
    RestoreFile { quarantine_id: String },

    /// Delete quarantined file permanently
    DeleteQuarantinedFile { quarantine_id: String },

    /// Request active network connections
    GetActiveConnections,

    /// Request process tree
    GetProcessTree,

    /// Kill process
    KillProcess { pid: u32 },

    /// Request agent version info
    GetVersion,

    /// Test connection to backend
    TestBackendConnection,

    /// Trigger manual update check
    CheckForUpdates,

    /// Apply pending update
    ApplyUpdate,

    /// Acknowledge alert
    AcknowledgeAlert { alert_id: String },

    // ==================== Component Status & Profile (NEW) ====================
    /// Request comprehensive component status (driver, collectors, backend, health)
    GetComponentStatus,

    /// Request current performance profile
    GetPerformanceProfile,

    /// Set performance profile (requires auth)
    SetPerformanceProfile { profile: PerformanceProfile },

    // ==================== Driver Control (GUI -> Service) ====================
    /// Load the kernel driver (requires admin and authentication)
    LoadDriver,

    /// Unload the kernel driver (requires admin and authentication)
    UnloadDriver,

    /// Get driver status
    GetDriverStatus,

    // ==================== Agent Control (GUI -> Service) ====================
    /// Request agent to gracefully stop (requires authentication)
    /// Note: This will terminate the IPC connection
    StopAgent,

    /// Request agent to restart (requires authentication)
    RestartAgent,

    // ==================== Event History (GUI -> Service) ====================
    /// Request telemetry events with filtering
    GetEvents {
        event_types: Option<Vec<String>>,
        severities: Option<Vec<String>>,
        search: Option<String>,
        date_from: Option<DateTime<Utc>>,
        date_to: Option<DateTime<Utc>>,
        limit: Option<usize>,
        offset: Option<usize>,
    },

    /// Request event statistics for dashboard
    GetEventStatistics {
        date_from: Option<DateTime<Utc>>,
        date_to: Option<DateTime<Utc>>,
    },

    /// Request single event by ID
    GetEvent { event_id: String },

    /// Request related events
    GetRelatedEvents { event_id: String },

    /// Authenticate with token hash (legacy - still supported for backwards compatibility)
    Authenticate { token_hash: String },

    /// Request authentication challenge (new challenge-response protocol)
    RequestChallenge,

    /// Respond to authentication challenge
    AuthenticateChallenge { response: ChallengeResponse },

    // ==================== Service -> GUI ====================
    /// Authentication challenge from server
    Challenge(AuthChallenge),

    /// Agent status update
    StatusUpdate(AgentStatus),

    /// Metrics update
    MetricsUpdate(AgentMetrics),

    /// Scan progress notification
    ScanProgress {
        scan_id: String,
        path: PathBuf,
        progress: f32,
        files_scanned: u64,
        threats_found: u32,
    },

    /// Scan completed
    ScanComplete {
        scan_id: String,
        results: ScanResults,
    },

    /// New alert notification
    Alert(AlertNotification),

    /// Log entries response
    LogEntries(Vec<LogEntry>),

    /// Alerts response
    Alerts(Vec<AlertNotification>),

    /// Quarantined files response
    QuarantinedFiles(Vec<QuarantineEntry>),

    /// Active connections response
    ActiveConnections(Vec<NetworkConnection>),

    /// Process tree response
    ProcessTree(Vec<ProcessInfo>),

    /// Version info response
    VersionInfo(VersionInfo),

    /// Backend connection test result
    BackendTestResult {
        connected: bool,
        latency_ms: Option<u64>,
        error: Option<String>,
    },

    /// Update check result
    UpdateCheckResult {
        update_available: bool,
        current_version: String,
        latest_version: Option<String>,
        release_notes: Option<String>,
        download_size: Option<u64>,
    },

    /// Update download progress
    UpdateProgress {
        version: String,
        downloaded_bytes: u64,
        total_bytes: u64,
        percent: f32,
    },

    /// Update installation started
    UpdateInstalling { version: String },

    /// Update completed, restart required
    UpdateReady {
        version: String,
        requires_restart: bool,
    },

    /// Update failed
    UpdateError { message: String, recoverable: bool },

    // ==================== Component Status & Profile Responses (NEW) ====================
    /// Comprehensive component status response
    ComponentStatusUpdate(ComponentStatus),

    /// Current performance profile response
    PerformanceProfileResponse(PerformanceProfile),

    /// Profile change notification
    ProfileChanged {
        old: PerformanceProfile,
        new: PerformanceProfile,
        collectors_affected: Vec<String>,
    },

    /// Profile change error
    ProfileChangeError { reason: String },

    /// Available performance profiles with detailed info
    PerformanceProfilesInfo(Vec<ProfileInfo>),

    // ==================== Driver & Agent Control Responses ====================
    /// Driver status response
    DriverStatusResponse(DriverStatusInfo),

    /// Driver operation result
    DriverOperationResult {
        operation: String,
        success: bool,
        message: Option<String>,
    },

    /// Agent stopping notification
    AgentStopping {
        reason: String,
        restart_scheduled: bool,
    },

    /// Response action execution result.
    ResponseCommandResult(ResponseCommandResult),

    // ==================== Event History Responses ====================
    /// Telemetry events response
    Events(Vec<TelemetryEvent>),

    /// Event statistics response
    EventStatisticsResponse(EventStatistics),

    /// Single event response
    Event(Option<TelemetryEvent>),

    /// Related events response
    RelatedEvents(Vec<TelemetryEvent>),

    /// Authentication successful
    Authenticated,

    // ==================== Generic Responses ====================
    /// Generic success response
    Success,

    /// Generic error response
    Error {
        message: String,
        code: Option<String>,
    },
}

/// Agent status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatus {
    pub agent_id: String,
    pub version: String,
    pub state: AgentState,
    pub backend_connected: bool,
    pub last_heartbeat: Option<DateTime<Utc>>,
    pub collectors_running: Vec<String>,
    pub protection_enabled: bool,
    pub scan_in_progress: bool,
    pub cpu_usage: f32,
    pub memory_usage: u64,
    pub uptime_seconds: u64,
}

/// Agent operational state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AgentState {
    Starting,
    Running,
    Degraded,
    Stopped,
    Error,
}

/// Agent performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMetrics {
    pub timestamp: DateTime<Utc>,
    pub events_processed: u64,
    pub events_per_second: f64,
    pub alerts_generated: u32,
    pub actions_executed: u32,
    pub cpu_usage: f32,
    pub memory_usage: u64,
    pub network_bytes_sent: u64,
    pub network_bytes_received: u64,
    pub collector_metrics: Vec<CollectorMetrics>,
}

/// Per-collector metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorMetrics {
    pub name: String,
    pub events_collected: u64,
    pub events_per_second: f64,
    pub errors: u32,
    pub cpu_percent: f32,
}

/// Alert notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertNotification {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub severity: AlertSeverity,
    pub title: String,
    pub description: String,
    pub threat_name: Option<String>,
    pub process_name: Option<String>,
    pub process_id: Option<u32>,
    pub file_path: Option<PathBuf>,
    pub mitre_tactics: Vec<String>,
    pub remediation: Option<String>,
    pub acknowledged: bool,
}

/// Alert severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    #[serde(default)]
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub level: String,
    pub message: String,
    pub module: Option<String>,
    pub fields: std::collections::HashMap<String, String>,
}

/// Scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResults {
    pub scan_id: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub files_scanned: u64,
    pub threats_found: u32,
    pub threats: Vec<ThreatDetection>,
    pub errors: Vec<String>,
}

/// Threat detection details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDetection {
    pub file_path: PathBuf,
    pub threat_name: String,
    pub severity: AlertSeverity,
    pub detection_method: String,
    pub action_taken: String,
}

/// Quarantine entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: PathBuf,
    pub quarantined_at: DateTime<Utc>,
    pub threat_name: String,
    pub file_size: u64,
    pub file_hash: String,
}

/// Network connection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: u32,
    pub process_name: String,
}

/// Process information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub path: PathBuf,
    pub command_line: String,
    pub user: String,
    pub cpu_usage: f32,
    pub memory_usage: u64,
    pub started_at: DateTime<Utc>,
    pub children: Vec<ProcessInfo>,
}

/// Version information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    pub version: String,
    pub build_date: String,
    pub commit_hash: String,
    pub rust_version: String,
}

/// Agent configuration update
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfigUpdate {
    pub scan_interval_seconds: Option<u64>,
    pub heartbeat_interval_seconds: Option<u64>,
    pub enable_real_time_protection: Option<bool>,
    pub enable_cloud_lookup: Option<bool>,
    pub excluded_paths: Option<Vec<PathBuf>>,
    pub excluded_processes: Option<Vec<String>>,
}

/// Response action to execute
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResponseAction {
    KillProcess { pid: u32 },
    QuarantineFile { path: PathBuf },
    IsolateHost,
    RestoreHost,
    BlockIp { ip: String },
    UnblockIp { ip: String },
}

// ==================== Component Status & Profile Types (NEW) ====================

/// Performance profile presets
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceProfile {
    /// Maximum detection coverage (15-25% CPU)
    Aggressive,
    /// Balanced detection and performance (5-10% CPU)
    Balanced,
    /// Minimal footprint (1-3% CPU)
    Lightweight,
}

impl PerformanceProfile {
    pub fn as_str(&self) -> &'static str {
        match self {
            PerformanceProfile::Aggressive => "aggressive",
            PerformanceProfile::Balanced => "balanced",
            PerformanceProfile::Lightweight => "lightweight",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            PerformanceProfile::Aggressive => "Maximum detection coverage (~15-25% CPU)",
            PerformanceProfile::Balanced => "Balanced detection and performance (~5-10% CPU)",
            PerformanceProfile::Lightweight => "Minimal footprint (~1-3% CPU)",
        }
    }

    pub fn cpu_target(&self) -> &'static str {
        match self {
            PerformanceProfile::Aggressive => "15-25%",
            PerformanceProfile::Balanced => "5-10%",
            PerformanceProfile::Lightweight => "1-3%",
        }
    }

    /// Get the list of collectors enabled for this profile
    pub fn enabled_collectors(&self) -> Vec<&'static str> {
        match self {
            PerformanceProfile::Aggressive => vec![
                "process",
                "file",
                "network",
                "dns",
                "registry",
                "usb",
                "ransomware_canary",
                "health",
                "etw",
                "persistence",
                "fim",
            ],
            PerformanceProfile::Balanced => vec![
                "process",
                "file",
                "network",
                "dns",
                "registry",
                "usb",
                "ransomware_canary",
                "health",
                "persistence",
                "fim",
                "etw",
            ],
            PerformanceProfile::Lightweight => vec![
                "process",
                "file",
                "network",
                "dns",
                "registry",
                "usb",
                "ransomware_canary",
                "health",
            ],
        }
    }
}

/// Detailed information about a performance profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileInfo {
    pub profile: PerformanceProfile,
    pub cpu_target: String,
    pub description: String,
    pub collectors_enabled: Vec<String>,
    pub features: Vec<String>,
}

/// Comprehensive component status for dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentStatus {
    pub driver: DriverStatus,
    pub collectors: Vec<CollectorStatus>,
    pub backend: BackendStatus,
    pub pressure_level: PressureLevel,
    pub health: HealthStatus,
    pub uptime_seconds: u64,
}

/// Driver/kernel module status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverStatus {
    pub loaded: bool,
    pub version: Option<String>,
    /// Total events captured via driver. None until telemetry connects.
    pub events_captured: Option<u64>,
    pub last_event_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

/// Individual collector status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorStatus {
    pub name: String,
    pub running: bool,
    pub events_per_second: f64,
    pub total_events: u64,
    pub errors: u32,
    pub last_error: Option<String>,
    pub cpu_percent: f32,
    pub memory_bytes: u64,
}

/// Backend connection status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendStatus {
    pub connected: bool,
    pub url: String,
    pub latency_ms: Option<u64>,
    pub events_queued: u64,
    pub events_sent: u64,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

/// Resource pressure level from governor
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PressureLevel {
    None,
    Light,
    Moderate,
    Heavy,
    Critical,
}

impl PressureLevel {
    pub fn multiplier(&self) -> f32 {
        match self {
            PressureLevel::None => 1.0,
            PressureLevel::Light => 2.0,
            PressureLevel::Moderate => 4.0,
            PressureLevel::Heavy => 8.0,
            PressureLevel::Critical => 16.0,
        }
    }
}

/// Health check status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub status: HealthState,
    pub checks: Vec<HealthCheck>,
    pub last_check_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub name: String,
    pub passed: bool,
    pub message: Option<String>,
}

/// Result returned by local response commands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseCommandResult {
    pub success: bool,
    pub error: Option<String>,
    pub result_data: Option<serde_json::Value>,
}

// ==================== Driver Control Types ====================

/// Detailed driver status information for GUI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverStatusInfo {
    /// Whether the driver is currently loaded (minifilter port accessible)
    pub loaded: bool,
    /// Whether an active communication channel exists with the driver.
    /// This reflects the kernel telemetry ring buffer connection state.
    pub connected: bool,
    /// Driver version string
    pub version: Option<String>,
    /// Service name in Windows SCM
    pub service_name: String,
    /// Path to the driver .sys file
    pub driver_path: Option<String>,
    /// Whether the agent is in usermode fallback mode (driver unavailable).
    pub usermode_fallback: bool,
    /// Consecutive communication failures.
    pub consecutive_failures: u32,
    /// Total events captured via driver. None until telemetry connects.
    pub events_captured: Option<u64>,
    /// Last driver telemetry timestamp. None until a driver event is consumed.
    pub last_communication: Option<DateTime<Utc>>,
    /// Current error message if any
    pub error: Option<String>,
    /// Whether driver installation is available (embedded driver present)
    pub install_available: bool,
}

// ==================== Event History Types ====================

/// Telemetry event for Event History
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub id: String,
    pub event_type: String,
    pub severity: String,
    pub timestamp: DateTime<Utc>,
    pub message: String,
    pub agent_id: String,
    pub hostname: String,
    // Process fields
    pub process_name: Option<String>,
    pub process_id: Option<u32>,
    pub parent_process_id: Option<u32>,
    pub command_line: Option<String>,
    pub exe_path: Option<String>,
    pub user: Option<String>,
    // File fields
    pub file_path: Option<String>,
    pub file_action: Option<String>,
    pub file_hash: Option<String>,
    // Network fields
    pub remote_ip: Option<String>,
    pub remote_port: Option<u16>,
    pub local_port: Option<u16>,
    pub protocol: Option<String>,
    pub direction: Option<String>,
    // Registry fields (Windows)
    pub registry_key: Option<String>,
    pub registry_value: Option<String>,
    pub registry_action: Option<String>,
    // Alert fields
    pub alert_source: Option<String>,
    pub alert_severity: Option<String>,
    pub rule_name: Option<String>,
    pub mitre_tactics: Option<Vec<String>>,
    // Raw data
    pub raw_data: Option<serde_json::Value>,
}

/// Event statistics for dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventStatistics {
    pub events_per_hour: Vec<HourlyCount>,
    pub event_type_distribution: Vec<TypeCount>,
    pub top_processes: Vec<ProcessCount>,
    pub total_events: u64,
    pub time_range_hours: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HourlyCount {
    pub hour: DateTime<Utc>,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeCount {
    pub event_type: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessCount {
    pub process_name: String,
    pub count: u64,
}

impl IpcMessage {
    /// Check if this message requires authentication.
    ///
    /// Per the threat model (ACCOUNT_INTEGRITY_THREAT_MODEL.md), sensitive read operations
    /// now require authentication to prevent local information disclosure:
    /// - GetLogs: Log entries may contain sensitive telemetry data
    /// - GetAlerts: Alert details contain detection information
    /// - GetProcessTree: Process information is security-sensitive
    /// - GetActiveConnections: Network connection details
    /// - GetQuarantinedFiles: Quarantine list reveals threat information
    /// - GetEvents: Telemetry events contain sensitive data
    /// - GetEventStatistics: Event statistics
    /// - GetEvent: Individual event details
    /// - GetRelatedEvents: Related event chains
    pub fn requires_auth(&self) -> bool {
        match self {
            // Basic status operations - safe without auth
            IpcMessage::GetStatus
            | IpcMessage::GetMetrics
            | IpcMessage::GetVersion
            | IpcMessage::GetComponentStatus
            | IpcMessage::GetPerformanceProfile
            | IpcMessage::TestBackendConnection => false,

            // Authentication messages - obviously don't require prior auth
            IpcMessage::Authenticate { .. }
            | IpcMessage::RequestChallenge
            | IpcMessage::AuthenticateChallenge { .. } => false,

            // SENSITIVE READ OPERATIONS - Now require authentication
            // These were identified in the threat model as information disclosure risks
            IpcMessage::GetLogs { .. }
            | IpcMessage::GetAlerts { .. }
            | IpcMessage::GetProcessTree
            | IpcMessage::GetActiveConnections
            | IpcMessage::GetQuarantinedFiles
            | IpcMessage::GetEvents { .. }
            | IpcMessage::GetEventStatistics { .. }
            | IpcMessage::GetEvent { .. }
            | IpcMessage::GetRelatedEvents { .. } => true,

            // Response messages don't require auth
            _ if self.is_response() => false,

            // All other operations (write/mutate) require auth
            _ => true,
        }
    }

    /// Check if this message is a sensitive read operation.
    ///
    /// Used to provide better error messages for unauthenticated sensitive reads.
    pub fn is_sensitive_read(&self) -> bool {
        matches!(
            self,
            IpcMessage::GetLogs { .. }
                | IpcMessage::GetAlerts { .. }
                | IpcMessage::GetProcessTree
                | IpcMessage::GetActiveConnections
                | IpcMessage::GetQuarantinedFiles
                | IpcMessage::GetEvents { .. }
                | IpcMessage::GetEventStatistics { .. }
                | IpcMessage::GetEvent { .. }
                | IpcMessage::GetRelatedEvents { .. }
        )
    }

    /// Check if this is a response message
    pub fn is_response(&self) -> bool {
        matches!(
            self,
            IpcMessage::Challenge(_)
                | IpcMessage::StatusUpdate(_)
                | IpcMessage::MetricsUpdate(_)
                | IpcMessage::ScanProgress { .. }
                | IpcMessage::ScanComplete { .. }
                | IpcMessage::Alert(_)
                | IpcMessage::LogEntries(_)
                | IpcMessage::Alerts(_)
                | IpcMessage::QuarantinedFiles(_)
                | IpcMessage::ActiveConnections(_)
                | IpcMessage::ProcessTree(_)
                | IpcMessage::VersionInfo(_)
                | IpcMessage::BackendTestResult { .. }
                | IpcMessage::UpdateCheckResult { .. }
                | IpcMessage::UpdateProgress { .. }
                | IpcMessage::UpdateInstalling { .. }
                | IpcMessage::UpdateReady { .. }
                | IpcMessage::UpdateError { .. }
                | IpcMessage::ComponentStatusUpdate(_)
                | IpcMessage::PerformanceProfileResponse(_)
                | IpcMessage::ProfileChanged { .. }
                | IpcMessage::ProfileChangeError { .. }
                | IpcMessage::PerformanceProfilesInfo(_)
                | IpcMessage::Events(_)
                | IpcMessage::EventStatisticsResponse(_)
                | IpcMessage::Event(_)
                | IpcMessage::RelatedEvents(_)
                | IpcMessage::ResponseCommandResult(_)
                | IpcMessage::Authenticated
                | IpcMessage::Success
                | IpcMessage::Error { .. }
        )
    }
}

// Tests are in tests.rs
