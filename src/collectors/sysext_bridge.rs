//! System Extension Bridge for macOS
//!
//! This module provides an XPC bridge to communicate with the TamanduaFileMonitor
//! System Extension. The System Extension runs as a separate process and provides
//! file monitoring events via an XPC Mach service.
//!
//! # Architecture
//!
//! ```text
//! +-------------------+       XPC        +----------------------+
//! | Tamandua Agent    | <--------------> | System Extension     |
//! | (this module)     |  Mach Service    | (TamanduaFileMonitor)|
//! +-------------------+                  +----------------------+
//!         |                                       |
//!    TelemetryEvent                     EndpointSecurity.framework
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! let (tx, rx) = mpsc::channel(1000);
//! let bridge = SysExtBridge::new(tx)?;
//! bridge.start().await?;
//!
//! // Events are sent to the channel
//! while let Some(event) = rx.recv().await {
//!     println!("File event: {:?}", event);
//! }
//! ```
//!
//! # Fallback
//!
//! If the System Extension is not installed or not running, the bridge will
//! fail to connect. The agent should fall back to direct EndpointSecurity
//! integration (which requires running as root).

use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

#[cfg(target_os = "macos")]
use super::macos::{system_extension_probe, CapabilityState};
use super::{EventPayload, EventType, FileEvent, Severity, TelemetryEvent};

/// Mach service name for the System Extension
const SYSEXT_SERVICE_NAME: &str = "com.tamandua.agent.filemonitor";

/// Poll interval for fetching events from the System Extension
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Reconnection delay after connection failure
const RECONNECT_DELAY: Duration = Duration::from_secs(5);

/// Maximum reconnection attempts before giving up
const MAX_RECONNECT_ATTEMPTS: u32 = 10;

// MARK: - FileMonitorEvent

/// File monitor event from the System Extension
///
/// This matches the `FileEvent` structure in the Swift code.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileMonitorEvent {
    /// Unique event identifier
    pub event_id: String,

    /// Event type (open, create, write, close, rename, unlink, exec)
    pub event_type: String,

    /// Full path to the affected file
    pub path: String,

    /// Path before operation (for rename events)
    #[serde(default)]
    pub old_path: Option<String>,

    /// Process ID that triggered the event
    pub pid: i32,

    /// Process path
    pub process_path: String,

    /// Process signing ID (if signed)
    #[serde(default)]
    pub signing_id: Option<String>,

    /// Process team ID (if signed)
    #[serde(default)]
    pub team_id: Option<String>,

    /// User ID
    pub uid: u32,

    /// Group ID
    pub gid: u32,

    /// Event timestamp (nanoseconds since boot)
    pub timestamp: u64,

    /// Whether this was an AUTH event (vs NOTIFY)
    pub is_auth: bool,

    /// Whether the operation was allowed (for AUTH events)
    #[serde(default = "default_allowed")]
    pub allowed: bool,
}

fn default_allowed() -> bool {
    true
}

impl FileMonitorEvent {
    /// Convert to a TelemetryEvent
    pub fn to_telemetry_event(&self) -> TelemetryEvent {
        let event_type = match self.event_type.as_str() {
            "create" => EventType::FileCreate,
            "write" => EventType::FileModify,
            "unlink" => EventType::FileDelete,
            "rename" => EventType::FileRename,
            "open" | "close" | _ => EventType::FileModify,
        };

        let severity = if self.is_auth && !self.allowed {
            Severity::High
        } else {
            Severity::Info
        };

        let file_event = FileEvent {
            path: self.path.clone(),
            old_path: self.old_path.clone(),
            operation: self.event_type.clone(),
            pid: self.pid as u32,
            process_name: std::path::Path::new(&self.process_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string(),
            sha256: Vec::new(), // Not computed by System Extension
            size: 0,            // Not tracked
            entropy: 0.0,       // Not computed
            file_type: infer_file_type(&self.path),
        };

        TelemetryEvent::new(event_type, severity, EventPayload::File(file_event))
    }
}

/// Infer file type from path extension
fn infer_file_type(path: &str) -> String {
    std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .unwrap_or_else(|| "unknown".to_string())
}

// MARK: - SysExtBridge

/// Bridge to the TamanduaFileMonitor System Extension
///
/// This struct manages the XPC connection to the System Extension and
/// converts received events to TelemetryEvents.
pub struct SysExtBridge {
    /// Channel for sending events to the agent
    event_tx: mpsc::Sender<TelemetryEvent>,

    /// Whether the bridge is currently running
    running: std::sync::atomic::AtomicBool,

    /// Connection state
    state: std::sync::Mutex<ConnectionState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Failed(String),
}

impl SysExtBridge {
    /// Create a new System Extension bridge
    ///
    /// # Arguments
    ///
    /// * `event_tx` - Channel for sending TelemetryEvents to the agent
    ///
    /// # Returns
    ///
    /// A new SysExtBridge instance, or an error if initialization fails.
    pub fn new(event_tx: mpsc::Sender<TelemetryEvent>) -> Result<Self, SysExtBridgeError> {
        info!("Initializing System Extension bridge");

        Ok(Self {
            event_tx,
            running: std::sync::atomic::AtomicBool::new(false),
            state: std::sync::Mutex::new(ConnectionState::Disconnected),
        })
    }

    /// Start the bridge and begin receiving events
    ///
    /// This method spawns a background task that polls the System Extension
    /// for events and sends them to the event channel.
    pub async fn start(&self) -> Result<(), SysExtBridgeError> {
        if self.running.load(std::sync::atomic::Ordering::SeqCst) {
            warn!("SysExtBridge already running");
            return Ok(());
        }

        info!("Starting System Extension bridge");
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = ConnectionState::Connecting;

        // Check if the System Extension service is available
        if !Self::check_service_available() {
            let report = Self::preflight_report();
            let msg = format!(
                "System Extension service '{}' is not available. \
                 The extension may not be installed or approved. Preflight: {}",
                SYSEXT_SERVICE_NAME, report
            );
            error!("{}", msg);
            *self.state.lock().unwrap_or_else(|e| e.into_inner()) =
                ConnectionState::Failed(msg.clone());
            return Err(SysExtBridgeError::ServiceUnavailable(msg));
        }

        self.running
            .store(true, std::sync::atomic::Ordering::SeqCst);
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = ConnectionState::Connected;

        info!("System Extension bridge started successfully");
        Ok(())
    }

    /// Stop the bridge
    pub fn stop(&self) {
        info!("Stopping System Extension bridge");
        self.running
            .store(false, std::sync::atomic::Ordering::SeqCst);
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = ConnectionState::Disconnected;
    }

    /// Check if the bridge is running
    pub fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Get the current connection state
    pub fn connection_state(&self) -> ConnectionState {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Human-readable bridge preflight summary for degraded-mode logs.
    pub fn preflight_report() -> String {
        #[cfg(target_os = "macos")]
        {
            let probe = system_extension_probe();
            let state = match probe.state {
                CapabilityState::Ready => "ready",
                CapabilityState::Degraded => "degraded",
                CapabilityState::Unavailable => "unavailable",
                CapabilityState::Unknown => "unknown",
            };
            let checks = probe
                .checks
                .iter()
                .map(|check| format!("{}={:?}", check.name, check.status))
                .collect::<Vec<_>>()
                .join(",");
            format!("state={}, checks=[{}]", state, checks)
        }

        #[cfg(not(target_os = "macos"))]
        {
            "state=unavailable, checks=[macos_host=Fail]".to_string()
        }
    }

    /// Poll for events from the System Extension
    ///
    /// This method should be called periodically to fetch events.
    /// Returns the number of events received.
    pub async fn poll_events(&self) -> Result<usize, SysExtBridgeError> {
        if !self.is_running() {
            return Err(SysExtBridgeError::NotRunning);
        }

        // In a real implementation, this would call the XPC service
        // For now, this is a placeholder that simulates the XPC call
        let events = self.fetch_events_from_xpc().await?;
        let count = events.len();

        for event in events {
            let telemetry_event = event.to_telemetry_event();
            if let Err(e) = self.event_tx.send(telemetry_event).await {
                warn!("Failed to send event: {}", e);
            }
        }

        Ok(count)
    }

    /// Set muted paths in the System Extension
    pub async fn set_muted_paths(&self, paths: &[String]) -> Result<(), SysExtBridgeError> {
        if !self.is_running() {
            return Err(SysExtBridgeError::NotRunning);
        }

        debug!("Setting muted paths: {:?}", paths);
        // In a real implementation, this would call the XPC service
        Ok(())
    }

    /// Enable or disable blocking mode
    pub async fn set_blocking_enabled(&self, enabled: bool) -> Result<(), SysExtBridgeError> {
        if !self.is_running() {
            return Err(SysExtBridgeError::NotRunning);
        }

        debug!("Setting blocking mode: {}", enabled);
        // In a real implementation, this would call the XPC service
        Ok(())
    }

    /// Get statistics from the System Extension
    pub async fn get_stats(&self) -> Result<SysExtStats, SysExtBridgeError> {
        if !self.is_running() {
            return Err(SysExtBridgeError::NotRunning);
        }

        // In a real implementation, this would call the XPC service
        Ok(SysExtStats::default())
    }

    // MARK: - Private Methods

    /// Check if the XPC service is available
    fn check_service_available() -> bool {
        #[cfg(target_os = "macos")]
        {
            debug!(
                "Checking for System Extension service: {}",
                SYSEXT_SERVICE_NAME
            );
            matches!(
                system_extension_probe().state,
                CapabilityState::Ready | CapabilityState::Unknown
            )
        }

        #[cfg(not(target_os = "macos"))]
        {
            false
        }
    }

    /// Fetch events from the XPC service
    async fn fetch_events_from_xpc(&self) -> Result<Vec<FileMonitorEvent>, SysExtBridgeError> {
        // In a real implementation, this would:
        // 1. Create an NSXPCConnection to the Mach service
        // 2. Call getEvents() on the remote proxy
        // 3. Decode the JSON data to FileMonitorEvent structs
        //
        // Since we can't use real XPC in a cross-compilation context,
        // this is a stub that returns an empty list.

        #[cfg(target_os = "macos")]
        {
            // STUB — PLATFORM-INCOMPLETE, not production. On macOS this returns an empty
            // event list instead of making the real NSXPCConnection call to the System
            // Extension, so the bridge never surfaces ES file-monitor events.
            // TODO: Implement actual XPC call using objc crate
            // This would require significant FFI work:
            // - Create NSXPCConnection
            // - Set up the remote object interface
            // - Call synchronously or with completion handler
            // - Decode JSON response
            Ok(Vec::new())
        }

        #[cfg(not(target_os = "macos"))]
        {
            Ok(Vec::new())
        }
    }
}

impl Drop for SysExtBridge {
    fn drop(&mut self) {
        self.stop();
    }
}

// MARK: - SysExtStats

/// Statistics from the System Extension
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SysExtStats {
    /// Total events processed
    pub total_events: u64,

    /// AUTH events processed
    pub auth_events: u64,

    /// NOTIFY events processed
    pub notify_events: u64,

    /// Unknown events (unhandled types)
    pub unknown_events: u64,

    /// Events dropped due to queue overflow
    pub dropped_events: u64,

    /// Events currently queued
    pub queued_events: u64,
}

// MARK: - SysExtBridgeError

/// Errors that can occur during System Extension bridge operations
#[derive(Debug, thiserror::Error)]
pub enum SysExtBridgeError {
    /// The XPC service is not available
    #[error("System Extension service unavailable: {0}")]
    ServiceUnavailable(String),

    /// Failed to connect to the XPC service
    #[error("Failed to connect to System Extension: {0}")]
    ConnectionFailed(String),

    /// The bridge is not running
    #[error("System Extension bridge is not running")]
    NotRunning,

    /// XPC communication error
    #[error("XPC communication error: {0}")]
    XpcError(String),

    /// Failed to decode event data
    #[error("Failed to decode event: {0}")]
    DecodeError(String),

    /// Channel send error
    #[error("Failed to send event: {0}")]
    SendError(String),
}

// MARK: - Helper Functions

/// Try to connect to the System Extension, with fallback to direct ES
pub async fn connect_with_fallback(
    event_tx: mpsc::Sender<TelemetryEvent>,
) -> Result<SysExtBridge, SysExtBridgeError> {
    info!("Attempting to connect to System Extension...");

    let bridge = SysExtBridge::new(event_tx)?;

    match bridge.start().await {
        Ok(()) => {
            info!("Connected to System Extension successfully");
            Ok(bridge)
        }
        Err(e) => {
            warn!(
                "Failed to connect to System Extension: {}. \
                 Consider using direct EndpointSecurity integration (requires root).",
                e
            );
            Err(e)
        }
    }
}

// MARK: - Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_monitor_event_deserialization() {
        let json = r#"{
            "eventId": "test-123",
            "eventType": "open",
            "path": "/tmp/test.txt",
            "pid": 1234,
            "processPath": "/usr/bin/cat",
            "signingId": "com.apple.cat",
            "teamId": "AAPL",
            "uid": 501,
            "gid": 20,
            "timestamp": 123456789,
            "isAuth": true,
            "allowed": true
        }"#;

        let event: FileMonitorEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.event_id, "test-123");
        assert_eq!(event.event_type, "open");
        assert_eq!(event.path, "/tmp/test.txt");
        assert_eq!(event.pid, 1234);
        assert!(event.is_auth);
        assert!(event.allowed);
    }

    #[test]
    fn test_file_monitor_event_to_telemetry() {
        let event = FileMonitorEvent {
            event_id: "test-456".to_string(),
            event_type: "create".to_string(),
            path: "/tmp/newfile.txt".to_string(),
            old_path: None,
            pid: 5678,
            process_path: "/bin/touch".to_string(),
            signing_id: None,
            team_id: None,
            uid: 501,
            gid: 20,
            timestamp: 987654321,
            is_auth: true,
            allowed: true,
        };

        let telemetry = event.to_telemetry_event();
        assert_eq!(telemetry.event_type, EventType::FileCreate);
        assert_eq!(telemetry.severity, Severity::Info);
    }

    #[test]
    fn test_infer_file_type() {
        assert_eq!(infer_file_type("/tmp/test.txt"), "txt");
        assert_eq!(infer_file_type("/usr/bin/ls"), "unknown");
        assert_eq!(infer_file_type("/path/to/script.py"), "py");
        assert_eq!(infer_file_type("/path/to/FILE.PDF"), "pdf");
    }

    #[tokio::test]
    async fn test_bridge_not_running() {
        let (tx, _rx) = mpsc::channel(10);
        let bridge = SysExtBridge::new(tx).unwrap();

        // Bridge is not started, so polling should fail
        let result = bridge.poll_events().await;
        assert!(matches!(result, Err(SysExtBridgeError::NotRunning)));
    }

    #[test]
    fn test_preflight_report_is_stable_text() {
        let report = SysExtBridge::preflight_report();
        assert!(report.contains("state="));
        assert!(report.contains("checks="));
    }
}
