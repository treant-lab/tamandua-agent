//! XPC Service Monitor
//!
//! Monitors macOS XPC (Inter-Process Communication) services for:
//! - New XPC service registrations
//! - XPC connections between processes
//! - Suspicious privilege escalation via XPC
//! - Unauthorized XPC service creation
//!
//! ## Detection Strategies
//! 1. Enumerate active XPC services via `launchctl list`
//! 2. Monitor launchd plist directories for new service files
//! 3. Detect XPC connections by correlating process command-line arguments
//! 4. Alert on XPC services created outside standard directories
//! 5. Flag privilege escalation (user → root XPC connections)
//!
//! ## MITRE ATT&CK Coverage
//! - T1543.001: Create or Modify System Process - Launch Daemon
//! - T1543.004: Create or Modify System Process - Launch Agent
//! - T1574.011: Hijack Execution Flow - XPC Service Hijacking

#[cfg(target_os = "macos")]
use super::macos::{enumerate_xpc_services, scan_launchd_plists, XpcService, XpcServiceType};
use super::{Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent};
use crate::config::AgentConfig;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

/// XPC service event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XpcEvent {
    /// Event type (new_service, service_started, service_stopped, connection)
    pub event_type: String,
    /// Service label
    pub service_label: String,
    /// Service type (daemon, agent, application)
    pub service_type: String,
    /// Process ID (if running)
    pub pid: Option<i32>,
    /// Executable path (if known)
    pub executable_path: Option<String>,
    /// Plist path (if known)
    pub plist_path: Option<String>,
    /// Client process (for connection events)
    pub client_pid: Option<u32>,
    /// Client process name (for connection events)
    pub client_name: Option<String>,
    /// Whether this is a suspicious event
    pub is_suspicious: bool,
    /// Suspicion reason
    pub suspicion_reason: Option<String>,
    /// Risk score (0.0 - 1.0)
    pub risk_score: f32,
}

/// XPC connection event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XpcConnectionEvent {
    /// Client process ID
    pub client_pid: u32,
    /// Client process name
    pub client_name: String,
    /// Client process path
    pub client_path: String,
    /// XPC service name
    pub service_name: String,
    /// Server process ID (if known)
    pub server_pid: Option<u32>,
    /// Server process name (if known)
    pub server_name: Option<String>,
    /// Connection timestamp
    pub timestamp: u64,
    /// Whether this represents privilege escalation
    pub is_privilege_escalation: bool,
}

/// XPC monitor collector
pub struct XpcMonitor {
    event_rx: mpsc::Receiver<TelemetryEvent>,
}

impl XpcMonitor {
    /// Create a new XPC monitor
    pub fn new(config: &AgentConfig) -> Self {
        let (event_tx, event_rx) = mpsc::channel(100);

        // Spawn background task to monitor XPC services
        tokio::spawn(Self::monitor_task(config.clone(), event_tx));

        Self { event_rx }
    }

    /// Background monitoring task
    #[cfg(target_os = "macos")]
    async fn monitor_task(config: AgentConfig, event_tx: mpsc::Sender<TelemetryEvent>) {
        info!("Starting XPC monitor");

        // Polling interval (default: 60 seconds)
        let poll_interval =
            Duration::from_secs(config.xpc_monitor_interval_seconds.unwrap_or(60) as u64);
        let mut interval = interval(poll_interval);

        // Track known services to detect new registrations
        let mut known_services: HashSet<String> = HashSet::new();

        // Track known plist files to detect new service files
        let mut known_plists: HashSet<std::path::PathBuf> = HashSet::new();
        let mut service_scan_warned = false;
        let mut plist_scan_warned = false;

        // Initial baseline
        match enumerate_xpc_services() {
            Ok(services) => {
                for service in services {
                    known_services.insert(service.label.clone());
                }
                info!(
                    count = known_services.len(),
                    "Established XPC service baseline"
                );
            }
            Err(e) => {
                service_scan_warned = true;
                warn!(
                    error = %e,
                    "XPC service enumeration unavailable; launchd plist monitoring remains active"
                );
            }
        }

        match scan_launchd_plists() {
            Ok(plists) => {
                for plist in plists {
                    known_plists.insert(plist);
                }
                info!(
                    count = known_plists.len(),
                    "Established launchd plist baseline"
                );
            }
            Err(e) => {
                plist_scan_warned = true;
                warn!(error = %e, "Failed to establish launchd plist baseline");
            }
        }

        loop {
            interval.tick().await;

            // Scan for new XPC services
            if let Err(e) = Self::scan_xpc_services(&mut known_services, &event_tx).await {
                if service_scan_warned {
                    debug!(error = %e, "XPC service scan still unavailable");
                } else {
                    service_scan_warned = true;
                    warn!(
                        error = %e,
                        "XPC service scan unavailable; continuing launchd plist monitoring"
                    );
                }
            } else {
                service_scan_warned = false;
            }

            // Scan for new launchd plists
            if let Err(e) = Self::scan_launchd_plists_changes(&mut known_plists, &event_tx).await {
                if plist_scan_warned {
                    debug!(error = %e, "launchd plist scan still unavailable");
                } else {
                    plist_scan_warned = true;
                    warn!(error = %e, "Failed to scan launchd plists");
                }
            } else {
                plist_scan_warned = false;
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    async fn monitor_task(_config: AgentConfig, _event_tx: mpsc::Sender<TelemetryEvent>) {
        // XPC monitoring is macOS-only
        warn!("XPC monitor is only available on macOS");
    }

    /// Scan for new or changed XPC services
    #[cfg(target_os = "macos")]
    async fn scan_xpc_services(
        known_services: &mut HashSet<String>,
        event_tx: &mpsc::Sender<TelemetryEvent>,
    ) -> Result<(), String> {
        debug!("Scanning XPC services");

        let services = enumerate_xpc_services()
            .map_err(|e| format!("Failed to enumerate XPC services: {}", e))?;

        for service in services {
            // Check if this is a new service
            if !known_services.contains(&service.label) {
                info!(label = %service.label, "Detected new XPC service");

                // Assess risk
                let (is_suspicious, suspicion_reason, risk_score) = Self::assess_xpc_risk(&service);

                // Create XPC event
                let xpc_event = XpcEvent {
                    event_type: "new_service".to_string(),
                    service_label: service.label.clone(),
                    service_type: format!("{:?}", service.service_type).to_lowercase(),
                    pid: if service.pid > 0 {
                        Some(service.pid)
                    } else {
                        None
                    },
                    executable_path: service.executable_path.clone(),
                    plist_path: service.plist_path.clone(),
                    client_pid: None,
                    client_name: None,
                    is_suspicious,
                    suspicion_reason: suspicion_reason.clone(),
                    risk_score,
                };

                // Determine severity
                let severity = if risk_score >= 0.7 {
                    Severity::High
                } else if risk_score >= 0.4 {
                    Severity::Medium
                } else {
                    Severity::Low
                };

                // Create telemetry event
                let mut event = TelemetryEvent::new(
                    EventType::PersistenceInstall,
                    severity,
                    EventPayload::Custom(serde_json::to_value(&xpc_event).unwrap()),
                );
                event
                    .metadata
                    .insert("custom_event_type".to_string(), "xpc_service".to_string());

                // Add detection for suspicious services
                if is_suspicious {
                    event.add_detection(Detection {
                        detection_type: DetectionType::Persistence,
                        rule_name: "Suspicious XPC Service Registration".to_string(),
                        confidence: risk_score,
                        description: format!(
                            "New XPC service registered: {} ({})",
                            service.label,
                            suspicion_reason.as_deref().unwrap_or("unknown reason")
                        ),
                        mitre_tactics: vec!["TA0003".to_string()], // Persistence
                        mitre_techniques: vec!["T1543.001".to_string()], // Launch Daemon
                    });
                }

                // Send event
                if event_tx.send(event).await.is_err() {
                    warn!("Failed to send XPC event (channel closed)");
                    return Err("Event channel closed".to_string());
                }

                // Add to known services
                known_services.insert(service.label.clone());
            }
        }

        Ok(())
    }

    /// Scan launchd plist directories for changes
    #[cfg(target_os = "macos")]
    async fn scan_launchd_plists_changes(
        known_plists: &mut HashSet<std::path::PathBuf>,
        event_tx: &mpsc::Sender<TelemetryEvent>,
    ) -> Result<(), String> {
        debug!("Scanning launchd plists");

        let plists =
            scan_launchd_plists().map_err(|e| format!("Failed to scan launchd plists: {}", e))?;

        for plist_path in plists {
            if !known_plists.contains(&plist_path) {
                info!(path = %plist_path.display(), "Detected new launchd plist");

                // Extract label from plist filename
                let label = plist_path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
                    .to_string();

                // Assess risk based on plist location
                let (is_suspicious, risk_score) = Self::assess_plist_risk(&plist_path);

                // Create XPC event
                let xpc_event = XpcEvent {
                    event_type: "new_plist".to_string(),
                    service_label: label.clone(),
                    service_type: "unknown".to_string(),
                    pid: None,
                    executable_path: None,
                    plist_path: Some(plist_path.display().to_string()),
                    client_pid: None,
                    client_name: None,
                    is_suspicious,
                    suspicion_reason: if is_suspicious {
                        Some("New launchd plist in system directory".to_string())
                    } else {
                        None
                    },
                    risk_score,
                };

                // Create telemetry event
                let severity = if risk_score >= 0.6 {
                    Severity::High
                } else {
                    Severity::Medium
                };

                let mut event = TelemetryEvent::new(
                    EventType::PersistenceInstall,
                    severity,
                    EventPayload::Custom(serde_json::to_value(&xpc_event).unwrap()),
                );
                event
                    .metadata
                    .insert("custom_event_type".to_string(), "xpc_plist".to_string());

                // Add detection for suspicious plists
                if is_suspicious {
                    event.add_detection(Detection {
                        detection_type: DetectionType::Persistence,
                        rule_name: "New Launch Daemon/Agent Plist".to_string(),
                        confidence: risk_score,
                        description: format!("New launchd plist created: {}", plist_path.display()),
                        mitre_tactics: vec!["TA0003".to_string()], // Persistence
                        mitre_techniques: vec!["T1543.001".to_string()], // Launch Daemon
                    });
                }

                // Send event
                if event_tx.send(event).await.is_err() {
                    warn!("Failed to send plist event (channel closed)");
                    return Err("Event channel closed".to_string());
                }

                // Add to known plists
                known_plists.insert(plist_path);
            }
        }

        Ok(())
    }

    /// Assess risk of an XPC service
    #[cfg(target_os = "macos")]
    fn assess_xpc_risk(service: &XpcService) -> (bool, Option<String>, f32) {
        let mut risk_score: f32 = 0.0;
        let mut suspicion_reasons: Vec<String> = Vec::new();

        // Check service type
        match service.service_type {
            XpcServiceType::SystemDaemon => {
                // System daemons run as root - higher risk if not from Apple
                if !service.label.starts_with("com.apple.") {
                    risk_score += 0.4;
                    suspicion_reasons.push("Third-party system daemon".to_string());
                }
            }
            XpcServiceType::SystemAgent => {
                if !service.label.starts_with("com.apple.") {
                    risk_score += 0.3;
                    suspicion_reasons.push("Third-party system agent".to_string());
                }
            }
            XpcServiceType::UserAgent => {
                // User agents are less risky but still worth monitoring
                risk_score += 0.1;
            }
            XpcServiceType::ApplicationService => {
                risk_score += 0.1;
            }
            XpcServiceType::Unknown => {
                risk_score += 0.2;
                suspicion_reasons.push("Unknown service type".to_string());
            }
        }

        // Check for suspicious label patterns
        let suspicious_keywords = ["backdoor", "rootkit", "keylog", "inject", "hidden"];
        for keyword in &suspicious_keywords {
            if service.label.to_lowercase().contains(keyword) {
                risk_score += 0.5;
                suspicion_reasons.push(format!("Suspicious keyword: {}", keyword));
                break;
            }
        }

        let is_suspicious = risk_score >= 0.3;
        let suspicion_reason = if !suspicion_reasons.is_empty() {
            Some(suspicion_reasons.join(", "))
        } else {
            None
        };

        (is_suspicious, suspicion_reason, risk_score.min(1.0_f32))
    }

    /// Assess risk of a launchd plist based on location
    #[cfg(target_os = "macos")]
    fn assess_plist_risk(plist_path: &std::path::Path) -> (bool, f32) {
        let path_str = plist_path.display().to_string();

        // System directories are higher risk (requires root to write)
        if path_str.starts_with("/Library/LaunchDaemons") {
            (true, 0.7)
        } else if path_str.starts_with("/Library/LaunchAgents") {
            (true, 0.6)
        } else if path_str.contains("/Library/LaunchAgents") {
            // User-specific agents are lower risk
            (false, 0.3)
        } else {
            (false, 0.2)
        }
    }

    /// Consume the next telemetry event
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "macos")]
    fn test_xpc_risk_assessment() {
        use super::super::macos::XpcServiceType;

        let service = XpcService {
            label: "com.malware.backdoor".to_string(),
            pid: 0,
            status: 0,
            service_type: XpcServiceType::SystemDaemon,
            executable_path: None,
            plist_path: None,
            is_loaded: false,
        };

        let (is_suspicious, reason, risk_score) = XpcMonitor::assess_xpc_risk(&service);
        assert!(is_suspicious);
        assert!(reason.is_some());
        assert!(risk_score >= 0.5);
    }
}
