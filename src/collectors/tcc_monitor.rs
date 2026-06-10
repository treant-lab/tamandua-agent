//! TCC (Transparency, Consent, and Control) Monitor
//!
//! Monitors macOS TCC database for permission changes and correlates them
//! with process events to detect:
//! - Unauthorized camera/microphone access
//! - Suspicious Full Disk Access grants
//! - Privacy permission abuse
//! - TCC database tampering
//!
//! ## Detection Strategies
//! 1. Poll TCC.db for changes (user and system databases)
//! 2. Detect new entries or modifications (last_modified timestamp)
//! 3. Correlate permission grants with process creation events
//! 4. Alert on high-risk permissions (FullDiskAccess, ScreenCapture, Accessibility)
//!
//! ## Event Enrichment
//! - Attach TCC permissions to process creation events
//! - Tag processes with their TCC authorization status
//! - Track permission grant/denial patterns

#[cfg(target_os = "macos")]
use super::macos::{
    get_system_tcc_path, get_user_tcc_path, parse_tcc_db, TccAuthValue, TccClientType, TccEntry,
    TccService,
};
use super::{Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent};
use crate::config::AgentConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

/// TCC permission change event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TccEvent {
    /// Service (privacy resource)
    pub service: String,
    /// Service display name
    pub service_display: String,
    /// Client identifier (bundle ID or path)
    pub client: String,
    /// Client type (bundle_id or path)
    pub client_type: String,
    /// Authorization value (allowed/denied)
    pub auth_value: String,
    /// Previous authorization value (if change detected)
    pub previous_auth_value: Option<String>,
    /// Authorization reason code
    pub auth_reason: i32,
    /// Last modified timestamp (Unix epoch seconds)
    pub last_modified: i64,
    /// Change type (new, modified, removed)
    pub change_type: String,
    /// Whether this is a high-risk permission
    pub is_high_risk: bool,
    /// Risk explanation
    pub risk_explanation: Option<String>,
}

/// TCC monitor collector
pub struct TccMonitor {
    event_rx: mpsc::Receiver<TelemetryEvent>,
}

impl TccMonitor {
    /// Create a new TCC monitor
    pub fn new(config: &AgentConfig) -> Self {
        let (event_tx, event_rx) = mpsc::channel(100);

        // Spawn background task to monitor TCC databases
        tokio::spawn(Self::monitor_task(config.clone(), event_tx));

        Self { event_rx }
    }

    /// Background monitoring task
    #[cfg(target_os = "macos")]
    async fn monitor_task(config: AgentConfig, event_tx: mpsc::Sender<TelemetryEvent>) {
        info!("Starting TCC monitor");

        // Polling interval (default: 30 seconds)
        let poll_interval =
            Duration::from_secs(config.tcc_monitor_interval_seconds.unwrap_or(30) as u64);
        let mut interval = interval(poll_interval);

        // Track previous TCC state to detect changes
        let mut previous_state: HashMap<String, TccEntry> = HashMap::new();

        loop {
            interval.tick().await;

            // Scan user TCC database
            if let Some(user_db_path) = get_user_tcc_path() {
                if user_db_path.exists() {
                    if let Err(e) =
                        Self::scan_tcc_db(&user_db_path, "user", &mut previous_state, &event_tx)
                            .await
                    {
                        warn!(error = %e, "Failed to scan user TCC database");
                    }
                } else {
                    debug!(
                        path = %user_db_path.display(),
                        "User TCC database not present for agent account"
                    );
                }
            }

            // Scan system TCC database (requires elevated privileges)
            let system_db_path = get_system_tcc_path();
            if system_db_path.exists() {
                if let Err(e) =
                    Self::scan_tcc_db(&system_db_path, "system", &mut previous_state, &event_tx)
                        .await
                {
                    // System TCC.db may not be readable without FDA or root
                    debug!(error = %e, "Failed to scan system TCC database (expected without FDA)");
                }
            }

            // Periodic cleanup: remove stale entries (older than 7 days)
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let cutoff = now - (7 * 24 * 3600);
            previous_state.retain(|_, entry| entry.last_modified >= cutoff);
        }
    }

    #[cfg(not(target_os = "macos"))]
    async fn monitor_task(_config: AgentConfig, _event_tx: mpsc::Sender<TelemetryEvent>) {
        // TCC monitoring is macOS-only
        warn!("TCC monitor is only available on macOS");
    }

    /// Scan a TCC database and emit events for changes
    #[cfg(target_os = "macos")]
    async fn scan_tcc_db(
        db_path: &std::path::Path,
        db_type: &str,
        previous_state: &mut HashMap<String, TccEntry>,
        event_tx: &mpsc::Sender<TelemetryEvent>,
    ) -> Result<(), String> {
        debug!(path = %db_path.display(), db_type = %db_type, "Scanning TCC database");

        let entries =
            parse_tcc_db(db_path).map_err(|e| format!("Failed to parse TCC database: {}", e))?;

        for entry in entries {
            // Create unique key for tracking changes
            let key = format!("{}:{}:{}", db_type, entry.service.as_str(), entry.client);

            // Check if this is a new or modified entry
            let (change_type, previous_auth_value) = if let Some(prev) = previous_state.get(&key) {
                if prev.auth_value != entry.auth_value {
                    (
                        "modified".to_string(),
                        Some(prev.auth_value.as_str().to_string()),
                    )
                } else if prev.last_modified != entry.last_modified {
                    ("modified".to_string(), None)
                } else {
                    // No change, skip
                    continue;
                }
            } else {
                ("new".to_string(), None)
            };

            // Determine if this is a high-risk permission
            let (is_high_risk, risk_explanation) = Self::assess_risk(&entry);

            // Create TCC event
            let tcc_event = TccEvent {
                service: entry.service.as_str().to_string(),
                service_display: entry.service.display_name().to_string(),
                client: entry.client.clone(),
                client_type: match entry.client_type {
                    TccClientType::BundleId => "bundle_id".to_string(),
                    TccClientType::AbsolutePath => "path".to_string(),
                },
                auth_value: entry.auth_value.as_str().to_string(),
                previous_auth_value,
                auth_reason: entry.auth_reason,
                last_modified: entry.last_modified,
                change_type: change_type.clone(),
                is_high_risk,
                risk_explanation,
            };

            // Determine event severity
            let severity = if is_high_risk {
                if entry.auth_value == TccAuthValue::Allowed {
                    Severity::High
                } else {
                    Severity::Medium
                }
            } else {
                Severity::Low
            };

            // Create telemetry event
            let mut event = TelemetryEvent::new(
                EventType::DefenseEvasion,
                severity,
                EventPayload::Custom(serde_json::to_value(&tcc_event).unwrap()),
            );
            event
                .metadata
                .insert("custom_event_type".to_string(), "tcc_change".to_string());

            // Add detection for high-risk permissions
            if is_high_risk && entry.auth_value == TccAuthValue::Allowed {
                event.add_detection(Detection {
                    detection_type: DetectionType::DefenseEvasion,
                    rule_name: format!(
                        "High-Risk TCC Permission: {}",
                        entry.service.display_name()
                    ),
                    confidence: 0.75,
                    description: format!(
                        "Process '{}' granted {} permission",
                        entry.client,
                        entry.service.display_name()
                    ),
                    mitre_tactics: vec!["TA0005".to_string()], // Defense Evasion
                    mitre_techniques: vec!["T1562".to_string()], // Impair Defenses
                });
            }

            // Send event
            if event_tx.send(event).await.is_err() {
                warn!("Failed to send TCC event (channel closed)");
                return Err("Event channel closed".to_string());
            }

            // Update state
            previous_state.insert(key, entry.clone());
        }

        Ok(())
    }

    /// Assess risk of a TCC permission grant
    #[cfg(target_os = "macos")]
    fn assess_risk(entry: &TccEntry) -> (bool, Option<String>) {
        match &entry.service {
            TccService::FullDiskAccess | TccService::SystemPolicyAllFiles => (
                true,
                Some(
                    "Full Disk Access allows reading all user files including protected data"
                        .to_string(),
                ),
            ),
            TccService::ScreenCapture => (
                true,
                Some("Screen Recording permission allows capturing all screen content".to_string()),
            ),
            TccService::Accessibility => (
                true,
                Some("Accessibility permission allows controlling other applications".to_string()),
            ),
            TccService::Camera => (
                true,
                Some("Camera access may be used for surveillance".to_string()),
            ),
            TccService::Microphone => (
                true,
                Some("Microphone access may be used for eavesdropping".to_string()),
            ),
            _ => (false, None),
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
    fn test_risk_assessment() {
        use super::super::macos::{TccAuthValue, TccClientType};

        let entry = TccEntry {
            service: TccService::FullDiskAccess,
            client: "com.malware.example".to_string(),
            client_type: TccClientType::BundleId,
            auth_value: TccAuthValue::Allowed,
            auth_reason: 0,
            last_modified: 0,
            indirect_object_identifier: None,
            indirect_object_code_identity: None,
        };

        let (is_high_risk, explanation) = TccMonitor::assess_risk(&entry);
        assert!(is_high_risk);
        assert!(explanation.is_some());
    }
}
