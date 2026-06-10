//! macOS XProtect Integration
//!
//! Provides integration with macOS security subsystems:
//! - XProtect (built-in malware detection)
//! - Gatekeeper status
//! - MRT (Malware Removal Tool) events
//! - Notarization status
//!
//! ## macOS Security Stack
//!
//! ```text
//! +------------------+     +------------------+     +------------------+
//! | Tamandua Agent   |<--->| Endpoint         |<--->| XProtect         |
//! |                  |     | Security API     |     | (System)         |
//! +------------------+     +------------------+     +------------------+
//!         |                       |
//!         v                       v
//! +------------------+     +------------------+
//! | Gatekeeper       |     | MRT              |
//! | Integration      |     | Monitoring       |
//! +------------------+     +------------------+
//! ```
//!
//! ## XProtect Database
//!
//! Located at: /Library/Apple/System/Library/CoreServices/XProtect.bundle
//!
//! ## References
//!
//! - Apple Endpoint Security framework
//! - XProtect configuration profiles
//! - Gatekeeper policy

#![cfg(target_os = "macos")]

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// XProtect threat detection event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XProtectEvent {
    /// File path
    pub file_path: String,
    /// Malware identifier
    pub malware_id: String,
    /// Detection timestamp
    pub timestamp: u64,
    /// Action taken
    pub action: String,
    /// Additional info
    pub details: HashMap<String, String>,
}

/// Gatekeeper status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatekeeperStatus {
    /// Gatekeeper enabled
    pub enabled: bool,
    /// Developer ID required
    pub developer_id_required: bool,
    /// App Store only mode
    pub app_store_only: bool,
    /// Assessment status
    pub assessment_enabled: bool,
}

/// XProtect database info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XProtectInfo {
    /// Database version
    pub version: String,
    /// Last update time
    pub last_update: Option<String>,
    /// Number of signatures
    pub signature_count: u32,
    /// Bundle path
    pub bundle_path: String,
}

/// XProtect integration configuration
#[derive(Debug, Clone)]
pub struct XProtectConfig {
    /// Monitor for XProtect events
    pub monitor_events: bool,
    /// Check Gatekeeper status
    pub check_gatekeeper: bool,
    /// Monitor MRT activity
    pub monitor_mrt: bool,
    /// Database update check interval
    pub update_check_interval: Duration,
}

impl Default for XProtectConfig {
    fn default() -> Self {
        Self {
            monitor_events: true,
            check_gatekeeper: true,
            monitor_mrt: true,
            update_check_interval: Duration::from_secs(3600),
        }
    }
}

/// XProtect integration statistics
#[derive(Debug, Default)]
pub struct XProtectStats {
    /// Detections observed
    pub detections: AtomicU64,
    /// Gatekeeper blocks
    pub gatekeeper_blocks: AtomicU64,
    /// MRT removals
    pub mrt_removals: AtomicU64,
}

/// XProtect integration handler
pub struct XProtectIntegration {
    config: XProtectConfig,
    stats: Arc<XProtectStats>,
    running: Arc<AtomicBool>,
    event_tx: Option<mpsc::Sender<XProtectEvent>>,
}

impl XProtectIntegration {
    /// Create new XProtect integration
    pub fn new(config: XProtectConfig) -> Result<Self> {
        Ok(Self {
            config,
            stats: Arc::new(XProtectStats::default()),
            running: Arc::new(AtomicBool::new(false)),
            event_tx: None,
        })
    }

    /// Set event channel
    pub fn set_event_channel(&mut self, tx: mpsc::Sender<XProtectEvent>) {
        self.event_tx = Some(tx);
    }

    /// Start the integration
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting macOS XProtect integration");

        self.running.store(true, Ordering::SeqCst);

        // Get initial status
        let info = self.get_xprotect_info()?;
        info!(
            version = %info.version,
            signatures = info.signature_count,
            "XProtect database loaded"
        );

        let gatekeeper = self.get_gatekeeper_status()?;
        info!(
            enabled = gatekeeper.enabled,
            app_store_only = gatekeeper.app_store_only,
            "Gatekeeper status"
        );

        // Start event monitoring
        if self.config.monitor_events {
            let running = self.running.clone();
            let tx = self.event_tx.clone();
            let stats = self.stats.clone();

            tokio::spawn(async move {
                Self::monitor_security_events(running, tx, stats).await;
            });
        }

        // Start database update monitoring
        let running = self.running.clone();
        let interval = self.config.update_check_interval;

        tokio::spawn(async move {
            Self::monitor_database_updates(running, interval).await;
        });

        Ok(())
    }

    /// Stop the integration
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Get XProtect database info
    pub fn get_xprotect_info(&self) -> Result<XProtectInfo> {
        let bundle_path = "/Library/Apple/System/Library/CoreServices/XProtect.bundle";

        // Check if XProtect bundle exists
        if !Path::new(bundle_path).exists() {
            // Try alternate location
            let alt_path = "/System/Library/CoreServices/XProtect.bundle";
            if !Path::new(alt_path).exists() {
                return Err(anyhow!("XProtect bundle not found"));
            }
        }

        // Get version from plist
        let output = Command::new("defaults")
            .args([
                "read",
                &format!("{}/Contents/Info", bundle_path),
                "CFBundleShortVersionString",
            ])
            .output()?;

        let version = if output.status.success() {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        } else {
            "unknown".to_string()
        };

        // Count signatures (approximate)
        let signature_count = self.count_xprotect_signatures(bundle_path)?;

        Ok(XProtectInfo {
            version,
            last_update: self.get_last_update_time(bundle_path),
            signature_count,
            bundle_path: bundle_path.to_string(),
        })
    }

    /// Get Gatekeeper status
    pub fn get_gatekeeper_status(&self) -> Result<GatekeeperStatus> {
        // Check spctl status
        let output = Command::new("spctl").args(["--status"]).output()?;

        let enabled = if output.status.success() {
            let status = String::from_utf8_lossy(&output.stdout);
            status.contains("assessments enabled")
        } else {
            // Try alternate method
            let stderr = String::from_utf8_lossy(&output.stderr);
            !stderr.contains("disabled")
        };

        // Check assessment policy
        let assessment_enabled = self.check_assessment_enabled();

        Ok(GatekeeperStatus {
            enabled,
            developer_id_required: enabled,
            app_store_only: self.check_app_store_only(),
            assessment_enabled,
        })
    }

    /// Check if a file is notarized
    pub fn check_notarization(&self, path: &str) -> Result<bool> {
        let output = Command::new("spctl")
            .args(["--assess", "--type", "execute", path])
            .output()?;

        Ok(output.status.success())
    }

    /// Check file against XProtect
    pub fn check_file(&self, path: &str) -> Result<Option<String>> {
        // Use xprotect_check if available (macOS 10.15+)
        let output = Command::new("/usr/libexec/XProtectCheck")
            .arg(path)
            .output();

        if let Ok(output) = output {
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if stderr.contains("malware") {
                    // Extract malware name from output
                    return Ok(Some(stderr.to_string()));
                }
            }
        }

        // Also check via quarantine
        let output = Command::new("xattr")
            .args(["-p", "com.apple.quarantine", path])
            .output()?;

        if output.status.success() {
            let quarantine = String::from_utf8_lossy(&output.stdout);
            if quarantine.contains("blocked") {
                return Ok(Some("Quarantine blocked".to_string()));
            }
        }

        Ok(None)
    }

    /// Get statistics
    pub fn get_stats(&self) -> &XProtectStats {
        &self.stats
    }

    // ========================================================================
    // Private Implementation
    // ========================================================================

    /// Count XProtect signatures
    fn count_xprotect_signatures(&self, bundle_path: &str) -> Result<u32> {
        // Read yara rules or plist signatures
        let rules_path = format!("{}/Contents/Resources/XProtect.yara", bundle_path);

        if Path::new(&rules_path).exists() {
            let content = std::fs::read_to_string(&rules_path)?;
            // Count "rule " occurrences
            let count = content.matches("rule ").count() as u32;
            return Ok(count);
        }

        // Try plist
        let plist_path = format!("{}/Contents/Resources/XProtect.plist", bundle_path);
        if Path::new(&plist_path).exists() {
            let output = Command::new("plutil")
                .args(["-convert", "json", "-o", "-", &plist_path])
                .output()?;

            if output.status.success() {
                let json = String::from_utf8_lossy(&output.stdout);
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&json) {
                    if let Some(array) = value.as_array() {
                        return Ok(array.len() as u32);
                    }
                }
            }
        }

        Ok(0)
    }

    /// Get last update time
    fn get_last_update_time(&self, bundle_path: &str) -> Option<String> {
        let metadata = std::fs::metadata(bundle_path).ok()?;
        let modified = metadata.modified().ok()?;

        let datetime: chrono::DateTime<chrono::Local> = modified.into();
        Some(datetime.format("%Y-%m-%d %H:%M:%S").to_string())
    }

    /// Check if assessment is enabled
    fn check_assessment_enabled(&self) -> bool {
        let output = Command::new("spctl").args(["--status"]).output();

        if let Ok(output) = output {
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return combined.contains("enabled");
        }

        false
    }

    /// Check if App Store only mode
    fn check_app_store_only(&self) -> bool {
        // Check security preferences
        let output = Command::new("defaults")
            .args(["read", "com.apple.security", "AllowAppStore"])
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                let value = String::from_utf8_lossy(&output.stdout);
                return value.trim() == "1";
            }
        }

        false
    }

    /// Monitor security events via unified logging
    async fn monitor_security_events(
        running: Arc<AtomicBool>,
        tx: Option<mpsc::Sender<XProtectEvent>>,
        stats: Arc<XProtectStats>,
    ) {
        info!("Starting XProtect event monitoring");

        // Use log stream to monitor for XProtect/Gatekeeper events
        let mut child = match Command::new("log")
            .args([
                "stream",
                "--predicate",
                "(subsystem == 'com.apple.xprotect') OR (subsystem == 'com.apple.gatekeeper')",
                "--style",
                "json",
            ])
            .stdout(std::process::Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                error!(error = %e, "Failed to start log stream");
                return;
            }
        };

        let stdout = match child.stdout.take() {
            Some(s) => s,
            None => return,
        };

        let reader = std::io::BufReader::new(stdout);
        use std::io::BufRead;

        for line in reader.lines() {
            if !running.load(Ordering::SeqCst) {
                break;
            }

            if let Ok(line) = line {
                // Parse JSON log entry
                if let Ok(entry) = serde_json::from_str::<serde_json::Value>(&line) {
                    let message = entry["eventMessage"].as_str().unwrap_or("");

                    // Check for detection events
                    if message.contains("XProtect") && message.contains("blocked") {
                        stats.detections.fetch_add(1, Ordering::Relaxed);

                        if let Some(ref tx) = tx {
                            let event = XProtectEvent {
                                file_path: String::new(),
                                malware_id: message.to_string(),
                                timestamp: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_millis() as u64,
                                action: "blocked".to_string(),
                                details: HashMap::new(),
                            };

                            let tx = tx.clone();
                            tokio::spawn(async move {
                                let _ = tx.send(event).await;
                            });
                        }
                    }

                    if message.contains("Gatekeeper") && message.contains("blocked") {
                        stats.gatekeeper_blocks.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }

        let _ = child.kill();
    }

    /// Monitor for database updates
    async fn monitor_database_updates(running: Arc<AtomicBool>, interval: Duration) {
        let mut previous_version: Option<String> = None;

        while running.load(Ordering::SeqCst) {
            // Check XProtect version
            let output = Command::new("defaults")
                .args([
                    "read",
                    "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info",
                    "CFBundleShortVersionString",
                ])
                .output();

            if let Ok(output) = output {
                if output.status.success() {
                    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();

                    if let Some(ref prev) = previous_version {
                        if *prev != version {
                            info!(
                                old = %prev,
                                new = %version,
                                "XProtect database updated"
                            );
                        }
                    }

                    previous_version = Some(version);
                }
            }

            tokio::time::sleep(interval).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = XProtectConfig::default();
        assert!(config.monitor_events);
        assert!(config.check_gatekeeper);
    }
}
