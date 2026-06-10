//! Safe Restoration Module for Quarantine Vault
//!
//! Provides secure file restoration capabilities:
//! - Authentication required before restore
//! - User risk acknowledgment
//! - Option to restore to original or safe location
//! - Re-scan after restore option
//! - Audit trail of all restorations

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::info;

use super::metadata::QuarantineEntry;

/// Restoration request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreRequest {
    /// Quarantine ID of the file to restore
    pub quarantine_id: String,
    /// Target path for restoration (None = original path)
    pub restore_path: Option<String>,
    /// User has acknowledged the risk
    pub risk_acknowledged: bool,
    /// Perform re-scan after restoration
    pub rescan_after_restore: bool,
    /// Authentication token (if required)
    pub auth_token: Option<String>,
    /// User who requested the restore
    pub requested_by: Option<String>,
    /// Reason for restoration
    pub restore_reason: Option<String>,
}

/// Restoration response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreResponse {
    /// Whether restoration succeeded
    pub success: bool,
    /// Quarantine ID
    pub quarantine_id: String,
    /// Path where file was restored
    pub restored_path: Option<String>,
    /// Error message if failed
    pub error: Option<String>,
    /// Re-scan results if performed
    pub rescan_result: Option<RescanInfo>,
    /// Timestamp of restoration
    pub restored_at: DateTime<Utc>,
}

/// Re-scan information after restoration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RescanInfo {
    /// Whether re-scan was performed
    pub performed: bool,
    /// File is still considered malicious
    pub is_malicious: bool,
    /// Detection name if malicious
    pub detection_name: Option<String>,
    /// Detection source (yara, ml, etc.)
    pub detection_source: Option<String>,
    /// Confidence score
    pub confidence: Option<f32>,
    /// Recommendation based on scan
    pub recommendation: RescanRecommendation,
}

/// Recommendation after re-scan
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RescanRecommendation {
    /// File appears safe, restoration OK
    AllowKeep,
    /// File still detected, recommend delete
    RecommendDelete,
    /// File still detected, recommend re-quarantine
    RecommendRequarantine,
    /// Inconclusive, manual review needed
    ManualReviewNeeded,
}

/// Safe restoration location options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeLocation {
    /// Path to the safe location
    pub path: PathBuf,
    /// Description of the location
    pub description: String,
    /// Whether the location is isolated (sandboxed)
    pub is_isolated: bool,
}

/// Restoration manager
pub struct RestoreManager {
    /// Whether authentication is required
    require_auth: bool,
    /// Whether to require risk acknowledgment
    require_acknowledgment: bool,
    /// Default safe locations for restoration
    safe_locations: Vec<SafeLocation>,
    /// Whether to enable re-scan by default
    #[allow(dead_code)]
    rescan_by_default: bool,
}

impl Default for RestoreManager {
    fn default() -> Self {
        Self::new(true, true, true)
    }
}

impl RestoreManager {
    /// Create a new restoration manager
    pub fn new(require_auth: bool, require_acknowledgment: bool, rescan_by_default: bool) -> Self {
        let safe_locations = Self::get_default_safe_locations();

        Self {
            require_auth,
            require_acknowledgment,
            safe_locations,
            rescan_by_default,
        }
    }

    /// Validate a restoration request
    pub fn validate_request(&self, request: &RestoreRequest) -> Result<()> {
        // Check authentication
        if self.require_auth && request.auth_token.is_none() {
            return Err(anyhow!("Authentication required for file restoration"));
        }

        // Check risk acknowledgment
        if self.require_acknowledgment && !request.risk_acknowledged {
            return Err(anyhow!(
                "Risk acknowledgment required. User must accept responsibility for \
                 restoring potentially malicious files."
            ));
        }

        // Validate restore path if provided
        if let Some(ref path) = request.restore_path {
            self.validate_restore_path(path)?;
        }

        Ok(())
    }

    /// Validate that a restore path is safe
    fn validate_restore_path(&self, path: &str) -> Result<()> {
        let path = Path::new(path);

        // Check for path traversal
        if path.to_string_lossy().contains("..") {
            return Err(anyhow!("Path traversal not allowed in restore path"));
        }

        // Check for system paths
        let blocked_paths = self.get_blocked_paths();
        for blocked in &blocked_paths {
            if path.starts_with(blocked) {
                return Err(anyhow!(
                    "Cannot restore to protected system path: {}",
                    blocked.display()
                ));
            }
        }

        Ok(())
    }

    /// Get list of paths where restoration is blocked
    fn get_blocked_paths(&self) -> Vec<PathBuf> {
        #[cfg(windows)]
        {
            vec![
                PathBuf::from("C:\\Windows"),
                PathBuf::from("C:\\Windows\\System32"),
                PathBuf::from("C:\\Windows\\SysWOW64"),
                PathBuf::from("C:\\Program Files"),
                PathBuf::from("C:\\Program Files (x86)"),
                PathBuf::from("C:\\ProgramData\\Tamandua"),
            ]
        }

        #[cfg(not(windows))]
        {
            vec![
                PathBuf::from("/bin"),
                PathBuf::from("/sbin"),
                PathBuf::from("/usr/bin"),
                PathBuf::from("/usr/sbin"),
                PathBuf::from("/usr/local/bin"),
                PathBuf::from("/etc"),
                PathBuf::from("/var/lib/tamandua"),
                PathBuf::from("/boot"),
            ]
        }
    }

    /// Get default safe locations for restoration
    fn get_default_safe_locations() -> Vec<SafeLocation> {
        #[cfg(windows)]
        {
            vec![
                SafeLocation {
                    path: PathBuf::from("C:\\Quarantine\\Restored"),
                    description: "Quarantine restoration folder".to_string(),
                    is_isolated: false,
                },
                SafeLocation {
                    path: dirs::download_dir()
                        .unwrap_or_else(|| PathBuf::from("C:\\Users\\Public\\Downloads")),
                    description: "Downloads folder".to_string(),
                    is_isolated: false,
                },
                SafeLocation {
                    path: dirs::desktop_dir()
                        .unwrap_or_else(|| PathBuf::from("C:\\Users\\Public\\Desktop")),
                    description: "Desktop folder".to_string(),
                    is_isolated: false,
                },
            ]
        }

        #[cfg(not(windows))]
        {
            vec![
                SafeLocation {
                    path: PathBuf::from("/tmp/quarantine-restored"),
                    description: "Temporary restoration folder".to_string(),
                    is_isolated: false,
                },
                SafeLocation {
                    path: dirs::download_dir().unwrap_or_else(|| PathBuf::from("/tmp")),
                    description: "Downloads folder".to_string(),
                    is_isolated: false,
                },
                SafeLocation {
                    path: PathBuf::from("/home"),
                    description: "User home directories".to_string(),
                    is_isolated: false,
                },
            ]
        }
    }

    /// Get available safe locations
    pub fn get_safe_locations(&self) -> &[SafeLocation] {
        &self.safe_locations
    }

    /// Determine the target path for restoration
    pub fn determine_restore_path(
        &self,
        request: &RestoreRequest,
        entry: &QuarantineEntry,
    ) -> Result<PathBuf> {
        if let Some(ref custom_path) = request.restore_path {
            let path = PathBuf::from(custom_path);

            // Ensure parent directory exists
            if let Some(parent) = path.parent() {
                if !parent.exists() {
                    std::fs::create_dir_all(parent)
                        .context("Failed to create restoration directory")?;
                }
            }

            Ok(path)
        } else {
            // Restore to original path
            let original = PathBuf::from(&entry.original_path);

            // Check if original path is blocked
            if let Err(_) = self.validate_restore_path(&entry.original_path) {
                // Fall back to first safe location
                let safe_location = self
                    .safe_locations
                    .first()
                    .ok_or_else(|| anyhow!("No safe locations available for restoration"))?;

                std::fs::create_dir_all(&safe_location.path)?;
                Ok(safe_location.path.join(&entry.original_name))
            } else {
                // Ensure parent directory exists
                if let Some(parent) = original.parent() {
                    if !parent.exists() {
                        std::fs::create_dir_all(parent)
                            .context("Failed to create original directory for restoration")?;
                    }
                }

                Ok(original)
            }
        }
    }

    /// Perform a simulated re-scan of a restored file
    ///
    /// In a real implementation, this would invoke the actual ML/YARA scanners.
    pub fn perform_rescan(&self, file_path: &Path, original_entry: &QuarantineEntry) -> RescanInfo {
        // This is a placeholder implementation
        // In production, this would call the actual scanning infrastructure

        info!(
            path = %file_path.display(),
            original_sha256 = %original_entry.sha256,
            "Performing re-scan of restored file"
        );

        // For now, we assume the file is still malicious if it was originally detected
        let is_malicious = original_entry.threat_name.is_some();

        let recommendation = if is_malicious {
            RescanRecommendation::RecommendRequarantine
        } else {
            RescanRecommendation::AllowKeep
        };

        RescanInfo {
            performed: true,
            is_malicious,
            detection_name: original_entry.threat_name.clone(),
            detection_source: Some(original_entry.detection_source.clone()),
            confidence: Some(0.85),
            recommendation,
        }
    }

    /// Check if the user should be warned about restoration
    pub fn should_warn(&self, entry: &QuarantineEntry) -> bool {
        // Always warn for high/critical severity
        matches!(
            entry.severity,
            super::ThreatSeverity::High | super::ThreatSeverity::Critical
        ) || entry.threat_family.is_some()
            || entry.mitre_tactics.contains(&"impact".to_string())
            || entry
                .mitre_techniques
                .iter()
                .any(|t| t.starts_with("T1486")) // Ransomware
    }

    /// Generate a warning message for the user
    pub fn generate_warning(&self, entry: &QuarantineEntry) -> String {
        let mut warnings = Vec::new();

        warnings.push(format!(
            "WARNING: You are about to restore a file that was quarantined as potentially malicious."
        ));

        if let Some(ref threat_name) = entry.threat_name {
            warnings.push(format!("Threat detected: {}", threat_name));
        }

        if let Some(ref family) = entry.threat_family {
            warnings.push(format!("Malware family: {}", family));
        }

        warnings.push(format!("Severity: {:?}", entry.severity));

        if !entry.mitre_tactics.is_empty() {
            warnings.push(format!(
                "MITRE ATT&CK tactics: {}",
                entry.mitre_tactics.join(", ")
            ));
        }

        warnings.push(String::new());
        warnings.push(
            "By restoring this file, you accept full responsibility for any damage it may cause."
                .to_string(),
        );
        warnings.push("Consider restoring to an isolated environment for analysis.".to_string());

        warnings.join("\n")
    }
}

/// Helper functions for restoration audit
pub mod audit {
    use super::*;

    /// Audit event for restoration
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RestoreAuditEvent {
        pub timestamp: DateTime<Utc>,
        pub quarantine_id: String,
        pub original_path: String,
        pub restored_path: String,
        pub sha256: String,
        pub threat_name: Option<String>,
        pub requested_by: Option<String>,
        pub reason: Option<String>,
        pub success: bool,
        pub error: Option<String>,
        pub rescan_performed: bool,
        pub rescan_malicious: Option<bool>,
    }

    /// Create an audit event from a restore operation
    pub fn create_audit_event(
        entry: &QuarantineEntry,
        request: &RestoreRequest,
        response: &RestoreResponse,
    ) -> RestoreAuditEvent {
        RestoreAuditEvent {
            timestamp: response.restored_at,
            quarantine_id: entry.id.clone(),
            original_path: entry.original_path.clone(),
            restored_path: response.restored_path.clone().unwrap_or_default(),
            sha256: entry.sha256.clone(),
            threat_name: entry.threat_name.clone(),
            requested_by: request.requested_by.clone(),
            reason: request.restore_reason.clone(),
            success: response.success,
            error: response.error.clone(),
            rescan_performed: response
                .rescan_result
                .as_ref()
                .map(|r| r.performed)
                .unwrap_or(false),
            rescan_malicious: response.rescan_result.as_ref().map(|r| r.is_malicious),
        }
    }

    /// Format audit event for logging
    pub fn format_for_log(event: &RestoreAuditEvent) -> String {
        format!(
            "[RESTORE_AUDIT] timestamp={} id={} sha256={} original_path={} restored_path={} \
             threat={} user={} success={} rescan_malicious={:?}",
            event.timestamp,
            event.quarantine_id,
            event.sha256,
            event.original_path,
            event.restored_path,
            event.threat_name.as_deref().unwrap_or("none"),
            event.requested_by.as_deref().unwrap_or("system"),
            event.success,
            event.rescan_malicious,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quarantine::metadata::QuarantineReason;
    use crate::quarantine::ThreatSeverity;

    fn create_test_entry() -> QuarantineEntry {
        QuarantineEntry {
            id: "test-id".to_string(),
            original_path: "/home/user/suspicious.exe".to_string(),
            original_name: "suspicious.exe".to_string(),
            file_size: 12345,
            md5: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
            sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string(),
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            quarantined_at: Utc::now(),
            reason: QuarantineReason::MlDetection,
            detection_source: "ml".to_string(),
            threat_name: Some("Trojan.Generic".to_string()),
            threat_family: Some("GenericTrojan".to_string()),
            severity: ThreatSeverity::High,
            mitre_tactics: vec!["execution".to_string()],
            mitre_techniques: vec!["T1059".to_string()],
            triggered_by: Some("system".to_string()),
            vault_path: "/vault/test.enc".to_string(),
            encryption_iv: "abcdef".to_string(),
            encryption_tag: "123456".to_string(),
            is_compressed: true,
            restoration_history: Vec::new(),
            is_deleted: false,
        }
    }

    #[test]
    fn test_validate_request_missing_auth() {
        let manager = RestoreManager::new(true, true, true);

        let request = RestoreRequest {
            quarantine_id: "test".to_string(),
            restore_path: None,
            risk_acknowledged: true,
            rescan_after_restore: false,
            auth_token: None,
            requested_by: None,
            restore_reason: None,
        };

        let result = manager.validate_request(&request);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Authentication required"));
    }

    #[test]
    fn test_validate_request_missing_acknowledgment() {
        let manager = RestoreManager::new(false, true, true);

        let request = RestoreRequest {
            quarantine_id: "test".to_string(),
            restore_path: None,
            risk_acknowledged: false,
            rescan_after_restore: false,
            auth_token: None,
            requested_by: None,
            restore_reason: None,
        };

        let result = manager.validate_request(&request);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Risk acknowledgment"));
    }

    #[test]
    fn test_validate_request_path_traversal() {
        let manager = RestoreManager::new(false, false, false);

        let request = RestoreRequest {
            quarantine_id: "test".to_string(),
            restore_path: Some("/home/user/../../../etc/passwd".to_string()),
            risk_acknowledged: true,
            rescan_after_restore: false,
            auth_token: None,
            requested_by: None,
            restore_reason: None,
        };

        let result = manager.validate_request(&request);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("traversal"));
    }

    #[test]
    fn test_should_warn() {
        let manager = RestoreManager::default();

        let mut entry = create_test_entry();
        assert!(manager.should_warn(&entry));

        entry.severity = ThreatSeverity::Low;
        entry.threat_family = None;
        entry.mitre_tactics = Vec::new();
        assert!(!manager.should_warn(&entry));
    }

    #[test]
    fn test_generate_warning() {
        let manager = RestoreManager::default();
        let entry = create_test_entry();

        let warning = manager.generate_warning(&entry);
        assert!(warning.contains("WARNING"));
        assert!(warning.contains("Trojan.Generic"));
        assert!(warning.contains("GenericTrojan"));
    }
}
