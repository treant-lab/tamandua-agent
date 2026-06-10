//! Secure Quarantine Vault for Tamandua EDR
//!
//! Provides encrypted, integrity-verified storage for quarantined malware samples.
//!
//! Features:
//! - AES-256-GCM encryption with per-file random IV
//! - Machine-specific key derivation (DPAPI on Windows, keychain on macOS, secret-tool on Linux)
//! - SQLite metadata database with full threat intelligence
//! - Configurable retention policies and size limits
//! - Safe restoration with re-scan capability
//! - HMAC integrity verification
//!
//! Storage layout:
//! - Windows: %ProgramData%\Tamandua\Quarantine\
//! - Linux: /var/lib/tamandua/quarantine/
//! - macOS: /var/lib/tamandua/quarantine/
//!
//! File structure:
//!   vault/{year}/{month}/{uuid}.enc - Encrypted files
//!   quarantine.db - SQLite metadata database
//!
//! MITRE ATT&CK:
//! - Defense against T1486 (Data Encrypted for Impact) - preserves malware samples
//! - Defense against T1485 (Data Destruction) - secure storage prevents sample loss

#[cfg(test)]
mod tests;

pub mod encryption;
pub mod metadata;
pub mod restore;
pub mod retention;
pub mod stats;
pub mod vault;

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};
use uuid::Uuid;

use encryption::EncryptionManager;
use metadata::MetadataDb;
use retention::RetentionPolicy;
use stats::VaultStats;
use vault::VaultStorage;

// Re-export commonly used types
pub use metadata::{QuarantineEntry, QuarantineReason, RestorationRecord, ThreatInfo};
pub use retention::RetentionConfig;
pub use stats::ThreatFamilyStats;

/// Quarantine vault configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct QuarantineConfig {
    /// Whether quarantine is enabled
    pub enabled: bool,
    /// Base directory for the quarantine vault
    pub vault_path: String,
    /// Maximum vault size in bytes (default: 10GB)
    pub max_size_bytes: u64,
    /// Default retention period in days (default: 90)
    pub retention_days: u32,
    /// Whether to require authentication for restore operations
    pub require_auth_for_restore: bool,
    /// Whether to re-scan files after restoration
    pub rescan_after_restore: bool,
    /// Master encryption key ID (for key rotation)
    pub master_key_id: Option<String>,
    /// Whether to compress files before encryption
    pub compress_before_encrypt: bool,
    /// Maximum individual file size to quarantine (default: 100MB)
    pub max_file_size_bytes: u64,
}

impl Default for QuarantineConfig {
    fn default() -> Self {
        let vault_path = if cfg!(windows) {
            "C:\\ProgramData\\Tamandua\\Quarantine".to_string()
        } else {
            "/var/lib/tamandua/quarantine".to_string()
        };

        Self {
            enabled: true,
            vault_path,
            max_size_bytes: 10 * 1024 * 1024 * 1024, // 10GB
            retention_days: 90,
            require_auth_for_restore: true,
            rescan_after_restore: true,
            master_key_id: None,
            compress_before_encrypt: true,
            max_file_size_bytes: 100 * 1024 * 1024, // 100MB
        }
    }
}

/// Result of a quarantine operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineResult {
    /// Unique ID assigned to the quarantined file
    pub quarantine_id: String,
    /// Original file path
    pub original_path: String,
    /// Whether the operation succeeded
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// File size in bytes
    pub file_size: u64,
    /// SHA256 hash of the original file
    pub sha256: String,
    /// Timestamp of quarantine
    pub quarantined_at: DateTime<Utc>,
}

/// Result of a restore operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreResult {
    /// Quarantine ID of the restored file
    pub quarantine_id: String,
    /// Path where the file was restored
    pub restored_path: String,
    /// Whether the operation succeeded
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// Whether user acknowledged the risk
    pub user_acknowledged_risk: bool,
    /// Re-scan result if performed
    pub rescan_result: Option<RescanResult>,
}

/// Result of a re-scan after restoration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RescanResult {
    /// Whether the file is still considered malicious
    pub is_malicious: bool,
    /// Detection details if malicious
    pub detection: Option<String>,
    /// Confidence score if available
    pub confidence: Option<f32>,
}

/// Quarantine file listing item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineListItem {
    pub id: String,
    pub original_path: String,
    pub original_name: String,
    pub file_size: u64,
    pub sha256: String,
    pub quarantined_at: DateTime<Utc>,
    pub reason: QuarantineReason,
    pub threat_name: Option<String>,
    pub severity: ThreatSeverity,
    pub can_restore: bool,
}

/// Threat severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl Default for ThreatSeverity {
    fn default() -> Self {
        ThreatSeverity::Medium
    }
}

impl ThreatSeverity {
    pub fn from_score(score: f32) -> Self {
        if score >= 0.9 {
            ThreatSeverity::Critical
        } else if score >= 0.7 {
            ThreatSeverity::High
        } else if score >= 0.4 {
            ThreatSeverity::Medium
        } else {
            ThreatSeverity::Low
        }
    }
}

/// Main quarantine manager
pub struct QuarantineManager {
    config: QuarantineConfig,
    vault: Arc<RwLock<VaultStorage>>,
    metadata_db: Arc<RwLock<MetadataDb>>,
    encryption: Arc<EncryptionManager>,
    retention: Arc<RetentionPolicy>,
}

impl QuarantineManager {
    /// Create a new quarantine manager
    pub async fn new(config: QuarantineConfig) -> Result<Self> {
        if !config.enabled {
            return Err(anyhow!("Quarantine is disabled by configuration"));
        }

        // Initialize vault storage
        let vault = VaultStorage::new(&config.vault_path)?;

        // Initialize encryption manager (retrieves/creates key from credential store)
        let encryption = EncryptionManager::new(config.master_key_id.as_deref())?;

        // Initialize metadata database
        let db_path = Path::new(&config.vault_path).join("quarantine.db");
        let metadata_db = MetadataDb::new(&db_path)?;

        // Initialize retention policy
        let retention = RetentionPolicy::new(RetentionConfig {
            retention_days: config.retention_days,
            max_size_bytes: config.max_size_bytes,
        });

        info!(
            vault_path = %config.vault_path,
            max_size_gb = config.max_size_bytes / (1024 * 1024 * 1024),
            retention_days = config.retention_days,
            "Quarantine vault initialized"
        );

        Ok(Self {
            config,
            vault: Arc::new(RwLock::new(vault)),
            metadata_db: Arc::new(RwLock::new(metadata_db)),
            encryption: Arc::new(encryption),
            retention: Arc::new(retention),
        })
    }

    /// Quarantine a file
    pub async fn quarantine_file(
        &self,
        file_path: &Path,
        reason: QuarantineReason,
        threat_info: Option<ThreatInfo>,
        triggered_by: Option<&str>,
    ) -> Result<QuarantineResult> {
        let original_path = file_path.to_string_lossy().to_string();
        info!(path = %original_path, reason = ?reason, "Quarantining file");

        // Check file exists and get metadata
        let file_metadata = std::fs::metadata(file_path)
            .with_context(|| format!("Failed to read file metadata: {}", original_path))?;

        let file_size = file_metadata.len();

        // Check file size limit
        if file_size > self.config.max_file_size_bytes {
            return Ok(QuarantineResult {
                quarantine_id: String::new(),
                original_path: original_path.clone(),
                success: false,
                error: Some(format!(
                    "File size ({} bytes) exceeds maximum allowed ({} bytes)",
                    file_size, self.config.max_file_size_bytes
                )),
                file_size,
                sha256: String::new(),
                quarantined_at: Utc::now(),
            });
        }

        // Read file content
        let content = std::fs::read(file_path)
            .with_context(|| format!("Failed to read file: {}", original_path))?;

        // Calculate hashes
        let sha256 = Self::calculate_sha256(&content);
        let sha1 = Self::calculate_sha1(&content);
        let md5 = Self::calculate_md5(&content);

        // Generate unique ID
        let quarantine_id = Uuid::new_v4().to_string();
        let now = Utc::now();

        // Optionally compress
        let content_to_encrypt = if self.config.compress_before_encrypt {
            Self::compress(&content)?
        } else {
            content.clone()
        };

        // Encrypt the file
        let encrypted = self
            .encryption
            .encrypt(&content_to_encrypt, &quarantine_id)?;

        // Store in vault
        let vault = self.vault.write().await;
        let vault_path = vault.store_file(&quarantine_id, &encrypted.ciphertext, now)?;
        drop(vault);

        // Get original filename
        let original_name = file_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Create metadata entry
        let entry = QuarantineEntry {
            id: quarantine_id.clone(),
            original_path: original_path.clone(),
            original_name,
            file_size,
            md5,
            sha1,
            sha256: sha256.clone(),
            quarantined_at: now,
            reason: reason.clone(),
            detection_source: threat_info
                .as_ref()
                .map(|t| t.detection_source.clone())
                .unwrap_or_default(),
            threat_name: threat_info.as_ref().and_then(|t| t.threat_name.clone()),
            threat_family: threat_info.as_ref().and_then(|t| t.threat_family.clone()),
            severity: threat_info.as_ref().map(|t| t.severity).unwrap_or_default(),
            mitre_tactics: threat_info
                .as_ref()
                .map(|t| t.mitre_tactics.clone())
                .unwrap_or_default(),
            mitre_techniques: threat_info
                .as_ref()
                .map(|t| t.mitre_techniques.clone())
                .unwrap_or_default(),
            triggered_by: triggered_by.map(|s| s.to_string()),
            vault_path: vault_path.to_string_lossy().to_string(),
            encryption_iv: hex::encode(&encrypted.iv),
            encryption_tag: hex::encode(&encrypted.tag),
            is_compressed: self.config.compress_before_encrypt,
            restoration_history: Vec::new(),
            is_deleted: false,
        };

        // Store metadata
        let db = self.metadata_db.write().await;
        db.insert_entry(&entry)?;
        drop(db);

        // Delete original file
        if let Err(e) = std::fs::remove_file(file_path) {
            warn!(
                path = %original_path,
                error = %e,
                "Failed to delete original file after quarantine"
            );
        }

        // Best-effort retention cleanup. Avoid spawning a Send-bound task because
        // the underlying SQLite-backed metadata store is not Send-safe.
        let retention = self.retention.clone();
        let metadata_db = self.metadata_db.clone();
        let vault = self.vault.clone();
        if let Err(e) = Self::run_retention_cleanup(&retention, &metadata_db, &vault).await {
            warn!(error = %e, "Retention cleanup failed");
        }

        info!(
            quarantine_id = %quarantine_id,
            sha256 = %sha256,
            "File quarantined successfully"
        );

        Ok(QuarantineResult {
            quarantine_id,
            original_path,
            success: true,
            error: None,
            file_size,
            sha256,
            quarantined_at: now,
        })
    }

    /// Restore a quarantined file
    pub async fn restore_file(
        &self,
        quarantine_id: &str,
        restore_path: Option<&Path>,
        user_acknowledged_risk: bool,
        auth_token: Option<&str>,
    ) -> Result<RestoreResult> {
        // Check authentication if required
        if self.config.require_auth_for_restore {
            if auth_token.is_none() {
                return Ok(RestoreResult {
                    quarantine_id: quarantine_id.to_string(),
                    restored_path: String::new(),
                    success: false,
                    error: Some("Authentication required for restore operations".to_string()),
                    user_acknowledged_risk,
                    rescan_result: None,
                });
            }
            // In production, validate the auth token here
        }

        if !user_acknowledged_risk {
            return Ok(RestoreResult {
                quarantine_id: quarantine_id.to_string(),
                restored_path: String::new(),
                success: false,
                error: Some(
                    "User must acknowledge the risk of restoring potentially malicious files"
                        .to_string(),
                ),
                user_acknowledged_risk: false,
                rescan_result: None,
            });
        }

        // Get metadata entry
        let db = self.metadata_db.read().await;
        let entry = db
            .get_entry(quarantine_id)?
            .ok_or_else(|| anyhow!("Quarantine entry not found: {}", quarantine_id))?;
        drop(db);

        if entry.is_deleted {
            return Ok(RestoreResult {
                quarantine_id: quarantine_id.to_string(),
                restored_path: String::new(),
                success: false,
                error: Some("File has been permanently deleted from quarantine".to_string()),
                user_acknowledged_risk,
                rescan_result: None,
            });
        }

        // Determine restore path
        let target_path = restore_path
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from(&entry.original_path));

        info!(
            quarantine_id = %quarantine_id,
            target_path = %target_path.display(),
            "Restoring quarantined file"
        );

        // Read encrypted file from vault
        let vault = self.vault.read().await;
        let encrypted_content = vault.read_file(&PathBuf::from(&entry.vault_path))?;
        drop(vault);

        // Reconstruct encryption parameters
        let iv = hex::decode(&entry.encryption_iv).context("Failed to decode IV")?;
        let tag =
            hex::decode(&entry.encryption_tag).context("Failed to decode authentication tag")?;

        // Decrypt
        let decrypted = self
            .encryption
            .decrypt(&encrypted_content, &iv, &tag, quarantine_id)?;

        // Decompress if needed
        let content = if entry.is_compressed {
            Self::decompress(&decrypted)?
        } else {
            decrypted
        };

        // Verify integrity
        let sha256 = Self::calculate_sha256(&content);
        if sha256 != entry.sha256 {
            return Ok(RestoreResult {
                quarantine_id: quarantine_id.to_string(),
                restored_path: String::new(),
                success: false,
                error: Some("Integrity verification failed: SHA256 mismatch".to_string()),
                user_acknowledged_risk,
                rescan_result: None,
            });
        }

        // Ensure parent directory exists
        if let Some(parent) = target_path.parent() {
            std::fs::create_dir_all(parent)
                .context("Failed to create parent directory for restored file")?;
        }

        // Write file
        std::fs::write(&target_path, &content)
            .with_context(|| format!("Failed to write restored file: {}", target_path.display()))?;

        // Re-scan if configured
        let rescan_result = if self.config.rescan_after_restore {
            // In a real implementation, this would invoke the ML scanner or YARA
            // For now, we return a placeholder
            Some(RescanResult {
                is_malicious: true, // Assume still malicious
                detection: entry.threat_name.clone(),
                confidence: Some(0.95),
            })
        } else {
            None
        };

        // Record restoration in metadata
        let db = self.metadata_db.write().await;
        db.record_restoration(quarantine_id, &target_path.to_string_lossy())?;
        drop(db);

        info!(
            quarantine_id = %quarantine_id,
            restored_path = %target_path.display(),
            "File restored successfully"
        );

        Ok(RestoreResult {
            quarantine_id: quarantine_id.to_string(),
            restored_path: target_path.to_string_lossy().to_string(),
            success: true,
            error: None,
            user_acknowledged_risk,
            rescan_result,
        })
    }

    /// Permanently delete a quarantined file
    pub async fn delete_quarantined(&self, quarantine_id: &str) -> Result<bool> {
        info!(quarantine_id = %quarantine_id, "Permanently deleting quarantined file");

        // Get metadata entry
        let db = self.metadata_db.read().await;
        let entry = db
            .get_entry(quarantine_id)?
            .ok_or_else(|| anyhow!("Quarantine entry not found: {}", quarantine_id))?;
        drop(db);

        // Delete encrypted file from vault
        let vault = self.vault.write().await;
        vault.delete_file(&PathBuf::from(&entry.vault_path))?;
        drop(vault);

        // Mark as deleted in metadata (keep record for audit trail)
        let db = self.metadata_db.write().await;
        db.mark_deleted(quarantine_id)?;
        drop(db);

        info!(quarantine_id = %quarantine_id, "Quarantined file permanently deleted");
        Ok(true)
    }

    /// Get list of quarantined files
    pub async fn get_list(
        &self,
        limit: Option<u32>,
        offset: Option<u32>,
        include_deleted: bool,
    ) -> Result<Vec<QuarantineListItem>> {
        let db = self.metadata_db.read().await;
        let entries = db.list_entries(limit, offset, include_deleted)?;

        Ok(entries
            .into_iter()
            .map(|e| QuarantineListItem {
                id: e.id,
                original_path: e.original_path,
                original_name: e.original_name,
                file_size: e.file_size,
                sha256: e.sha256,
                quarantined_at: e.quarantined_at,
                reason: e.reason,
                threat_name: e.threat_name,
                severity: e.severity,
                can_restore: !e.is_deleted,
            })
            .collect())
    }

    /// Get detailed information about a quarantined file
    pub async fn get_details(&self, quarantine_id: &str) -> Result<Option<QuarantineEntry>> {
        let db = self.metadata_db.read().await;
        db.get_entry(quarantine_id)
    }

    /// Get vault statistics
    pub async fn get_stats(&self) -> Result<VaultStats> {
        let db = self.metadata_db.read().await;
        let vault = self.vault.read().await;
        stats::calculate_stats(&db, &vault)
    }

    /// Export quarantine report
    pub async fn export_report(&self, format: ReportFormat) -> Result<Vec<u8>> {
        let db = self.metadata_db.read().await;
        let entries = db.list_entries(None, None, false)?;
        let stats = stats::calculate_stats(&db, &*self.vault.read().await)?;

        match format {
            ReportFormat::Json => {
                let report = serde_json::json!({
                    "generated_at": Utc::now(),
                    "statistics": stats,
                    "entries": entries,
                });
                Ok(serde_json::to_vec_pretty(&report)?)
            }
            ReportFormat::Csv => {
                let mut csv = String::new();
                csv.push_str("id,original_path,original_name,file_size,sha256,quarantined_at,reason,threat_name,severity\n");
                for e in entries {
                    csv.push_str(&format!(
                        "{},{},{},{},{},{},{:?},{},{:?}\n",
                        e.id,
                        e.original_path.replace(',', ";"),
                        e.original_name.replace(',', ";"),
                        e.file_size,
                        e.sha256,
                        e.quarantined_at,
                        e.reason,
                        e.threat_name.unwrap_or_default(),
                        e.severity,
                    ));
                }
                Ok(csv.into_bytes())
            }
        }
    }

    /// Run retention cleanup
    async fn run_retention_cleanup(
        retention: &RetentionPolicy,
        metadata_db: &Arc<RwLock<MetadataDb>>,
        vault: &Arc<RwLock<VaultStorage>>,
    ) -> Result<()> {
        let db = metadata_db.read().await;
        let v = vault.read().await;

        // Get current stats
        let stats = stats::calculate_stats(&db, &v)?;
        drop(db);
        drop(v);

        // Check if cleanup needed
        let entries_to_delete = {
            let db = metadata_db.read().await;
            retention.get_entries_to_delete(&db, &stats)?
        };

        if entries_to_delete.is_empty() {
            return Ok(());
        }

        info!(count = entries_to_delete.len(), "Running retention cleanup");

        // Delete expired/excess entries
        for entry_id in entries_to_delete {
            let db = metadata_db.read().await;
            if let Ok(Some(entry)) = db.get_entry(&entry_id) {
                drop(db);

                let v = vault.write().await;
                if let Err(e) = v.delete_file(&PathBuf::from(&entry.vault_path)) {
                    warn!(id = %entry_id, error = %e, "Failed to delete vault file during cleanup");
                }
                drop(v);

                let db = metadata_db.write().await;
                if let Err(e) = db.mark_deleted(&entry_id) {
                    warn!(id = %entry_id, error = %e, "Failed to mark entry as deleted");
                }
            }
        }

        Ok(())
    }

    // Hash calculation helpers
    fn calculate_sha256(data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    fn calculate_sha1(data: &[u8]) -> String {
        use sha1::{Digest, Sha1};
        let mut hasher = Sha1::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    fn calculate_md5(data: &[u8]) -> String {
        let digest = md5::compute(data);
        hex::encode(digest.0)
    }

    fn compress(data: &[u8]) -> Result<Vec<u8>> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data)?;
        Ok(encoder.finish()?)
    }

    fn decompress(data: &[u8]) -> Result<Vec<u8>> {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let mut decoder = GzDecoder::new(data);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)?;
        Ok(decompressed)
    }
}

/// Report export format
#[derive(Debug, Clone, Copy)]
pub enum ReportFormat {
    Json,
    Csv,
}
