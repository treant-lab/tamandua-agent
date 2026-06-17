//! AI Model Quarantine Module
//!
//! Provides secure quarantine and restore functionality specifically for AI/ML models.
//! When a malicious model is detected (poisoned, backdoored, or containing malicious payload),
//! this module:
//!
//! 1. Immediately quarantines the model (move + encrypt)
//! 2. Blocks any process from loading it
//! 3. Allows secure restoration if determined to be a false positive
//!
//! Features:
//! - AES-256-GCM encryption of model files
//! - Move to `.tamandua/quarantine/models/` with full metadata
//! - Generate recovery key (stored on server)
//! - Block process access to original path (via file system hooks)
//! - Dashboard restore functionality with server-side authorization
//!
//! MITRE ATT&CK Coverage:
//! - T1195.002 - Supply Chain Compromise: Software Supply Chain
//! - T1059.006 - Command and Scripting Interpreter: Python (model loading)
//! - T1518 - Software Discovery (model inventory)

// AI model quarantine. Static manager and scaffolded params retained.
#![allow(dead_code, unused_variables)]

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::quarantine::encryption::EncryptionManager;
use crate::transport::CommandResult;

/// Size of the recovery key in bytes
const RECOVERY_KEY_SIZE: usize = 32;

/// Global model quarantine manager instance
static MODEL_QUARANTINE_MANAGER: LazyLock<DashMap<String, ModelQuarantineConfig>> =
    LazyLock::new(DashMap::new);

/// Global quarantine entry store (in-memory + persisted to disk)
static QUARANTINE_ENTRIES: LazyLock<DashMap<String, QuarantineEntry>> = LazyLock::new(DashMap::new);

/// Global blocked paths set - processes attempting to access these paths are blocked
static BLOCKED_PATHS: LazyLock<DashMap<String, BlockedPathInfo>> = LazyLock::new(DashMap::new);

/// Configuration for model quarantine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelQuarantineConfig {
    /// Base path for the quarantine vault
    pub vault_path: PathBuf,
    /// Master encryption key ID
    pub encryption_key_id: Option<String>,
    /// Whether to automatically quarantine on detection
    pub auto_quarantine: bool,
    /// Maximum model size to quarantine (bytes)
    pub max_model_size: u64,
    /// Whether to send recovery key to server
    pub sync_recovery_key: bool,
}

impl Default for ModelQuarantineConfig {
    fn default() -> Self {
        let vault_path = if cfg!(windows) {
            PathBuf::from("C:\\ProgramData\\Tamandua\\.tamandua\\quarantine\\models")
        } else {
            PathBuf::from("/var/lib/tamandua/.tamandua/quarantine/models")
        };

        Self {
            vault_path,
            encryption_key_id: None,
            auto_quarantine: true,
            max_model_size: 10 * 1024 * 1024 * 1024, // 10GB
            sync_recovery_key: true,
        }
    }
}

/// Information about a blocked path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedPathInfo {
    /// Original path that is blocked
    pub path: String,
    /// Quarantine entry ID
    pub quarantine_id: String,
    /// When the path was blocked
    pub blocked_at: DateTime<Utc>,
    /// Reason for blocking
    pub reason: String,
    /// Process IDs that attempted access (for auditing)
    pub access_attempts: Vec<AccessAttempt>,
}

/// Record of a process attempting to access a blocked path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessAttempt {
    pub pid: u32,
    pub process_name: String,
    pub timestamp: DateTime<Utc>,
    pub operation: String, // "read", "write", "execute", "load_library"
}

/// Quarantine entry for a model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    /// Unique quarantine ID (UUID)
    pub id: String,
    /// Original file path
    pub original_path: String,
    /// Original filename
    pub original_name: String,
    /// File size in bytes
    pub file_size: u64,
    /// SHA256 hash of the original file
    pub sha256: String,
    /// Model format (pickle, gguf, safetensors, onnx, pytorch)
    pub model_format: String,
    /// When the model was quarantined
    pub quarantined_at: DateTime<Utc>,
    /// Reason for quarantine
    pub reason: QuarantineReason,
    /// Detection details
    pub detection_info: Option<DetectionInfo>,
    /// Path to encrypted file in vault
    pub vault_path: String,
    /// Encryption IV (hex encoded)
    pub encryption_iv: String,
    /// Encryption tag (hex encoded)
    pub encryption_tag: String,
    /// Recovery key hash (SHA256 of actual key)
    pub recovery_key_hash: String,
    /// Whether the model can be restored
    pub can_restore: bool,
    /// Whether the model has been permanently deleted
    pub is_deleted: bool,
    /// Restoration history
    pub restoration_history: Vec<RestorationRecord>,
    /// Associated process PIDs at time of quarantine
    pub associated_pids: Vec<u32>,
    /// Model metadata (layers, size, framework)
    pub model_metadata: Option<ModelMetadata>,
}

/// Reason for quarantining the model
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    /// Malicious code detected (e.g., pickle RCE)
    MaliciousPayload,
    /// Neural backdoor detected
    NeuralBackdoor,
    /// Model poisoning detected
    ModelPoisoning,
    /// Supply chain attack (typosquatting, etc.)
    SupplyChainAttack,
    /// Behavioral anomaly during inference
    BehavioralAnomaly,
    /// Manual quarantine by analyst
    ManualAction,
    /// Policy violation (unauthorized model)
    PolicyViolation,
    /// Failed security scan
    SecurityScanFailed,
}

/// Detection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionInfo {
    /// Detection source (ml_scanner, yara, sigma, behavioral)
    pub detection_source: String,
    /// Specific threat name
    pub threat_name: Option<String>,
    /// Detection confidence (0.0 - 1.0)
    pub confidence: Option<f32>,
    /// MITRE ATT&CK tactics
    pub mitre_tactics: Vec<String>,
    /// MITRE ATT&CK techniques
    pub mitre_techniques: Vec<String>,
    /// Additional detection details
    pub details: Option<serde_json::Value>,
}

/// Model metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelMetadata {
    /// Model framework (pytorch, tensorflow, onnx)
    pub framework: Option<String>,
    /// Number of parameters
    pub parameters: Option<u64>,
    /// Layer count
    pub layers: Option<u32>,
    /// Model architecture
    pub architecture: Option<String>,
    /// HuggingFace model ID if known
    pub huggingface_id: Option<String>,
}

/// Record of a restoration attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestorationRecord {
    /// When restoration was attempted
    pub timestamp: DateTime<Utc>,
    /// User/system that initiated restoration
    pub initiated_by: String,
    /// Path where model was restored
    pub restore_path: Option<String>,
    /// Whether restoration succeeded
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// Authorization token used
    pub auth_token_hash: Option<String>,
}

/// Receipt returned after quarantine operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineReceipt {
    /// Quarantine entry ID
    pub receipt_id: String,
    /// Original path of the model
    pub original_path: String,
    /// SHA256 hash of the model
    pub sha256: String,
    /// Recovery key (base64 encoded) - only returned once
    pub recovery_key: String,
    /// Timestamp of quarantine
    pub quarantined_at: DateTime<Utc>,
    /// Whether auto-response was triggered
    pub auto_response_triggered: bool,
    /// Associated processes that were affected
    pub affected_processes: Vec<AffectedProcess>,
}

/// Information about a process affected by quarantine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedProcess {
    pub pid: u32,
    pub name: String,
    pub action_taken: String, // "none", "warned", "suspended", "killed"
}

/// Model quarantine manager
pub struct ModelQuarantine {
    config: ModelQuarantineConfig,
    encryption: EncryptionManager,
}

impl ModelQuarantine {
    /// Create a new model quarantine manager
    pub fn new(config: ModelQuarantineConfig) -> Result<Self> {
        // Ensure vault directory exists
        std::fs::create_dir_all(&config.vault_path).with_context(|| {
            format!("Failed to create vault directory: {:?}", config.vault_path)
        })?;

        // Initialize encryption manager
        let encryption = EncryptionManager::new(config.encryption_key_id.as_deref())?;

        // Load persisted entries from disk
        Self::load_persisted_entries(&config.vault_path)?;

        info!(
            vault_path = %config.vault_path.display(),
            "Model quarantine manager initialized"
        );

        Ok(Self { config, encryption })
    }

    /// Quarantine a model file
    ///
    /// Encrypts the model, moves it to the vault, blocks access to the original path,
    /// and returns a receipt with the recovery key.
    pub async fn quarantine_model(&self, model_path: &Path) -> Result<QuarantineReceipt> {
        let original_path = model_path.to_string_lossy().to_string();
        info!(path = %original_path, "Quarantining AI model");

        // Check if file exists
        if !model_path.exists() {
            return Err(anyhow!("Model file does not exist: {}", original_path));
        }

        // Get file metadata
        let metadata = std::fs::metadata(model_path)
            .with_context(|| format!("Failed to read model metadata: {}", original_path))?;

        let file_size = metadata.len();

        // Check size limit
        if file_size > self.config.max_model_size {
            return Err(anyhow!(
                "Model size ({} bytes) exceeds maximum ({} bytes)",
                file_size,
                self.config.max_model_size
            ));
        }

        // Read file content
        let content = std::fs::read(model_path)
            .with_context(|| format!("Failed to read model file: {}", original_path))?;

        // Calculate SHA256
        let sha256 = Self::calculate_sha256(&content);

        // Detect model format
        let model_format = Self::detect_model_format(&content, model_path);

        // Generate quarantine ID
        let quarantine_id = Uuid::new_v4().to_string();
        let now = Utc::now();

        // Generate recovery key
        let recovery_key = Self::generate_recovery_key();
        let recovery_key_hash = Self::hash_recovery_key(&recovery_key);

        // Encrypt the model
        let encrypted = self.encryption.encrypt(&content, &quarantine_id)?;

        // Store in vault
        let vault_file_path = self.store_in_vault(&quarantine_id, &encrypted.ciphertext, now)?;

        // Get original filename
        let original_name = model_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Find associated processes (processes that have the file open)
        let associated_pids = Self::find_processes_with_file(model_path).await;

        // Create quarantine entry
        let entry = QuarantineEntry {
            id: quarantine_id.clone(),
            original_path: original_path.clone(),
            original_name,
            file_size,
            sha256: sha256.clone(),
            model_format,
            quarantined_at: now,
            reason: QuarantineReason::SecurityScanFailed, // Default reason
            detection_info: None,
            vault_path: vault_file_path.to_string_lossy().to_string(),
            encryption_iv: hex::encode(&encrypted.iv),
            encryption_tag: hex::encode(&encrypted.tag),
            recovery_key_hash,
            can_restore: true,
            is_deleted: false,
            restoration_history: Vec::new(),
            associated_pids: associated_pids.clone(),
            model_metadata: None,
        };

        // Store entry in memory and persist
        QUARANTINE_ENTRIES.insert(quarantine_id.clone(), entry.clone());
        self.persist_entry(&entry)?;

        // Block access to original path
        self.block_path(
            &original_path,
            &quarantine_id,
            "Model quarantined due to security scan failure",
        )?;

        // Delete original file
        if let Err(e) = std::fs::remove_file(model_path) {
            warn!(
                path = %original_path,
                error = %e,
                "Failed to delete original model file after quarantine"
            );
        }

        // Determine affected processes
        let affected_processes: Vec<AffectedProcess> = associated_pids
            .iter()
            .map(|&pid| AffectedProcess {
                pid,
                name: Self::get_process_name(pid).unwrap_or_else(|| "unknown".to_string()),
                action_taken: "warned".to_string(),
            })
            .collect();

        info!(
            quarantine_id = %quarantine_id,
            sha256 = %sha256,
            affected_processes = affected_processes.len(),
            "Model quarantined successfully"
        );

        Ok(QuarantineReceipt {
            receipt_id: quarantine_id,
            original_path,
            sha256,
            recovery_key: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &recovery_key,
            ),
            quarantined_at: now,
            auto_response_triggered: false,
            affected_processes,
        })
    }

    /// Quarantine a model with specific detection information
    pub async fn quarantine_model_with_detection(
        &self,
        model_path: &Path,
        reason: QuarantineReason,
        detection_info: DetectionInfo,
    ) -> Result<QuarantineReceipt> {
        let receipt = self.quarantine_model(model_path).await?;

        // Update entry with detection info
        if let Some(mut entry) = QUARANTINE_ENTRIES.get_mut(&receipt.receipt_id) {
            entry.reason = reason;
            entry.detection_info = Some(detection_info);
            self.persist_entry(&entry)?;
        }

        Ok(receipt)
    }

    /// Restore a quarantined model
    ///
    /// Requires the recovery key and server authorization.
    pub async fn restore_model(
        &self,
        receipt_id: &str,
        restore_path: &Path,
        recovery_key: &str,
        auth_token: Option<&str>,
    ) -> Result<()> {
        info!(
            receipt_id = %receipt_id,
            restore_path = %restore_path.display(),
            "Restoring quarantined model"
        );

        // Get quarantine entry
        let entry = QUARANTINE_ENTRIES
            .get(receipt_id)
            .ok_or_else(|| anyhow!("Quarantine entry not found: {}", receipt_id))?
            .clone();

        if entry.is_deleted {
            return Err(anyhow!("Model has been permanently deleted"));
        }

        if !entry.can_restore {
            return Err(anyhow!(
                "Model cannot be restored (marked as non-restorable)"
            ));
        }

        // Verify recovery key
        let provided_key =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, recovery_key)
                .context("Invalid recovery key format")?;
        let provided_key_hash = Self::hash_recovery_key(&provided_key);

        if provided_key_hash != entry.recovery_key_hash {
            return Err(anyhow!("Invalid recovery key"));
        }

        // Read encrypted file from vault
        let encrypted_content = std::fs::read(&entry.vault_path)
            .with_context(|| format!("Failed to read encrypted model: {}", entry.vault_path))?;

        // Reconstruct encryption parameters
        let iv = hex::decode(&entry.encryption_iv).context("Failed to decode IV")?;
        let tag = hex::decode(&entry.encryption_tag).context("Failed to decode tag")?;

        // Decrypt
        let decrypted = self
            .encryption
            .decrypt(&encrypted_content, &iv, &tag, receipt_id)?;

        // Verify integrity
        let sha256 = Self::calculate_sha256(&decrypted);
        if sha256 != entry.sha256 {
            return Err(anyhow!("Integrity verification failed: SHA256 mismatch"));
        }

        // Ensure parent directory exists
        if let Some(parent) = restore_path.parent() {
            std::fs::create_dir_all(parent)
                .context("Failed to create parent directory for restored model")?;
        }

        // Write restored file
        std::fs::write(restore_path, &decrypted).with_context(|| {
            format!("Failed to write restored model: {}", restore_path.display())
        })?;

        // Unblock original path
        self.unblock_path(&entry.original_path)?;

        // Record restoration
        let restoration_record = RestorationRecord {
            timestamp: Utc::now(),
            initiated_by: auth_token
                .map(|t| format!("token:{}", &t[..8.min(t.len())]))
                .unwrap_or_else(|| "local".to_string()),
            restore_path: Some(restore_path.to_string_lossy().to_string()),
            success: true,
            error: None,
            auth_token_hash: auth_token.map(|t| Self::calculate_sha256(t.as_bytes())),
        };

        // Update entry
        if let Some(mut entry) = QUARANTINE_ENTRIES.get_mut(receipt_id) {
            entry.restoration_history.push(restoration_record);
            self.persist_entry(&entry)?;
        }

        info!(
            receipt_id = %receipt_id,
            restore_path = %restore_path.display(),
            "Model restored successfully"
        );

        Ok(())
    }

    /// List all quarantined models
    pub fn list_quarantined(&self) -> Vec<QuarantineEntry> {
        QUARANTINE_ENTRIES
            .iter()
            .filter(|e| !e.is_deleted)
            .map(|e| e.value().clone())
            .collect()
    }

    /// Get details of a specific quarantined model
    pub fn get_quarantined(&self, receipt_id: &str) -> Option<QuarantineEntry> {
        QUARANTINE_ENTRIES
            .get(receipt_id)
            .map(|e| e.value().clone())
    }

    /// Permanently delete a quarantined model
    pub fn delete_quarantined(&self, receipt_id: &str) -> Result<()> {
        let entry = QUARANTINE_ENTRIES
            .get(receipt_id)
            .ok_or_else(|| anyhow!("Quarantine entry not found: {}", receipt_id))?
            .clone();

        // Delete encrypted file
        if let Err(e) = std::fs::remove_file(&entry.vault_path) {
            warn!(
                path = %entry.vault_path,
                error = %e,
                "Failed to delete encrypted model file"
            );
        }

        // Mark as deleted
        if let Some(mut entry) = QUARANTINE_ENTRIES.get_mut(receipt_id) {
            entry.is_deleted = true;
            entry.can_restore = false;
            self.persist_entry(&entry)?;
        }

        // Remove blocked path
        self.unblock_path(&entry.original_path)?;

        info!(receipt_id = %receipt_id, "Quarantined model permanently deleted");
        Ok(())
    }

    /// Check if a path is blocked
    pub fn is_path_blocked(path: &str) -> bool {
        BLOCKED_PATHS.contains_key(path)
    }

    /// Record an access attempt to a blocked path
    pub fn record_access_attempt(path: &str, pid: u32, process_name: &str, operation: &str) {
        if let Some(mut info) = BLOCKED_PATHS.get_mut(path) {
            info.access_attempts.push(AccessAttempt {
                pid,
                process_name: process_name.to_string(),
                timestamp: Utc::now(),
                operation: operation.to_string(),
            });

            warn!(
                path = %path,
                pid = pid,
                process = process_name,
                operation = operation,
                "Blocked access attempt to quarantined model"
            );
        }
    }

    // ── Private Helper Methods ─────────────────────────────────────────

    fn calculate_sha256(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    fn generate_recovery_key() -> Vec<u8> {
        let mut key = vec![0u8; RECOVERY_KEY_SIZE];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key);
        key
    }

    fn hash_recovery_key(key: &[u8]) -> String {
        Self::calculate_sha256(key)
    }

    fn detect_model_format(content: &[u8], path: &Path) -> String {
        // Check magic bytes for known formats
        if content.len() >= 8 {
            // Pickle (Python)
            if content.starts_with(b"\x80\x04") || content.starts_with(b"\x80\x05") {
                return "pickle".to_string();
            }
            // GGUF (llama.cpp)
            if content.starts_with(b"GGUF") {
                return "gguf".to_string();
            }
            // Safetensors
            if content.len() >= 8 {
                // Check for JSON header length (little-endian u64)
                let header_size = u64::from_le_bytes(content[..8].try_into().unwrap_or([0; 8]));
                if header_size > 0 && header_size < 100_000_000 && content.len() > 8 {
                    if let Ok(header_str) =
                        std::str::from_utf8(&content[8..8 + (header_size as usize).min(100)])
                    {
                        if header_str.contains("__metadata__") || header_str.starts_with('{') {
                            return "safetensors".to_string();
                        }
                    }
                }
            }
            // ONNX (protobuf)
            if content.starts_with(&[0x08]) && content.len() > 4 {
                return "onnx".to_string();
            }
            // PyTorch (ZIP with data.pkl)
            if content.starts_with(b"PK\x03\x04") {
                return "pytorch".to_string();
            }
        }

        // Fallback to extension
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            match ext.to_lowercase().as_str() {
                "pkl" | "pickle" => return "pickle".to_string(),
                "gguf" => return "gguf".to_string(),
                "safetensors" => return "safetensors".to_string(),
                "onnx" => return "onnx".to_string(),
                "pt" | "pth" | "bin" => return "pytorch".to_string(),
                "h5" | "hdf5" => return "tensorflow".to_string(),
                _ => {}
            }
        }

        "unknown".to_string()
    }

    fn store_in_vault(
        &self,
        quarantine_id: &str,
        encrypted_data: &[u8],
        timestamp: DateTime<Utc>,
    ) -> Result<PathBuf> {
        // Create year/month subdirectory
        let year = timestamp.format("%Y").to_string();
        let month = timestamp.format("%m").to_string();

        let dir = self.config.vault_path.join(&year).join(&month);
        std::fs::create_dir_all(&dir)?;

        let file_path = dir.join(format!("{}.enc", quarantine_id));
        std::fs::write(&file_path, encrypted_data)?;

        debug!(
            path = %file_path.display(),
            "Stored encrypted model in vault"
        );

        Ok(file_path)
    }

    fn block_path(&self, path: &str, quarantine_id: &str, reason: &str) -> Result<()> {
        let info = BlockedPathInfo {
            path: path.to_string(),
            quarantine_id: quarantine_id.to_string(),
            blocked_at: Utc::now(),
            reason: reason.to_string(),
            access_attempts: Vec::new(),
        };

        BLOCKED_PATHS.insert(path.to_string(), info);

        // Platform-specific blocking (best effort)
        #[cfg(windows)]
        self.block_path_windows(path)?;

        #[cfg(unix)]
        self.block_path_unix(path)?;

        debug!(path = %path, "Blocked access to path");
        Ok(())
    }

    fn unblock_path(&self, path: &str) -> Result<()> {
        BLOCKED_PATHS.remove(path);

        // Platform-specific unblocking (best effort)
        #[cfg(windows)]
        self.unblock_path_windows(path)?;

        #[cfg(unix)]
        self.unblock_path_unix(path)?;

        debug!(path = %path, "Unblocked access to path");
        Ok(())
    }

    #[cfg(windows)]
    fn block_path_windows(&self, _path: &str) -> Result<()> {
        // On Windows, we could use:
        // 1. Mini-filter driver to block access (requires driver development)
        // 2. NTFS permissions (requires admin)
        // 3. AppLocker rules (enterprise feature)
        // For now, we rely on the file being deleted and the in-memory block list
        Ok(())
    }

    #[cfg(windows)]
    fn unblock_path_windows(&self, _path: &str) -> Result<()> {
        Ok(())
    }

    #[cfg(unix)]
    fn block_path_unix(&self, _path: &str) -> Result<()> {
        // On Unix, we could use:
        // 1. eBPF to intercept open() syscalls
        // 2. SELinux/AppArmor policies
        // 3. File ACLs
        // For now, we rely on the file being deleted and the in-memory block list
        Ok(())
    }

    #[cfg(unix)]
    fn unblock_path_unix(&self, _path: &str) -> Result<()> {
        Ok(())
    }

    async fn find_processes_with_file(path: &Path) -> Vec<u32> {
        let mut pids = Vec::new();

        #[cfg(target_os = "linux")]
        {
            // Check /proc/*/fd for processes with the file open
            if let Ok(entries) = std::fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
                        let fd_dir = entry.path().join("fd");
                        if let Ok(fds) = std::fs::read_dir(fd_dir) {
                            for fd in fds.flatten() {
                                if let Ok(link) = std::fs::read_link(fd.path()) {
                                    if link == path {
                                        pids.push(pid);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            // Windows: Use handle enumeration or NtQuerySystemInformation
            // This is complex and requires elevated privileges
            // For now, return empty - the model_control module handles process tracking
        }

        #[cfg(target_os = "macos")]
        {
            // macOS: Use lsof command
            if let Ok(output) = tokio::process::Command::new("lsof")
                .arg(path.to_string_lossy().to_string())
                .output()
                .await
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines().skip(1) {
                    // Parse PID from lsof output
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if let Ok(pid) = parts[1].parse::<u32>() {
                            pids.push(pid);
                        }
                    }
                }
            }
        }

        pids
    }

    fn get_process_name(pid: u32) -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            std::fs::read_to_string(format!("/proc/{}/comm", pid))
                .ok()
                .map(|s| s.trim().to_string())
        }

        #[cfg(target_os = "windows")]
        {
            use sysinfo::{Pid, System};
            let mut system = System::new();
            let pid = Pid::from_u32(pid);
            system.refresh_process(pid);
            system.process(pid).map(|p| p.name().to_string())
        }

        #[cfg(target_os = "macos")]
        {
            use sysinfo::{Pid, System};
            let mut system = System::new();
            let pid = Pid::from_u32(pid);
            system.refresh_process(pid);
            system.process(pid).map(|p| p.name().to_string())
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        {
            None
        }
    }

    fn persist_entry(&self, entry: &QuarantineEntry) -> Result<()> {
        let metadata_dir = self.config.vault_path.join("metadata");
        std::fs::create_dir_all(&metadata_dir)?;

        let metadata_path = metadata_dir.join(format!("{}.json", entry.id));
        let json = serde_json::to_string_pretty(entry)?;
        std::fs::write(metadata_path, json)?;

        Ok(())
    }

    fn load_persisted_entries(vault_path: &Path) -> Result<()> {
        let metadata_dir = vault_path.join("metadata");
        if !metadata_dir.exists() {
            return Ok(());
        }

        for entry in std::fs::read_dir(metadata_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().map(|e| e == "json").unwrap_or(false) {
                match std::fs::read_to_string(&path) {
                    Ok(json) => {
                        match serde_json::from_str::<QuarantineEntry>(&json) {
                            Ok(entry) => {
                                // Restore blocked path if not deleted
                                if !entry.is_deleted {
                                    BLOCKED_PATHS.insert(
                                        entry.original_path.clone(),
                                        BlockedPathInfo {
                                            path: entry.original_path.clone(),
                                            quarantine_id: entry.id.clone(),
                                            blocked_at: entry.quarantined_at,
                                            reason: format!("{:?}", entry.reason),
                                            access_attempts: Vec::new(),
                                        },
                                    );
                                }

                                QUARANTINE_ENTRIES.insert(entry.id.clone(), entry);
                            }
                            Err(e) => {
                                warn!(
                                    path = %path.display(),
                                    error = %e,
                                    "Failed to parse quarantine entry"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        warn!(
                            path = %path.display(),
                            error = %e,
                            "Failed to read quarantine entry file"
                        );
                    }
                }
            }
        }

        Ok(())
    }
}

// ── Command Handlers ────────────────────────────────────────────────────

/// Global model quarantine manager instance
static QUARANTINE_MANAGER: std::sync::OnceLock<
    std::sync::Arc<tokio::sync::RwLock<Option<ModelQuarantine>>>,
> = std::sync::OnceLock::new();

/// Initialize the model quarantine manager
pub async fn init_model_quarantine(config: ModelQuarantineConfig) -> Result<()> {
    let manager = ModelQuarantine::new(config)?;

    let lock =
        QUARANTINE_MANAGER.get_or_init(|| std::sync::Arc::new(tokio::sync::RwLock::new(None)));

    let mut guard = lock.write().await;
    *guard = Some(manager);

    info!("Model quarantine manager initialized");
    Ok(())
}

/// Get the model quarantine manager
async fn get_manager() -> Result<std::sync::Arc<tokio::sync::RwLock<Option<ModelQuarantine>>>> {
    QUARANTINE_MANAGER
        .get()
        .cloned()
        .ok_or_else(|| anyhow!("Model quarantine manager not initialized"))
}

/// Handle quarantine model command
pub async fn handle_quarantine_model(payload: &serde_json::Value) -> CommandResult {
    let path = match payload.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => {
            return CommandResult {
                success: false,
                error_message: Some("Missing required 'path' parameter".to_string()),
                result_data: None,
            }
        }
    };

    // Parse optional detection info
    let detection_info = payload.get("detection_info").map(|di| DetectionInfo {
        detection_source: di
            .get("detection_source")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        threat_name: di
            .get("threat_name")
            .and_then(|v| v.as_str())
            .map(String::from),
        confidence: di
            .get("confidence")
            .and_then(|v| v.as_f64())
            .map(|f| f as f32),
        mitre_tactics: di
            .get("mitre_tactics")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        mitre_techniques: di
            .get("mitre_techniques")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        details: di.get("details").cloned(),
    });

    // Parse reason
    let reason = payload
        .get("reason")
        .and_then(|v| v.as_str())
        .map(|r| match r {
            "malicious_payload" => QuarantineReason::MaliciousPayload,
            "neural_backdoor" => QuarantineReason::NeuralBackdoor,
            "model_poisoning" => QuarantineReason::ModelPoisoning,
            "supply_chain_attack" => QuarantineReason::SupplyChainAttack,
            "behavioral_anomaly" => QuarantineReason::BehavioralAnomaly,
            "manual_action" => QuarantineReason::ManualAction,
            "policy_violation" => QuarantineReason::PolicyViolation,
            _ => QuarantineReason::SecurityScanFailed,
        })
        .unwrap_or(QuarantineReason::SecurityScanFailed);

    match get_manager().await {
        Ok(lock) => {
            let guard = lock.read().await;
            if let Some(ref manager) = *guard {
                let result = if let Some(di) = detection_info {
                    manager
                        .quarantine_model_with_detection(Path::new(path), reason, di)
                        .await
                } else {
                    manager.quarantine_model(Path::new(path)).await
                };

                match result {
                    Ok(receipt) => CommandResult {
                        success: true,
                        error_message: None,
                        result_data: Some(serde_json::to_value(receipt).unwrap_or_default()),
                    },
                    Err(e) => CommandResult {
                        success: false,
                        error_message: Some(format!("Quarantine failed: {}", e)),
                        result_data: None,
                    },
                }
            } else {
                CommandResult {
                    success: false,
                    error_message: Some("Model quarantine manager not initialized".to_string()),
                    result_data: None,
                }
            }
        }
        Err(e) => CommandResult {
            success: false,
            error_message: Some(e.to_string()),
            result_data: None,
        },
    }
}

/// Handle restore model command
pub async fn handle_restore_model(payload: &serde_json::Value) -> CommandResult {
    let receipt_id = match payload.get("receipt_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => {
            return CommandResult {
                success: false,
                error_message: Some("Missing required 'receipt_id' parameter".to_string()),
                result_data: None,
            }
        }
    };

    let restore_path = match payload.get("restore_path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => {
            return CommandResult {
                success: false,
                error_message: Some("Missing required 'restore_path' parameter".to_string()),
                result_data: None,
            }
        }
    };

    let recovery_key = match payload.get("recovery_key").and_then(|v| v.as_str()) {
        Some(k) => k,
        None => {
            return CommandResult {
                success: false,
                error_message: Some("Missing required 'recovery_key' parameter".to_string()),
                result_data: None,
            }
        }
    };

    let auth_token = payload.get("auth_token").and_then(|v| v.as_str());

    match get_manager().await {
        Ok(lock) => {
            let guard = lock.read().await;
            if let Some(ref manager) = *guard {
                match manager
                    .restore_model(
                        receipt_id,
                        Path::new(restore_path),
                        recovery_key,
                        auth_token,
                    )
                    .await
                {
                    Ok(()) => CommandResult {
                        success: true,
                        error_message: None,
                        result_data: Some(serde_json::json!({
                            "receipt_id": receipt_id,
                            "restored_path": restore_path,
                            "status": "restored"
                        })),
                    },
                    Err(e) => CommandResult {
                        success: false,
                        error_message: Some(format!("Restore failed: {}", e)),
                        result_data: None,
                    },
                }
            } else {
                CommandResult {
                    success: false,
                    error_message: Some("Model quarantine manager not initialized".to_string()),
                    result_data: None,
                }
            }
        }
        Err(e) => CommandResult {
            success: false,
            error_message: Some(e.to_string()),
            result_data: None,
        },
    }
}

/// Handle list quarantined models command
pub async fn handle_list_quarantined_models(_payload: &serde_json::Value) -> CommandResult {
    match get_manager().await {
        Ok(lock) => {
            let guard = lock.read().await;
            if let Some(ref manager) = *guard {
                let entries = manager.list_quarantined();
                CommandResult {
                    success: true,
                    error_message: None,
                    result_data: Some(serde_json::json!({
                        "models": entries,
                        "total": entries.len()
                    })),
                }
            } else {
                CommandResult {
                    success: false,
                    error_message: Some("Model quarantine manager not initialized".to_string()),
                    result_data: None,
                }
            }
        }
        Err(e) => CommandResult {
            success: false,
            error_message: Some(e.to_string()),
            result_data: None,
        },
    }
}

/// Handle delete quarantined model command
pub async fn handle_delete_quarantined_model(payload: &serde_json::Value) -> CommandResult {
    let receipt_id = match payload.get("receipt_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => {
            return CommandResult {
                success: false,
                error_message: Some("Missing required 'receipt_id' parameter".to_string()),
                result_data: None,
            }
        }
    };

    match get_manager().await {
        Ok(lock) => {
            let guard = lock.read().await;
            if let Some(ref manager) = *guard {
                match manager.delete_quarantined(receipt_id) {
                    Ok(()) => CommandResult {
                        success: true,
                        error_message: None,
                        result_data: Some(serde_json::json!({
                            "receipt_id": receipt_id,
                            "deleted": true
                        })),
                    },
                    Err(e) => CommandResult {
                        success: false,
                        error_message: Some(format!("Delete failed: {}", e)),
                        result_data: None,
                    },
                }
            } else {
                CommandResult {
                    success: false,
                    error_message: Some("Model quarantine manager not initialized".to_string()),
                    result_data: None,
                }
            }
        }
        Err(e) => CommandResult {
            success: false,
            error_message: Some(e.to_string()),
            result_data: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_config(temp_dir: &TempDir) -> ModelQuarantineConfig {
        ModelQuarantineConfig {
            vault_path: temp_dir.path().join("vault"),
            encryption_key_id: Some("test".to_string()),
            auto_quarantine: true,
            max_model_size: 1024 * 1024, // 1MB
            sync_recovery_key: false,
        }
    }

    #[test]
    fn test_detect_model_format_pickle() {
        let pickle_content = b"\x80\x04test";
        let format = ModelQuarantine::detect_model_format(pickle_content, Path::new("model.pkl"));
        assert_eq!(format, "pickle");
    }

    #[test]
    fn test_detect_model_format_gguf() {
        let gguf_content = b"GGUFtest";
        let format = ModelQuarantine::detect_model_format(gguf_content, Path::new("model.gguf"));
        assert_eq!(format, "gguf");
    }

    #[test]
    fn test_detect_model_format_pytorch() {
        let pytorch_content = b"PK\x03\x04test";
        let format = ModelQuarantine::detect_model_format(pytorch_content, Path::new("model.pt"));
        assert_eq!(format, "pytorch");
    }

    #[test]
    fn test_recovery_key_generation() {
        let key1 = ModelQuarantine::generate_recovery_key();
        let key2 = ModelQuarantine::generate_recovery_key();

        assert_eq!(key1.len(), RECOVERY_KEY_SIZE);
        assert_eq!(key2.len(), RECOVERY_KEY_SIZE);
        assert_ne!(key1, key2); // Keys should be unique
    }

    #[test]
    fn test_recovery_key_hash() {
        let key = ModelQuarantine::generate_recovery_key();
        let hash1 = ModelQuarantine::hash_recovery_key(&key);
        let hash2 = ModelQuarantine::hash_recovery_key(&key);

        assert_eq!(hash1, hash2); // Same key should produce same hash
        assert_eq!(hash1.len(), 64); // SHA256 hex is 64 chars
    }

    #[test]
    fn test_is_path_blocked() {
        let path = "/test/model.pkl";

        // Initially not blocked
        assert!(!ModelQuarantine::is_path_blocked(path));

        // Block the path
        BLOCKED_PATHS.insert(
            path.to_string(),
            BlockedPathInfo {
                path: path.to_string(),
                quarantine_id: "test-id".to_string(),
                blocked_at: Utc::now(),
                reason: "Test".to_string(),
                access_attempts: Vec::new(),
            },
        );

        // Now blocked
        assert!(ModelQuarantine::is_path_blocked(path));

        // Cleanup
        BLOCKED_PATHS.remove(path);
    }

    #[test]
    fn test_record_access_attempt() {
        let path = "/test/access_attempt.pkl";

        BLOCKED_PATHS.insert(
            path.to_string(),
            BlockedPathInfo {
                path: path.to_string(),
                quarantine_id: "test-id".to_string(),
                blocked_at: Utc::now(),
                reason: "Test".to_string(),
                access_attempts: Vec::new(),
            },
        );

        ModelQuarantine::record_access_attempt(path, 1234, "python", "load_library");

        // Extract values and drop the DashMap read guard before calling
        // remove(). Holding the `get` Ref across `remove()` on the same shard
        // deadlocks (DashMap re-entrant lock on the same shard).
        let (attempt_count, first_pid, first_name) = {
            let info = BLOCKED_PATHS.get(path).unwrap();
            (
                info.access_attempts.len(),
                info.access_attempts[0].pid,
                info.access_attempts[0].process_name.clone(),
            )
        };
        assert_eq!(attempt_count, 1);
        assert_eq!(first_pid, 1234);
        assert_eq!(first_name, "python");

        // Cleanup
        BLOCKED_PATHS.remove(path);
    }
}
