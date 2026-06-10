//! Process Trust Manager
//!
//! Manages trust decisions for processes:
//! - Persist trust decisions to disk
//! - Integration with ML for behavioral trust scoring
//! - Support for manual trust overrides
//!
//! Trust levels range from Untrusted (malicious) to Trusted (verified safe).

use super::{explorer::get_process_details, ProcessManagerError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Trust level for processes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrustLevel {
    /// Process is known to be malicious
    Untrusted,
    /// Process behavior is suspicious
    Suspicious,
    /// Process trust is unknown (default)
    Unknown,
    /// Process behavior appears normal
    Normal,
    /// Process is verified as trusted
    Trusted,
}

impl TrustLevel {
    /// Get numeric score for this trust level
    pub fn score(&self) -> i32 {
        match self {
            Self::Untrusted => -100,
            Self::Suspicious => -50,
            Self::Unknown => 0,
            Self::Normal => 50,
            Self::Trusted => 100,
        }
    }

    /// Create from numeric score
    pub fn from_score(score: i32) -> Self {
        match score {
            s if s <= -75 => Self::Untrusted,
            s if s <= -25 => Self::Suspicious,
            s if s <= 25 => Self::Unknown,
            s if s <= 75 => Self::Normal,
            _ => Self::Trusted,
        }
    }

    /// Check if this level indicates the process should be blocked
    pub fn should_block(&self) -> bool {
        matches!(self, Self::Untrusted)
    }

    /// Check if this level indicates the process is suspicious
    pub fn is_suspicious(&self) -> bool {
        matches!(self, Self::Untrusted | Self::Suspicious)
    }
}

impl Default for TrustLevel {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Detailed trust information for a process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTrustInfo {
    /// Process ID
    pub pid: u32,
    /// Process name
    pub name: String,
    /// Executable path (if known)
    pub path: Option<String>,
    /// Current trust level
    pub trust_level: TrustLevel,
    /// Reason for the trust level
    pub reason: String,
    /// When the trust decision was made (Unix timestamp)
    pub timestamp: u64,
    /// ML confidence score (0.0-1.0)
    pub ml_confidence: Option<f32>,
    /// Behavioral score from ML
    pub behavioral_score: Option<f32>,
    /// Whether this was a manual override
    pub manual_override: bool,
    /// Source of the trust decision
    pub source: TrustSource,
    /// Historical trust decisions for this process
    pub history: Vec<TrustDecision>,
}

/// Source of a trust decision
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustSource {
    /// User/analyst manually set the trust level
    Manual,
    /// ML model determined the trust level
    MlModel,
    /// Based on process signature
    Signature,
    /// Based on hash matching known good/bad
    HashMatch,
    /// Based on behavioral analysis
    Behavioral,
    /// Default/unknown
    Default,
}

/// A single trust decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustDecision {
    /// Trust level assigned
    pub level: TrustLevel,
    /// Reason for the decision
    pub reason: String,
    /// When the decision was made (Unix timestamp)
    pub timestamp: u64,
    /// Source of the decision
    pub source: TrustSource,
}

/// Persistent trust entry (saved to disk)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedTrustEntry {
    /// Key: hash of path or name
    key: String,
    /// Process name
    name: String,
    /// Executable path
    path: Option<String>,
    /// Trust level
    level: TrustLevel,
    /// Reason
    reason: String,
    /// Last updated timestamp
    timestamp: u64,
    /// Source
    source: TrustSource,
}

/// Trust Manager
///
/// Manages trust decisions for processes with persistence and ML integration.
pub struct TrustManager {
    /// In-memory trust cache: PID -> TrustInfo
    pid_cache: HashMap<u32, ProcessTrustInfo>,
    /// Persistent trust by path hash
    persisted: HashMap<String, PersistedTrustEntry>,
    /// Path to persistence file
    persistence_path: PathBuf,
    /// Whether ML integration is enabled
    ml_enabled: bool,
    /// Lock for thread safety
    lock: Arc<RwLock<()>>,
}

impl TrustManager {
    /// Create a new TrustManager
    pub async fn new() -> std::result::Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let persistence_path = get_trust_db_path();

        // Load persisted trust decisions
        let persisted = Self::load_persisted(&persistence_path).await;

        Ok(Self {
            pid_cache: HashMap::new(),
            persisted,
            persistence_path,
            ml_enabled: false, // Will be enabled if ML service is available
            lock: Arc::new(RwLock::new(())),
        })
    }

    /// Enable ML integration
    pub fn enable_ml(&mut self) {
        self.ml_enabled = true;
        info!("ML integration enabled for trust decisions");
    }

    /// Disable ML integration
    pub fn disable_ml(&mut self) {
        self.ml_enabled = false;
        info!("ML integration disabled for trust decisions");
    }

    /// Set trust level for a process
    pub async fn set_trust(
        &mut self,
        pid: u32,
        level: TrustLevel,
        reason: &str,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let _guard = self.lock.write().await;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Get process details
        let (name, path) = match get_process_details(pid).await {
            Ok(details) => (details.name, details.path),
            Err(_) => ("Unknown".to_string(), None),
        };

        // Create or update trust info
        let decision = TrustDecision {
            level,
            reason: reason.to_string(),
            timestamp: now,
            source: TrustSource::Manual,
        };

        let trust_info = self
            .pid_cache
            .entry(pid)
            .or_insert_with(|| ProcessTrustInfo {
                pid,
                name: name.clone(),
                path: path.clone(),
                trust_level: level,
                reason: reason.to_string(),
                timestamp: now,
                ml_confidence: None,
                behavioral_score: None,
                manual_override: true,
                source: TrustSource::Manual,
                history: Vec::new(),
            });

        // Add to history
        trust_info.history.push(decision);

        // Update current values
        trust_info.trust_level = level;
        trust_info.reason = reason.to_string();
        trust_info.timestamp = now;
        trust_info.manual_override = true;
        trust_info.source = TrustSource::Manual;

        info!(
            pid = pid,
            name = %name,
            level = ?level,
            reason = %reason,
            "Trust level set manually"
        );

        // Persist for future lookups by path
        if let Some(ref path) = path {
            let key = hash_path(path);
            self.persisted.insert(
                key.clone(),
                PersistedTrustEntry {
                    key,
                    name,
                    path: Some(path.clone()),
                    level,
                    reason: reason.to_string(),
                    timestamp: now,
                    source: TrustSource::Manual,
                },
            );
            self.save_persisted().await?;
        }

        Ok(())
    }

    /// Get trust information for a process
    pub async fn get_trust(
        &self,
        pid: u32,
    ) -> std::result::Result<Option<ProcessTrustInfo>, Box<dyn std::error::Error + Send + Sync>>
    {
        // Check PID cache first
        if let Some(info) = self.pid_cache.get(&pid) {
            return Ok(Some(info.clone()));
        }

        // Try to look up by path
        if let Ok(details) = get_process_details(pid).await {
            if let Some(ref path) = details.path {
                let key = hash_path(path);
                if let Some(entry) = self.persisted.get(&key) {
                    return Ok(Some(ProcessTrustInfo {
                        pid,
                        name: entry.name.clone(),
                        path: entry.path.clone(),
                        trust_level: entry.level,
                        reason: entry.reason.clone(),
                        timestamp: entry.timestamp,
                        ml_confidence: None,
                        behavioral_score: None,
                        manual_override: entry.source == TrustSource::Manual,
                        source: entry.source,
                        history: Vec::new(),
                    }));
                }
            }
        }

        Ok(None)
    }

    /// Get trust level for a process (simplified)
    pub async fn get_trust_level(&self, pid: u32) -> TrustLevel {
        self.get_trust(pid)
            .await
            .ok()
            .flatten()
            .map(|info| info.trust_level)
            .unwrap_or(TrustLevel::Unknown)
    }

    /// Update trust based on ML behavioral score
    pub async fn update_from_ml(
        &mut self,
        pid: u32,
        behavioral_score: f32,
        confidence: f32,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.ml_enabled {
            return Ok(());
        }

        let _guard = self.lock.write().await;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Convert behavioral score to trust level
        // Score range: 0.0 (malicious) to 1.0 (benign)
        let level = if behavioral_score < 0.2 {
            TrustLevel::Untrusted
        } else if behavioral_score < 0.4 {
            TrustLevel::Suspicious
        } else if behavioral_score < 0.6 {
            TrustLevel::Unknown
        } else if behavioral_score < 0.8 {
            TrustLevel::Normal
        } else {
            TrustLevel::Trusted
        };

        let reason = format!(
            "ML behavioral score: {:.2} (confidence: {:.2})",
            behavioral_score, confidence
        );

        // Get process details
        let (name, path) = match get_process_details(pid).await {
            Ok(details) => (details.name, details.path),
            Err(_) => ("Unknown".to_string(), None),
        };

        let decision = TrustDecision {
            level,
            reason: reason.clone(),
            timestamp: now,
            source: TrustSource::MlModel,
        };

        // Only update if not manually overridden or ML has high confidence
        if let Some(existing) = self.pid_cache.get_mut(&pid) {
            if !existing.manual_override || confidence > 0.9 {
                existing.history.push(decision);
                existing.trust_level = level;
                existing.reason = reason;
                existing.timestamp = now;
                existing.ml_confidence = Some(confidence);
                existing.behavioral_score = Some(behavioral_score);
                existing.source = TrustSource::MlModel;
            }
        } else {
            self.pid_cache.insert(
                pid,
                ProcessTrustInfo {
                    pid,
                    name,
                    path,
                    trust_level: level,
                    reason,
                    timestamp: now,
                    ml_confidence: Some(confidence),
                    behavioral_score: Some(behavioral_score),
                    manual_override: false,
                    source: TrustSource::MlModel,
                    history: vec![decision],
                },
            );
        }

        debug!(
            pid = pid,
            behavioral_score = behavioral_score,
            confidence = confidence,
            level = ?level,
            "Trust updated from ML"
        );

        Ok(())
    }

    /// Clear trust for a process
    pub async fn clear_trust(&mut self, pid: u32) {
        self.pid_cache.remove(&pid);
        info!(pid = pid, "Trust cleared");
    }

    /// Clear all trust cache (doesn't affect persisted data)
    pub async fn clear_cache(&mut self) {
        self.pid_cache.clear();
        info!("Trust cache cleared");
    }

    /// Get all trusted processes
    pub fn get_trusted(&self) -> Vec<&ProcessTrustInfo> {
        self.pid_cache
            .values()
            .filter(|info| info.trust_level == TrustLevel::Trusted)
            .collect()
    }

    /// Get all untrusted/suspicious processes
    pub fn get_suspicious(&self) -> Vec<&ProcessTrustInfo> {
        self.pid_cache
            .values()
            .filter(|info| info.trust_level.is_suspicious())
            .collect()
    }

    /// Load persisted trust decisions from disk
    async fn load_persisted(path: &PathBuf) -> HashMap<String, PersistedTrustEntry> {
        match tokio::fs::read_to_string(path).await {
            Ok(content) => match serde_json::from_str::<Vec<PersistedTrustEntry>>(&content) {
                Ok(entries) => {
                    let map: HashMap<_, _> =
                        entries.into_iter().map(|e| (e.key.clone(), e)).collect();
                    info!(count = map.len(), "Loaded persisted trust decisions");
                    map
                }
                Err(e) => {
                    warn!(error = %e, "Failed to parse trust database");
                    HashMap::new()
                }
            },
            Err(_) => {
                debug!("No existing trust database found");
                HashMap::new()
            }
        }
    }

    /// Save persisted trust decisions to disk
    async fn save_persisted(
        &self,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let entries: Vec<_> = self.persisted.values().cloned().collect();
        let content = serde_json::to_string_pretty(&entries)?;

        // Ensure parent directory exists
        if let Some(parent) = self.persistence_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        tokio::fs::write(&self.persistence_path, content).await?;
        debug!(path = %self.persistence_path.display(), "Saved trust database");

        Ok(())
    }
}

/// Get the path to the trust database file
fn get_trust_db_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"C:\ProgramData\Tamandua\trust_db.json")
    }

    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/var/lib/tamandua/trust_db.json")
    }

    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/Tamandua/trust_db.json")
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        PathBuf::from("trust_db.json")
    }
}

/// Hash a path for use as a key
fn hash_path(path: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(path.to_lowercase().as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_level_score() {
        assert_eq!(TrustLevel::Untrusted.score(), -100);
        assert_eq!(TrustLevel::Suspicious.score(), -50);
        assert_eq!(TrustLevel::Unknown.score(), 0);
        assert_eq!(TrustLevel::Normal.score(), 50);
        assert_eq!(TrustLevel::Trusted.score(), 100);
    }

    #[test]
    fn test_trust_level_from_score() {
        assert_eq!(TrustLevel::from_score(-100), TrustLevel::Untrusted);
        assert_eq!(TrustLevel::from_score(-75), TrustLevel::Untrusted);
        assert_eq!(TrustLevel::from_score(-50), TrustLevel::Suspicious);
        assert_eq!(TrustLevel::from_score(0), TrustLevel::Unknown);
        assert_eq!(TrustLevel::from_score(50), TrustLevel::Normal);
        assert_eq!(TrustLevel::from_score(100), TrustLevel::Trusted);
    }

    #[test]
    fn test_trust_level_flags() {
        assert!(TrustLevel::Untrusted.should_block());
        assert!(!TrustLevel::Suspicious.should_block());
        assert!(!TrustLevel::Unknown.should_block());

        assert!(TrustLevel::Untrusted.is_suspicious());
        assert!(TrustLevel::Suspicious.is_suspicious());
        assert!(!TrustLevel::Unknown.is_suspicious());
        assert!(!TrustLevel::Normal.is_suspicious());
        assert!(!TrustLevel::Trusted.is_suspicious());
    }

    #[test]
    fn test_hash_path() {
        let hash1 = hash_path("C:\\Windows\\System32\\cmd.exe");
        let hash2 = hash_path("c:\\windows\\system32\\cmd.exe");
        // Should be case-insensitive
        assert_eq!(hash1, hash2);

        let hash3 = hash_path("/usr/bin/bash");
        assert_ne!(hash1, hash3);
    }

    #[tokio::test]
    async fn test_trust_manager_creation() {
        let manager = TrustManager::new().await;
        assert!(manager.is_ok());
    }

    #[test]
    fn test_trust_decision_serialization() {
        let decision = TrustDecision {
            level: TrustLevel::Suspicious,
            reason: "Test reason".to_string(),
            timestamp: 1234567890,
            source: TrustSource::MlModel,
        };

        let json = serde_json::to_string(&decision).unwrap();
        let deserialized: TrustDecision = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.level, TrustLevel::Suspicious);
        assert_eq!(deserialized.reason, "Test reason");
        assert_eq!(deserialized.timestamp, 1234567890);
        assert_eq!(deserialized.source, TrustSource::MlModel);
    }
}
