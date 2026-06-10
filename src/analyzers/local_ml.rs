//! Local ML-based Pre-Execution Detection Engine
//!
//! This module provides a high-level interface for on-device ML-based malware
//! detection with pre-execution blocking capabilities. It wraps the ONNX scanner
//! and integrates with file events for real-time protection.
//!
//! ## Features
//! - Pre-execution blocking for detected malware
//! - Configurable thresholds per file type and context
//! - Caching for performance (hash-based deduplication)
//! - Integration with file write/execute events
//! - Quarantine support for blocked files

use anyhow::{Context, Result};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

#[cfg(feature = "onnx")]
use super::onnx_scanner::{OnnxScanner, OnnxScannerConfig};

/// Action to take when malware is detected
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionAction {
    /// Allow execution (log only)
    Allow,
    /// Alert but don't block
    Alert,
    /// Block execution
    Block,
    /// Block and quarantine
    BlockAndQuarantine,
}

/// Result of a pre-execution scan
#[derive(Debug, Clone)]
pub struct PreExecutionResult {
    /// Path of the scanned file
    pub path: PathBuf,
    /// SHA256 hash of the file
    pub sha256: String,
    /// Whether the file is classified as malicious
    pub is_malicious: bool,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// Predicted malware family (if malicious)
    pub family: Option<String>,
    /// Action taken
    pub action: DetectionAction,
    /// Whether execution was blocked
    pub blocked: bool,
    /// Whether the file was quarantined
    pub quarantined: bool,
    /// Scan duration in milliseconds
    pub scan_time_ms: u64,
    /// Reason for the decision
    pub reason: String,
}

/// Configuration for the local ML engine
#[derive(Debug, Clone)]
pub struct LocalMLConfig {
    /// Path to the ONNX model file
    pub model_path: PathBuf,
    /// Confidence threshold for blocking (0.0 - 1.0)
    pub block_threshold: f32,
    /// Confidence threshold for alerting (0.0 - 1.0)
    pub alert_threshold: f32,
    /// Whether to enable pre-execution blocking
    pub enable_blocking: bool,
    /// Whether to quarantine blocked files
    pub enable_quarantine: bool,
    /// Quarantine directory
    pub quarantine_dir: PathBuf,
    /// Maximum file size to scan (bytes)
    pub max_file_size: u64,
    /// Per-extension threshold overrides (extension -> threshold)
    pub extension_thresholds: HashMap<String, f32>,
    /// Paths to exclude from scanning (glob patterns)
    pub exclusion_paths: Vec<String>,
    /// Enable aggressive mode (lower thresholds)
    pub aggressive_mode: bool,
    /// Timeout for scan operations (ms)
    pub scan_timeout_ms: u64,
    /// Family labels for the model
    pub family_labels: Vec<String>,
}

impl Default for LocalMLConfig {
    fn default() -> Self {
        let quarantine_dir = Self::default_quarantine_dir();

        let mut extension_thresholds = HashMap::new();
        // Higher thresholds for commonly abused extensions
        extension_thresholds.insert("exe".to_string(), 0.65);
        extension_thresholds.insert("dll".to_string(), 0.70);
        extension_thresholds.insert("scr".to_string(), 0.60);
        extension_thresholds.insert("bat".to_string(), 0.55);
        extension_thresholds.insert("cmd".to_string(), 0.55);
        extension_thresholds.insert("ps1".to_string(), 0.50);
        extension_thresholds.insert("vbs".to_string(), 0.50);
        extension_thresholds.insert("js".to_string(), 0.55);
        extension_thresholds.insert("wsf".to_string(), 0.50);
        extension_thresholds.insert("hta".to_string(), 0.45);
        extension_thresholds.insert("msi".to_string(), 0.65);

        Self {
            model_path: Self::default_model_path(),
            block_threshold: 0.80,
            alert_threshold: 0.60,
            enable_blocking: true,
            enable_quarantine: true,
            quarantine_dir,
            max_file_size: 100 * 1024 * 1024, // 100MB
            extension_thresholds,
            exclusion_paths: vec![
                "**/Windows/System32/**".to_string(),
                "**/Windows/WinSxS/**".to_string(),
                "**/Program Files/Windows Defender/**".to_string(),
            ],
            aggressive_mode: false,
            scan_timeout_ms: 5000,
            family_labels: vec![
                "benign".to_string(),
                "trojan".to_string(),
                "ransomware".to_string(),
                "backdoor".to_string(),
                "worm".to_string(),
                "dropper".to_string(),
                "spyware".to_string(),
                "adware".to_string(),
                "miner".to_string(),
                "rootkit".to_string(),
            ],
        }
    }
}

impl LocalMLConfig {
    fn default_model_path() -> PathBuf {
        #[cfg(target_os = "windows")]
        {
            PathBuf::from("C:\\ProgramData\\Tamandua\\models\\malware_smell.onnx")
        }
        #[cfg(target_os = "linux")]
        {
            PathBuf::from("/var/lib/tamandua/models/malware_smell.onnx")
        }
        #[cfg(target_os = "macos")]
        {
            PathBuf::from("/Library/Application Support/Tamandua/models/malware_smell.onnx")
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            PathBuf::from("./models/malware_smell.onnx")
        }
    }

    fn default_quarantine_dir() -> PathBuf {
        #[cfg(target_os = "windows")]
        {
            PathBuf::from("C:\\ProgramData\\Tamandua\\quarantine")
        }
        #[cfg(target_os = "linux")]
        {
            PathBuf::from("/var/lib/tamandua/quarantine")
        }
        #[cfg(target_os = "macos")]
        {
            PathBuf::from("/Library/Application Support/Tamandua/quarantine")
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            PathBuf::from("./quarantine")
        }
    }
}

/// Statistics for the local ML engine
#[derive(Debug, Default, Clone)]
pub struct LocalMLStats {
    /// Total files scanned
    pub files_scanned: u64,
    /// Files blocked
    pub files_blocked: u64,
    /// Files quarantined
    pub files_quarantined: u64,
    /// Files allowed
    pub files_allowed: u64,
    /// Alerts generated
    pub alerts_generated: u64,
    /// Scan errors
    pub scan_errors: u64,
    /// Cache hits
    pub cache_hits: u64,
    /// Average scan time (ms)
    pub avg_scan_time_ms: f64,
    /// Total scan time (ms)
    total_scan_time_ms: u64,
}

/// Event types that trigger ML scanning
#[derive(Debug, Clone)]
pub enum ScanTrigger {
    /// File was created
    FileCreate { path: PathBuf },
    /// File was modified
    FileModify { path: PathBuf },
    /// File is about to be executed
    PreExecute { path: PathBuf, pid: Option<u32> },
    /// Manual scan request
    ManualScan { path: PathBuf },
    /// Scheduled scan
    ScheduledScan { path: PathBuf },
}

/// Detection event to send to the transport layer
#[derive(Debug, Clone)]
pub struct MLDetectionEvent {
    pub path: PathBuf,
    pub sha256: String,
    pub is_malicious: bool,
    pub confidence: f32,
    pub family: Option<String>,
    pub action: DetectionAction,
    pub blocked: bool,
    pub quarantined: bool,
    pub trigger: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Local ML-based malware detection engine
pub struct LocalMLEngine {
    #[cfg(feature = "onnx")]
    scanner: Option<OnnxScanner>,
    #[cfg(not(feature = "onnx"))]
    scanner: Option<()>,
    config: RwLock<LocalMLConfig>,
    stats: Arc<RwLock<LocalMLStats>>,
    /// Channel for sending detection events
    event_tx: Option<mpsc::Sender<MLDetectionEvent>>,
    /// Recent scan results cache (sha256 -> (result, timestamp))
    recent_scans: Arc<RwLock<HashMap<String, (PreExecutionResult, Instant)>>>,
    /// Whether the engine is operational
    is_operational: bool,
}

impl LocalMLEngine {
    /// Create a new local ML engine with the given configuration
    pub fn new(config: LocalMLConfig) -> Self {
        let (scanner, is_operational) = Self::create_scanner(&config);

        if is_operational {
            info!(
                model_path = %config.model_path.display(),
                block_threshold = config.block_threshold,
                "Local ML engine initialized"
            );
        } else {
            warn!(
                model_path = %config.model_path.display(),
                "Local ML engine in fallback mode - model not available"
            );
        }

        // Ensure quarantine directory exists
        if config.enable_quarantine {
            if let Err(e) = std::fs::create_dir_all(&config.quarantine_dir) {
                warn!(error = %e, "Failed to create quarantine directory");
            }
        }

        Self {
            scanner,
            config: RwLock::new(config),
            stats: Arc::new(RwLock::new(LocalMLStats::default())),
            event_tx: None,
            recent_scans: Arc::new(RwLock::new(HashMap::new())),
            is_operational,
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(LocalMLConfig::default())
    }

    #[cfg(feature = "onnx")]
    fn create_scanner(config: &LocalMLConfig) -> (Option<OnnxScanner>, bool) {
        let onnx_config = OnnxScannerConfig {
            model_path: config.model_path.clone(),
            confidence_threshold: config.alert_threshold,
            image_size: 224,
            max_file_size: config.max_file_size,
            cache_ttl_secs: 3600,
            max_cache_entries: 10000,
            enable_batching: true,
            max_batch_size: 8,
            family_labels: config.family_labels.clone(),
            inference_timeout_secs: (config.scan_timeout_ms / 1000).max(1), // Convert ms to secs, min 1s
        };

        let scanner = OnnxScanner::new(onnx_config);
        let operational = scanner.is_operational();
        (Some(scanner), operational)
    }

    #[cfg(not(feature = "onnx"))]
    fn create_scanner(_config: &LocalMLConfig) -> (Option<()>, bool) {
        warn!("ONNX feature not enabled - ML engine in fallback mode");
        (None, false)
    }

    /// Set the event channel for sending detection events
    pub fn set_event_channel(&mut self, tx: mpsc::Sender<MLDetectionEvent>) {
        self.event_tx = Some(tx);
    }

    /// Check if the engine is operational
    pub fn is_operational(&self) -> bool {
        self.is_operational
    }

    /// Get engine statistics
    pub fn get_stats(&self) -> LocalMLStats {
        self.stats.read().clone()
    }

    /// Update configuration at runtime
    pub fn update_config(&mut self, config: LocalMLConfig) {
        let need_reload = {
            let current = self.config.read();
            current.model_path != config.model_path
        };

        *self.config.write() = config.clone();

        if need_reload {
            let (scanner, operational) = Self::create_scanner(&config);
            self.scanner = scanner;
            self.is_operational = operational;
        }
    }

    /// Scan a file on creation or modification
    pub async fn scan_on_write(&self, path: &Path) -> Result<PreExecutionResult> {
        self.scan_file(
            path,
            ScanTrigger::FileCreate {
                path: path.to_path_buf(),
            },
        )
        .await
    }

    /// Scan a file before execution (pre-execution hook)
    pub async fn scan_pre_execute(
        &self,
        path: &Path,
        pid: Option<u32>,
    ) -> Result<PreExecutionResult> {
        self.scan_file(
            path,
            ScanTrigger::PreExecute {
                path: path.to_path_buf(),
                pid,
            },
        )
        .await
    }

    /// Scan a file with a specific trigger type
    pub async fn scan_file(&self, path: &Path, trigger: ScanTrigger) -> Result<PreExecutionResult> {
        let start = Instant::now();
        let config = self.config.read().clone();

        // Check exclusions
        if self.should_exclude(path, &config) {
            return Ok(PreExecutionResult {
                path: path.to_path_buf(),
                sha256: String::new(),
                is_malicious: false,
                confidence: 0.0,
                family: None,
                action: DetectionAction::Allow,
                blocked: false,
                quarantined: false,
                scan_time_ms: start.elapsed().as_millis() as u64,
                reason: "Excluded path".to_string(),
            });
        }

        // Check file size
        let metadata = tokio::fs::metadata(path)
            .await
            .with_context(|| format!("Failed to get metadata for {}", path.display()))?;

        if metadata.len() > config.max_file_size {
            debug!(
                path = %path.display(),
                size = metadata.len(),
                max_size = config.max_file_size,
                "File too large for ML scan"
            );
            return Ok(PreExecutionResult {
                path: path.to_path_buf(),
                sha256: String::new(),
                is_malicious: false,
                confidence: 0.0,
                family: None,
                action: DetectionAction::Allow,
                blocked: false,
                quarantined: false,
                scan_time_ms: start.elapsed().as_millis() as u64,
                reason: "File too large".to_string(),
            });
        }

        // Read file and calculate hash
        let data = tokio::fs::read(path)
            .await
            .with_context(|| format!("Failed to read file {}", path.display()))?;

        let sha256 = {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(&data);
            hex::encode(hash)
        };

        // Check recent scans cache
        if let Some(cached) = self.get_cached_result(&sha256) {
            self.stats.write().cache_hits += 1;
            return Ok(cached);
        }

        // Perform ML scan
        let result = self
            .perform_scan(path, &data, &sha256, &trigger, &config)
            .await?;

        // Cache result
        self.cache_result(&sha256, result.clone());

        // Update stats
        {
            let mut stats = self.stats.write();
            stats.files_scanned += 1;
            let scan_time = start.elapsed().as_millis() as u64;
            stats.total_scan_time_ms += scan_time;
            stats.avg_scan_time_ms = stats.total_scan_time_ms as f64 / stats.files_scanned as f64;

            match result.action {
                DetectionAction::Allow => stats.files_allowed += 1,
                DetectionAction::Alert => stats.alerts_generated += 1,
                DetectionAction::Block => stats.files_blocked += 1,
                DetectionAction::BlockAndQuarantine => {
                    stats.files_blocked += 1;
                    if result.quarantined {
                        stats.files_quarantined += 1;
                    }
                }
            }
        }

        // Send detection event if configured
        if result.is_malicious {
            self.send_detection_event(&result, &trigger).await;
        }

        Ok(result)
    }

    /// Perform the actual ML scan
    #[cfg(feature = "onnx")]
    async fn perform_scan(
        &self,
        path: &Path,
        data: &[u8],
        sha256: &str,
        trigger: &ScanTrigger,
        config: &LocalMLConfig,
    ) -> Result<PreExecutionResult> {
        let start = Instant::now();

        let scanner = match &self.scanner {
            Some(s) => s,
            None => {
                return Ok(PreExecutionResult {
                    path: path.to_path_buf(),
                    sha256: sha256.to_string(),
                    is_malicious: false,
                    confidence: 0.0,
                    family: None,
                    action: DetectionAction::Allow,
                    blocked: false,
                    quarantined: false,
                    scan_time_ms: start.elapsed().as_millis() as u64,
                    reason: "Scanner not available".to_string(),
                });
            }
        };

        // Run ML inference with timeout
        let scan_result = tokio::time::timeout(
            Duration::from_millis(config.scan_timeout_ms),
            scanner.scan_bytes(data),
        )
        .await
        .with_context(|| "ML scan timed out")?
        .with_context(|| "ML scan failed")?;

        // Determine threshold based on file extension
        let extension = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase())
            .unwrap_or_default();

        let effective_threshold = config
            .extension_thresholds
            .get(&extension)
            .copied()
            .unwrap_or(config.block_threshold);

        // Adjust threshold for aggressive mode
        let effective_threshold = if config.aggressive_mode {
            effective_threshold * 0.85
        } else {
            effective_threshold
        };

        // Determine action based on confidence
        let (action, reason) = if scan_result.is_malicious
            && scan_result.confidence >= effective_threshold
        {
            if config.enable_quarantine {
                (DetectionAction::BlockAndQuarantine, format!(
                    "Blocked and quarantined: {} detected with {:.1}% confidence (threshold: {:.1}%)",
                    scan_result.family.as_deref().unwrap_or("malware"),
                    scan_result.confidence * 100.0,
                    effective_threshold * 100.0
                ))
            } else if config.enable_blocking {
                (
                    DetectionAction::Block,
                    format!(
                        "Blocked: {} detected with {:.1}% confidence",
                        scan_result.family.as_deref().unwrap_or("malware"),
                        scan_result.confidence * 100.0
                    ),
                )
            } else {
                (
                    DetectionAction::Alert,
                    format!(
                        "Alert: {} detected with {:.1}% confidence (blocking disabled)",
                        scan_result.family.as_deref().unwrap_or("malware"),
                        scan_result.confidence * 100.0
                    ),
                )
            }
        } else if scan_result.is_malicious && scan_result.confidence >= config.alert_threshold {
            (
                DetectionAction::Alert,
                format!(
                    "Alert: {} detected with {:.1}% confidence (below block threshold)",
                    scan_result.family.as_deref().unwrap_or("suspicious"),
                    scan_result.confidence * 100.0
                ),
            )
        } else {
            (DetectionAction::Allow, "Clean".to_string())
        };

        // Execute blocking/quarantine if needed
        let (blocked, quarantined) = match action {
            DetectionAction::BlockAndQuarantine => {
                let quarantined = self.quarantine_file(path, sha256, config).await;
                (true, quarantined)
            }
            DetectionAction::Block => (true, false),
            _ => (false, false),
        };

        if blocked {
            warn!(
                path = %path.display(),
                sha256 = %sha256,
                family = ?scan_result.family,
                confidence = scan_result.confidence,
                quarantined = quarantined,
                "Malware blocked by pre-execution scan"
            );
        }

        Ok(PreExecutionResult {
            path: path.to_path_buf(),
            sha256: sha256.to_string(),
            is_malicious: scan_result.is_malicious,
            confidence: scan_result.confidence,
            family: scan_result.family,
            action,
            blocked,
            quarantined,
            scan_time_ms: start.elapsed().as_millis() as u64,
            reason,
        })
    }

    #[cfg(not(feature = "onnx"))]
    async fn perform_scan(
        &self,
        path: &Path,
        _data: &[u8],
        sha256: &str,
        _trigger: &ScanTrigger,
        _config: &LocalMLConfig,
    ) -> Result<PreExecutionResult> {
        Ok(PreExecutionResult {
            path: path.to_path_buf(),
            sha256: sha256.to_string(),
            is_malicious: false,
            confidence: 0.0,
            family: None,
            action: DetectionAction::Allow,
            blocked: false,
            quarantined: false,
            scan_time_ms: 0,
            reason: "ONNX feature not enabled".to_string(),
        })
    }

    /// Quarantine a malicious file
    #[allow(dead_code)]
    async fn quarantine_file(&self, path: &Path, sha256: &str, config: &LocalMLConfig) -> bool {
        let quarantine_path = config.quarantine_dir.join(format!("{}.quarantine", sha256));

        // Create quarantine metadata
        let metadata = serde_json::json!({
            "original_path": path.display().to_string(),
            "sha256": sha256,
            "quarantine_time": chrono::Utc::now().to_rfc3339(),
        });

        let metadata_path = config.quarantine_dir.join(format!("{}.meta.json", sha256));

        // Move file to quarantine
        match tokio::fs::rename(path, &quarantine_path).await {
            Ok(_) => {
                // Write metadata
                let _ = tokio::fs::write(&metadata_path, metadata.to_string()).await;
                info!(
                    original = %path.display(),
                    quarantine = %quarantine_path.display(),
                    "File quarantined"
                );
                true
            }
            Err(e) => {
                // If rename fails (cross-device), try copy + delete
                warn!(error = %e, "Rename failed, trying copy+delete");
                match tokio::fs::copy(path, &quarantine_path).await {
                    Ok(_) => {
                        let _ = tokio::fs::remove_file(path).await;
                        let _ = tokio::fs::write(&metadata_path, metadata.to_string()).await;
                        info!(
                            original = %path.display(),
                            quarantine = %quarantine_path.display(),
                            "File quarantined (copy+delete)"
                        );
                        true
                    }
                    Err(e) => {
                        error!(error = %e, path = %path.display(), "Failed to quarantine file");
                        false
                    }
                }
            }
        }
    }

    /// Check if a path should be excluded from scanning
    fn should_exclude(&self, path: &Path, config: &LocalMLConfig) -> bool {
        let path_str = path.display().to_string();

        for pattern in &config.exclusion_paths {
            if glob_matches(&path_str, pattern) {
                return true;
            }
        }

        false
    }

    /// Get a cached result if available
    fn get_cached_result(&self, sha256: &str) -> Option<PreExecutionResult> {
        let cache = self.recent_scans.read();
        if let Some((result, timestamp)) = cache.get(sha256) {
            // Cache valid for 5 minutes
            if timestamp.elapsed() < Duration::from_secs(300) {
                return Some(result.clone());
            }
        }
        None
    }

    /// Cache a scan result
    fn cache_result(&self, sha256: &str, result: PreExecutionResult) {
        let mut cache = self.recent_scans.write();

        // Limit cache size
        if cache.len() > 10000 {
            // Remove entries older than 5 minutes
            let cutoff = Instant::now() - Duration::from_secs(300);
            cache.retain(|_, (_, ts)| *ts > cutoff);
        }

        cache.insert(sha256.to_string(), (result, Instant::now()));
    }

    /// Send a detection event through the channel
    async fn send_detection_event(&self, result: &PreExecutionResult, trigger: &ScanTrigger) {
        if let Some(tx) = &self.event_tx {
            let event = MLDetectionEvent {
                path: result.path.clone(),
                sha256: result.sha256.clone(),
                is_malicious: result.is_malicious,
                confidence: result.confidence,
                family: result.family.clone(),
                action: result.action,
                blocked: result.blocked,
                quarantined: result.quarantined,
                trigger: match trigger {
                    ScanTrigger::FileCreate { .. } => "file_create",
                    ScanTrigger::FileModify { .. } => "file_modify",
                    ScanTrigger::PreExecute { .. } => "pre_execute",
                    ScanTrigger::ManualScan { .. } => "manual",
                    ScanTrigger::ScheduledScan { .. } => "scheduled",
                }
                .to_string(),
                timestamp: chrono::Utc::now(),
            };

            if let Err(e) = tx.send(event).await {
                warn!(error = %e, "Failed to send detection event");
            }
        }
    }

    /// Restore a quarantined file
    pub async fn restore_from_quarantine(&self, sha256: &str) -> Result<PathBuf> {
        let config = self.config.read();
        let quarantine_path = config.quarantine_dir.join(format!("{}.quarantine", sha256));
        let metadata_path = config.quarantine_dir.join(format!("{}.meta.json", sha256));

        // Read metadata to get original path
        let metadata_str = tokio::fs::read_to_string(&metadata_path)
            .await
            .with_context(|| "Failed to read quarantine metadata")?;

        let metadata: serde_json::Value = serde_json::from_str(&metadata_str)
            .with_context(|| "Failed to parse quarantine metadata")?;

        let original_path = metadata["original_path"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing original_path in metadata"))?;

        let original_path = PathBuf::from(original_path);

        // Restore file
        tokio::fs::rename(&quarantine_path, &original_path)
            .await
            .with_context(|| "Failed to restore file from quarantine")?;

        // Remove metadata
        let _ = tokio::fs::remove_file(&metadata_path).await;

        info!(
            sha256 = %sha256,
            restored_to = %original_path.display(),
            "File restored from quarantine"
        );

        // Remove from cache to allow re-scanning
        self.recent_scans.write().remove(sha256);

        Ok(original_path)
    }

    /// List quarantined files
    pub async fn list_quarantine(&self) -> Result<Vec<QuarantinedFile>> {
        let config = self.config.read();
        let mut files = Vec::new();

        let mut dir = tokio::fs::read_dir(&config.quarantine_dir)
            .await
            .with_context(|| "Failed to read quarantine directory")?;

        while let Some(entry) = dir.next_entry().await? {
            let path = entry.path();
            if path.extension().map(|e| e == "meta.json").unwrap_or(false) {
                if let Ok(metadata_str) = tokio::fs::read_to_string(&path).await {
                    if let Ok(metadata) = serde_json::from_str::<serde_json::Value>(&metadata_str) {
                        files.push(QuarantinedFile {
                            sha256: metadata["sha256"].as_str().unwrap_or("").to_string(),
                            original_path: metadata["original_path"]
                                .as_str()
                                .unwrap_or("")
                                .to_string(),
                            quarantine_time: metadata["quarantine_time"]
                                .as_str()
                                .unwrap_or("")
                                .to_string(),
                        });
                    }
                }
            }
        }

        Ok(files)
    }

    /// Clear the scan cache
    pub fn clear_cache(&self) {
        self.recent_scans.write().clear();
    }
}

/// Information about a quarantined file
#[derive(Debug, Clone)]
pub struct QuarantinedFile {
    pub sha256: String,
    pub original_path: String,
    pub quarantine_time: String,
}

/// Simple glob pattern matching
fn glob_matches(path: &str, pattern: &str) -> bool {
    let path = path.replace('\\', "/");
    let pattern = pattern.replace('\\', "/");

    // Convert glob pattern to regex-like matching
    let parts: Vec<&str> = pattern.split("**").collect();

    if parts.len() == 1 {
        // No ** in pattern, simple matching
        simple_glob_match(&path, &pattern)
    } else {
        // Has ** for recursive matching
        let first = parts.first().unwrap_or(&"");
        let last = parts.last().unwrap_or(&"");

        let matches_start = first.is_empty() || path.starts_with(first.trim_end_matches('/'));
        let matches_end = last.is_empty() || path.ends_with(last.trim_start_matches('/'));

        // Every segment between consecutive `**` must also appear in the path.
        let matches_middle = parts[1..parts.len().saturating_sub(1)]
            .iter()
            .all(|mid| mid.is_empty() || path.contains(&**mid));

        matches_start && matches_end && matches_middle
    }
}

fn simple_glob_match(path: &str, pattern: &str) -> bool {
    let pattern_parts: Vec<&str> = pattern.split('*').collect();

    if pattern_parts.len() == 1 {
        return path == pattern;
    }

    let mut pos = 0;
    for (i, part) in pattern_parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }

        if let Some(found) = path[pos..].find(part) {
            if i == 0 && found != 0 {
                return false; // First part must match at start
            }
            pos += found + part.len();
        } else {
            return false;
        }
    }

    // Last part must match at end if pattern doesn't end with *
    if !pattern.ends_with('*') {
        if let Some(last_part) = pattern_parts.last() {
            if !last_part.is_empty() {
                return path.ends_with(last_part);
            }
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = LocalMLConfig::default();
        assert_eq!(config.block_threshold, 0.80);
        assert_eq!(config.alert_threshold, 0.60);
        assert!(config.enable_blocking);
        assert!(config.enable_quarantine);
    }

    #[test]
    fn test_glob_matching() {
        assert!(glob_matches("/home/user/test.exe", "**/test.exe"));
        assert!(glob_matches(
            "C:/Windows/System32/cmd.exe",
            "**/Windows/System32/**"
        ));
        assert!(glob_matches("/var/lib/test.txt", "/var/**"));
        assert!(!glob_matches("/home/user/test.exe", "**/Windows/**"));
    }

    #[test]
    fn test_extension_thresholds() {
        let config = LocalMLConfig::default();
        assert!(config.extension_thresholds.get("exe").is_some());
        assert!(config.extension_thresholds.get("ps1").is_some());
        assert!(config.extension_thresholds.get("hta").is_some());
    }
}
