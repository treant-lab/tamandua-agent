//! Schedule execution engine

use super::schedule::{
    CpuPriority, DetectionAction, ScanOptions, Schedule, ScheduleId, ScheduleScanType,
};
use super::RunningSchedule;
use crate::analyzers::ml_local::LocalMLFeatureEngine;
use crate::config::AgentConfig;
use anyhow::Result;
use chrono::Utc;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info};
use walkdir::WalkDir;

/// Result of a schedule execution
#[derive(Debug)]
pub struct ExecutionResult {
    pub files_scanned: u64,
    pub threats_found: u32,
    pub duration_ms: u64,
}

/// Schedule executor handles running scans
pub struct ScheduleExecutor {
    /// Cancellation tokens for running scans
    cancel_tokens: Arc<RwLock<HashMap<ScheduleId, mpsc::Sender<()>>>>,
    /// ONNX image-based malware scanner used for scheduled scans.
    #[cfg(feature = "onnx")]
    onnx_scanner: Option<Arc<crate::analyzers::onnx_scanner::OnnxScanner>>,
    /// Feature-based local ML engine used for scheduled scans.
    ml_feature_engine: Option<Arc<LocalMLFeatureEngine>>,
    /// Maximum file size for feature-based ML scheduled scans.
    ml_feature_max_file_size_bytes: u64,
}

impl ScheduleExecutor {
    /// Create a new executor
    pub fn new() -> Self {
        Self {
            cancel_tokens: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(feature = "onnx")]
            onnx_scanner: None,
            ml_feature_engine: None,
            ml_feature_max_file_size_bytes: 0,
        }
    }

    /// Create a scheduler executor wired to the configured agent ML engines.
    pub fn from_config(config: &AgentConfig) -> Self {
        let mut executor = Self::new();

        #[cfg(feature = "onnx")]
        if config.ml_scanning_enabled && !config.collector_tuning.skip_expensive_analysis {
            let mut scanner_config = crate::analyzers::onnx_scanner::OnnxScannerConfig {
                confidence_threshold: config.ml_confidence_threshold.unwrap_or(0.7),
                inference_timeout_secs: config.ml_inference_timeout_secs,
                ..Default::default()
            };
            if let Some(model_path) = &config.ml_model_path {
                scanner_config.model_path = PathBuf::from(model_path);
            }
            executor.onnx_scanner = Some(Arc::new(
                crate::analyzers::onnx_scanner::OnnxScanner::new(scanner_config),
            ));
        }

        if config.ml_local.enabled {
            let engine = LocalMLFeatureEngine::from_config(config);
            if engine.is_operational() {
                executor.ml_feature_engine = Some(Arc::new(engine));
                executor.ml_feature_max_file_size_bytes =
                    config.ml_local.max_file_size_mb * 1024 * 1024;
            }
        }

        executor
    }

    /// Execute a scheduled scan
    pub async fn execute_schedule(
        &self,
        schedule: &Schedule,
        running: Arc<RwLock<HashMap<ScheduleId, RunningSchedule>>>,
    ) -> Result<ExecutionResult> {
        let start_time = Utc::now();
        info!("Starting scheduled scan: {}", schedule.name);

        // Create cancellation channel
        let (cancel_tx, mut cancel_rx) = mpsc::channel::<()>(1);
        {
            let mut tokens = self.cancel_tokens.write();
            tokens.insert(schedule.id, cancel_tx);
        }

        // Set up running status
        {
            let mut running_guard = running.write();
            running_guard.insert(
                schedule.id,
                RunningSchedule {
                    schedule_id: schedule.id,
                    started_at: start_time,
                    files_scanned: 0,
                    total_files: 0,
                    threats_found: 0,
                    current_path: String::new(),
                },
            );
        }

        // Set process priority
        self.set_process_priority(schedule.config.options.cpu_priority);

        // Get paths to scan
        let paths = self.get_scan_paths(schedule);
        debug!("Scanning {} paths", paths.len());

        let mut files_scanned: u64 = 0;
        let mut threats_found: u32 = 0;

        // Collect all files first
        let files: Vec<PathBuf> = paths
            .iter()
            .flat_map(|p| self.collect_files(p, &schedule.config.options))
            .collect();

        let total_files = files.len() as u64;

        // Update total count
        {
            let mut running_guard = running.write();
            if let Some(status) = running_guard.get_mut(&schedule.id) {
                status.total_files = total_files;
            }
        }

        // Process files
        for file_path in files {
            // Check for cancellation
            if cancel_rx.try_recv().is_ok() {
                info!("Schedule {} cancelled", schedule.name);
                break;
            }

            // Update current path
            {
                let mut running_guard = running.write();
                if let Some(status) = running_guard.get_mut(&schedule.id) {
                    status.current_path = file_path.display().to_string();
                    status.files_scanned = files_scanned;
                }
            }

            // Scan the file
            match self.scan_file(&file_path, &schedule.config.options).await {
                Ok(result) => {
                    if result.is_threat {
                        threats_found += 1;
                        info!("Threat detected: {} in {:?}", result.threat_name, file_path);

                        // Take action based on configuration
                        self.handle_detection(
                            &file_path,
                            &result,
                            &schedule.config.detection_action,
                        )
                        .await;
                    }
                }
                Err(e) => {
                    debug!("Error scanning {:?}: {}", file_path, e);
                }
            }

            files_scanned += 1;

            // Update progress
            {
                let mut running_guard = running.write();
                if let Some(status) = running_guard.get_mut(&schedule.id) {
                    status.files_scanned = files_scanned;
                    status.threats_found = threats_found;
                }
            }

            // Yield to allow other tasks
            tokio::task::yield_now().await;
        }

        // Clean up
        {
            let mut tokens = self.cancel_tokens.write();
            tokens.remove(&schedule.id);
        }

        // Reset process priority
        self.set_process_priority(CpuPriority::Normal);

        let end_time = Utc::now();
        let duration_ms = (end_time - start_time).num_milliseconds() as u64;

        info!(
            "Scheduled scan {} completed: {} files scanned, {} threats in {}ms",
            schedule.name, files_scanned, threats_found, duration_ms
        );

        Ok(ExecutionResult {
            files_scanned,
            threats_found,
            duration_ms,
        })
    }

    /// Cancel a running schedule
    pub fn cancel(&self, id: ScheduleId) -> Result<()> {
        let tokens = self.cancel_tokens.read();
        if let Some(tx) = tokens.get(&id) {
            let _ = tx.try_send(());
            info!("Sent cancellation signal to schedule {}", id);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Schedule {} is not running", id))
        }
    }

    /// Get paths to scan based on scan type
    fn get_scan_paths(&self, schedule: &Schedule) -> Vec<PathBuf> {
        match schedule.config.scan_type {
            ScheduleScanType::Quick => self.get_quick_scan_paths(),
            ScheduleScanType::Full => self.get_full_scan_paths(),
            ScheduleScanType::Custom => schedule.config.paths.clone(),
        }
    }

    /// Get paths for quick scan (common malware locations)
    fn get_quick_scan_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();

        // User home directories
        if let Some(home) = dirs::home_dir() {
            paths.push(home.join("Downloads"));
            paths.push(home.join("Desktop"));
            paths.push(home.join("Documents"));

            #[cfg(target_os = "windows")]
            {
                paths.push(home.join("AppData").join("Local").join("Temp"));
                paths.push(home.join("AppData").join("Roaming"));
            }

            #[cfg(target_os = "linux")]
            {
                paths.push(home.join(".local").join("share"));
                paths.push(PathBuf::from("/tmp"));
            }

            #[cfg(target_os = "macos")]
            {
                paths.push(home.join("Library").join("Caches"));
                paths.push(PathBuf::from("/tmp"));
            }
        }

        // System temp directories
        if let Some(temp) = dirs::cache_dir() {
            paths.push(temp);
        }

        // Common startup/persistence locations
        #[cfg(target_os = "windows")]
        {
            if let Some(program_data) = std::env::var_os("ProgramData") {
                paths.push(PathBuf::from(program_data));
            }
            paths.push(PathBuf::from(r"C:\Windows\Temp"));
        }

        #[cfg(target_os = "linux")]
        {
            paths.push(PathBuf::from("/etc/cron.d"));
            paths.push(PathBuf::from("/etc/systemd/system"));
        }

        #[cfg(target_os = "macos")]
        {
            paths.push(PathBuf::from("/Library/LaunchAgents"));
            paths.push(PathBuf::from("/Library/LaunchDaemons"));
        }

        // Filter to existing paths
        paths.into_iter().filter(|p| p.exists()).collect()
    }

    /// Get paths for full system scan
    fn get_full_scan_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();

        #[cfg(target_os = "windows")]
        {
            // Get all drives
            for letter in b'A'..=b'Z' {
                let drive = format!("{}:\\", letter as char);
                let path = PathBuf::from(&drive);
                if path.exists() {
                    paths.push(path);
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            paths.push(PathBuf::from("/"));
        }

        #[cfg(target_os = "macos")]
        {
            paths.push(PathBuf::from("/"));
        }

        paths
    }

    /// Collect files from a path based on options
    fn collect_files(&self, path: &PathBuf, options: &ScanOptions) -> Vec<PathBuf> {
        let mut files = Vec::new();

        let walker = WalkDir::new(path)
            .follow_links(options.follow_symlinks)
            .into_iter()
            .filter_entry(|e| !self.should_skip_entry(e));

        for entry in walker.filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                files.push(entry.into_path());
            }
        }

        files
    }

    /// Check if an entry should be skipped
    fn should_skip_entry(&self, entry: &walkdir::DirEntry) -> bool {
        // Skip hidden system directories
        let skip_dirs = [
            ".git",
            ".svn",
            ".hg",
            "node_modules",
            "__pycache__",
            "$Recycle.Bin",
            "System Volume Information",
        ];

        if let Some(name) = entry.file_name().to_str() {
            if skip_dirs.contains(&name) {
                return true;
            }
        }

        false
    }

    /// Scan a single file
    async fn scan_file(&self, path: &PathBuf, options: &ScanOptions) -> Result<ScanFileResult> {
        // Check file size
        let metadata = tokio::fs::metadata(path).await?;
        let size = metadata.len();

        // Skip very large files
        if size > 500 * 1024 * 1024 {
            return Ok(ScanFileResult {
                is_threat: false,
                threat_name: String::new(),
                severity: String::new(),
                detection_method: String::new(),
            });
        }

        // Read file for scanning
        let contents = tokio::fs::read(path).await?;

        // Calculate hash
        let hash = sha256_hash(&contents);

        // Check against known threat hashes (stub - integrate with real detection)
        if self.check_hash_reputation(&hash).await {
            return Ok(ScanFileResult {
                is_threat: true,
                threat_name: "Known malware hash".to_string(),
                severity: "high".to_string(),
                detection_method: "hash".to_string(),
            });
        }

        // YARA scan (stub - integrate with real YARA engine)
        if let Some(result) = self.scan_with_yara(&contents, path).await? {
            return Ok(result);
        }

        // ML scan (stub - integrate with real ML engine)
        if let Some(result) = self.scan_with_ml(&contents, path).await? {
            return Ok(result);
        }

        // Check archives if enabled
        if options.scan_archives && self.is_archive(path) {
            if let Some(result) = self.scan_archive(path, options).await? {
                return Ok(result);
            }
        }

        Ok(ScanFileResult {
            is_threat: false,
            threat_name: String::new(),
            severity: String::new(),
            detection_method: String::new(),
        })
    }

    /// Check hash against reputation database
    async fn check_hash_reputation(&self, _hash: &str) -> bool {
        // STUB — PRODUCTION-GAP, not production. Always returns false (no match).
        // Reached by the scheduled-scan loop via scan_file(); means hash-reputation
        // checks are silently disabled and known-bad hashes will scan as clean.
        // Missing: threat-intel/reputation lookup integration.
        false
    }

    /// Scan with YARA rules
    async fn scan_with_yara(
        &self,
        _contents: &[u8],
        _path: &PathBuf,
    ) -> Result<Option<ScanFileResult>> {
        // STUB — PRODUCTION-GAP, not production. Always returns None (no detection).
        // Reached by the scheduled-scan loop via scan_file(); YARA scanning is silently
        // disabled here even though a real YARA engine exists elsewhere in the agent.
        // Missing: wiring this code path to the agent's YARA scanner.
        Ok(None)
    }

    /// Scan with ML model
    async fn scan_with_ml(
        &self,
        contents: &[u8],
        path: &PathBuf,
    ) -> Result<Option<ScanFileResult>> {
        #[cfg(feature = "onnx")]
        if let Some(scanner) = &self.onnx_scanner {
            if crate::analyzers::onnx_scanner::is_executable_file(path, Some(contents)) {
                let result = scanner.scan_file(path).await?;
                if result.is_malicious {
                    let family = result
                        .family
                        .clone()
                        .unwrap_or_else(|| "unknown_malware".to_string());
                    return Ok(Some(ScanFileResult {
                        is_threat: true,
                        threat_name: format!("ONNX ML malware: {family}"),
                        severity: severity_for_confidence(result.confidence),
                        detection_method: "ml_onnx".to_string(),
                    }));
                }
            }
        }

        if let Some(engine) = &self.ml_feature_engine {
            if self.ml_feature_max_file_size_bytes > 0 {
                if let Ok(meta) = std::fs::metadata(path) {
                    if meta.len() > self.ml_feature_max_file_size_bytes {
                        return Ok(None);
                    }
                }
            }

            if is_pe_file(contents) {
                let classification = engine.classify_file(path)?;
                if classification.is_malicious {
                    return Ok(Some(ScanFileResult {
                        is_threat: true,
                        threat_name: "Feature ML malware".to_string(),
                        severity: severity_for_confidence(classification.confidence),
                        detection_method: "ml_features".to_string(),
                    }));
                }
            }
        }

        Ok(None)
    }

    /// Check if file is an archive
    fn is_archive(&self, path: &PathBuf) -> bool {
        if let Some(ext) = path.extension() {
            let ext = ext.to_string_lossy().to_lowercase();
            matches!(ext.as_str(), "zip" | "tar" | "gz" | "7z" | "rar" | "bz2")
        } else {
            false
        }
    }

    /// Scan archive contents
    async fn scan_archive(
        &self,
        _path: &PathBuf,
        _options: &ScanOptions,
    ) -> Result<Option<ScanFileResult>> {
        // STUB — PRODUCTION-GAP, not production. Always returns None.
        // Even when ScanOptions.scan_archives is enabled, archive members are never
        // unpacked or scanned. Missing: archive extraction + recursive member scanning.
        Ok(None)
    }

    /// Handle a detection based on configured action
    async fn handle_detection(
        &self,
        path: &PathBuf,
        result: &ScanFileResult,
        action: &DetectionAction,
    ) {
        match action {
            DetectionAction::Alert => {
                // Just log - actual alerting handled by alert system
                info!(
                    "Alert: {} detected in {:?} ({})",
                    result.threat_name, path, result.severity
                );
            }
            DetectionAction::Quarantine => {
                info!("Quarantining: {:?}", path);
                if let Err(e) = self.quarantine_file(path).await {
                    error!("Failed to quarantine {:?}: {}", path, e);
                }
            }
            DetectionAction::Custom {
                action_name,
                params,
            } => {
                info!(
                    "Executing custom action '{}' with params: {:?}",
                    action_name, params
                );
                // STUB — PRODUCTION-GAP, not production. Custom detection actions are
                // logged only; they are never dispatched to the response executor.
            }
        }
    }

    /// Quarantine a file
    async fn quarantine_file(&self, path: &PathBuf) -> Result<()> {
        // Get quarantine directory
        let quarantine_dir = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("tamandua")
            .join("quarantine");

        tokio::fs::create_dir_all(&quarantine_dir).await?;

        // Generate unique quarantine name
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let quarantine_name = format!("{}_{}", uuid::Uuid::new_v4(), file_name);
        let quarantine_path = quarantine_dir.join(&quarantine_name);

        // Move file to quarantine
        tokio::fs::rename(path, &quarantine_path).await?;

        info!("Quarantined {:?} to {:?}", path, quarantine_path);
        Ok(())
    }

    /// Set process priority based on CPU priority setting
    fn set_process_priority(&self, priority: CpuPriority) {
        #[cfg(target_os = "windows")]
        {
            use windows::Win32::System::Threading::{
                GetCurrentProcess, SetPriorityClass, ABOVE_NORMAL_PRIORITY_CLASS,
                BELOW_NORMAL_PRIORITY_CLASS, NORMAL_PRIORITY_CLASS,
            };

            unsafe {
                let handle = GetCurrentProcess();
                let class = match priority {
                    CpuPriority::Low => BELOW_NORMAL_PRIORITY_CLASS,
                    CpuPriority::Normal => NORMAL_PRIORITY_CLASS,
                    CpuPriority::High => ABOVE_NORMAL_PRIORITY_CLASS,
                };
                let _ = SetPriorityClass(handle, class);
            }
        }

        #[cfg(target_os = "linux")]
        {
            use nix::sys::resource::{setpriority, Priority, Resource};
            let nice = priority.nice_value();
            let _ = unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, nice) };
        }

        #[cfg(target_os = "macos")]
        {
            let nice = priority.nice_value();
            let _ = unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, nice) };
        }
    }
}

impl Default for ScheduleExecutor {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of scanning a single file
#[derive(Debug)]
struct ScanFileResult {
    is_threat: bool,
    threat_name: String,
    severity: String,
    detection_method: String,
}

/// Calculate SHA256 hash of data
fn sha256_hash(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn is_pe_file(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A
}

fn severity_for_confidence(confidence: f32) -> String {
    if confidence >= 0.9 {
        "critical".to_string()
    } else if confidence >= 0.7 {
        "high".to_string()
    } else {
        "medium".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hash() {
        let hash = sha256_hash(b"test");
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_is_archive() {
        let executor = ScheduleExecutor::new();
        assert!(executor.is_archive(&PathBuf::from("test.zip")));
        assert!(executor.is_archive(&PathBuf::from("test.tar.gz")));
        assert!(!executor.is_archive(&PathBuf::from("test.exe")));
        assert!(!executor.is_archive(&PathBuf::from("test.txt")));
    }

    #[test]
    fn test_ml_helpers() {
        assert!(is_pe_file(b"MZfixture"));
        assert!(!is_pe_file(b"fixture"));
        assert_eq!(severity_for_confidence(0.95), "critical");
        assert_eq!(severity_for_confidence(0.75), "high");
        assert_eq!(severity_for_confidence(0.55), "medium");
    }
}
