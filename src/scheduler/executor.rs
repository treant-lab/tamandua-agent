//! Schedule execution engine

use super::schedule::{
    CpuPriority, DetectionAction, ScanOptions, Schedule, ScheduleId, ScheduleScanType,
};
use super::RunningSchedule;
use crate::analyzers::ml_local::LocalMLFeatureEngine;
use crate::analyzers::threat_intel::{IocType, ThreatIntelDb};
use crate::collectors::{
    Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent,
};
use crate::config::AgentConfig;
use anyhow::Result;
use chrono::Utc;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use walkdir::WalkDir;

const MAX_ARCHIVE_MEMBERS: usize = 512;
const MAX_ARCHIVE_MEMBER_SIZE_BYTES: u64 = 100 * 1024 * 1024;
const MAX_ARCHIVE_TOTAL_BYTES: u64 = 512 * 1024 * 1024;

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
    /// Lazily loaded YARA scanner used by scheduled scans.
    #[cfg(feature = "yara")]
    yara_scanner: tokio::sync::OnceCell<Option<Arc<crate::analyzers::yara::YaraScanner>>>,
    /// Local directory containing `.yar`/`.yara` files for scheduled scans.
    #[cfg(feature = "yara")]
    yara_rules_dir: Option<String>,
    /// Cached IOC database used for hash reputation during scheduled scans.
    ioc_db: tokio::sync::RwLock<Option<CachedIocDb>>,
    /// Local IOC list path installed by the model/rule updater.
    ioc_list_path: PathBuf,
    /// Optional telemetry sink for scheduled-scan detections.
    telemetry_tx: Option<mpsc::Sender<TelemetryEvent>>,
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
            #[cfg(feature = "yara")]
            yara_scanner: tokio::sync::OnceCell::new(),
            #[cfg(feature = "yara")]
            yara_rules_dir: None,
            ioc_db: tokio::sync::RwLock::new(None),
            ioc_list_path: default_ioc_list_path(),
            telemetry_tx: None,
        }
    }

    /// Attach a telemetry sink used to report scheduled-scan detections.
    pub fn with_telemetry_sender(mut self, telemetry_tx: mpsc::Sender<TelemetryEvent>) -> Self {
        self.telemetry_tx = Some(telemetry_tx);
        self
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

        #[cfg(feature = "yara")]
        if !config.offline_detection.yara_rules_dir.trim().is_empty() {
            executor.yara_rules_dir = Some(config.offline_detection.yara_rules_dir.clone());
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
                            schedule,
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
                confidence: None,
            });
        }

        // Read file for scanning
        let contents = tokio::fs::read(path).await?;

        if let Some(result) = self.scan_contents(&contents, path, true).await? {
            return Ok(result);
        }

        // Check archives if enabled
        if options.scan_archives && self.is_archive(path) {
            if let Some(result) = self.scan_archive(path, &contents).await? {
                return Ok(result);
            }
        }

        Ok(ScanFileResult {
            is_threat: false,
            threat_name: String::new(),
            severity: String::new(),
            detection_method: String::new(),
            confidence: None,
        })
    }

    async fn scan_contents(
        &self,
        contents: &[u8],
        path: &PathBuf,
        allow_ml: bool,
    ) -> Result<Option<ScanFileResult>> {
        // Calculate hash
        let hash = sha256_hash(&contents);

        if let Some(hash_match) = self.check_hash_reputation(&hash).await {
            return Ok(Some(ScanFileResult {
                is_threat: true,
                threat_name: hash_match.threat_name,
                severity: hash_match.severity,
                detection_method: "hash".to_string(),
                confidence: hash_match.confidence,
            }));
        }

        // YARA scan
        if let Some(result) = self.scan_with_yara(&contents, path).await? {
            return Ok(Some(result));
        }

        if allow_ml {
            if let Some(result) = self.scan_with_ml(&contents, path).await? {
                return Ok(Some(result));
            }
        }

        Ok(None)
    }

    /// Check hash against reputation database
    async fn check_hash_reputation(&self, hash: &str) -> Option<HashReputationMatch> {
        let db = self.get_ioc_database().await?;

        let matches = db.check(IocType::Sha256, hash).await;
        if matches.is_empty() {
            return None;
        }

        let best = matches
            .iter()
            .max_by(|left, right| {
                left.confidence
                    .partial_cmp(&right.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .cloned()?;

        let description = best.description.unwrap_or_default();
        let threat_name = if description.is_empty() {
            format!("Known malicious hash from {}", best.source)
        } else {
            format!("Known malicious hash from {}: {}", best.source, description)
        };

        Some(HashReputationMatch {
            threat_name,
            severity: severity_to_string(best.severity),
            confidence: Some(best.confidence),
        })
    }

    async fn get_ioc_database(&self) -> Option<Arc<ThreatIntelDb>> {
        let metadata = match tokio::fs::metadata(&self.ioc_list_path).await {
            Ok(metadata) if metadata.is_file() => metadata,
            _ => {
                let mut cached = self.ioc_db.write().await;
                if cached.is_some() {
                    info!(
                        path = %self.ioc_list_path.display(),
                        "Local IOC list disappeared; disabling scheduled scan hash reputation cache"
                    );
                    *cached = None;
                }
                return None;
            }
        };
        let modified = metadata.modified().ok();

        {
            let cached = self.ioc_db.read().await;
            if let Some(cached) = cached.as_ref() {
                if cached.modified == modified {
                    return Some(cached.db.clone());
                }
            }
        }

        let loaded = self.load_ioc_database(modified).await?;
        let db = loaded.db.clone();

        let mut cached = self.ioc_db.write().await;
        *cached = Some(loaded);

        Some(db)
    }

    async fn load_ioc_database(&self, modified: Option<SystemTime>) -> Option<CachedIocDb> {
        if !self.ioc_list_path.is_file() {
            info!(
                path = %self.ioc_list_path.display(),
                "No local IOC list found for scheduled scan hash reputation"
            );
            return None;
        }

        let json_data = match tokio::fs::read_to_string(&self.ioc_list_path).await {
            Ok(data) => data,
            Err(error) => {
                warn!(
                    error = %error,
                    path = %self.ioc_list_path.display(),
                    "Failed to read local IOC list for scheduled scans"
                );
                return None;
            }
        };

        let cache_path = default_ioc_cache_path();
        let db = Arc::new(ThreatIntelDb::new(cache_path));
        if let Err(error) = db.init().await {
            warn!(error = %error, "Failed to initialize scheduled scan IOC database");
        }

        match db.load_from_json(&json_data).await {
            Ok(count) => {
                info!(
                    count,
                    path = %self.ioc_list_path.display(),
                    "Loaded local IOC list for scheduled scan hash reputation"
                );
                Some(CachedIocDb { db, modified })
            }
            Err(error) => {
                warn!(
                    error = %error,
                    path = %self.ioc_list_path.display(),
                    "Failed to parse local IOC list for scheduled scans"
                );
                None
            }
        }
    }

    /// Scan with YARA rules
    async fn scan_with_yara(
        &self,
        contents: &[u8],
        _path: &PathBuf,
    ) -> Result<Option<ScanFileResult>> {
        #[cfg(feature = "yara")]
        {
            let scanner = self
                .yara_scanner
                .get_or_init(|| async { self.load_yara_scanner().await })
                .await;

            let Some(scanner) = scanner.as_ref() else {
                return Ok(None);
            };

            let matches = scanner.scan_bytes(contents).await?;
            if matches.is_empty() {
                return Ok(None);
            }

            let first_match = &matches[0];
            let threat_name = if matches.len() == 1 {
                format!("YARA rule match: {}", first_match.rule_name)
            } else {
                format!(
                    "YARA rule matches: {} (+{} more)",
                    first_match.rule_name,
                    matches.len() - 1
                )
            };

            return Ok(Some(ScanFileResult {
                is_threat: true,
                threat_name,
                severity: if matches.len() >= 2 {
                    "critical".to_string()
                } else {
                    "high".to_string()
                },
                detection_method: "yara".to_string(),
                confidence: Some(0.95),
            }));
        }

        #[cfg(not(feature = "yara"))]
        {
            let _ = contents;
        }

        Ok(None)
    }

    #[cfg(feature = "yara")]
    async fn load_yara_scanner(&self) -> Option<Arc<crate::analyzers::yara::YaraScanner>> {
        let Some(rules_dir) = self.yara_rules_dir.as_deref() else {
            return None;
        };

        let rule_files = load_yara_rule_files(rules_dir);
        if rule_files.is_empty() {
            info!(dir = %rules_dir, "No YARA rule files found for scheduled scans");
            return None;
        }

        let scanner = Arc::new(crate::analyzers::yara::YaraScanner::new());
        match scanner.load_rules(rule_files).await {
            Ok(count) => {
                info!(count, dir = %rules_dir, "Loaded YARA rules for scheduled scans");
                Some(scanner)
            }
            Err(error) => {
                warn!(error = %error, dir = %rules_dir, "Failed to load YARA rules for scheduled scans");
                None
            }
        }
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
                        confidence: Some(result.confidence),
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
                        confidence: Some(classification.confidence),
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
        path: &PathBuf,
        contents: &[u8],
    ) -> Result<Option<ScanFileResult>> {
        match archive_kind(path) {
            Some(ArchiveKind::Zip) => self.scan_zip_archive(path, contents).await,
            Some(ArchiveKind::Tar) => self.scan_tar_archive(path, contents).await,
            Some(ArchiveKind::TarGz) => self.scan_targz_archive(path, contents).await,
            Some(ArchiveKind::Gz) => self.scan_gzip_member(path, contents).await,
            Some(ArchiveKind::Unsupported(kind)) => {
                debug!(
                    path = %path.display(),
                    kind,
                    "Scheduled scan archive format is recognized but not yet supported"
                );
                Ok(None)
            }
            None => Ok(None),
        }
    }

    async fn scan_zip_archive(
        &self,
        path: &PathBuf,
        contents: &[u8],
    ) -> Result<Option<ScanFileResult>> {
        let members = collect_zip_members(path, contents)?;
        self.scan_archive_members(members).await
    }

    async fn scan_tar_archive(
        &self,
        path: &PathBuf,
        contents: &[u8],
    ) -> Result<Option<ScanFileResult>> {
        let members = collect_tar_members(path, Cursor::new(contents))?;
        self.scan_archive_members(members).await
    }

    async fn scan_targz_archive(
        &self,
        path: &PathBuf,
        contents: &[u8],
    ) -> Result<Option<ScanFileResult>> {
        let decoder = flate2::read::GzDecoder::new(Cursor::new(contents));
        let members = collect_tar_members(path, decoder)?;
        self.scan_archive_members(members).await
    }

    async fn scan_gzip_member(
        &self,
        path: &PathBuf,
        contents: &[u8],
    ) -> Result<Option<ScanFileResult>> {
        let mut decoder = flate2::read::GzDecoder::new(Cursor::new(contents));
        let mut member_contents = Vec::new();
        decoder
            .by_ref()
            .take(MAX_ARCHIVE_MEMBER_SIZE_BYTES + 1)
            .read_to_end(&mut member_contents)?;
        if member_contents.len() as u64 > MAX_ARCHIVE_MEMBER_SIZE_BYTES {
            debug!(archive = %path.display(), "Skipping oversized GZIP member during scheduled scan");
            return Ok(None);
        }

        let member_name = path
            .file_stem()
            .map(|stem| sanitize_archive_member_label(&stem.to_string_lossy()))
            .unwrap_or_else(|| "gzip-member".to_string());
        let label = archive_member_label(path, &member_name);
        self.scan_archive_members(vec![(label, member_contents)])
            .await
    }

    async fn scan_archive_members(
        &self,
        members: Vec<(String, Vec<u8>)>,
    ) -> Result<Option<ScanFileResult>> {
        for (label, member_contents) in members {
            if let Some(result) = self.scan_archive_member(&member_contents, &label).await? {
                return Ok(Some(result));
            }
        }

        Ok(None)
    }

    async fn scan_archive_member(
        &self,
        contents: &[u8],
        label: &str,
    ) -> Result<Option<ScanFileResult>> {
        let virtual_path = PathBuf::from(label);
        let Some(mut result) = self.scan_contents(contents, &virtual_path, false).await? else {
            return Ok(None);
        };

        result.threat_name = format!("{} in {}", result.threat_name, label);
        Ok(Some(result))
    }

    /// Handle a detection based on configured action
    async fn handle_detection(
        &self,
        path: &PathBuf,
        result: &ScanFileResult,
        schedule: &Schedule,
        action: &DetectionAction,
    ) {
        self.emit_detection_event(path, result, schedule).await;

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

    async fn emit_detection_event(
        &self,
        path: &PathBuf,
        result: &ScanFileResult,
        schedule: &Schedule,
    ) {
        let Some(tx) = &self.telemetry_tx else {
            return;
        };

        let detection_source = if result.detection_method.starts_with("ml") {
            "ml"
        } else {
            result.detection_method.as_str()
        };

        let mut event = TelemetryEvent::new(
            EventType::MalwareDetection,
            severity_from_string(&result.severity),
            EventPayload::Custom(serde_json::json!({
                "source": "scheduled_scan",
                "detection_source": detection_source,
                "path": path.display().to_string(),
                "file_path": path.display().to_string(),
                "threat_name": result.threat_name,
                "severity": result.severity,
                "detection_method": result.detection_method,
                "confidence": result.confidence,
                "schedule_id": schedule.id.to_string(),
                "schedule_name": schedule.name,
                "scan_type": format!("{:?}", schedule.config.scan_type),
            })),
        );

        event
            .metadata
            .insert("source".to_string(), "scheduled_scan".to_string());
        event
            .metadata
            .insert("provider".to_string(), "tamandua_agent".to_string());
        event
            .metadata
            .insert("detection_source".to_string(), detection_source.to_string());
        if detection_source == "ml" {
            event
                .metadata
                .insert("ml_source".to_string(), result.detection_method.clone());
        }

        event.add_detection(Detection {
            detection_type: detection_type_for_method(&result.detection_method),
            rule_name: format!(
                "SCHEDULED_SCAN_{}",
                result.detection_method.to_ascii_uppercase()
            ),
            confidence: result.confidence.unwrap_or(1.0),
            description: format!(
                "Scheduled scan '{}' detected {} in {}",
                schedule.name,
                result.threat_name,
                path.display()
            ),
            mitre_tactics: vec!["execution".to_string()],
            mitre_techniques: vec!["T1204".to_string()],
        });

        if let Err(error) = tx.send(event).await {
            debug!(error = %error, "Scheduled scan detection telemetry receiver is closed");
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
    confidence: Option<f32>,
}

#[derive(Debug)]
struct HashReputationMatch {
    threat_name: String,
    severity: String,
    confidence: Option<f32>,
}

#[derive(Clone)]
struct CachedIocDb {
    db: Arc<ThreatIntelDb>,
    modified: Option<SystemTime>,
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

fn severity_from_string(severity: &str) -> Severity {
    match severity {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

fn severity_to_string(severity: Severity) -> String {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
    .to_string()
}

fn detection_type_for_method(method: &str) -> DetectionType {
    match method {
        "ml_onnx" | "ml_features" => DetectionType::Ml,
        "hash" => DetectionType::ThreatIntel,
        "yara" => DetectionType::Yara,
        _ => DetectionType::Malware,
    }
}

fn default_ioc_list_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"C:\ProgramData\Tamandua\iocs.json")
    }
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/var/lib/tamandua/iocs.json")
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/Tamandua/iocs.json")
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        PathBuf::from("./iocs.json")
    }
}

fn default_ioc_cache_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"C:\ProgramData\Tamandua\cache\scheduled_scan_iocs.db")
    }
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/var/lib/tamandua/cache/scheduled_scan_iocs.db")
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/Tamandua/cache/scheduled_scan_iocs.db")
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        PathBuf::from("./cache/scheduled_scan_iocs.db")
    }
}

#[derive(Debug, Clone, Copy)]
enum ArchiveKind {
    Zip,
    Tar,
    TarGz,
    Gz,
    Unsupported(&'static str),
}

fn archive_kind(path: &PathBuf) -> Option<ArchiveKind> {
    let file_name = path.file_name()?.to_string_lossy().to_lowercase();
    if file_name.ends_with(".tar.gz") || file_name.ends_with(".tgz") {
        return Some(ArchiveKind::TarGz);
    }

    match path
        .extension()
        .map(|ext| ext.to_string_lossy().to_lowercase())
        .as_deref()
    {
        Some("zip") => Some(ArchiveKind::Zip),
        Some("tar") => Some(ArchiveKind::Tar),
        Some("gz") => Some(ArchiveKind::Gz),
        Some("7z") => Some(ArchiveKind::Unsupported("7z")),
        Some("rar") => Some(ArchiveKind::Unsupported("rar")),
        Some("bz2") => Some(ArchiveKind::Unsupported("bz2")),
        _ => None,
    }
}

fn archive_member_label(archive_path: &PathBuf, member_name: &str) -> String {
    format!("{}::{}", archive_path.display(), member_name)
}

fn sanitize_archive_member_label(member_name: &str) -> String {
    let sanitized = member_name
        .replace('\\', "/")
        .split('/')
        .filter(|part| {
            !part.is_empty()
                && *part != "."
                && *part != ".."
                && !part.contains(':')
                && !part.starts_with('\0')
        })
        .collect::<Vec<_>>()
        .join("/");

    if sanitized.is_empty() {
        "archive-member".to_string()
    } else {
        sanitized
            .chars()
            .map(|ch| if ch.is_control() { '_' } else { ch })
            .collect()
    }
}

fn collect_zip_members(path: &PathBuf, contents: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let reader = Cursor::new(contents);
    let mut archive = zip::ZipArchive::new(reader)?;
    let mut total_bytes = 0u64;
    let mut members = Vec::new();

    for index in 0..archive.len().min(MAX_ARCHIVE_MEMBERS) {
        let mut member = archive.by_index(index)?;
        if !member.is_file() {
            continue;
        }

        let member_name = sanitize_archive_member_label(member.name());
        if member.size() > MAX_ARCHIVE_MEMBER_SIZE_BYTES {
            debug!(
                archive = %path.display(),
                member = %member_name,
                size = member.size(),
                "Skipping oversized ZIP member during scheduled scan"
            );
            continue;
        }

        let mut member_contents = Vec::new();
        member
            .by_ref()
            .take(MAX_ARCHIVE_MEMBER_SIZE_BYTES + 1)
            .read_to_end(&mut member_contents)?;
        if member_contents.len() as u64 > MAX_ARCHIVE_MEMBER_SIZE_BYTES {
            continue;
        }

        total_bytes = total_bytes.saturating_add(member_contents.len() as u64);
        if total_bytes > MAX_ARCHIVE_TOTAL_BYTES {
            debug!(
                archive = %path.display(),
                "Stopping ZIP scan after decompressed byte limit"
            );
            break;
        }

        members.push((archive_member_label(path, &member_name), member_contents));
    }

    Ok(members)
}

fn collect_tar_members<R: Read>(path: &PathBuf, reader: R) -> Result<Vec<(String, Vec<u8>)>> {
    let mut archive = tar::Archive::new(reader);
    let mut total_bytes = 0u64;
    let mut members_scanned = 0usize;
    let mut members = Vec::new();

    for entry_result in archive.entries()? {
        if members_scanned >= MAX_ARCHIVE_MEMBERS {
            break;
        }

        let mut entry = entry_result?;
        if !entry.header().entry_type().is_file() {
            continue;
        }

        let size = entry.header().size().unwrap_or(0);
        let member_name = entry
            .path()
            .ok()
            .map(|p| sanitize_archive_member_label(&p.to_string_lossy()))
            .unwrap_or_else(|| format!("member-{members_scanned}"));

        if size > MAX_ARCHIVE_MEMBER_SIZE_BYTES {
            debug!(
                archive = %path.display(),
                member = %member_name,
                size,
                "Skipping oversized TAR member during scheduled scan"
            );
            continue;
        }

        let mut member_contents = Vec::new();
        entry
            .by_ref()
            .take(MAX_ARCHIVE_MEMBER_SIZE_BYTES + 1)
            .read_to_end(&mut member_contents)?;
        if member_contents.len() as u64 > MAX_ARCHIVE_MEMBER_SIZE_BYTES {
            continue;
        }

        members_scanned += 1;
        total_bytes = total_bytes.saturating_add(member_contents.len() as u64);
        if total_bytes > MAX_ARCHIVE_TOTAL_BYTES {
            debug!(
                archive = %path.display(),
                "Stopping TAR scan after decompressed byte limit"
            );
            break;
        }

        members.push((archive_member_label(path, &member_name), member_contents));
    }

    Ok(members)
}

#[cfg(feature = "yara")]
fn load_yara_rule_files(rules_dir: &str) -> Vec<(String, String)> {
    let rules_path = std::path::Path::new(rules_dir);
    if !rules_path.is_dir() {
        info!(dir = %rules_dir, "YARA rules directory does not exist for scheduled scans");
        return Vec::new();
    }

    let mut rule_files = Vec::new();
    let Ok(entries) = std::fs::read_dir(rules_path) else {
        warn!(dir = %rules_dir, "Failed to read YARA rules directory for scheduled scans");
        return rule_files;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if ext != "yar" && ext != "yara" {
            continue;
        }

        match std::fs::read_to_string(&path) {
            Ok(content) => {
                let name = path
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| path.display().to_string());
                rule_files.push((name, content));
            }
            Err(error) => {
                warn!(
                    error = %error,
                    path = %path.display(),
                    "Failed to read YARA rule file for scheduled scans"
                );
            }
        }
    }

    rule_files
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
