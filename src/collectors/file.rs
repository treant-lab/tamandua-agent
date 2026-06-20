//! File event collector
//!
//! Monitors file system events using platform-specific APIs.
//!
//! PID correlation:
//! - Linux: fanotify with FAN_REPORT_PID (preferred), fallback to /proc scanning and inotify
//! - Windows: GetProcessImageFileName via handle enumeration
//! - macOS: lsof command
//!
//! On Linux, fanotify provides better PID correlation than inotify because:
//! 1. Events include the PID directly (no need to scan /proc)
//! 2. More accurate - events are delivered synchronously
//! 3. Can monitor entire mount points efficiently
//!
//! Pre-execution ML scanning:
//! When the `onnx` feature is enabled, new/modified executables are scanned
//! using the ONNX ML model before they can execute.
//!
//! Pre-execution blocking (Linux only):
//! When `pre_execution_blocking.enabled` is true, the fanotify collector
//! uses `FAN_OPEN_EXEC_PERM` permission events with `FAN_CLASS_PRE_CONTENT`
//! to intercept file executions. The `PreExecutionGate` evaluates each
//! execution attempt via the ONNX scanner and writes `FAN_DENY` for files
//! classified as malicious with high confidence. Requires `CAP_SYS_ADMIN`.
//! Falls back to notification-only mode if permission initialization fails.
//! All errors and timeouts default to ALLOW (fail-open design).
//!
//! Feature-based ML scanning:
//! The `ml-local` `LocalMLFeatureEngine` extracts 16
//! structural features from PE files and runs a lightweight ONNX model for
//! fast classification. This runs independently of the image-based scanner.

// File collector. Scaffolded fields and helper functions retained.
#![allow(dead_code, unused_variables)]

use super::{
    Detection, DetectionType, EventPayload, EventType, FileEvent, HoneyfileEvent, Severity,
    TelemetryEvent,
};
use crate::analyzers;
use crate::analyzers::ml_local::LocalMLFeatureEngine;
use crate::config::AgentConfig;
use anyhow::Result;
use notify::{Event as NotifyEvent, EventKind, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

#[cfg(feature = "onnx")]
use crate::analyzers::onnx_scanner::{is_executable_file, OnnxScanner, OnnxScannerConfig};

/// File collector
pub struct FileCollector {
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    /// ONNX ML scanner for pre-execution malware detection
    #[cfg(feature = "onnx")]
    onnx_scanner: Option<Arc<OnnxScanner>>,
    /// Feature-based ML engine for lightweight PE classification.
    /// Available regardless of the `onnx` feature flag.
    ml_feature_engine: Option<Arc<LocalMLFeatureEngine>>,
}

impl FileCollector {
    /// Create a new file collector
    /// On Linux, tries fanotify first (better PID correlation), falls back to inotify
    pub fn new(config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(1000);

        // Initialize ONNX scanner if feature is enabled.
        // Skip entirely when skip_expensive_analysis is set (lightweight/balanced
        // profiles) — model loading is CPU-intensive and would cause a startup spike.
        #[cfg(feature = "onnx")]
        let onnx_scanner = if config.collector_tuning.skip_expensive_analysis {
            debug!("ONNX ML scanner skipped (skip_expensive_analysis=true)");
            None
        } else {
            let scanner_config = OnnxScannerConfig {
                confidence_threshold: config.ml_confidence_threshold.unwrap_or(0.7),
                inference_timeout_secs: config.ml_inference_timeout_secs,
                ..Default::default()
            };
            let scanner = OnnxScanner::new(scanner_config);
            if scanner.is_operational() {
                info!("ONNX ML scanner initialized for pre-execution scanning");
                Some(Arc::new(scanner))
            } else {
                warn!("ONNX ML scanner not available - pre-execution scanning disabled");
                None
            }
        };

        // Initialize the feature-based ML engine (works with or without `onnx` feature).
        let ml_feature_engine = if config.ml_local.enabled {
            let model_path = if config.ml_local.model_path.is_empty() {
                // Use model_path from top-level config if ml_local.model_path is empty
                config
                    .ml_model_path
                    .as_ref()
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(LocalMLFeatureEngine::default_model_path)
            } else {
                std::path::PathBuf::from(&config.ml_local.model_path)
            };
            let engine = LocalMLFeatureEngine::new(
                model_path,
                config.ml_local.confidence_threshold,
                config.ml_local.enabled,
            );
            if engine.is_operational() {
                info!("Feature-based ML engine initialized for file scanning");
                Some(Arc::new(engine))
            } else {
                debug!("Feature-based ML engine not operational (model not found or disabled)");
                None
            }
        } else {
            debug!("Feature-based ML engine disabled by configuration");
            None
        };

        // Start file watcher in background
        let config_clone = config.clone();
        #[cfg(feature = "onnx")]
        let scanner_clone = onnx_scanner.clone();
        let feature_engine_clone = ml_feature_engine.clone();

        std::thread::spawn(move || {
            // On Linux, try fanotify first for better PID correlation.
            // When ONNX is enabled AND pre-execution blocking is configured,
            // fanotify is initialized with FAN_CLASS_PRE_CONTENT for permission
            // events. The ONNX scanner is passed to the fanotify monitor for
            // pre-execution ML scanning. If fanotify fails, fall back to
            // notify-based watcher with ML integration.
            #[cfg(all(target_os = "linux", not(feature = "onnx")))]
            {
                if let Err(e) = fanotify::start_fanotify_monitor(tx.clone(), config_clone.clone()) {
                    warn!(error = %e, "Fanotify not available, falling back to inotify");
                    if let Err(e) = Self::watch_files(tx, config_clone, feature_engine_clone) {
                        error!(error = %e, "File watcher error");
                    }
                }
                return;
            }

            #[cfg(all(target_os = "linux", feature = "onnx"))]
            {
                // When pre-execution blocking is enabled, prefer fanotify with
                // permission events + ML scanning. Falls back to notify-based
                // watcher if fanotify is unavailable.
                if config_clone.pre_execution_blocking.enabled {
                    info!("Pre-execution blocking enabled, using fanotify with ML scanner");
                    if let Err(e) = fanotify::start_fanotify_monitor(
                        tx.clone(),
                        config_clone.clone(),
                        scanner_clone.clone(),
                    ) {
                        warn!(error = %e, "Fanotify not available, falling back to notify watcher");
                        if let Err(e) =
                            Self::watch_files(tx, config_clone, scanner_clone, feature_engine_clone)
                        {
                            error!(error = %e, "File watcher error");
                        }
                    }
                } else {
                    // No pre-execution blocking: use notify-based watcher for ML
                    info!("Using notify-based file watcher for ML integration");
                    if let Err(e) =
                        Self::watch_files(tx, config_clone, scanner_clone, feature_engine_clone)
                    {
                        error!(error = %e, "File watcher error");
                    }
                }
                return;
            }

            // macOS uses FSEvents for efficient file monitoring
            #[cfg(target_os = "macos")]
            {
                info!("Starting macOS FSEvents-based file monitoring");
                #[cfg(feature = "onnx")]
                if let Err(e) = fsevents::start_fsevents_monitor(
                    tx,
                    config_clone,
                    scanner_clone,
                    feature_engine_clone,
                ) {
                    error!(error = %e, "FSEvents monitor failed");
                }
                #[cfg(not(feature = "onnx"))]
                if let Err(e) =
                    fsevents::start_fsevents_monitor(tx, config_clone, None, feature_engine_clone)
                {
                    error!(error = %e, "FSEvents monitor failed");
                }
            }

            // Other non-Linux platforms use notify-style watcher
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                #[cfg(feature = "onnx")]
                if let Err(e) =
                    Self::watch_files(tx, config_clone, scanner_clone, feature_engine_clone)
                {
                    error!(error = %e, "File watcher error");
                }
                #[cfg(not(feature = "onnx"))]
                if let Err(e) = Self::watch_files(tx, config_clone, feature_engine_clone) {
                    error!(error = %e, "File watcher error");
                }
            }
        });

        Self {
            config: config.clone(),
            event_rx: rx,
            #[cfg(feature = "onnx")]
            onnx_scanner,
            ml_feature_engine,
        }
    }

    #[cfg(not(feature = "onnx"))]
    fn watch_files(
        tx: mpsc::Sender<TelemetryEvent>,
        config: AgentConfig,
        feature_engine: Option<Arc<LocalMLFeatureEngine>>,
    ) -> Result<()> {
        Self::watch_files_impl(tx, config, None, feature_engine)
    }

    #[cfg(feature = "onnx")]
    fn watch_files(
        tx: mpsc::Sender<TelemetryEvent>,
        config: AgentConfig,
        scanner: Option<Arc<OnnxScanner>>,
        feature_engine: Option<Arc<LocalMLFeatureEngine>>,
    ) -> Result<()> {
        Self::watch_files_impl(tx, config, scanner, feature_engine)
    }

    fn watch_files_impl(
        tx: mpsc::Sender<TelemetryEvent>,
        config: AgentConfig,
        #[cfg(feature = "onnx")] scanner: Option<Arc<OnnxScanner>>,
        #[cfg(not(feature = "onnx"))] _scanner: Option<()>,
        feature_engine: Option<Arc<LocalMLFeatureEngine>>,
    ) -> Result<()> {
        let (notify_tx, notify_rx) = std::sync::mpsc::channel();

        let mut watcher = notify::recommended_watcher(move |res: notify::Result<NotifyEvent>| {
            if let Ok(event) = res {
                let _ = notify_tx.send(event);
            }
        })?;

        // Watch common directories
        let watch_paths = Self::get_watch_paths(&config);
        for path in &watch_paths {
            if Path::new(path).exists() {
                if let Err(e) = watcher.watch(Path::new(path), RecursiveMode::Recursive) {
                    warn!(path = %path, error = %e, "Failed to watch path");
                }
            }
        }

        // Watch honeyfile directories
        for path in &config.honeyfile_paths {
            if Path::new(path).exists() {
                if let Err(e) = watcher.watch(Path::new(path), RecursiveMode::NonRecursive) {
                    warn!(path = %path, error = %e, "Failed to watch honeyfile path");
                }
            }
        }

        debug!(paths = ?watch_paths, "File watcher started");

        // Process events
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        for event in notify_rx {
            for path in &event.paths {
                let path_str = path.to_string_lossy().to_string();

                // Check if excluded
                if config.excluded_paths.iter().any(|p| path_str.contains(p)) {
                    continue;
                }

                // Check if honeyfile
                if config.honeyfile_paths.iter().any(|p| path_str.contains(p)) {
                    if let Some(event) =
                        runtime.block_on(Self::create_honeyfile_event(&event, path, &config))
                    {
                        if tx.blocking_send(event).is_err() {
                            return Ok(());
                        }
                    }
                    continue;
                }

                // Check file pattern match
                if !Self::matches_pattern(path, &config.monitored_file_patterns) {
                    continue;
                }

                #[cfg(feature = "onnx")]
                let mut telemetry_event = runtime.block_on(Self::create_file_event_with_ml(
                    &event,
                    path,
                    &config,
                    scanner.as_ref(),
                ));
                #[cfg(not(feature = "onnx"))]
                let mut telemetry_event =
                    runtime.block_on(Self::create_file_event(&event, path, &config));

                // Enrich with feature-based ML classification (if engine available).
                if let (Some(ref mut te), Some(ref engine)) =
                    (&mut telemetry_event, &feature_engine)
                {
                    Self::enrich_event_with_feature_ml(te, path, &config, engine);
                }

                if let Some(telemetry_event) = telemetry_event {
                    if tx.blocking_send(telemetry_event).is_err() {
                        return Ok(());
                    }
                }
            }
        }

        Ok(())
    }

    fn get_watch_paths(config: &AgentConfig) -> Vec<String> {
        #[cfg(target_os = "windows")]
        {
            let mut scoped_temp_paths = Vec::new();
            for key in ["TEMP", "TMP"] {
                if let Ok(path) = std::env::var(key) {
                    if !path.trim().is_empty() && !scoped_temp_paths.contains(&path) {
                        scoped_temp_paths.push(path);
                    }
                }
            }
            if let Ok(system_root) = std::env::var("SystemRoot") {
                let system_temp = format!("{}\\Temp", system_root.trim_end_matches(['\\', '/']));
                if !scoped_temp_paths.contains(&system_temp) {
                    scoped_temp_paths.push(system_temp);
                }
            }
            if scoped_temp_paths.is_empty() {
                scoped_temp_paths.push("C:\\Windows\\Temp".to_string());
            }

            if config.performance_profile == crate::config::PerformanceProfile::Lightweight {
                // In lightweight mode, avoid recursive watching of C:\Users and C:\ProgramData
                // as these can generate massive event volume (browser cache, logs, etc.)
                // causing high CPU especially when running as Admin. Use the actual
                // system temp roots instead of assuming Windows lives on C:.
                return scoped_temp_paths;
            }

            let mut paths = vec!["C:\\Users".to_string(), "C:\\ProgramData".to_string()];
            paths.extend(scoped_temp_paths);
            return paths;
        }

        #[cfg(target_os = "linux")]
        {
            if config.performance_profile == crate::config::PerformanceProfile::Lightweight {
                return vec!["/tmp".to_string(), "/var/tmp".to_string()];
            }

            return vec![
                "/home".to_string(),
                "/tmp".to_string(),
                "/var/tmp".to_string(),
                "/opt".to_string(),
            ];
        }

        #[cfg(target_os = "macos")]
        {
            if config.performance_profile == crate::config::PerformanceProfile::Lightweight {
                return vec!["/tmp".to_string()];
            }

            return vec![
                "/Users".to_string(),
                "/tmp".to_string(),
                "/Applications".to_string(),
            ];
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            return vec!["/tmp".to_string()];
        }
    }

    fn matches_pattern(path: &Path, patterns: &[String]) -> bool {
        if patterns.is_empty() {
            return true;
        }

        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        patterns.iter().any(|pattern| {
            let pattern = pattern.to_lowercase();
            if pattern.starts_with('*') {
                filename.ends_with(&pattern[1..])
            } else if pattern.ends_with('*') {
                filename.starts_with(&pattern[..pattern.len() - 1])
            } else {
                filename == pattern
            }
        })
    }

    fn is_common_browser_cache_path(path: &str) -> bool {
        let normalized = path.replace('\\', "/").to_lowercase();

        const SENSITIVE_BROWSER_FILES: &[&str] = &[
            "/login data",
            "/logins.json",
            "/key4.db",
            "/cert9.db",
            "/cookies",
        ];

        if SENSITIVE_BROWSER_FILES
            .iter()
            .any(|marker| normalized.ends_with(marker))
        {
            return false;
        }

        const CACHE_MARKERS: &[&str] = &[
            "/cache/",
            "/cache2/",
            "/code cache/",
            "/gpucache/",
            "/gpu cache/",
            "/shadercache/",
            "/grshadercache/",
            "/dawncache/",
            "/startupcache/",
            "/cachestorage/",
            "/service worker/cache",
            "/network/cache/",
            "/com.apple.safari/",
            "/safari/fscacheddata/",
            "/safari/favicon cache/",
        ];

        const PROFILE_CHURN_MARKERS: &[&str] = &[
            "/cookies-journal",
            "/network persistent state",
            "/secure preferences",
            "/preferences",
            "/reporting and nel-journal",
            "/history-journal",
            "/favicons-journal",
            "/top sites-journal",
            "/visited links",
            "/session storage/",
            "/local storage/",
            "/indexeddb/",
            "/shared_proto_db/",
            "/transportsecurity",
        ];

        let is_profile_churn = CACHE_MARKERS
            .iter()
            .chain(PROFILE_CHURN_MARKERS.iter())
            .any(|marker| normalized.contains(marker));

        if !is_profile_churn {
            return false;
        }

        const BROWSER_PROFILE_MARKERS: &[&str] = &[
            "/google/chrome/",
            "/brave software/",
            "/bravesoftware/",
            "/microsoft/edge/",
            "/mozilla/firefox/",
            "/firefox/profiles/",
            "/library/caches/firefox/",
            "/library/caches/com.apple.safari/",
            "/library/safari/",
            "/library/application support/google/chrome/",
            "/library/application support/brave software/",
            "/library/application support/microsoft edge/",
            "/.mozilla/firefox/",
            "/.cache/google-chrome/",
            "/.cache/chromium/",
            "/.cache/brave/",
            "/.cache/mozilla/firefox/",
            "/.config/google-chrome/",
            "/.config/chromium/",
            "/.config/brave-browser/",
        ];

        BROWSER_PROFILE_MARKERS
            .iter()
            .any(|marker| normalized.contains(marker))
    }

    fn browser_cache_event_severity(path: &str) -> Severity {
        if Self::is_common_browser_cache_path(path) {
            Severity::Low
        } else {
            Severity::Info
        }
    }

    fn annotate_browser_cache_event(event: &mut TelemetryEvent, path: &str) {
        if Self::is_common_browser_cache_path(path) {
            event
                .metadata
                .insert("browser_cache".to_string(), "true".to_string());
        }
    }

    async fn create_file_event(
        notify_event: &NotifyEvent,
        path: &Path,
        config: &AgentConfig,
    ) -> Option<TelemetryEvent> {
        let (event_type, operation) = match &notify_event.kind {
            EventKind::Create(_) => (EventType::FileCreate, "create"),
            EventKind::Modify(_) => (EventType::FileModify, "modify"),
            EventKind::Remove(_) => (EventType::FileDelete, "delete"),
            _ => return None,
        };

        let path_str = path.to_string_lossy().to_string();
        let is_browser_cache = Self::is_common_browser_cache_path(&path_str);
        let skip_expensive = config.collector_tuning.skip_expensive_analysis;

        // Get file info.
        // In lightweight mode, skip SHA256 + entropy computation and process
        // enumeration.  These are extremely expensive per-event operations
        // (hash reads entire file; find_process enumerates all PIDs + modules).
        let (sha256, entropy, size) = if skip_expensive {
            let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            (Vec::new(), 0.0, size)
        } else if path.exists() {
            match analyzers::hash_file(&path_str).await {
                Ok((hash, ent)) => {
                    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
                    (hash, ent, size)
                }
                Err(_) => (Vec::new(), 0.0, 0),
            }
        } else {
            (Vec::new(), 0.0, 0)
        };

        let file_type = Self::detect_file_type(path);

        // find_process_for_file is the HEAVIEST per-event operation on Windows:
        // it calls EnumProcesses -> OpenProcess -> EnumProcessModules for every PID,
        // producing ~15,000 kernel calls per file event.
        //
        // Optimization:
        // - Windows: Only perform this in Aggressive mode. In Balanced/Lightweight,
        //   we rely on ETW (Kernel-File) for efficient PID correlation.
        // - Linux/macOS: Cheaper implementation or uses different mechanisms.
        let perform_pid_lookup = if cfg!(target_os = "windows") {
            !skip_expensive
                && config.performance_profile == crate::config::PerformanceProfile::Aggressive
        } else {
            !skip_expensive
        };

        let (pid, process_name, _process_path, _process_sha256) = if !perform_pid_lookup {
            (0, String::new(), None, None)
        } else if let Some((p, name, path_str)) = Self::find_process_for_file(path) {
            let sha256 = if !path_str.is_empty() {
                analyzers::hash_file(&path_str)
                    .await
                    .map(|(hash, _)| hash)
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            (p, name, Some(path_str), Some(sha256))
        } else {
            (0, String::new(), None, None)
        };

        let mut event = TelemetryEvent::new(
            event_type,
            Self::browser_cache_event_severity(&path_str),
            EventPayload::File(FileEvent {
                path: path_str,
                old_path: None,
                operation: operation.to_string(),
                pid,
                process_name,
                sha256,
                size,
                entropy,
                file_type,
            }),
        );
        Self::annotate_browser_cache_event(&mut event, path.to_string_lossy().as_ref());

        // Check entropy (skip in lightweight — not computed)
        if !is_browser_cache
            && !skip_expensive
            && config.entropy_check_enabled
            && entropy > config.entropy_threshold
        {
            event.add_detection(Detection {
                detection_type: DetectionType::Entropy,
                rule_name: "high_entropy_file".to_string(),
                confidence: 0.7,
                description: format!("High entropy file detected: {:.2}", entropy),
                mitre_tactics: vec!["defense-evasion".to_string()],
                mitre_techniques: vec!["T1027".to_string()],
            });
            event.severity = Severity::Medium;
        }

        Some(event)
    }

    /// Create a file event with ML-based malware scanning (ONNX feature)
    ///
    /// This function extends `create_file_event` with pre-execution ML scanning
    /// for executable files. If the ML model detects malware, a detection is
    /// added to the event with the malware family and confidence score.
    #[cfg(feature = "onnx")]
    async fn create_file_event_with_ml(
        notify_event: &NotifyEvent,
        path: &Path,
        config: &AgentConfig,
        scanner: Option<&Arc<OnnxScanner>>,
    ) -> Option<TelemetryEvent> {
        let (event_type, operation) = match &notify_event.kind {
            EventKind::Create(_) => (EventType::FileCreate, "create"),
            EventKind::Modify(_) => (EventType::FileModify, "modify"),
            EventKind::Remove(_) => (EventType::FileDelete, "delete"),
            _ => return None,
        };

        let path_str = path.to_string_lossy().to_string();
        let is_browser_cache = Self::is_common_browser_cache_path(&path_str);
        let skip_expensive = config.collector_tuning.skip_expensive_analysis;

        // Get file info — in lightweight mode skip hash/entropy/ML entirely
        let (sha256, entropy, size, file_data) = if skip_expensive {
            let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            (Vec::new(), 0.0, size, None)
        } else if path.exists() {
            match tokio::fs::read(path).await {
                Ok(data) => {
                    let hash = {
                        use sha2::{Digest, Sha256};
                        Sha256::digest(&data).to_vec()
                    };
                    let ent = analyzers::calculate_entropy(&data);
                    let size = data.len() as u64;
                    (hash, ent, size, Some(data))
                }
                Err(_) => (Vec::new(), 0.0, 0, None),
            }
        } else {
            (Vec::new(), 0.0, 0, None)
        };

        let file_type = Self::detect_file_type(path);

        // Skip find_process_for_file in lightweight mode (see create_file_event)
        let (pid, process_name, _process_path, _process_sha256) = if skip_expensive {
            (0, String::new(), None, None)
        } else if let Some((p, name, ppath)) = Self::find_process_for_file(path) {
            let psha256 = if !ppath.is_empty() {
                analyzers::hash_file(&ppath)
                    .await
                    .map(|(hash, _)| hash)
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            (p, name, Some(ppath), Some(psha256))
        } else {
            (0, String::new(), None, None)
        };

        let mut event = TelemetryEvent::new(
            event_type,
            Self::browser_cache_event_severity(&path_str),
            EventPayload::File(FileEvent {
                path: path_str.clone(),
                old_path: None,
                operation: operation.to_string(),
                pid,
                process_name: process_name.clone(),
                sha256: sha256.clone(),
                size,
                entropy,
                file_type: file_type.clone(),
            }),
        );
        Self::annotate_browser_cache_event(&mut event, &path_str);

        // Check entropy (skip in lightweight — not computed)
        if !is_browser_cache
            && !skip_expensive
            && config.entropy_check_enabled
            && entropy > config.entropy_threshold
        {
            event.add_detection(Detection {
                detection_type: DetectionType::Entropy,
                rule_name: "high_entropy_file".to_string(),
                confidence: 0.7,
                description: format!("High entropy file detected: {:.2}", entropy),
                mitre_tactics: vec!["defense-evasion".to_string()],
                mitre_techniques: vec!["T1027".to_string()],
            });
            event.severity = Severity::Medium;
        }

        // Perform ML scanning for executable files
        if let (Some(scanner), Some(data)) = (scanner, file_data.as_ref()) {
            // Only scan executable files for performance
            if is_executable_file(path, Some(data)) {
                debug!(
                    path = %path_str,
                    size = size,
                    "Performing pre-execution ML scan"
                );

                match scanner.scan_bytes(data).await {
                    Ok(scan_result) => {
                        if scan_result.is_malicious {
                            let family_name = scan_result.family.as_deref().unwrap_or("unknown");
                            warn!(
                                path = %path_str,
                                family = %family_name,
                                confidence = scan_result.confidence,
                                inference_ms = scan_result.inference_time_ms,
                                from_cache = scan_result.from_cache,
                                "ML scanner detected malware"
                            );

                            event.add_detection(Detection {
                                detection_type: DetectionType::Ml,
                                rule_name: format!("ML_MALWARE_{}", family_name.to_uppercase()),
                                confidence: scan_result.confidence,
                                description: format!(
                                    "ML model detected {} malware with {:.1}% confidence (inference: {}ms)",
                                    family_name,
                                    scan_result.confidence * 100.0,
                                    scan_result.inference_time_ms
                                ),
                                mitre_tactics: vec!["execution".to_string()],
                                mitre_techniques: vec!["T1204".to_string()],
                            });

                            // Upgrade severity based on confidence
                            if scan_result.confidence >= 0.9 {
                                event.severity = Severity::Critical;
                            } else if scan_result.confidence >= 0.7 {
                                event.severity = Severity::High;
                            } else {
                                event.severity = Severity::Medium;
                            }

                            // Add metadata
                            event
                                .metadata
                                .insert("ml_family".to_string(), family_name.to_string());
                            event.metadata.insert(
                                "ml_confidence".to_string(),
                                format!("{:.4}", scan_result.confidence),
                            );
                            event.metadata.insert(
                                "ml_inference_ms".to_string(),
                                scan_result.inference_time_ms.to_string(),
                            );
                        } else {
                            debug!(
                                path = %path_str,
                                confidence = scan_result.confidence,
                                inference_ms = scan_result.inference_time_ms,
                                "ML scanner classified as benign"
                            );
                        }
                    }
                    Err(e) => {
                        debug!(
                            path = %path_str,
                            error = %e,
                            "ML scan failed, continuing without ML detection"
                        );
                    }
                }
            }
        }

        Some(event)
    }

    async fn create_honeyfile_event(
        notify_event: &NotifyEvent,
        path: &Path,
        _config: &AgentConfig,
    ) -> Option<TelemetryEvent> {
        let operation = match &notify_event.kind {
            EventKind::Access(_) => "read",
            EventKind::Modify(_) => "modify",
            EventKind::Remove(_) => "delete",
            _ => return None,
        };

        let path_str = path.to_string_lossy().to_string();

        let (pid, process_name, process_path, process_sha256) =
            if let Some((p, name, path_str)) = Self::find_process_for_file(path) {
                let sha256 = if !path_str.is_empty() {
                    analyzers::hash_file(&path_str)
                        .await
                        .map(|(hash, _)| hash)
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };
                (p, name, Some(path_str), Some(sha256))
            } else {
                (0, String::new(), None, None)
            };

        let mut event = TelemetryEvent::new(
            EventType::HoneyfileAccess,
            Severity::Critical,
            EventPayload::Honeyfile(HoneyfileEvent {
                path: path_str,
                operation: operation.to_string(),
                pid,
                process_name,
                process_path: process_path.unwrap_or_default(),
                process_sha256: process_sha256.unwrap_or_default(),
            }),
        );

        event.add_detection(Detection {
            detection_type: DetectionType::Honeyfile,
            rule_name: "honeyfile_access".to_string(),
            confidence: 1.0,
            description: "Honeyfile accessed - potential ransomware or data theft".to_string(),
            mitre_tactics: vec!["impact".to_string(), "collection".to_string()],
            mitre_techniques: vec!["T1486".to_string(), "T1005".to_string()],
        });

        Some(event)
    }

    fn detect_file_type(path: &Path) -> String {
        let extension = path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        match extension.as_str() {
            "exe" | "dll" | "sys" | "scr" => "pe".to_string(),
            "so" | "elf" => "elf".to_string(),
            "ps1" | "bat" | "cmd" | "vbs" | "js" => "script".to_string(),
            "doc" | "docx" | "xls" | "xlsx" | "pdf" => "document".to_string(),
            "zip" | "rar" | "7z" | "tar" | "gz" => "archive".to_string(),
            _ => "unknown".to_string(),
        }
    }

    /// Get next event from collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }

    /// Check if ML scanning is operational
    #[cfg(feature = "onnx")]
    pub fn is_ml_scanning_operational(&self) -> bool {
        self.onnx_scanner
            .as_ref()
            .map(|s| s.is_operational())
            .unwrap_or(false)
    }

    /// Get ML scanner statistics
    #[cfg(feature = "onnx")]
    pub fn get_ml_stats(&self) -> Option<crate::analyzers::onnx_scanner::ScannerStats> {
        self.onnx_scanner.as_ref().map(|s| s.get_stats())
    }

    /// Perform on-demand ML scan of a file
    #[cfg(feature = "onnx")]
    pub async fn scan_file_ml(
        &self,
        path: &Path,
    ) -> Option<crate::analyzers::onnx_scanner::ScanResult> {
        if let Some(scanner) = &self.onnx_scanner {
            match scanner.scan_file(path).await {
                Ok(result) => Some(result),
                Err(e) => {
                    debug!(
                        path = %path.display(),
                        error = %e,
                        "ML scan failed"
                    );
                    None
                }
            }
        } else {
            None
        }
    }

    /// Check if the feature-based ML engine is operational
    pub fn is_ml_feature_scanning_operational(&self) -> bool {
        self.ml_feature_engine
            .as_ref()
            .map(|e| e.is_operational())
            .unwrap_or(false)
    }

    /// Run the feature-based ML engine on a file and enrich a telemetry event
    /// with the classification result (adds detection + metadata if malicious).
    ///
    /// This is a synchronous, blocking call suitable for the file watcher thread.
    /// It respects the `max_file_size_mb`, `scan_on_create`, and `scan_on_modify`
    /// settings from `MLLocalConfig`.
    fn enrich_event_with_feature_ml(
        event: &mut TelemetryEvent,
        path: &Path,
        config: &AgentConfig,
        engine: &LocalMLFeatureEngine,
    ) {
        // Check whether this event type should trigger a scan.
        let operation = match &event.payload {
            EventPayload::File(f) => f.operation.as_str(),
            _ => return,
        };

        let should_scan = match operation {
            "create" => config.ml_local.scan_on_create,
            "modify" => config.ml_local.scan_on_modify,
            _ => false,
        };

        if !should_scan {
            return;
        }

        // Check file size limit.
        let max_bytes = config.ml_local.max_file_size_mb * 1024 * 1024;
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.len() > max_bytes {
                debug!(
                    path = %path.display(),
                    size = meta.len(),
                    max_mb = config.ml_local.max_file_size_mb,
                    "File exceeds ML feature scan size limit, skipping"
                );
                return;
            }
        }

        // Only scan PE/executable files. Read just the first 2 bytes (MZ header)
        // instead of the entire file to avoid unnecessary I/O for non-PE files.
        let is_pe = std::fs::File::open(path)
            .and_then(|mut f| {
                use std::io::Read;
                let mut magic = [0u8; 2];
                f.read_exact(&mut magic)?;
                Ok(magic[0] == 0x4D && magic[1] == 0x5A)
            })
            .unwrap_or(false);

        if !is_pe {
            // For non-PE files the feature vector is mostly zeros; skip to
            // avoid false positives.
            return;
        }

        match engine.classify_file(path) {
            Ok(classification) if classification.is_malicious => {
                warn!(
                    path = %path.display(),
                    probability = classification.malware_probability,
                    confidence = classification.confidence,
                    inference_ms = classification.inference_time_ms,
                    features = classification.features_extracted,
                    "Feature-based ML engine detected malware"
                );

                event.add_detection(Detection {
                    detection_type: DetectionType::Ml,
                    rule_name: "ML_FEATURE_MALWARE".to_string(),
                    confidence: classification.confidence,
                    description: format!(
                        "Feature-based ML model detected malware with {:.1}% confidence (inference: {}ms, {} features)",
                        classification.confidence * 100.0,
                        classification.inference_time_ms,
                        classification.features_extracted,
                    ),
                    mitre_tactics: vec!["execution".to_string()],
                    mitre_techniques: vec!["T1204".to_string()],
                });

                // Upgrade severity based on confidence.
                if classification.confidence >= 0.9 {
                    event.severity = Severity::Critical;
                } else if classification.confidence >= 0.7 {
                    event.severity = Severity::High;
                } else {
                    event.severity = Severity::Medium;
                }

                event.metadata.insert(
                    "ml_feature_confidence".to_string(),
                    format!("{:.4}", classification.confidence),
                );
                event.metadata.insert(
                    "ml_feature_probability".to_string(),
                    format!("{:.4}", classification.malware_probability),
                );
                event.metadata.insert(
                    "ml_feature_inference_ms".to_string(),
                    classification.inference_time_ms.to_string(),
                );
                event.metadata.insert(
                    "ml_feature_model_version".to_string(),
                    classification.model_version.clone(),
                );
            }
            Ok(classification) => {
                debug!(
                    path = %path.display(),
                    probability = classification.malware_probability,
                    inference_ms = classification.inference_time_ms,
                    "Feature-based ML engine classified file as benign"
                );
            }
            Err(e) => {
                debug!(
                    path = %path.display(),
                    error = %e,
                    "Feature-based ML scan failed, continuing without detection"
                );
            }
        }
    }

    /// Find process that has a file open
    ///
    /// Returns (pid, process_name, process_path) if a process is found with the file open.
    /// Platform-specific implementations:
    /// - Linux: scans /proc/*/fd/ symlinks and /proc/*/maps, falls back to lsof
    /// - Windows: enumerates process modules via EnumProcessModules, falls back to handle.exe
    /// - macOS: uses lsof
    pub fn find_process_for_file(path: &Path) -> Option<(u32, String, String)> {
        #[cfg(target_os = "linux")]
        {
            return Self::find_process_linux(path);
        }

        #[cfg(target_os = "windows")]
        {
            return Self::find_process_windows(path);
        }

        #[cfg(target_os = "macos")]
        {
            return Self::find_process_macos(path);
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        {
            return None;
        }
    }

    #[cfg(target_os = "linux")]
    fn find_process_linux(path: &Path) -> Option<(u32, String, String)> {
        use std::fs;

        let path_str = path.to_string_lossy();

        // Scan /proc for processes with the file open
        let proc_dir = match fs::read_dir("/proc") {
            Ok(d) => d,
            Err(_) => return None,
        };

        for entry in proc_dir.filter_map(|e| e.ok()) {
            let pid_str = entry.file_name().to_string_lossy().to_string();

            // Skip non-numeric entries
            let pid: u32 = match pid_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Check /proc/[pid]/fd for file descriptors
            let fd_path = format!("/proc/{}/fd", pid);
            if let Ok(fd_entries) = fs::read_dir(&fd_path) {
                for fd_entry in fd_entries.filter_map(|e| e.ok()) {
                    if let Ok(link_target) = fs::read_link(fd_entry.path()) {
                        if link_target.to_string_lossy().contains(&*path_str) {
                            // Found the process, get its name and path
                            let comm_path = format!("/proc/{}/comm", pid);
                            let exe_path = format!("/proc/{}/exe", pid);

                            let process_name = fs::read_to_string(&comm_path)
                                .map(|s| s.trim().to_string())
                                .unwrap_or_default();

                            let process_path = fs::read_link(&exe_path)
                                .map(|p| p.to_string_lossy().to_string())
                                .unwrap_or_default();

                            return Some((pid, process_name, process_path));
                        }
                    }
                }
            }

            // Also check /proc/[pid]/maps for memory-mapped files
            let maps_path = format!("/proc/{}/maps", pid);
            if let Ok(maps_content) = fs::read_to_string(&maps_path) {
                if maps_content.contains(&*path_str) {
                    let comm_path = format!("/proc/{}/comm", pid);
                    let exe_path = format!("/proc/{}/exe", pid);

                    let process_name = fs::read_to_string(&comm_path)
                        .map(|s| s.trim().to_string())
                        .unwrap_or_default();

                    let process_path = fs::read_link(&exe_path)
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_default();

                    return Some((pid, process_name, process_path));
                }
            }
        }

        // Fallback: Use lsof if available
        Self::find_process_lsof(path)
    }

    #[cfg(target_os = "macos")]
    fn find_process_macos(path: &Path) -> Option<(u32, String, String)> {
        Self::find_process_lsof(path)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn find_process_lsof(path: &Path) -> Option<(u32, String, String)> {
        use std::process::Command;

        let path_str = path.to_string_lossy();

        // Use lsof to find process with file open
        let output = Command::new("lsof")
            .args(["-F", "pcn", &path_str])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut pid: Option<u32> = None;
        let mut process_name = String::new();

        for line in stdout.lines() {
            if line.starts_with('p') {
                pid = line[1..].parse().ok();
            } else if line.starts_with('c') {
                process_name = line[1..].to_string();
            }
        }

        if let Some(pid) = pid {
            // Get process path
            #[cfg(target_os = "linux")]
            let process_path = std::fs::read_link(format!("/proc/{}/exe", pid))
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();

            #[cfg(target_os = "macos")]
            let process_path = {
                // On macOS, use ps to get path
                let ps_output = Command::new("ps")
                    .args(["-p", &pid.to_string(), "-o", "comm="])
                    .output()
                    .ok()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .unwrap_or_default();
                ps_output
            };

            return Some((pid, process_name, process_path));
        }

        None
    }

    #[cfg(target_os = "windows")]
    fn find_process_windows(path: &Path) -> Option<(u32, String, String)> {
        use std::cell::RefCell;
        use std::time::Instant;
        use sysinfo::{ProcessRefreshKind, System, UpdateKind};

        // ---------------------------------------------------------------
        // Cached process-to-exe-path lookup.
        //
        // The previous implementation called EnumProcesses + OpenProcess +
        // EnumProcessModules + GetModuleFileNameExW for EVERY file event,
        // producing ~15 000 kernel syscalls per event.  With C:\Users
        // watched recursively, this consumed >80% CPU on a single core.
        //
        // The new approach: keep a thread-local cache of (pid, name, exe)
        // tuples refreshed every 30 s via sysinfo.  For each file event
        // we do a simple linear scan over ~300 entries — orders of
        // magnitude cheaper than full module enumeration.
        //
        // Trade-off: we only match against process *exe* paths, not every
        // loaded DLL.  DLL-level correlation is better handled by the
        // injection / defense-evasion collectors.
        // ---------------------------------------------------------------
        thread_local! {
            static PROC_CACHE: RefCell<(Instant, Vec<(u32, String, String)>)> =
                RefCell::new((
                    Instant::now() - std::time::Duration::from_secs(9999),
                    Vec::new(),
                ));
        }

        let path_lower = path.to_string_lossy().to_lowercase();

        PROC_CACHE.with(|cache| {
            let mut c = cache.borrow_mut();
            let now = Instant::now();

            // Refresh every 30 seconds (cheap: single NtQuerySystemInformation call)
            if now.duration_since(c.0).as_secs() >= 30 || c.1.is_empty() {
                let mut system = System::new();
                system.refresh_processes_specifics(
                    ProcessRefreshKind::new().with_exe(UpdateKind::Always),
                );

                c.1.clear();
                for (pid, process) in system.processes() {
                    if let Some(exe) = process.exe() {
                        let exe_lower = exe.to_string_lossy().to_lowercase();
                        let name = process.name().to_string();
                        c.1.push((pid.as_u32(), name, exe_lower));
                    }
                }
                c.0 = now;
                tracing::debug!(
                    process_count = c.1.len(),
                    "Refreshed file-to-process correlation cache"
                );
            }

            // Linear scan for matching exe path
            c.1.iter()
                .find(|(_, _, exe)| exe.contains(&path_lower) || path_lower.contains(exe.as_str()))
                .map(|(pid, name, exe)| (*pid, name.clone(), exe.clone()))
        })
    }

    #[cfg(target_os = "windows")]
    fn find_process_handle_exe(path: &Path) -> Option<(u32, String, String)> {
        use std::process::Command;

        let path_str = path.to_string_lossy();

        // Try handle.exe from Sysinternals
        let output = Command::new("handle.exe")
            .args(["-nobanner", &path_str])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse output: process.exe pid: handle_type path
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                if let Some(pid_str) = parts.get(1).and_then(|s| s.strip_prefix("pid:")) {
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        let process_name = parts[0].to_string();
                        return Some((pid, process_name, String::new()));
                    }
                }
            }
        }

        None
    }
}

/// Fanotify-based file collector for Linux (provides better PID correlation)
#[cfg(target_os = "linux")]
pub mod fanotify {
    use super::*;
    use std::ffi::CString;
    use std::os::unix::io::{AsRawFd, RawFd};

    // fanotify constants (from linux/fanotify.h)
    const FAN_CLASS_NOTIF: libc::c_uint = 0x00000000;
    #[allow(dead_code)] // Defined for completeness; only PRE_CONTENT is used for blocking.
    const FAN_CLASS_CONTENT: libc::c_uint = 0x00000004;
    const FAN_CLASS_PRE_CONTENT: libc::c_uint = 0x00000008;
    const FAN_CLOEXEC: libc::c_uint = 0x00000001;
    const FAN_NONBLOCK: libc::c_uint = 0x00000002;
    const FAN_REPORT_FID: libc::c_uint = 0x00000200;
    const FAN_REPORT_DFID_NAME: libc::c_uint = 0x00000c00;

    // Event masks
    const FAN_ACCESS: u64 = 0x00000001;
    const FAN_MODIFY: u64 = 0x00000002;
    const FAN_CLOSE_WRITE: u64 = 0x00000008;
    const FAN_OPEN: u64 = 0x00000020;
    const FAN_OPEN_EXEC: u64 = 0x00001000;
    const FAN_OPEN_EXEC_PERM: u64 = 0x00040000;
    const FAN_EVENT_ON_CHILD: u64 = 0x08000000;

    // Permission event response values
    const FAN_ALLOW: u32 = 0x01;
    const FAN_DENY: u32 = 0x02;

    // Mark flags
    const FAN_MARK_ADD: libc::c_uint = 0x00000001;
    const FAN_MARK_MOUNT: libc::c_uint = 0x00000010;
    const FAN_MARK_FILESYSTEM: libc::c_uint = 0x00000100;

    /// fanotify event metadata structure
    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    struct FanotifyEventMetadata {
        event_len: u32,
        vers: u8,
        reserved: u8,
        metadata_len: u16,
        mask: u64,
        fd: i32,
        pid: i32,
    }

    const FANOTIFY_METADATA_VERSION: u8 = 3;

    /// Response struct written back to the fanotify fd for permission events.
    /// The kernel expects exactly this layout: the fd that triggered the event
    /// followed by a u32 response code (FAN_ALLOW or FAN_DENY).
    #[repr(C)]
    struct FanotifyResponse {
        fd: i32,
        response: u32,
    }

    // ========================================================================
    // Pre-Execution Gate
    // ========================================================================

    /// Metrics tracked by the PreExecutionGate.
    #[derive(Debug, Default)]
    pub struct GateMetrics {
        /// Total permission events received.
        pub total_scanned: std::sync::atomic::AtomicU64,
        /// Executions blocked (FAN_DENY).
        pub blocked: std::sync::atomic::AtomicU64,
        /// Executions allowed (FAN_ALLOW).
        pub allowed: std::sync::atomic::AtomicU64,
        /// Scans that timed out (allowed by default).
        pub timeouts: std::sync::atomic::AtomicU64,
        /// Executions allowed because path is in the trusted whitelist.
        pub whitelisted: std::sync::atomic::AtomicU64,
        /// Scan errors (allowed by default).
        pub errors: std::sync::atomic::AtomicU64,
    }

    /// Decision made by the pre-execution gate for a single event.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum GateDecision {
        Allow,
        Deny,
    }

    /// Reason for the gate decision (for logging and telemetry).
    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    enum GateReason {
        Whitelisted,
        NoScanner,
        ScanBenign {
            confidence: f32,
        },
        ScanTimeout,
        ScanError(String),
        FileTooLarge(u64),
        FileReadError(String),
        Malicious {
            confidence: f32,
            family: Option<String>,
        },
    }

    /// Pre-execution gate that intercepts `FAN_OPEN_EXEC_PERM` events and
    /// decides whether to allow or deny the execution based on ML scanning.
    ///
    /// When the ONNX scanner is available and the file is not whitelisted,
    /// the gate reads the file through the event fd, runs ML inference with
    /// a configurable timeout, and writes either `FAN_ALLOW` or `FAN_DENY`
    /// back to the fanotify fd.
    ///
    /// Design principles:
    /// - **Fail-open:** Any error, timeout, or missing scanner results in ALLOW.
    /// - **Fast path:** Whitelisted paths and oversized files skip ML entirely.
    /// - **Observability:** Every decision is logged and counted in metrics.
    pub struct PreExecutionGate {
        /// The fanotify file descriptor (stored for potential future use;
        /// responses are written via the fd passed to `evaluate()`).
        #[allow(dead_code)]
        fanotify_fd: RawFd,
        /// Pre-execution blocking configuration.
        config: crate::config::PreExecutionBlockingConfig,
        /// Optional ONNX scanner for ML inference.
        #[cfg(feature = "onnx")]
        scanner: Option<Arc<crate::analyzers::onnx_scanner::OnnxScanner>>,
        /// Accumulated gate metrics.
        pub metrics: Arc<GateMetrics>,
    }

    impl PreExecutionGate {
        /// Create a new gate.
        ///
        /// If `scanner` is `None`, the gate will always allow executions.
        #[cfg(feature = "onnx")]
        pub fn new(
            fanotify_fd: RawFd,
            config: crate::config::PreExecutionBlockingConfig,
            scanner: Option<Arc<crate::analyzers::onnx_scanner::OnnxScanner>>,
        ) -> Self {
            Self {
                fanotify_fd,
                config,
                scanner,
                metrics: Arc::new(GateMetrics::default()),
            }
        }

        /// Create a new gate without ONNX support (always allows).
        #[cfg(not(feature = "onnx"))]
        pub fn new(fanotify_fd: RawFd, config: crate::config::PreExecutionBlockingConfig) -> Self {
            Self {
                fanotify_fd,
                config,
                metrics: Arc::new(GateMetrics::default()),
            }
        }

        /// Evaluate a permission event and decide whether to allow or deny.
        ///
        /// This is the hot path -- called for every `FAN_OPEN_EXEC_PERM` event.
        /// It must respond within the kernel timeout (typically 5 seconds) or
        /// the process is killed. We aim for < 100ms end-to-end.
        ///
        /// Returns the telemetry event to emit (if any). The fanotify response
        /// is written directly to the fd inside this method.
        pub fn evaluate(
            &self,
            meta: &FanotifyEventMetadata,
            fanotify_fd: RawFd,
            runtime: &tokio::runtime::Runtime,
        ) -> Option<TelemetryEvent> {
            use std::sync::atomic::Ordering;

            self.metrics.total_scanned.fetch_add(1, Ordering::Relaxed);

            // 1. Resolve the file path from the event fd.
            let path_str = match Self::path_from_fd(meta.fd) {
                Some(p) => p,
                None => {
                    // Cannot determine path -- allow to be safe.
                    self.write_response(meta.fd, fanotify_fd, FAN_ALLOW);
                    self.metrics.allowed.fetch_add(1, Ordering::Relaxed);
                    self.metrics.errors.fetch_add(1, Ordering::Relaxed);
                    debug!("Pre-exec gate: could not resolve path from fd, allowing");
                    return None;
                }
            };

            // 2. Check whitelist (fast path -- no I/O needed).
            if self.is_whitelisted(&path_str) {
                self.write_response(meta.fd, fanotify_fd, FAN_ALLOW);
                self.metrics.allowed.fetch_add(1, Ordering::Relaxed);
                self.metrics.whitelisted.fetch_add(1, Ordering::Relaxed);
                debug!(path = %path_str, "Pre-exec gate: whitelisted, allowing");
                return None;
            }

            // 3. Run the ML scan and decide.
            let (decision, reason) = self.scan_and_decide(&path_str, meta.fd, runtime);

            // 4. Write the response to the fanotify fd.
            let response_code = match decision {
                GateDecision::Allow => FAN_ALLOW,
                GateDecision::Deny => FAN_DENY,
            };
            self.write_response(meta.fd, fanotify_fd, response_code);

            // 5. Update metrics.
            match decision {
                GateDecision::Allow => self.metrics.allowed.fetch_add(1, Ordering::Relaxed),
                GateDecision::Deny => self.metrics.blocked.fetch_add(1, Ordering::Relaxed),
            };

            // 6. Build telemetry event for blocked executions or malicious
            //    detections (always emit for blocked, optionally for allowed).
            self.build_telemetry_event(&path_str, meta, decision, &reason)
        }

        /// Determine whether `path` starts with any of the trusted paths.
        fn is_whitelisted(&self, path: &str) -> bool {
            self.config
                .trusted_paths
                .iter()
                .any(|tp| path.starts_with(tp))
        }

        /// Read the file (via the event fd), run the ONNX scanner, and return
        /// a decision with a reason.
        fn scan_and_decide(
            &self,
            path: &str,
            _event_fd: i32,
            runtime: &tokio::runtime::Runtime,
        ) -> (GateDecision, GateReason) {
            // Without the ONNX feature, always allow.
            #[cfg(not(feature = "onnx"))]
            {
                let _ = (path, _event_fd, runtime);
                return (GateDecision::Allow, GateReason::NoScanner);
            }

            #[cfg(feature = "onnx")]
            {
                use std::sync::atomic::Ordering;

                // Check scanner availability.
                let scanner = match &self.scanner {
                    Some(s) if s.is_operational() => s,
                    _ => {
                        debug!(path = %path, "Pre-exec gate: no operational scanner, allowing");
                        return (GateDecision::Allow, GateReason::NoScanner);
                    }
                };

                // Check file size before reading (avoid huge reads).
                match std::fs::metadata(path) {
                    Ok(m) if m.len() > self.config.max_scan_file_size => {
                        debug!(
                            path = %path,
                            size = m.len(),
                            max = self.config.max_scan_file_size,
                            "Pre-exec gate: file too large, allowing"
                        );
                        return (GateDecision::Allow, GateReason::FileTooLarge(m.len()));
                    }
                    Err(e) => {
                        debug!(path = %path, error = %e, "Pre-exec gate: metadata error, allowing");
                        self.metrics.errors.fetch_add(1, Ordering::Relaxed);
                        return (
                            GateDecision::Allow,
                            GateReason::FileReadError(e.to_string()),
                        );
                    }
                    _ => {}
                }

                // Read the file contents.
                let data = match std::fs::read(path) {
                    Ok(d) => d,
                    Err(e) => {
                        debug!(path = %path, error = %e, "Pre-exec gate: file read error, allowing");
                        self.metrics.errors.fetch_add(1, Ordering::Relaxed);
                        return (
                            GateDecision::Allow,
                            GateReason::FileReadError(e.to_string()),
                        );
                    }
                };

                // Run the scan with a timeout.
                let timeout = std::time::Duration::from_millis(self.config.scan_timeout_ms);
                let scan_result = runtime.block_on(async {
                    tokio::time::timeout(timeout, scanner.scan_bytes(&data)).await
                });

                match scan_result {
                    Ok(Ok(result)) => {
                        if result.is_malicious
                            && result.confidence >= self.config.block_confidence_threshold
                        {
                            warn!(
                                path = %path,
                                confidence = result.confidence,
                                family = ?result.family,
                                inference_ms = result.inference_time_ms,
                                "Pre-exec gate: BLOCKING malicious execution"
                            );
                            (
                                GateDecision::Deny,
                                GateReason::Malicious {
                                    confidence: result.confidence,
                                    family: result.family.clone(),
                                },
                            )
                        } else {
                            debug!(
                                path = %path,
                                confidence = result.confidence,
                                is_malicious = result.is_malicious,
                                inference_ms = result.inference_time_ms,
                                "Pre-exec gate: scan benign, allowing"
                            );
                            (
                                GateDecision::Allow,
                                GateReason::ScanBenign {
                                    confidence: result.confidence,
                                },
                            )
                        }
                    }
                    Ok(Err(e)) => {
                        debug!(path = %path, error = %e, "Pre-exec gate: scan error, allowing");
                        self.metrics.errors.fetch_add(1, Ordering::Relaxed);
                        (GateDecision::Allow, GateReason::ScanError(e.to_string()))
                    }
                    Err(_) => {
                        // Timeout -- must not block the process.
                        debug!(
                            path = %path,
                            timeout_ms = self.config.scan_timeout_ms,
                            "Pre-exec gate: scan timeout, allowing"
                        );
                        self.metrics.timeouts.fetch_add(1, Ordering::Relaxed);
                        (GateDecision::Allow, GateReason::ScanTimeout)
                    }
                }
            }
        }

        /// Write a `fanotify_response` struct to the fanotify fd.
        ///
        /// The kernel expects us to write exactly `sizeof(fanotify_response)` bytes
        /// for each permission event. If the write fails, the kernel will eventually
        /// time out and kill the target process, so we log the error prominently.
        fn write_response(&self, event_fd: i32, fanotify_fd: RawFd, response: u32) {
            let resp = FanotifyResponse {
                fd: event_fd,
                response,
            };
            unsafe {
                let written = libc::write(
                    fanotify_fd,
                    &resp as *const FanotifyResponse as *const libc::c_void,
                    std::mem::size_of::<FanotifyResponse>(),
                );
                if written < 0 {
                    let err = std::io::Error::last_os_error();
                    error!(
                        event_fd = event_fd,
                        response = response,
                        error = %err,
                        "CRITICAL: Failed to write fanotify permission response"
                    );
                }
            }
        }

        /// Resolve a file path from a fanotify event file descriptor.
        fn path_from_fd(fd: i32) -> Option<String> {
            let link_path = format!("/proc/self/fd/{}", fd);
            std::fs::read_link(&link_path)
                .map(|p| p.to_string_lossy().to_string())
                .ok()
        }

        /// Build a telemetry event for blocked executions or malicious detections.
        ///
        /// For blocked executions, emits a `FileExecuteBlocked` event with
        /// critical severity. For allowed-but-detected cases, emits a
        /// `FileExecute` event with appropriate severity.
        fn build_telemetry_event(
            &self,
            path: &str,
            meta: &FanotifyEventMetadata,
            decision: GateDecision,
            reason: &GateReason,
        ) -> Option<TelemetryEvent> {
            match reason {
                GateReason::Malicious { confidence, family } => {
                    let pid = meta.pid as u32;
                    let (process_name, process_path) = {
                        let comm_path = format!("/proc/{}/comm", pid);
                        let exe_path = format!("/proc/{}/exe", pid);
                        let name = std::fs::read_to_string(&comm_path)
                            .map(|s| s.trim().to_string())
                            .unwrap_or_else(|_| format!("pid:{}", pid));
                        let ppath = std::fs::read_link(&exe_path)
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_default();
                        (name, ppath)
                    };

                    let family_name = family.as_deref().unwrap_or("unknown");
                    let event_type = if decision == GateDecision::Deny {
                        EventType::FileExecuteBlocked
                    } else {
                        EventType::FileExecute
                    };
                    let severity = if decision == GateDecision::Deny {
                        Severity::Critical
                    } else if *confidence >= 0.9 {
                        Severity::High
                    } else {
                        Severity::Medium
                    };

                    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
                    let file_type = FileCollector::detect_file_type(Path::new(path));

                    let mut event = TelemetryEvent::new(
                        event_type,
                        severity,
                        EventPayload::File(FileEvent {
                            path: path.to_string(),
                            old_path: None,
                            operation: if decision == GateDecision::Deny {
                                "execute_blocked".to_string()
                            } else {
                                "execute".to_string()
                            },
                            pid,
                            process_name,
                            sha256: Vec::new(),
                            size,
                            entropy: 0.0,
                            file_type,
                        }),
                    );

                    let rule_name = format!("PRE_EXEC_ML_{}", family_name.to_uppercase());
                    let description = if decision == GateDecision::Deny {
                        format!(
                            "Pre-execution gate BLOCKED {} malware with {:.1}% confidence",
                            family_name,
                            confidence * 100.0,
                        )
                    } else {
                        format!(
                            "Pre-execution gate detected {} malware with {:.1}% confidence (below block threshold)",
                            family_name,
                            confidence * 100.0,
                        )
                    };

                    event.add_detection(Detection {
                        detection_type: DetectionType::Ml,
                        rule_name,
                        confidence: *confidence,
                        description,
                        mitre_tactics: vec!["execution".to_string(), "defense-evasion".to_string()],
                        mitre_techniques: vec!["T1204".to_string(), "T1059".to_string()],
                    });

                    event.metadata.insert(
                        "pre_exec_decision".to_string(),
                        if decision == GateDecision::Deny {
                            "blocked"
                        } else {
                            "allowed"
                        }
                        .to_string(),
                    );
                    event
                        .metadata
                        .insert("ml_confidence".to_string(), format!("{:.4}", confidence));
                    event
                        .metadata
                        .insert("ml_family".to_string(), family_name.to_string());
                    event
                        .metadata
                        .insert("requesting_process".to_string(), process_path);

                    Some(event)
                }
                // For non-malicious decisions, do not emit telemetry events
                // to avoid flooding the pipeline with benign exec events.
                _ => None,
            }
        }
    }

    /// Fanotify-based file collector
    pub struct FanotifyCollector {
        fd: RawFd,
        config: AgentConfig,
        /// Pre-execution gate for permission events (only active when
        /// `pre_execution_blocking.enabled` is true and the fanotify fd
        /// was initialized with `FAN_CLASS_PRE_CONTENT`).
        gate: Option<PreExecutionGate>,
    }

    impl FanotifyCollector {
        /// Try to create a fanotify collector. Returns None if fanotify is not available.
        ///
        /// When `config.pre_execution_blocking.enabled` is true, the collector
        /// is initialized with `FAN_CLASS_PRE_CONTENT` to support permission
        /// events (`FAN_OPEN_EXEC_PERM`). This requires `CAP_SYS_ADMIN`.
        /// If the permission-class init fails, falls back to notification mode.
        ///
        /// The `scanner` parameter is forwarded to `PreExecutionGate` when the
        /// gate is active. Pass `None` if the ONNX feature is disabled.
        #[cfg(feature = "onnx")]
        pub fn try_new(
            config: &AgentConfig,
            scanner: Option<Arc<crate::analyzers::onnx_scanner::OnnxScanner>>,
        ) -> Option<Self> {
            Self::try_new_impl(config, scanner)
        }

        #[cfg(not(feature = "onnx"))]
        pub fn try_new(config: &AgentConfig) -> Option<Self> {
            Self::try_new_impl(config)
        }

        fn try_new_impl(
            config: &AgentConfig,
            #[cfg(feature = "onnx")] scanner: Option<
                Arc<crate::analyzers::onnx_scanner::OnnxScanner>,
            >,
        ) -> Option<Self> {
            let blocking_enabled = config.pre_execution_blocking.enabled;

            unsafe {
                // When pre-execution blocking is requested, try FAN_CLASS_PRE_CONTENT
                // first. If that fails (missing CAP_SYS_ADMIN), fall back to
                // FAN_CLASS_NOTIF (notification-only mode, no blocking).
                let (fd, perm_mode) = if blocking_enabled {
                    // FAN_CLASS_PRE_CONTENT requires CAP_SYS_ADMIN.
                    // Note: When using FAN_CLASS_PRE_CONTENT or FAN_CLASS_CONTENT,
                    // FAN_REPORT_FID and FAN_REPORT_DFID_NAME are NOT supported
                    // alongside permission events in older kernels. We omit them
                    // here to maximize compatibility.
                    let perm_flags = FAN_CLASS_PRE_CONTENT | FAN_CLOEXEC;
                    let event_flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_LARGEFILE;

                    let fd = libc::syscall(
                        libc::SYS_fanotify_init,
                        perm_flags as libc::c_int,
                        event_flags as libc::c_int,
                    );

                    if fd >= 0 {
                        info!("Fanotify initialized with FAN_CLASS_PRE_CONTENT (permission events enabled)");
                        (fd as RawFd, true)
                    } else {
                        let err = std::io::Error::last_os_error();
                        warn!(
                            error = %err,
                            "fanotify_init with FAN_CLASS_PRE_CONTENT failed, \
                             falling back to notification mode (pre-execution blocking disabled)"
                        );
                        // Fall through to notification mode below
                        let notif_flags = FAN_CLASS_NOTIF
                            | FAN_CLOEXEC
                            | FAN_NONBLOCK
                            | FAN_REPORT_FID
                            | FAN_REPORT_DFID_NAME;
                        let fd = libc::syscall(
                            libc::SYS_fanotify_init,
                            notif_flags as libc::c_int,
                            event_flags as libc::c_int,
                        );
                        if fd < 0 {
                            let err2 = std::io::Error::last_os_error();
                            warn!(error = %err2, "fanotify_init notification mode also failed");
                            return None;
                        }
                        info!("Fanotify initialized in notification-only mode (FAN_CLASS_NOTIF)");
                        (fd as RawFd, false)
                    }
                } else {
                    // Standard notification mode
                    let flags = FAN_CLASS_NOTIF
                        | FAN_CLOEXEC
                        | FAN_NONBLOCK
                        | FAN_REPORT_FID
                        | FAN_REPORT_DFID_NAME;
                    let event_flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_LARGEFILE;

                    let fd = libc::syscall(
                        libc::SYS_fanotify_init,
                        flags as libc::c_int,
                        event_flags as libc::c_int,
                    );

                    if fd < 0 {
                        let err = std::io::Error::last_os_error();
                        warn!(error = %err, "fanotify_init failed - falling back to inotify");
                        return None;
                    }
                    info!("Fanotify initialized in notification mode");
                    (fd as RawFd, false)
                };

                // Create the pre-execution gate if we got permission mode
                let gate = if perm_mode {
                    #[cfg(feature = "onnx")]
                    let gate =
                        PreExecutionGate::new(fd, config.pre_execution_blocking.clone(), scanner);
                    #[cfg(not(feature = "onnx"))]
                    let gate = PreExecutionGate::new(fd, config.pre_execution_blocking.clone());
                    info!("Pre-execution gate created for fanotify permission events");
                    Some(gate)
                } else {
                    None
                };

                Some(Self {
                    fd,
                    config: config.clone(),
                    gate,
                })
            }
        }

        /// Mark a path for monitoring.
        ///
        /// When the pre-execution gate is active, `FAN_OPEN_EXEC_PERM` is added
        /// to the mask so the kernel generates permission events for file executions.
        pub fn mark_path(&self, path: &str, recursive: bool) -> Result<()> {
            let c_path = CString::new(path)?;

            let mut mask = FAN_ACCESS | FAN_MODIFY | FAN_CLOSE_WRITE | FAN_OPEN | FAN_OPEN_EXEC;
            if self.gate.is_some() {
                mask |= FAN_OPEN_EXEC_PERM;
            }
            let mask = if recursive {
                mask | FAN_EVENT_ON_CHILD
            } else {
                mask
            };

            let flags = FAN_MARK_ADD | if recursive { FAN_MARK_MOUNT } else { 0 };

            unsafe {
                let result = libc::syscall(
                    libc::SYS_fanotify_mark,
                    self.fd,
                    flags as libc::c_int,
                    mask,
                    libc::AT_FDCWD,
                    c_path.as_ptr(),
                );

                if result < 0 {
                    let err = std::io::Error::last_os_error();
                    return Err(anyhow::anyhow!("fanotify_mark failed: {}", err));
                }
            }

            debug!(path = path, "Marked path for fanotify monitoring");
            Ok(())
        }

        /// Mark the root filesystem for monitoring.
        ///
        /// When the pre-execution gate is active, `FAN_OPEN_EXEC_PERM` is
        /// included for permission-based interception of file executions.
        pub fn mark_filesystem(&self) -> Result<()> {
            let c_path = CString::new("/")?;
            let mut mask = FAN_ACCESS
                | FAN_MODIFY
                | FAN_CLOSE_WRITE
                | FAN_OPEN
                | FAN_OPEN_EXEC
                | FAN_EVENT_ON_CHILD;
            if self.gate.is_some() {
                mask |= FAN_OPEN_EXEC_PERM;
            }
            let flags = FAN_MARK_ADD | FAN_MARK_FILESYSTEM;

            unsafe {
                let result = libc::syscall(
                    libc::SYS_fanotify_mark,
                    self.fd,
                    flags as libc::c_int,
                    mask,
                    libc::AT_FDCWD,
                    c_path.as_ptr(),
                );

                if result < 0 {
                    let err = std::io::Error::last_os_error();
                    return Err(anyhow::anyhow!("fanotify_mark filesystem failed: {}", err));
                }
            }

            info!("Marked filesystem for fanotify monitoring");
            Ok(())
        }

        /// Read events from fanotify fd.
        ///
        /// For normal notification events, processes them and closes the fd.
        /// For permission events (`FAN_OPEN_EXEC_PERM`), routes them through
        /// the `PreExecutionGate` which writes the `FAN_ALLOW`/`FAN_DENY`
        /// response before the fd is closed.
        pub fn read_events(
            &self,
            tx: &mpsc::Sender<TelemetryEvent>,
            runtime: &tokio::runtime::Runtime,
        ) -> Result<()> {
            let mut buffer = [0u8; 8192];

            unsafe {
                let bytes_read = libc::read(
                    self.fd,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                );

                if bytes_read < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        return Ok(());
                    }
                    return Err(anyhow::anyhow!("fanotify read failed: {}", err));
                }

                if bytes_read == 0 {
                    return Ok(());
                }

                let mut offset = 0usize;
                while offset < bytes_read as usize {
                    let meta = &*(buffer.as_ptr().add(offset) as *const FanotifyEventMetadata);

                    if meta.vers != FANOTIFY_METADATA_VERSION {
                        warn!(version = meta.vers, "Unknown fanotify metadata version");
                        break;
                    }

                    if meta.fd >= 0 {
                        // Check if this is a permission event that requires a response.
                        let is_perm_event = (meta.mask & FAN_OPEN_EXEC_PERM) != 0;

                        if is_perm_event {
                            // Permission event: route through the pre-execution gate.
                            // The gate will write the FAN_ALLOW/FAN_DENY response and
                            // optionally produce a telemetry event.
                            if let Some(ref gate) = self.gate {
                                if let Some(event) = gate.evaluate(meta, self.fd, runtime) {
                                    let _ = tx.blocking_send(event);
                                }
                            } else {
                                // Gate not active (should not happen for perm events,
                                // but be safe). Write FAN_ALLOW to avoid hanging.
                                let resp = FanotifyResponse {
                                    fd: meta.fd,
                                    response: FAN_ALLOW,
                                };
                                libc::write(
                                    self.fd,
                                    &resp as *const FanotifyResponse as *const libc::c_void,
                                    std::mem::size_of::<FanotifyResponse>(),
                                );
                                warn!("Received permission event but no gate active, allowing");
                            }
                        } else {
                            // Normal notification event -- process as before.
                            if let Some(event) = self.process_event(meta, runtime) {
                                let _ = tx.blocking_send(event);
                            }
                        }

                        // Close the fd (must happen after the gate has finished
                        // reading the file and writing the response).
                        libc::close(meta.fd);
                    }

                    offset += meta.event_len as usize;
                }
            }

            Ok(())
        }

        /// Process a fanotify event and create a TelemetryEvent
        fn process_event(
            &self,
            meta: &FanotifyEventMetadata,
            runtime: &tokio::runtime::Runtime,
        ) -> Option<TelemetryEvent> {
            // Get path from fd
            let path_str = self.get_path_from_fd(meta.fd)?;
            let path = Path::new(&path_str);
            let is_browser_cache = FileCollector::is_common_browser_cache_path(&path_str);

            // Check exclusions
            if self
                .config
                .excluded_paths
                .iter()
                .any(|p| path_str.contains(p))
            {
                return None;
            }

            // Determine event type
            let (event_type, operation) = if meta.mask & FAN_MODIFY != 0
                || meta.mask & FAN_CLOSE_WRITE != 0
            {
                (EventType::FileModify, "modify")
            } else if meta.mask & FAN_ACCESS != 0 || meta.mask & FAN_OPEN != 0 {
                // For access events, check if it's a honeyfile
                if self
                    .config
                    .honeyfile_paths
                    .iter()
                    .any(|p| path_str.contains(p))
                {
                    return self.create_honeyfile_event_with_pid(path, meta.pid as u32, runtime);
                }
                // Check if it's a credential file read (T1555.003, T1552, etc.)
                if let Some(cred_event) =
                    self.check_credential_file_access(&path_str, meta.pid as u32)
                {
                    return Some(cred_event);
                }
                return None; // Skip regular access events to reduce noise
            } else if meta.mask & FAN_OPEN_EXEC != 0 {
                (EventType::FileExecute, "execute")
            } else {
                return None;
            };

            // Check file pattern match
            if !self.config.monitored_file_patterns.is_empty()
                && !FileCollector::matches_pattern(path, &self.config.monitored_file_patterns)
            {
                return None;
            }

            // Get process info using the PID from fanotify
            let pid = meta.pid as u32;
            let (process_name, process_path) = self.get_process_info(pid);

            // Get file info
            let (sha256, entropy, size) = if path.exists() {
                match runtime.block_on(analyzers::hash_file(&path_str)) {
                    Ok((hash, ent)) => {
                        let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
                        (hash, ent, size)
                    }
                    Err(_) => (Vec::new(), 0.0, 0),
                }
            } else {
                (Vec::new(), 0.0, 0)
            };

            let file_type = FileCollector::detect_file_type(path);

            let mut event = TelemetryEvent::new(
                event_type,
                FileCollector::browser_cache_event_severity(&path_str),
                EventPayload::File(FileEvent {
                    path: path_str.clone(),
                    old_path: None,
                    operation: operation.to_string(),
                    pid,
                    process_name,
                    sha256,
                    size,
                    entropy,
                    file_type,
                }),
            );
            FileCollector::annotate_browser_cache_event(
                &mut event,
                path.to_string_lossy().as_ref(),
            );

            // Check entropy
            if !is_browser_cache
                && self.config.entropy_check_enabled
                && entropy > self.config.entropy_threshold
            {
                event.add_detection(Detection {
                    detection_type: DetectionType::Entropy,
                    rule_name: "high_entropy_file".to_string(),
                    confidence: 0.7,
                    description: format!("High entropy file detected: {:.2}", entropy),
                    mitre_tactics: vec!["defense-evasion".to_string()],
                    mitre_techniques: vec!["T1027".to_string()],
                });
                event.severity = Severity::Medium;
            }

            Some(event)
        }

        /// Create honeyfile event with PID from fanotify
        fn create_honeyfile_event_with_pid(
            &self,
            path: &Path,
            pid: u32,
            runtime: &tokio::runtime::Runtime,
        ) -> Option<TelemetryEvent> {
            let path_str = path.to_string_lossy().to_string();
            let (process_name, process_path) = self.get_process_info(pid);

            let process_sha256 = if !process_path.is_empty() {
                runtime
                    .block_on(analyzers::hash_file(&process_path))
                    .map(|(hash, _)| hash)
                    .unwrap_or_default()
            } else {
                Vec::new()
            };

            let mut event = TelemetryEvent::new(
                EventType::HoneyfileAccess,
                Severity::Critical,
                EventPayload::Honeyfile(HoneyfileEvent {
                    path: path_str,
                    operation: "access".to_string(),
                    pid,
                    process_name,
                    process_path,
                    process_sha256,
                }),
            );

            event.add_detection(Detection {
                detection_type: DetectionType::Honeyfile,
                rule_name: "honeyfile_access".to_string(),
                confidence: 1.0,
                description: "Honeyfile accessed - potential ransomware or data theft".to_string(),
                mitre_tactics: vec!["impact".to_string(), "collection".to_string()],
                mitre_techniques: vec!["T1486".to_string(), "T1005".to_string()],
            });

            Some(event)
        }

        /// Get path from file descriptor using /proc/self/fd
        fn get_path_from_fd(&self, fd: i32) -> Option<String> {
            let link_path = format!("/proc/self/fd/{}", fd);
            std::fs::read_link(&link_path)
                .map(|p| p.to_string_lossy().to_string())
                .ok()
        }

        /// Get process info from PID
        fn get_process_info(&self, pid: u32) -> (String, String) {
            let comm_path = format!("/proc/{}/comm", pid);
            let exe_path = format!("/proc/{}/exe", pid);

            let process_name = std::fs::read_to_string(&comm_path)
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| format!("pid:{}", pid));

            let process_path = std::fs::read_link(&exe_path)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();

            (process_name, process_path)
        }

        /// Check if the accessed file is a sensitive credential file.
        /// Returns a CredentialTheft event if the file matches known credential paths.
        /// This enables detection of browser credential theft (T1555.003), SSH key theft (T1552.004),
        /// cloud credential theft, and other credential access attacks.
        fn check_credential_file_access(&self, path: &str, pid: u32) -> Option<TelemetryEvent> {
            use crate::collectors::{credential_theft::CredentialAttackType, CredentialTheftEvent};

            let path_lower = path.to_lowercase();

            // Credential file patterns for Linux with their attack types
            let linux_credential_patterns: &[(&str, CredentialAttackType, &str)] = &[
                // Browser credentials - Chrome/Chromium (T1555.003)
                (
                    "/.config/google-chrome/default/login data",
                    CredentialAttackType::BrowserCredentials,
                    "Chrome Login Data",
                ),
                (
                    "/.config/google-chrome/default/cookies",
                    CredentialAttackType::BrowserCredentials,
                    "Chrome Cookies",
                ),
                (
                    "/.config/google-chrome/default/web data",
                    CredentialAttackType::BrowserCredentials,
                    "Chrome Web Data",
                ),
                (
                    "/.config/chromium/default/login data",
                    CredentialAttackType::BrowserCredentials,
                    "Chromium Login Data",
                ),
                (
                    "/.config/chromium/default/cookies",
                    CredentialAttackType::BrowserCredentials,
                    "Chromium Cookies",
                ),
                // Browser credentials - Firefox
                (
                    "/.mozilla/firefox",
                    CredentialAttackType::BrowserCredentials,
                    "Firefox Profile",
                ),
                (
                    "/logins.json",
                    CredentialAttackType::BrowserCredentials,
                    "Firefox Logins",
                ),
                (
                    "/key4.db",
                    CredentialAttackType::BrowserCredentials,
                    "Firefox Key DB",
                ),
                (
                    "/cookies.sqlite",
                    CredentialAttackType::BrowserCredentials,
                    "Firefox Cookies",
                ),
                // Browser credentials - Brave
                (
                    "/.config/bravesoftware/brave-browser/default/login data",
                    CredentialAttackType::BrowserCredentials,
                    "Brave Login Data",
                ),
                // SSH keys (T1552.004)
                (
                    "/.ssh/id_rsa",
                    CredentialAttackType::SshKeyTheft,
                    "SSH Private Key (RSA)",
                ),
                (
                    "/.ssh/id_ed25519",
                    CredentialAttackType::SshKeyTheft,
                    "SSH Private Key (Ed25519)",
                ),
                (
                    "/.ssh/id_ecdsa",
                    CredentialAttackType::SshKeyTheft,
                    "SSH Private Key (ECDSA)",
                ),
                (
                    "/.ssh/id_dsa",
                    CredentialAttackType::SshKeyTheft,
                    "SSH Private Key (DSA)",
                ),
                // Cloud credentials
                (
                    "/.aws/credentials",
                    CredentialAttackType::CredentialFile,
                    "AWS Credentials",
                ),
                (
                    "/.azure/accesstokens.json",
                    CredentialAttackType::CredentialFile,
                    "Azure Access Tokens",
                ),
                (
                    "/.config/gcloud/credentials.db",
                    CredentialAttackType::CredentialFile,
                    "GCP Credentials",
                ),
                (
                    "/.config/gcloud/access_tokens.db",
                    CredentialAttackType::CredentialFile,
                    "GCP Access Tokens",
                ),
                // Kubernetes
                (
                    "/.kube/config",
                    CredentialAttackType::CredentialFile,
                    "Kubernetes Config",
                ),
                // Docker
                (
                    "/.docker/config.json",
                    CredentialAttackType::CredentialFile,
                    "Docker Config",
                ),
                // Git credentials
                (
                    "/.git-credentials",
                    CredentialAttackType::CredentialFile,
                    "Git Credentials",
                ),
                // Password managers
                (
                    ".kdbx",
                    CredentialAttackType::PasswordManager,
                    "KeePass Database",
                ),
                // Linux system credentials (T1003.008)
                (
                    "/etc/shadow",
                    CredentialAttackType::LinuxShadow,
                    "Linux Shadow File",
                ),
                (
                    "/etc/gshadow",
                    CredentialAttackType::LinuxShadow,
                    "Linux GShadow File",
                ),
                // Network credentials
                (
                    "/.netrc",
                    CredentialAttackType::CredentialFile,
                    "Netrc File",
                ),
                (
                    "/.pgpass",
                    CredentialAttackType::CredentialFile,
                    "PostgreSQL Password File",
                ),
                // GNOME Keyring
                (
                    "/.local/share/keyrings",
                    CredentialAttackType::CredentialVault,
                    "GNOME Keyring",
                ),
                // Crypto wallet extensions (T1528)
                (
                    "/metamask/",
                    CredentialAttackType::BrowserCredentials,
                    "MetaMask Wallet",
                ),
                (
                    "/phantom/",
                    CredentialAttackType::BrowserCredentials,
                    "Phantom Wallet",
                ),
                (
                    "/solflare/",
                    CredentialAttackType::BrowserCredentials,
                    "Solflare Wallet",
                ),
                (
                    "/backpack/",
                    CredentialAttackType::BrowserCredentials,
                    "Backpack Wallet",
                ),
            ];

            for (pattern, attack_type, target_name) in linux_credential_patterns {
                if path_lower.contains(pattern) {
                    let (process_name, process_path) = self.get_process_info(pid);

                    // Skip legitimate system processes
                    let legitimate_processes = [
                        "systemd",
                        "dbus-daemon",
                        "gnome-keyring",
                        "firefox",
                        "chrome",
                        "brave",
                        "chromium",
                        "code",
                        "electron",
                        "seahorse",
                    ];
                    if legitimate_processes
                        .iter()
                        .any(|p| process_name.to_lowercase().contains(p))
                    {
                        return None;
                    }

                    warn!(
                        pid = pid,
                        process = %process_name,
                        path = %path,
                        attack_type = %attack_type.as_str(),
                        "Credential file read detected"
                    );

                    let mut event = TelemetryEvent::new(
                        EventType::CredentialTheft,
                        attack_type.severity(),
                        EventPayload::CredentialTheft(CredentialTheftEvent {
                            attack_type: attack_type.as_str().to_string(),
                            mitre_technique: attack_type.mitre_technique().to_string(),
                            target: target_name.to_string(),
                            process_name: process_name.clone(),
                            pid,
                            process_path: process_path.clone(),
                            process_cmdline: String::new(), // Would need /proc/pid/cmdline read
                            username: std::env::var("USER")
                                .unwrap_or_else(|_| "unknown".to_string()),
                            blocked: false,
                            details: format!(
                                "Process '{}' (PID: {}) read credential file: {}",
                                process_name, pid, path
                            ),
                        }),
                    );

                    event.add_detection(Detection {
                        detection_type: DetectionType::CredentialTheft,
                        rule_name: format!("credential_file_access_{}", attack_type.as_str()),
                        confidence: 0.85,
                        description: format!(
                            "{}: {} accessed by {} (PID: {})",
                            attack_type.description(),
                            target_name,
                            process_name,
                            pid
                        ),
                        mitre_tactics: attack_type.mitre_tactics(),
                        mitre_techniques: vec![attack_type.mitre_technique().to_string()],
                    });

                    return Some(event);
                }
            }

            None
        }
    }

    impl Drop for FanotifyCollector {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    impl AsRawFd for FanotifyCollector {
        fn as_raw_fd(&self) -> RawFd {
            self.fd
        }
    }

    /// Start fanotify-based file monitoring (requires CAP_SYS_ADMIN).
    ///
    /// When the `onnx` feature is enabled, `scanner` is forwarded to the
    /// `PreExecutionGate` for ML-based pre-execution blocking. Pass `None`
    /// when the scanner is not available.
    #[cfg(feature = "onnx")]
    pub fn start_fanotify_monitor(
        tx: mpsc::Sender<TelemetryEvent>,
        config: AgentConfig,
        scanner: Option<Arc<crate::analyzers::onnx_scanner::OnnxScanner>>,
    ) -> Result<()> {
        let collector = match FanotifyCollector::try_new(&config, scanner) {
            Some(c) => c,
            None => return Err(anyhow::anyhow!("Fanotify not available")),
        };

        start_fanotify_event_loop(collector, tx, config)
    }

    #[cfg(not(feature = "onnx"))]
    pub fn start_fanotify_monitor(
        tx: mpsc::Sender<TelemetryEvent>,
        config: AgentConfig,
    ) -> Result<()> {
        let collector = match FanotifyCollector::try_new(&config) {
            Some(c) => c,
            None => return Err(anyhow::anyhow!("Fanotify not available")),
        };

        start_fanotify_event_loop(collector, tx, config)
    }

    /// Shared event loop for both ONNX and non-ONNX code paths.
    fn start_fanotify_event_loop(
        collector: FanotifyCollector,
        tx: mpsc::Sender<TelemetryEvent>,
        config: AgentConfig,
    ) -> Result<()> {
        // Mark paths for monitoring
        let watch_paths = FileCollector::get_watch_paths(&config);
        for path in &watch_paths {
            if Path::new(path).exists() {
                if let Err(e) = collector.mark_path(path, true) {
                    warn!(path = path, error = %e, "Failed to mark path for fanotify");
                }
            }
        }

        // Mark honeyfile directories
        for path in &config.honeyfile_paths {
            if Path::new(path).exists() {
                if let Err(e) = collector.mark_path(path, false) {
                    warn!(path = path, error = %e, "Failed to mark honeyfile path for fanotify");
                }
            }
        }

        if collector.gate.is_some() {
            info!(
                paths = ?watch_paths,
                pre_exec_blocking = true,
                "Fanotify file watcher started with pre-execution blocking"
            );
        } else {
            info!(paths = ?watch_paths, "Fanotify file watcher started (notification mode)");
        }

        // Create runtime for async operations
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        // Periodic metrics logging interval for the pre-execution gate.
        let metrics_log_interval = std::time::Duration::from_secs(60);
        let mut last_metrics_log = std::time::Instant::now();

        // Event loop
        loop {
            if let Err(e) = collector.read_events(&tx, &runtime) {
                error!(error = %e, "Fanotify read error");
                break;
            }

            // Periodically log pre-execution gate metrics.
            if let Some(ref gate) = collector.gate {
                if last_metrics_log.elapsed() >= metrics_log_interval {
                    use std::sync::atomic::Ordering;
                    let m = &gate.metrics;
                    info!(
                        total = m.total_scanned.load(Ordering::Relaxed),
                        allowed = m.allowed.load(Ordering::Relaxed),
                        blocked = m.blocked.load(Ordering::Relaxed),
                        whitelisted = m.whitelisted.load(Ordering::Relaxed),
                        timeouts = m.timeouts.load(Ordering::Relaxed),
                        errors = m.errors.load(Ordering::Relaxed),
                        "Pre-execution gate metrics"
                    );
                    last_metrics_log = std::time::Instant::now();
                }
            }

            // Sleep to prevent busy-waiting when using non-blocking IO
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        Ok(())
    }
}

// ============================================================================
// macOS FSEvents API for File System Monitoring
// ============================================================================

/// macOS-specific file system monitoring using FSEvents API
/// Provides efficient recursive directory monitoring with detailed event info
#[cfg(target_os = "macos")]
pub mod fsevents {
    use super::*;
    use std::ffi::{c_void, CStr, CString};
    use std::os::raw::c_char;
    use std::process::Command;
    use std::sync::Arc;
    use tracing::info;

    // FSEvents event flags
    const K_FS_EVENT_STREAM_EVENT_FLAG_NONE: u32 = 0x00000000;
    const K_FS_EVENT_STREAM_EVENT_FLAG_MUST_SCAN_SUB_DIRS: u32 = 0x00000001;
    const K_FS_EVENT_STREAM_EVENT_FLAG_USER_DROPPED: u32 = 0x00000002;
    const K_FS_EVENT_STREAM_EVENT_FLAG_KERNEL_DROPPED: u32 = 0x00000004;
    const K_FS_EVENT_STREAM_EVENT_FLAG_EVENT_IDS_WRAPPED: u32 = 0x00000008;
    const K_FS_EVENT_STREAM_EVENT_FLAG_HISTORY_DONE: u32 = 0x00000010;
    const K_FS_EVENT_STREAM_EVENT_FLAG_ROOT_CHANGED: u32 = 0x00000020;
    const K_FS_EVENT_STREAM_EVENT_FLAG_MOUNT: u32 = 0x00000040;
    const K_FS_EVENT_STREAM_EVENT_FLAG_UNMOUNT: u32 = 0x00000080;

    // Item-specific flags (macOS 10.7+)
    const K_FS_EVENT_STREAM_EVENT_FLAG_ITEM_CREATED: u32 = 0x00000100;
    const K_FS_EVENT_STREAM_EVENT_FLAG_ITEM_REMOVED: u32 = 0x00000200;
    const K_FS_EVENT_STREAM_EVENT_FLAG_ITEM_INODE_META_MOD: u32 = 0x00000400;
    const K_FS_EVENT_STREAM_EVENT_FLAG_ITEM_RENAMED: u32 = 0x00000800;
    const K_FS_EVENT_STREAM_EVENT_FLAG_ITEM_MODIFIED: u32 = 0x00001000;
    const K_FS_EVENT_STREAM_EVENT_FLAG_ITEM_FINDER_INFO_MOD: u32 = 0x00002000;
    const K_FS_EVENT_STREAM_EVENT_FLAG_ITEM_CHANGE_OWNER: u32 = 0x00004000;
    const K_FS_EVENT_STREAM_EVENT_FLAG_ITEM_XATTR_MOD: u32 = 0x00008000;
    const K_FS_EVENT_STREAM_EVENT_FLAG_ITEM_IS_FILE: u32 = 0x00010000;
    const K_FS_EVENT_STREAM_EVENT_FLAG_ITEM_IS_DIR: u32 = 0x00020000;
    const K_FS_EVENT_STREAM_EVENT_FLAG_ITEM_IS_SYMLINK: u32 = 0x00040000;
    const K_FS_EVENT_STREAM_EVENT_FLAG_OWN_EVENT: u32 = 0x00080000;
    const K_FS_EVENT_STREAM_EVENT_FLAG_ITEM_IS_HARDLINK: u32 = 0x00100000;
    const K_FS_EVENT_STREAM_EVENT_FLAG_ITEM_IS_LAST_HARDLINK: u32 = 0x00200000;
    const K_FS_EVENT_STREAM_EVENT_FLAG_ITEM_CLONED: u32 = 0x00400000;

    // FSEventStream creation flags
    const K_FS_EVENT_STREAM_CREATE_FLAG_NONE: u32 = 0x00000000;
    const K_FS_EVENT_STREAM_CREATE_FLAG_USE_CF_TYPES: u32 = 0x00000001;
    const K_FS_EVENT_STREAM_CREATE_FLAG_NO_DEFER: u32 = 0x00000002;
    const K_FS_EVENT_STREAM_CREATE_FLAG_WATCH_ROOT: u32 = 0x00000004;
    const K_FS_EVENT_STREAM_CREATE_FLAG_IGNORE_SELF: u32 = 0x00000008;
    const K_FS_EVENT_STREAM_CREATE_FLAG_FILE_EVENTS: u32 = 0x00000010;
    const K_FS_EVENT_STREAM_CREATE_FLAG_MARK_SELF: u32 = 0x00000020;
    const K_FS_EVENT_STREAM_CREATE_FLAG_USE_EXTENDED_DATA: u32 = 0x00000040;
    const K_FS_EVENT_STREAM_CREATE_FLAG_FULL_HISTORY: u32 = 0x00000080;

    // Core Foundation types
    type CFIndex = i64;
    type CFTimeInterval = f64;
    type CFAbsoluteTime = f64;
    type FSEventStreamEventId = u64;
    type FSEventStreamRef = *mut c_void;
    type CFRunLoopRef = *mut c_void;
    type CFStringRef = *mut c_void;
    type CFArrayRef = *mut c_void;
    type CFAllocatorRef = *mut c_void;

    const K_CF_ALLOCATOR_DEFAULT: CFAllocatorRef = std::ptr::null_mut();
    const K_FS_EVENT_STREAM_EVENT_ID_SINCE_NOW: FSEventStreamEventId = 0xFFFFFFFFFFFFFFFF;

    // FSEventStreamContext
    #[repr(C)]
    struct FSEventStreamContext {
        version: CFIndex,
        info: *mut c_void,
        retain: Option<extern "C" fn(*const c_void) -> *const c_void>,
        release: Option<extern "C" fn(*const c_void)>,
        copy_description: Option<extern "C" fn(*const c_void) -> CFStringRef>,
    }

    // FSEvents callback type
    type FSEventStreamCallback = extern "C" fn(
        FSEventStreamRef,
        *mut c_void,
        usize,
        *mut c_void,
        *const u32,
        *const FSEventStreamEventId,
    );

    // Core Foundation and FSEvents function declarations
    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFArrayCreate(
            allocator: CFAllocatorRef,
            values: *const *const c_void,
            num_values: CFIndex,
            callbacks: *const c_void,
        ) -> CFArrayRef;

        fn CFArrayGetCount(array: CFArrayRef) -> CFIndex;

        fn CFStringCreateWithCString(
            allocator: CFAllocatorRef,
            cstr: *const c_char,
            encoding: u32,
        ) -> CFStringRef;

        fn CFRunLoopGetCurrent() -> CFRunLoopRef;
        fn CFRunLoopRun();
        fn CFRunLoopStop(rl: CFRunLoopRef);
        fn CFRelease(cf: *const c_void);
    }

    #[link(name = "CoreServices", kind = "framework")]
    extern "C" {
        fn FSEventStreamCreate(
            allocator: CFAllocatorRef,
            callback: FSEventStreamCallback,
            context: *mut FSEventStreamContext,
            paths_to_watch: CFArrayRef,
            since_when: FSEventStreamEventId,
            latency: CFTimeInterval,
            flags: u32,
        ) -> FSEventStreamRef;

        fn FSEventStreamScheduleWithRunLoop(
            stream: FSEventStreamRef,
            run_loop: CFRunLoopRef,
            run_loop_mode: CFStringRef,
        );

        fn FSEventStreamStart(stream: FSEventStreamRef) -> bool;
        fn FSEventStreamStop(stream: FSEventStreamRef);
        fn FSEventStreamInvalidate(stream: FSEventStreamRef);
        fn FSEventStreamRelease(stream: FSEventStreamRef);
    }

    /// FSEvents file system event
    #[derive(Debug, Clone)]
    pub struct FSEventInfo {
        pub path: String,
        pub flags: u32,
        pub event_id: u64,
        pub is_file: bool,
        pub is_dir: bool,
        pub is_symlink: bool,
        pub created: bool,
        pub removed: bool,
        pub modified: bool,
        pub renamed: bool,
        pub xattr_modified: bool,
        pub owner_changed: bool,
    }

    impl FSEventInfo {
        fn from_raw(path: &str, flags: u32, event_id: u64) -> Self {
            Self {
                path: path.to_string(),
                flags,
                event_id,
                is_file: (flags & K_FS_EVENT_STREAM_EVENT_FLAG_ITEM_IS_FILE) != 0,
                is_dir: (flags & K_FS_EVENT_STREAM_EVENT_FLAG_ITEM_IS_DIR) != 0,
                is_symlink: (flags & K_FS_EVENT_STREAM_EVENT_FLAG_ITEM_IS_SYMLINK) != 0,
                created: (flags & K_FS_EVENT_STREAM_EVENT_FLAG_ITEM_CREATED) != 0,
                removed: (flags & K_FS_EVENT_STREAM_EVENT_FLAG_ITEM_REMOVED) != 0,
                modified: (flags & K_FS_EVENT_STREAM_EVENT_FLAG_ITEM_MODIFIED) != 0,
                renamed: (flags & K_FS_EVENT_STREAM_EVENT_FLAG_ITEM_RENAMED) != 0,
                xattr_modified: (flags & K_FS_EVENT_STREAM_EVENT_FLAG_ITEM_XATTR_MOD) != 0,
                owner_changed: (flags & K_FS_EVENT_STREAM_EVENT_FLAG_ITEM_CHANGE_OWNER) != 0,
            }
        }

        /// Convert to telemetry event type
        fn to_event_type(&self) -> EventType {
            if self.created {
                EventType::FileCreate
            } else if self.removed {
                EventType::FileDelete
            } else if self.renamed {
                EventType::FileRename
            } else if self.modified {
                EventType::FileModify
            } else {
                EventType::FileModify
            }
        }

        /// Get operation string
        fn operation(&self) -> &'static str {
            if self.created {
                "create"
            } else if self.removed {
                "delete"
            } else if self.renamed {
                "rename"
            } else if self.modified {
                "modify"
            } else if self.xattr_modified {
                "xattr_modify"
            } else if self.owner_changed {
                "chown"
            } else {
                "access"
            }
        }
    }

    /// Context passed to FSEvents callback
    struct FSEventsContext {
        tx: mpsc::Sender<TelemetryEvent>,
        config: AgentConfig,
        honeyfile_paths: Vec<String>,
        #[cfg(feature = "onnx")]
        onnx_scanner: Option<Arc<crate::analyzers::onnx_scanner::OnnxScanner>>,
        ml_feature_engine: Option<Arc<LocalMLFeatureEngine>>,
    }

    /// FSEvents callback function
    extern "C" fn fs_events_callback(
        _stream: FSEventStreamRef,
        context: *mut c_void,
        num_events: usize,
        event_paths: *mut c_void,
        event_flags: *const u32,
        event_ids: *const FSEventStreamEventId,
    ) {
        if context.is_null() {
            return;
        }

        let ctx = unsafe { &*(context as *const FSEventsContext) };

        let paths = event_paths as *const *const c_char;

        for i in 0..num_events {
            let path_ptr = unsafe { *paths.add(i) };
            let path = unsafe { CStr::from_ptr(path_ptr).to_string_lossy().to_string() };

            let flags = unsafe { *event_flags.add(i) };
            let event_id = unsafe { *event_ids.add(i) };

            let event_info = FSEventInfo::from_raw(&path, flags, event_id);

            // Skip directories unless it's a significant event
            if event_info.is_dir && !event_info.created && !event_info.removed {
                continue;
            }

            // Apply path filtering to exclude system directories
            if should_exclude_path(&path) {
                continue;
            }

            // Check if this is a honeyfile access
            let is_honeyfile = ctx.honeyfile_paths.iter().any(|hp| path.starts_with(hp));

            if is_honeyfile && !event_info.removed {
                // Get process info for the accessor
                let (pid, process_name, process_path) = get_file_accessor(&path);

                let event = TelemetryEvent::new(
                    EventType::HoneyfileAccess,
                    Severity::Critical,
                    EventPayload::Honeyfile(HoneyfileEvent {
                        path: path.clone(),
                        operation: event_info.operation().to_string(),
                        pid,
                        process_name,
                        process_path,
                        process_sha256: Vec::new(),
                    }),
                );

                let _ = ctx.tx.blocking_send(event);
                continue;
            }

            // Regular file event
            let (pid, process_name, _) = get_file_accessor(&path);

            // Compute hash and entropy only if not in lightweight mode
            let skip_expensive = ctx.config.collector_tuning.skip_expensive_analysis;
            let (sha256, entropy, size) = if skip_expensive {
                let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                (Vec::new(), 0.0, size)
            } else if Path::new(&path).exists() {
                // Run async hash computation in a blocking context
                let hash_path = path.clone();
                match std::thread::spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .ok()?;
                    rt.block_on(async { crate::analyzers::hash_file(&hash_path).await.ok() })
                })
                .join()
                {
                    Ok(Some((hash, ent))) => {
                        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                        (hash, ent, size)
                    }
                    _ => (Vec::new(), 0.0, 0),
                }
            } else {
                (Vec::new(), 0.0, 0)
            };

            let file_type = detect_file_type(&path);

            let file_event = FileEvent {
                path: path.clone(),
                old_path: None,
                operation: event_info.operation().to_string(),
                pid,
                process_name,
                sha256,
                size,
                entropy,
                file_type,
            };

            let mut event = TelemetryEvent::new(
                event_info.to_event_type(),
                super::FileCollector::browser_cache_event_severity(&path),
                EventPayload::File(file_event.clone()),
            );
            super::FileCollector::annotate_browser_cache_event(&mut event, &path);

            // Run ML scanners if enabled
            #[cfg(feature = "onnx")]
            if let Some(scanner) = &ctx.onnx_scanner {
                if event_info.created || event_info.modified {
                    if crate::analyzers::onnx_scanner::is_executable_file(Path::new(&path)) {
                        if let Ok(result) = scanner.scan_file(Path::new(&path)) {
                            if result.is_malicious {
                                event.add_detection(Detection {
                                    detection_type: DetectionType::Ml,
                                    rule_name: "ONNX_ML_MALWARE".to_string(),
                                    confidence: result.confidence,
                                    description: format!(
                                        "ONNX ML model detected malware with {:.1}% confidence",
                                        result.confidence * 100.0
                                    ),
                                    mitre_tactics: vec!["execution".to_string()],
                                    mitre_techniques: vec!["T1204".to_string()],
                                });

                                if result.confidence >= 0.9 {
                                    event.severity = Severity::Critical;
                                } else if result.confidence >= 0.7 {
                                    event.severity = Severity::High;
                                } else {
                                    event.severity = Severity::Medium;
                                }
                            }
                        }
                    }
                }
            }

            // Run feature-based ML scanner
            if let Some(engine) = &ctx.ml_feature_engine {
                if event_info.created || event_info.modified {
                    super::FileCollector::enrich_event_with_feature_ml(
                        &mut event,
                        Path::new(&path),
                        &ctx.config,
                        engine,
                    );
                }
            }

            let _ = ctx.tx.blocking_send(event);
        }
    }

    /// Check if a path should be excluded from monitoring
    fn should_exclude_path(path: &str) -> bool {
        const EXCLUDED_PREFIXES: &[&str] = &[
            "/System/Library/Caches/",
            "/Library/Caches/",
            "/private/var/folders/",
            "/dev/",
            "/private/var/db/",
            "/private/var/log/",
            "/.Spotlight-V100/",
            "/.fseventsd/",
            "/.DocumentRevisions-V100/",
            "/.TemporaryItems/",
            "/.Trashes/",
        ];

        const EXCLUDED_EXTENSIONS: &[&str] =
            &[".tmp", ".temp", ".cache", ".DS_Store", ".localized"];

        // Check excluded prefixes
        for prefix in EXCLUDED_PREFIXES {
            if path.starts_with(prefix) {
                return true;
            }
        }

        // Check excluded extensions
        if let Some(ext) = Path::new(path).extension() {
            let ext_str = ext.to_string_lossy().to_lowercase();
            for excluded_ext in EXCLUDED_EXTENSIONS {
                if ext_str == excluded_ext.trim_start_matches('.') {
                    return true;
                }
            }
        }

        false
    }

    /// Try to determine which process accessed a file using lsof
    fn get_file_accessor(path: &str) -> (u32, String, String) {
        // Try lsof to find who has the file open
        let output = Command::new("lsof").args(["-F", "pcn", path]).output();

        match output {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let mut pid = 0u32;
                let mut name = String::new();

                for line in stdout.lines() {
                    if line.starts_with('p') {
                        pid = line[1..].parse().unwrap_or(0);
                    } else if line.starts_with('c') {
                        name = line[1..].to_string();
                    }
                }

                // Get process path
                let proc_path = if pid > 0 {
                    super::super::process::macos_process::get_process_path(pid as i32)
                        .unwrap_or_default()
                } else {
                    String::new()
                };

                (pid, name, proc_path)
            }
            _ => (0, String::new(), String::new()),
        }
    }

    /// Detect file type from path
    fn detect_file_type(path: &str) -> String {
        let path = Path::new(path);
        match path.extension().and_then(|e| e.to_str()) {
            Some("exe") | Some("app") | Some("dylib") | Some("so") => "executable".to_string(),
            Some("sh") | Some("py") | Some("rb") | Some("pl") => "script".to_string(),
            Some("plist") | Some("xml") | Some("json") | Some("yaml") | Some("yml") => {
                "config".to_string()
            }
            Some("zip") | Some("tar") | Some("gz") | Some("bz2") | Some("dmg") => {
                "archive".to_string()
            }
            Some("doc") | Some("docx") | Some("pdf") | Some("xls") | Some("xlsx") => {
                "document".to_string()
            }
            _ => "unknown".to_string(),
        }
    }

    /// Start FSEvents-based file monitoring
    #[cfg(not(feature = "onnx"))]
    pub fn start_fsevents_monitor(
        tx: mpsc::Sender<TelemetryEvent>,
        config: AgentConfig,
        _scanner: Option<()>,
        feature_engine: Option<Arc<LocalMLFeatureEngine>>,
    ) -> Result<()> {
        start_fsevents_monitor_impl(tx, config, None, feature_engine)
    }

    #[cfg(feature = "onnx")]
    pub fn start_fsevents_monitor(
        tx: mpsc::Sender<TelemetryEvent>,
        config: AgentConfig,
        scanner: Option<Arc<crate::analyzers::onnx_scanner::OnnxScanner>>,
        feature_engine: Option<Arc<LocalMLFeatureEngine>>,
    ) -> Result<()> {
        start_fsevents_monitor_impl(tx, config, scanner, feature_engine)
    }

    fn start_fsevents_monitor_impl(
        tx: mpsc::Sender<TelemetryEvent>,
        config: AgentConfig,
        #[cfg(feature = "onnx")] scanner: Option<Arc<crate::analyzers::onnx_scanner::OnnxScanner>>,
        #[cfg(not(feature = "onnx"))] _scanner: Option<()>,
        feature_engine: Option<Arc<LocalMLFeatureEngine>>,
    ) -> Result<()> {
        // Determine paths to watch based on performance profile
        let paths_to_watch =
            if config.performance_profile == crate::config::PerformanceProfile::Lightweight {
                vec!["/tmp", "/Users"]
            } else if config.performance_profile == crate::config::PerformanceProfile::Balanced {
                vec!["/Applications", "/Users", "/tmp", "/usr/local"]
            } else {
                // Aggressive mode - watch everything
                vec![
                    "/Applications",
                    "/Library",
                    "/System/Library",
                    "/Users",
                    "/private/var",
                    "/tmp",
                    "/usr/local",
                ]
            };

        info!(
            profile = ?config.performance_profile,
            paths = ?paths_to_watch,
            "Initializing FSEvents file monitor"
        );

        let context = FSEventsContext {
            tx,
            config: config.clone(),
            honeyfile_paths: config.honeyfile_paths.clone(),
            #[cfg(feature = "onnx")]
            onnx_scanner: scanner,
            ml_feature_engine: feature_engine,
        };
        let context_ptr = Box::into_raw(Box::new(context));

        // Create CFString for each path
        let mut cf_paths: Vec<CFStringRef> = Vec::new();
        for path in &paths_to_watch {
            let c_path = CString::new(*path).map_err(|e| anyhow::anyhow!("Invalid path: {}", e))?;
            let cf_path = unsafe {
                CFStringCreateWithCString(K_CF_ALLOCATOR_DEFAULT, c_path.as_ptr(), 0x08000100)
                // kCFStringEncodingUTF8
            };
            if !cf_path.is_null() {
                cf_paths.push(cf_path);
            }
        }

        if cf_paths.is_empty() {
            unsafe {
                drop(Box::from_raw(context_ptr));
            }
            return Err(anyhow::anyhow!("No valid paths to watch"));
        }

        // Create CFArray of paths
        let paths_array = unsafe {
            CFArrayCreate(
                K_CF_ALLOCATOR_DEFAULT,
                cf_paths.as_ptr() as *const *const c_void,
                cf_paths.len() as CFIndex,
                std::ptr::null(),
            )
        };

        if paths_array.is_null() {
            // Clean up CF strings
            for cf_path in cf_paths {
                unsafe { CFRelease(cf_path as *const c_void) };
            }
            unsafe {
                drop(Box::from_raw(context_ptr));
            }
            return Err(anyhow::anyhow!("Failed to create paths array"));
        }

        // Create context structure
        let mut ctx = FSEventStreamContext {
            version: 0,
            info: context_ptr as *mut c_void,
            retain: None,
            release: None,
            copy_description: None,
        };

        // Create event stream with file-level events
        // IGNORE_SELF prevents our own modifications from triggering events
        let flags = K_FS_EVENT_STREAM_CREATE_FLAG_FILE_EVENTS
            | K_FS_EVENT_STREAM_CREATE_FLAG_NO_DEFER
            | K_FS_EVENT_STREAM_CREATE_FLAG_WATCH_ROOT
            | K_FS_EVENT_STREAM_CREATE_FLAG_IGNORE_SELF;

        // Latency controls event batching - 2 seconds is recommended for production
        let latency = if config.performance_profile == crate::config::PerformanceProfile::Aggressive
        {
            0.5 // 500ms for aggressive mode
        } else {
            2.0 // 2 seconds for balanced/lightweight
        };

        let stream = unsafe {
            FSEventStreamCreate(
                K_CF_ALLOCATOR_DEFAULT,
                fs_events_callback,
                &mut ctx,
                paths_array,
                K_FS_EVENT_STREAM_EVENT_ID_SINCE_NOW,
                latency,
                flags,
            )
        };

        if stream.is_null() {
            // Clean up paths array
            unsafe { CFRelease(paths_array as *const c_void) };
            for cf_path in cf_paths {
                unsafe { CFRelease(cf_path as *const c_void) };
            }
            unsafe {
                drop(Box::from_raw(context_ptr));
            }
            return Err(anyhow::anyhow!("Failed to create FSEventStream"));
        }

        // Get kCFRunLoopDefaultMode string
        let mode = unsafe {
            CFStringCreateWithCString(
                K_CF_ALLOCATOR_DEFAULT,
                b"kCFRunLoopDefaultMode\0".as_ptr() as *const c_char,
                0x08000100,
            )
        };

        // Schedule with run loop
        let run_loop = unsafe { CFRunLoopGetCurrent() };
        unsafe {
            FSEventStreamScheduleWithRunLoop(stream, run_loop, mode);
        }

        // Start the stream
        if !unsafe { FSEventStreamStart(stream) } {
            unsafe {
                FSEventStreamInvalidate(stream);
                FSEventStreamRelease(stream);
                CFRelease(paths_array as *const c_void);
                CFRelease(mode as *const c_void);
            }
            for cf_path in cf_paths {
                unsafe { CFRelease(cf_path as *const c_void) };
            }
            unsafe {
                drop(Box::from_raw(context_ptr));
            }
            return Err(anyhow::anyhow!("Failed to start FSEventStream"));
        }

        info!(paths = ?paths_to_watch, "FSEvents file watcher started");

        // Run the event loop (blocking)
        unsafe { CFRunLoopRun() };

        // Cleanup (if we ever exit the run loop)
        unsafe {
            FSEventStreamStop(stream);
            FSEventStreamInvalidate(stream);
            FSEventStreamRelease(stream);
            CFRelease(paths_array as *const c_void);
            CFRelease(mode as *const c_void);
        }

        for cf_path in cf_paths {
            unsafe { CFRelease(cf_path as *const c_void) };
        }
        unsafe {
            drop(Box::from_raw(context_ptr));
        }

        Ok(())
    }

    /// Check if a file has quarantine xattr (downloaded from internet)
    pub fn has_quarantine_xattr(path: &str) -> bool {
        use std::process::Command;

        let output = Command::new("xattr")
            .args(["-p", "com.apple.quarantine", path])
            .output();

        match output {
            Ok(out) => out.status.success(),
            Err(_) => false,
        }
    }

    /// Get quarantine info for a file
    pub fn get_quarantine_info(path: &str) -> Option<QuarantineInfo> {
        use std::process::Command;

        let output = Command::new("xattr")
            .args(["-p", "com.apple.quarantine", path])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let data = String::from_utf8_lossy(&output.stdout);
        let parts: Vec<&str> = data.trim().split(';').collect();

        if parts.len() >= 3 {
            Some(QuarantineInfo {
                flags: parts.get(0).unwrap_or(&"").to_string(),
                timestamp: parts.get(1).unwrap_or(&"").to_string(),
                download_agent: parts.get(2).unwrap_or(&"").to_string(),
                origin_url: parts.get(3).map(|s| s.to_string()),
            })
        } else {
            None
        }
    }

    /// Quarantine extended attribute information
    #[derive(Debug, Clone)]
    pub struct QuarantineInfo {
        pub flags: String,
        pub timestamp: String,
        pub download_agent: String,
        pub origin_url: Option<String>,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_browser_cache_paths_are_low_signal() {
        let paths = [
            r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Cache\Cache_Data\f_000123",
            r"C:\Users\alice\AppData\Local\Microsoft\Edge\User Data\Default\Code Cache\js\index",
            r"C:\Users\alice\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\GPUCache\data_0",
            "/home/alice/.cache/mozilla/firefox/abcd.default-release/cache2/entries/123ABC",
            "/Users/alice/Library/Caches/com.apple.Safari/WebKitCache/Version 16/Records/record",
            "/Users/alice/Library/Safari/Favicon Cache/favicons.db",
            "/Users/alice/Library/Application Support/Google/Chrome/Default/Cookies-journal",
            "/Users/alice/Library/Application Support/Google/Chrome/Default/Secure Preferences",
            "/Users/alice/Library/Application Support/Google/Chrome/Default/Network Persistent State",
            "/Users/alice/Library/Application Support/Brave Software/Brave-Browser/Default/Reporting and NEL-journal",
        ];

        for path in paths {
            assert!(
                FileCollector::is_common_browser_cache_path(path),
                "expected browser cache path: {}",
                path
            );
            assert_eq!(
                FileCollector::browser_cache_event_severity(path),
                Severity::Low
            );
        }
    }

    #[test]
    fn browser_credential_and_regular_files_are_not_cache_noise() {
        let paths = [
            r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Login Data",
            r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Cookies",
            "/home/alice/.mozilla/firefox/abcd.default-release/logins.json",
            "/home/alice/.mozilla/firefox/abcd.default-release/key4.db",
            "/home/alice/.ssh/id_ed25519",
            "/tmp/payload.bin",
        ];

        for path in paths {
            assert!(
                !FileCollector::is_common_browser_cache_path(path),
                "credential or regular path must not be treated as cache noise: {}",
                path
            );
            assert_eq!(
                FileCollector::browser_cache_event_severity(path),
                Severity::Info
            );
        }
    }
}
