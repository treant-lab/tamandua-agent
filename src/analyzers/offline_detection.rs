//! Autonomous Offline Detection Pipeline
//!
//! When the agent cannot reach the backend ML service this module provides
//! local malware detection using:
//!
//! - **ONNX Runtime** -- runs the Malware-SMELL model locally for ML inference.
//! - **YARA rules**   -- fast signature-based scanning that is always available.
//!
//! Verdicts produced while offline are queued (bounded) and automatically
//! synchronized with the backend once connectivity is restored.
//!
//! ## Design decisions
//!
//! * All ONNX operations run on a blocking thread via `tokio::task::spawn_blocking`
//!   to avoid stalling the async event loop.
//! * Backend availability is cached for `backend_check_interval` seconds so we do
//!   not spam the server with health checks.
//! * The verdict queue is bounded (`verdict_queue_max`); when full the oldest
//!   entries are dropped.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::Path;
#[cfg(feature = "onnx")]
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
#[cfg(feature = "onnx")]
use tracing::error;
use tracing::{debug, info, warn};

#[cfg(feature = "onnx")]
use super::onnx_inference::{OnnxInferenceConfig, OnnxInferenceEngine};

#[cfg(feature = "yara")]
use super::yara::YaraScanner;

use crate::collectors::{Detection, DetectionType};

/// Feature-agnostic ML result used internally by [`OfflineDetector`].
///
/// This decouples the offline detection pipeline from the concrete
/// `InferenceResult` type which only exists when the `onnx` feature is
/// enabled.
#[derive(Debug, Clone)]
struct MlResult {
    /// Predicted class label.
    predicted_class: String,
    /// Confidence score in [0.0, 1.0].
    confidence: f32,
    /// Whether the model considers the file malicious.
    is_malicious: bool,
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Combined verdict from ML and YARA analysis performed offline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineVerdict {
    /// Wall-clock time the analysis was performed.
    pub timestamp: DateTime<Utc>,
    /// Absolute path to the analysed file.
    pub file_path: String,
    /// SHA-256 hex digest of the file.
    pub file_hash: String,
    /// File size in bytes.
    pub file_size: u64,
    /// ML confidence score (0.0-1.0), `None` when ML was not available.
    pub ml_score: Option<f32>,
    /// ML predicted class label (e.g. "trojan"), `None` when ML was not available.
    pub ml_verdict: Option<String>,
    /// Names of YARA rules that matched.
    pub yara_matches: Vec<String>,
    /// Final combined verdict.
    pub combined_verdict: Verdict,
    /// Version string of the ONNX model that produced the ML score.
    pub model_version: String,
    /// Version string of the YARA rule set.
    pub rules_version: String,
}

/// Final verdict for a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// File appears clean.
    Clean,
    /// Low-confidence detection -- needs further analysis.
    Suspicious,
    /// High-confidence malware detection.
    Malicious,
    /// Analysis could not be completed (model missing, file unreadable, ...).
    Unknown,
}

/// Re-export the canonical config type from the config module so users of
/// this module do not need to import from two places.
pub use crate::config::OfflineDetectionConfig;

/// Aggregate statistics for the offline detector.
#[derive(Debug, Clone, Default)]
pub struct OfflineDetectorStats {
    pub files_analyzed: u64,
    pub ml_inferences: u64,
    pub yara_scans: u64,
    pub malicious_detected: u64,
    pub suspicious_detected: u64,
    pub verdicts_queued: u64,
    pub verdicts_synced: u64,
    pub backend_checks: u64,
}

// ---------------------------------------------------------------------------
// OfflineDetector
// ---------------------------------------------------------------------------

/// Orchestrator for local (offline) malware detection.
///
/// Safe to share across threads via `Arc<OfflineDetector>`.
pub struct OfflineDetector {
    // -- ML engine (behind a RwLock so we can hot-reload) --------------------
    #[cfg(feature = "onnx")]
    onnx_engine: RwLock<OnnxInferenceEngine>,
    #[cfg(not(feature = "onnx"))]
    _onnx_placeholder: (),

    // -- YARA scanner --------------------------------------------------------
    #[cfg(feature = "yara")]
    yara_scanner: Arc<YaraScanner>,
    #[cfg(not(feature = "yara"))]
    _yara_placeholder: (),

    // -- Verdict queue -------------------------------------------------------
    verdict_queue: RwLock<VecDeque<OfflineVerdict>>,
    verdict_queue_max: usize,

    // -- Backend availability cache ------------------------------------------
    backend_available: AtomicBool,
    last_backend_check: RwLock<Option<Instant>>,
    backend_check_interval: Duration,

    // -- Versioning ----------------------------------------------------------
    model_version: RwLock<String>,
    rules_version: RwLock<String>,

    // -- Config & stats ------------------------------------------------------
    config: OfflineDetectionConfig,
    stats: RwLock<OfflineDetectorStats>,
}

impl OfflineDetector {
    /// Create a new offline detector.
    ///
    /// Loads the ONNX model and YARA rules from the paths specified in
    /// `config`.  Missing files are handled gracefully (the corresponding
    /// engine is simply disabled).
    pub async fn new(config: OfflineDetectionConfig) -> Self {
        info!(
            enabled = config.enabled,
            onnx_model = %config.onnx_model_path,
            yara_dir = %config.yara_rules_dir,
            "Initializing offline detector"
        );

        // -- ONNX engine ----------------------------------------------------
        #[cfg(feature = "onnx")]
        let onnx_engine = {
            use super::onnx_inference::ModelInputFormat;
            use crate::config::LocalModelType;

            let input_format = match config.model_type {
                LocalModelType::Smell => ModelInputFormat::ImageNCHW,
                LocalModelType::Transformer | LocalModelType::Ensemble => {
                    ModelInputFormat::RawBytes1D
                }
            };

            let onnx_cfg = OnnxInferenceConfig {
                model_path: PathBuf::from(&config.onnx_model_path),
                image_size: config.onnx_image_size,
                input_format,
                max_input_length: config.max_input_length,
                ..Default::default()
            };

            info!(
                model_type = ?config.model_type,
                input_format = ?input_format,
                "ONNX engine configured for model type"
            );

            RwLock::new(OnnxInferenceEngine::new(onnx_cfg))
        };

        // -- YARA scanner ----------------------------------------------------
        #[cfg(feature = "yara")]
        let yara_scanner = {
            let scanner = Arc::new(YaraScanner::new());
            // Load all .yar / .yara files from the rules directory.
            let rules_dir = Path::new(&config.yara_rules_dir);
            if rules_dir.is_dir() {
                let mut rule_files: Vec<(String, String)> = Vec::new();
                if let Ok(entries) = std::fs::read_dir(rules_dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        let ext = path
                            .extension()
                            .map(|e| e.to_string_lossy().to_lowercase())
                            .unwrap_or_default();
                        if ext == "yar" || ext == "yara" {
                            match std::fs::read_to_string(&path) {
                                Ok(content) => {
                                    let name = path
                                        .file_stem()
                                        .map(|s| s.to_string_lossy().to_string())
                                        .unwrap_or_default();
                                    rule_files.push((name, content));
                                }
                                Err(e) => {
                                    warn!(
                                        path = %path.display(),
                                        error = %e,
                                        "Failed to read YARA rule file"
                                    );
                                }
                            }
                        }
                    }
                }
                if !rule_files.is_empty() {
                    match scanner.load_rules(rule_files).await {
                        Ok(n) => info!(count = n, "Loaded YARA rules for offline detection"),
                        Err(e) => warn!(error = %e, "Failed to compile YARA rules"),
                    }
                } else {
                    info!(dir = %config.yara_rules_dir, "No YARA rule files found");
                }
            } else {
                info!(dir = %config.yara_rules_dir, "YARA rules directory does not exist");
            }
            scanner
        };

        Self {
            #[cfg(feature = "onnx")]
            onnx_engine,
            #[cfg(not(feature = "onnx"))]
            _onnx_placeholder: (),

            #[cfg(feature = "yara")]
            yara_scanner,
            #[cfg(not(feature = "yara"))]
            _yara_placeholder: (),

            verdict_queue: RwLock::new(VecDeque::new()),
            verdict_queue_max: config.verdict_queue_max,

            backend_available: AtomicBool::new(false),
            last_backend_check: RwLock::new(None),
            backend_check_interval: Duration::from_secs(config.backend_check_interval_secs),

            model_version: RwLock::new("unknown".to_string()),
            rules_version: RwLock::new("unknown".to_string()),

            config,
            stats: RwLock::new(OfflineDetectorStats::default()),
        }
    }

    /// Returns `true` when the backend ML service is believed to be reachable.
    ///
    /// The check is cached for `backend_check_interval` seconds.  When the
    /// cache is stale a new HTTP HEAD request is made against the backend
    /// health endpoint.
    pub async fn is_backend_available(&self, backend_url: &str) -> bool {
        // Fast path: return cached value if still fresh.
        {
            let last = self.last_backend_check.read();
            if let Some(ts) = *last {
                if ts.elapsed() < self.backend_check_interval {
                    return self.backend_available.load(Ordering::Relaxed);
                }
            }
        }

        // Slow path: actually check.
        self.stats.write().backend_checks += 1;
        let available = Self::check_backend(backend_url).await;

        self.backend_available.store(available, Ordering::Relaxed);
        *self.last_backend_check.write() = Some(Instant::now());

        if !available {
            debug!(url = %backend_url, "Backend ML service unreachable -- using offline detection");
        }

        available
    }

    /// Force-set the backend availability flag (useful when the transport layer
    /// already knows the connection state).
    pub fn set_backend_available(&self, available: bool) {
        self.backend_available.store(available, Ordering::Relaxed);
        *self.last_backend_check.write() = Some(Instant::now());
    }

    /// Analyse a file using local ML and YARA.
    ///
    /// The combined verdict is queued for later sync with the backend.
    /// Returns a list of [`Detection`]s suitable for attaching to a
    /// `TelemetryEvent`.
    pub async fn analyze_file(&self, path: &Path) -> Result<(OfflineVerdict, Vec<Detection>)> {
        if !self.config.enabled {
            anyhow::bail!("Offline detection is disabled");
        }

        // Read file
        let file_path_str = path.display().to_string();
        let metadata =
            std::fs::metadata(path).with_context(|| format!("Cannot stat {}", file_path_str))?;

        if metadata.len() > self.config.max_file_size {
            debug!(
                path = %file_path_str,
                size = metadata.len(),
                max = self.config.max_file_size,
                "File too large for offline scanning"
            );
            anyhow::bail!("File exceeds max_file_size");
        }

        let data = tokio::fs::read(path)
            .await
            .with_context(|| format!("Cannot read {}", file_path_str))?;

        // SHA-256
        let file_hash = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(&data))
        };

        self.stats.write().files_analyzed += 1;

        // -- ML inference (on blocking thread) --------------------------------
        let ml_result = self.run_ml(&data).await;

        // -- YARA scanning ----------------------------------------------------
        let yara_matches = self.run_yara(&data).await;

        // -- Fallback detection (when YARA & ONNX disabled) -------------------
        let fallback_result = if ml_result.is_none() && yara_matches.is_empty() {
            self.run_fallback_detection(&data, &file_path_str).await
        } else {
            None
        };

        // -- Combine verdicts -------------------------------------------------
        let (combined_verdict, detections) = self.combine_verdicts(
            &ml_result,
            &yara_matches,
            &fallback_result,
            &file_path_str,
            &file_hash,
        );

        let verdict = OfflineVerdict {
            timestamp: Utc::now(),
            file_path: file_path_str,
            file_hash,
            file_size: metadata.len(),
            ml_score: ml_result.as_ref().map(|r| r.confidence),
            ml_verdict: ml_result.as_ref().map(|r| r.predicted_class.clone()),
            yara_matches: yara_matches.iter().map(|n| n.clone()).collect(),
            combined_verdict,
            model_version: self.model_version.read().clone(),
            rules_version: self.rules_version.read().clone(),
        };

        // Queue verdict for sync.
        self.enqueue_verdict(verdict.clone());

        // Stats
        {
            let mut s = self.stats.write();
            match combined_verdict {
                Verdict::Malicious => s.malicious_detected += 1,
                Verdict::Suspicious => s.suspicious_detected += 1,
                _ => {}
            }
        }

        Ok((verdict, detections))
    }

    /// Run only the local YARA layer for a file.
    ///
    /// This is used while the backend is reachable so the agent still applies
    /// fast signature rules distributed by the cloud without also running local
    /// ML inference.
    pub async fn analyze_file_yara_only(&self, path: &Path) -> Result<Vec<Detection>> {
        if !self.config.enabled {
            anyhow::bail!("Offline detection is disabled");
        }

        let file_path_str = path.display().to_string();
        let metadata =
            std::fs::metadata(path).with_context(|| format!("Cannot stat {}", file_path_str))?;

        if metadata.len() > self.config.max_file_size {
            debug!(
                path = %file_path_str,
                size = metadata.len(),
                max = self.config.max_file_size,
                "File too large for YARA scanning"
            );
            anyhow::bail!("File exceeds max_file_size");
        }

        let data = tokio::fs::read(path)
            .await
            .with_context(|| format!("Cannot read {}", file_path_str))?;

        let file_hash = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(&data))
        };

        let yara_matches = self.run_yara(&data).await;
        if yara_matches.is_empty() {
            return Ok(Vec::new());
        }

        let (_verdict, detections) =
            self.combine_verdicts(&None, &yara_matches, &None, &file_path_str, &file_hash);

        Ok(detections)
    }

    /// Analyse raw bytes (e.g. from memory or network capture).
    pub async fn analyze_bytes(
        &self,
        data: &[u8],
        label: &str,
    ) -> Result<(OfflineVerdict, Vec<Detection>)> {
        if !self.config.enabled {
            anyhow::bail!("Offline detection is disabled");
        }

        let file_hash = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(data))
        };

        self.stats.write().files_analyzed += 1;

        let ml_result = self.run_ml(data).await;
        let yara_matches = self.run_yara(data).await;

        // Fallback detection for bytes
        let fallback_result = if ml_result.is_none() && yara_matches.is_empty() {
            self.run_fallback_detection(data, label).await
        } else {
            None
        };

        let (combined_verdict, detections) = self.combine_verdicts(
            &ml_result,
            &yara_matches,
            &fallback_result,
            label,
            &file_hash,
        );

        let verdict = OfflineVerdict {
            timestamp: Utc::now(),
            file_path: label.to_string(),
            file_hash,
            file_size: data.len() as u64,
            ml_score: ml_result.as_ref().map(|r| r.confidence),
            ml_verdict: ml_result.as_ref().map(|r| r.predicted_class.clone()),
            yara_matches: yara_matches.iter().map(|n| n.clone()).collect(),
            combined_verdict,
            model_version: self.model_version.read().clone(),
            rules_version: self.rules_version.read().clone(),
        };

        self.enqueue_verdict(verdict.clone());

        Ok((verdict, detections))
    }

    /// Return pending verdicts for sync without removing them from the queue.
    ///
    /// Call [`ack_verdicts`] only after the transport has accepted an
    /// `offline_verdict_sync` telemetry event. Keeping this as peek/ack avoids
    /// dropping offline detections during reconnect churn.
    pub fn peek_verdicts(&self, limit: usize) -> Vec<OfflineVerdict> {
        if limit == 0 {
            return Vec::new();
        }

        self.verdict_queue
            .read()
            .iter()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Acknowledge verdicts already accepted by the telemetry transport.
    pub fn ack_verdicts(&self, count: usize) -> usize {
        if count == 0 {
            return 0;
        }

        let mut q = self.verdict_queue.write();
        let acked = count.min(q.len());
        for _ in 0..acked {
            q.pop_front();
        }
        self.stats.write().verdicts_synced += acked as u64;
        if acked > 0 {
            info!(
                count = acked,
                remaining = q.len(),
                "Acked offline verdict sync"
            );
        }
        acked
    }

    /// Drain the verdict queue and return all pending verdicts for sync.
    ///
    /// Prefer [`peek_verdicts`] + [`ack_verdicts`] for transport paths. This
    /// method remains for callers/tests that explicitly need destructive drain.
    pub fn drain_verdicts(&self) -> Vec<OfflineVerdict> {
        let mut q = self.verdict_queue.write();
        let drained: Vec<OfflineVerdict> = q.drain(..).collect();
        self.stats.write().verdicts_synced += drained.len() as u64;
        if !drained.is_empty() {
            info!(
                count = drained.len(),
                "Draining offline verdict queue for sync"
            );
        }
        drained
    }

    /// Number of verdicts currently queued.
    pub fn queued_verdict_count(&self) -> usize {
        self.verdict_queue.read().len()
    }

    /// Get a snapshot of the detector statistics.
    pub fn get_stats(&self) -> OfflineDetectorStats {
        self.stats.read().clone()
    }

    /// Hot-reload the ONNX model from new bytes.
    pub fn update_model(&self, model_bytes: &[u8]) -> Result<()> {
        #[cfg(feature = "onnx")]
        {
            let mut engine = self.onnx_engine.write();
            engine.reload_from_bytes(model_bytes)?;
            info!("Offline detector ONNX model updated");
        }
        #[cfg(not(feature = "onnx"))]
        {
            let _ = model_bytes;
            warn!("Cannot update ONNX model -- feature not compiled in");
        }
        Ok(())
    }

    /// Hot-reload YARA rules from raw bytes (concatenated rule text).
    pub async fn update_rules(&self, rules_text: &str, name: &str) -> Result<()> {
        #[cfg(feature = "yara")]
        {
            self.yara_scanner
                .add_rule(name.to_string(), rules_text.to_string())
                .await?;
            info!(name = %name, "Offline detector YARA rules updated");
        }
        #[cfg(not(feature = "yara"))]
        {
            let _ = (rules_text, name);
            warn!("Cannot update YARA rules -- feature not compiled in");
        }
        Ok(())
    }

    /// Whether ML inference is available.
    pub fn has_ml(&self) -> bool {
        #[cfg(feature = "onnx")]
        {
            self.onnx_engine.read().is_operational()
        }
        #[cfg(not(feature = "onnx"))]
        {
            false
        }
    }

    /// Whether YARA scanning is available.
    pub fn has_yara(&self) -> bool {
        #[cfg(feature = "yara")]
        {
            // Use try_lock to avoid blocking; if we can't acquire assume true.
            true
        }
        #[cfg(not(feature = "yara"))]
        {
            false
        }
    }

    // =======================================================================
    // Private helpers
    // =======================================================================

    /// Run ML inference on a blocking thread.
    ///
    /// Returns a feature-agnostic [`MlResult`] so callers do not need to
    /// care about whether the `onnx` feature is compiled in.
    async fn run_ml(&self, data: &[u8]) -> Option<MlResult> {
        #[cfg(feature = "onnx")]
        {
            let data = data.to_vec();
            // We grab the lock inside the blocking task to avoid holding it
            // across the await point.
            let engine_ptr = &self.onnx_engine as *const RwLock<OnnxInferenceEngine>;
            // SAFETY: `self` is Arc-wrapped and lives as long as the task.
            let engine_ref = unsafe { &*engine_ptr };

            let result = tokio::task::spawn_blocking(move || {
                let mut guard = engine_ref.write();
                guard.predict(&data)
            })
            .await;

            match result {
                Ok(Some(r)) => {
                    self.stats.write().ml_inferences += 1;
                    Some(MlResult {
                        predicted_class: r.predicted_class,
                        confidence: r.confidence,
                        is_malicious: r.is_malicious,
                    })
                }
                Ok(None) => None,
                Err(e) => {
                    error!(error = %e, "ML inference task panicked");
                    None
                }
            }
        }

        #[cfg(not(feature = "onnx"))]
        {
            let _ = data;
            None
        }
    }

    /// Run YARA scanning.
    async fn run_yara(&self, data: &[u8]) -> Vec<String> {
        #[cfg(feature = "yara")]
        {
            match self.yara_scanner.scan_bytes(data).await {
                Ok(matches) => {
                    self.stats.write().yara_scans += 1;
                    matches.into_iter().map(|m| m.rule_name).collect()
                }
                Err(e) => {
                    warn!(error = %e, "YARA scan failed");
                    Vec::new()
                }
            }
        }

        #[cfg(not(feature = "yara"))]
        {
            let _ = data;
            Vec::new()
        }
    }

    /// Entropy-based fallback detection when YARA and ONNX are unavailable.
    ///
    /// Uses heuristics:
    /// - High entropy (> 7.2) indicates encryption/packing
    /// - Suspicious patterns (MZ header with high entropy)
    /// - File size anomalies
    async fn run_fallback_detection(&self, data: &[u8], file_path: &str) -> Option<MlResult> {
        if is_low_signal_entropy_path(file_path) {
            return None;
        }

        // Calculate Shannon entropy
        let mut counts = [0u64; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let entropy: f64 = counts
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f64 / len;
                -p * p.log2()
            })
            .sum();

        // High entropy + PE/ELF header = suspicious
        let is_executable = data.len() > 4
            && (
                (data[0] == b'M' && data[1] == b'Z') || // PE
            (data[0] == 0x7F && data[1] == b'E' && data[2] == b'L' && data[3] == b'F')
                // ELF
            );

        let is_suspicious = (entropy > 7.2 && is_executable) || // Packed/encrypted executable
                           (entropy > 7.7 && data.len() < 50_000 && has_suspicious_entropy_extension(file_path)); // Small high-entropy payload-like file

        if is_suspicious {
            info!(
                path = %file_path,
                entropy = %entropy,
                size = data.len(),
                "Fallback detection: high entropy file"
            );

            Some(MlResult {
                predicted_class: "suspicious".to_string(),
                confidence: if entropy > 7.5 { 0.7 } else { 0.5 },
                is_malicious: false, // Mark as suspicious, not malicious
            })
        } else {
            None
        }
    }

    /// Combine ML and YARA results into a final verdict plus a list of
    /// `Detection` structs for the telemetry event.
    fn combine_verdicts(
        &self,
        ml: &Option<MlResult>,
        yara_matches: &[String],
        fallback: &Option<MlResult>,
        file_path: &str,
        _file_hash: &str,
    ) -> (Verdict, Vec<Detection>) {
        let mut detections = Vec::new();
        let mut verdict = Verdict::Clean;

        // -- YARA detections -------------------------------------------------
        if !yara_matches.is_empty() {
            for rule in yara_matches {
                detections.push(Detection {
                    detection_type: DetectionType::Yara,
                    rule_name: format!("OFFLINE_YARA_{}", rule),
                    confidence: 0.85,
                    description: format!("Offline YARA rule matched: {} on {}", rule, file_path),
                    mitre_tactics: vec!["Execution".to_string()],
                    mitre_techniques: vec![],
                });
            }
            // Any YARA match is at least suspicious.
            verdict = Verdict::Suspicious;
            // Multiple matches or high-confidence rules -> malicious.
            if yara_matches.len() >= 2 {
                verdict = Verdict::Malicious;
            }
        }

        // -- ML detections ---------------------------------------------------
        if let Some(result) = ml {
            if result.is_malicious && result.confidence >= self.config.ml_confidence_threshold {
                detections.push(Detection {
                    detection_type: DetectionType::Ml,
                    rule_name: format!("OFFLINE_ML_{}", result.predicted_class.to_uppercase()),
                    confidence: result.confidence,
                    description: format!(
                        "Offline ML classified {} as {} (confidence {:.2})",
                        file_path, result.predicted_class, result.confidence
                    ),
                    mitre_tactics: vec!["Execution".to_string()],
                    mitre_techniques: vec![],
                });
                verdict = Verdict::Malicious;
            } else if result.is_malicious {
                // Below threshold but still flagged -- suspicious.
                detections.push(Detection {
                    detection_type: DetectionType::Ml,
                    rule_name: "OFFLINE_ML_SUSPICIOUS".to_string(),
                    confidence: result.confidence,
                    description: format!(
                        "Offline ML suspects {} as {} (confidence {:.2}, below threshold {:.2})",
                        file_path,
                        result.predicted_class,
                        result.confidence,
                        self.config.ml_confidence_threshold,
                    ),
                    mitre_tactics: vec![],
                    mitre_techniques: vec![],
                });
                if verdict == Verdict::Clean {
                    verdict = Verdict::Suspicious;
                }
            }
        }

        // When both ML and YARA agree on malicious, boost confidence.
        if let Some(result) = ml {
            if result.is_malicious && !yara_matches.is_empty() {
                verdict = Verdict::Malicious;
                // Add a corroboration detection.
                detections.push(Detection {
                    detection_type: DetectionType::Ml,
                    rule_name: "OFFLINE_ML_YARA_CORROBORATE".to_string(),
                    confidence: (result.confidence + 0.85) / 2.0, // average
                    description: format!(
                        "Offline ML and YARA both flagged {} (ML: {}, YARA: {:?})",
                        file_path, result.predicted_class, yara_matches
                    ),
                    mitre_tactics: vec!["Execution".to_string()],
                    mitre_techniques: vec![],
                });
            }
        }

        // -- Fallback detection (entropy-based) -------------------------------
        if let Some(fb) = fallback {
            detections.push(Detection {
                detection_type: DetectionType::Entropy,
                rule_name: "OFFLINE_FALLBACK_ENTROPY".to_string(),
                confidence: fb.confidence,
                description: format!(
                    "Fallback entropy-based detection flagged {} (class: {})",
                    file_path, fb.predicted_class
                ),
                mitre_tactics: vec!["Defense Evasion".to_string()],
                mitre_techniques: vec!["T1027".to_string()], // Obfuscated Files or Information
            });
            if verdict == Verdict::Clean {
                verdict = Verdict::Suspicious;
            }
        }

        (verdict, detections)
    }

    /// Push a verdict onto the bounded queue, dropping the oldest if full.
    fn enqueue_verdict(&self, verdict: OfflineVerdict) {
        let mut q = self.verdict_queue.write();
        if q.len() >= self.verdict_queue_max {
            let dropped = q.len() - self.verdict_queue_max + 1;
            for _ in 0..dropped {
                q.pop_front();
            }
            debug!(
                dropped = dropped,
                max = self.verdict_queue_max,
                "Dropped oldest offline verdicts (queue full)"
            );
        }
        q.push_back(verdict);
        self.stats.write().verdicts_queued += 1;
    }

    /// Perform an HTTP HEAD against the backend health endpoint.
    async fn check_backend(backend_url: &str) -> bool {
        // Derive health URL from the WebSocket URL.
        let health_url = backend_url
            .replace("wss://", "https://")
            .replace("ws://", "http://")
            .replace("/socket/agent/websocket", "/api/health")
            .replace("/socket/agent", "/api/health");

        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .danger_accept_invalid_certs(true) // dev convenience
            .build()
        {
            Ok(c) => c,
            Err(_) => return false,
        };

        match client.head(&health_url).send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }
}

// SAFETY: The raw pointer usage in `run_ml` is safe because the
// `OfflineDetector` is always wrapped in an `Arc` and the spawned blocking
// task completes before the Arc is dropped.
unsafe impl Send for OfflineDetector {}
unsafe impl Sync for OfflineDetector {}

fn is_low_signal_entropy_path(file_path: &str) -> bool {
    let path = file_path.to_lowercase().replace('\\', "/");
    let low_signal_patterns = [
        "/library/caches/",
        "/library/application support/spotify/",
        "/library/application support/com.apple.ap.promotedcontentd/",
        "/movies/tv/tv library.tvlibrary/",
        "/cache/cache_data/",
        "/appdata/local/steam/htmlcache/",
        "/target/debug/",
        "/target/release/",
        "/node_modules/",
    ];

    low_signal_patterns
        .iter()
        .any(|pattern| path.contains(pattern))
}

fn has_suspicious_entropy_extension(file_path: &str) -> bool {
    let path = file_path.to_lowercase();
    let suspicious_exts = [
        ".exe", ".dll", ".sys", ".scr", ".com", ".ps1", ".vbs", ".js", ".jse", ".hta", ".bin",
        ".dat", ".tmp",
    ];

    suspicious_exts.iter().any(|ext| path.ends_with(ext))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = OfflineDetectionConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.verdict_queue_max, 10_000);
        assert_eq!(cfg.backend_check_interval_secs, 30);
        assert!((cfg.ml_confidence_threshold - 0.7).abs() < f32::EPSILON);
    }

    #[test]
    fn test_verdict_queue_bounded() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let cfg = OfflineDetectionConfig {
                verdict_queue_max: 3,
                ..Default::default()
            };
            let detector = OfflineDetector::new(cfg).await;

            // Enqueue 5 verdicts; only the last 3 should remain.
            for i in 0..5 {
                detector.enqueue_verdict(OfflineVerdict {
                    timestamp: Utc::now(),
                    file_path: format!("file_{}", i),
                    file_hash: format!("hash_{}", i),
                    file_size: 100,
                    ml_score: None,
                    ml_verdict: None,
                    yara_matches: vec![],
                    combined_verdict: Verdict::Clean,
                    model_version: "test".to_string(),
                    rules_version: "test".to_string(),
                });
            }

            assert_eq!(detector.queued_verdict_count(), 3);

            let drained = detector.drain_verdicts();
            assert_eq!(drained.len(), 3);
            assert_eq!(drained[0].file_path, "file_2");
            assert_eq!(drained[1].file_path, "file_3");
            assert_eq!(drained[2].file_path, "file_4");
            assert_eq!(detector.queued_verdict_count(), 0);
        });
    }

    #[test]
    fn test_verdict_queue_peek_requires_ack() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let cfg = OfflineDetectionConfig {
                verdict_queue_max: 3,
                ..Default::default()
            };
            let detector = OfflineDetector::new(cfg).await;

            for i in 0..2 {
                detector.enqueue_verdict(OfflineVerdict {
                    timestamp: Utc::now(),
                    file_path: format!("file_{}", i),
                    file_hash: format!("hash_{}", i),
                    file_size: 100,
                    ml_score: None,
                    ml_verdict: None,
                    yara_matches: vec![],
                    combined_verdict: Verdict::Suspicious,
                    model_version: "test".to_string(),
                    rules_version: "test".to_string(),
                });
            }

            let pending = detector.peek_verdicts(10);
            assert_eq!(pending.len(), 2);
            assert_eq!(detector.queued_verdict_count(), 2);

            assert_eq!(detector.ack_verdicts(1), 1);
            assert_eq!(detector.queued_verdict_count(), 1);
            assert_eq!(detector.peek_verdicts(10)[0].file_path, "file_1");

            assert_eq!(detector.ack_verdicts(10), 1);
            assert_eq!(detector.queued_verdict_count(), 0);
        });
    }

    #[test]
    fn test_combine_verdicts_clean() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let cfg = OfflineDetectionConfig::default();
            let detector = OfflineDetector::new(cfg).await;

            let (verdict, detections) =
                detector.combine_verdicts(&None, &[], &None, "test.exe", "abc123");
            assert_eq!(verdict, Verdict::Clean);
            assert!(detections.is_empty());
        });
    }

    #[test]
    fn test_combine_verdicts_yara_only() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let cfg = OfflineDetectionConfig::default();
            let detector = OfflineDetector::new(cfg).await;

            let yara = vec!["MALWARE_Generic".to_string()];
            let (verdict, detections) =
                detector.combine_verdicts(&None, &yara, &None, "test.exe", "abc123");
            assert_eq!(verdict, Verdict::Suspicious);
            assert_eq!(detections.len(), 1);
            assert_eq!(detections[0].detection_type, DetectionType::Yara);
        });
    }

    #[test]
    fn test_combine_verdicts_multi_yara() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let cfg = OfflineDetectionConfig::default();
            let detector = OfflineDetector::new(cfg).await;

            let yara = vec![
                "MALWARE_Generic".to_string(),
                "RANSOMWARE_Indicator".to_string(),
            ];
            let (verdict, _) = detector.combine_verdicts(&None, &yara, &None, "test.exe", "abc123");
            assert_eq!(verdict, Verdict::Malicious);
        });
    }

    #[test]
    fn test_set_backend_available() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let cfg = OfflineDetectionConfig::default();
            let detector = OfflineDetector::new(cfg).await;

            detector.set_backend_available(true);
            assert!(detector.backend_available.load(Ordering::Relaxed));

            detector.set_backend_available(false);
            assert!(!detector.backend_available.load(Ordering::Relaxed));
        });
    }
}
