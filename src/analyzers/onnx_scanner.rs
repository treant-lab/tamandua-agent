//! ONNX Runtime ML Scanner for Pre-Execution Malware Detection
//!
//! This module provides real-time ML-based malware detection using ONNX Runtime.
//! It converts binary files to grayscale images (like Malware-SMELL architecture)
//! and runs inference to detect malicious files BEFORE they execute.
//!
//! Model expects:
//! - Input: [1, 3, 64, 64] image tensor (NCHW format)
//! - Output: [1, N] family probabilities where index 0 = benign

use anyhow::{Context, Result};
use parking_lot::RwLock;
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

#[cfg(feature = "onnx")]
use ndarray::Array4;
#[cfg(feature = "onnx")]
use ort::{
    inputs,
    session::{Session, SessionOutputs},
    value::Value,
};

/// Result of an ONNX scan
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Whether the file is classified as malicious
    pub is_malicious: bool,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// Predicted malware family (if malicious)
    pub family: Option<String>,
    /// Family index from model output
    pub family_index: usize,
    /// Raw probabilities for all families
    pub probabilities: Vec<f32>,
    /// Inference time in milliseconds
    pub inference_time_ms: u64,
    /// Whether the result came from cache
    pub from_cache: bool,
}

impl Default for ScanResult {
    fn default() -> Self {
        Self {
            is_malicious: false,
            confidence: 0.0,
            family: None,
            family_index: 0,
            probabilities: Vec::new(),
            inference_time_ms: 0,
            from_cache: false,
        }
    }
}

/// Cache entry for scan results
#[derive(Clone)]
struct CacheEntry {
    result: ScanResult,
    cached_at: Instant,
}

/// Configuration for the ONNX scanner
#[derive(Debug, Clone)]
pub struct OnnxScannerConfig {
    /// Path to the ONNX model file
    pub model_path: PathBuf,
    /// Confidence threshold for malware classification (0.0 - 1.0)
    pub confidence_threshold: f32,
    /// Image size for the model input (default: 64)
    pub image_size: usize,
    /// Maximum file size to scan in bytes (default: 50MB)
    pub max_file_size: u64,
    /// Cache TTL in seconds (default: 3600 = 1 hour)
    pub cache_ttl_secs: u64,
    /// Maximum cache entries (default: 10000)
    pub max_cache_entries: usize,
    /// Enable batching for multiple files
    pub enable_batching: bool,
    /// Maximum batch size
    pub max_batch_size: usize,
    /// Family labels (index 0 should be "benign")
    pub family_labels: Vec<String>,
    /// Inference timeout in seconds (default: 30)
    pub inference_timeout_secs: u64,
}

impl Default for OnnxScannerConfig {
    fn default() -> Self {
        Self {
            model_path: Self::default_model_path(),
            confidence_threshold: 0.7,
            image_size: 64,
            max_file_size: 50 * 1024 * 1024, // 50MB
            cache_ttl_secs: 3600,            // 1 hour
            max_cache_entries: 10000,
            enable_batching: true,
            max_batch_size: 8,
            family_labels: vec![
                "benign".to_string(),
                "trojan".to_string(),
                "ransomware".to_string(),
                "spyware".to_string(),
                "adware".to_string(),
                "worm".to_string(),
                "backdoor".to_string(),
                "unknown_malware".to_string(),
            ],
            inference_timeout_secs: 30, // 30 seconds
        }
    }
}

impl OnnxScannerConfig {
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

    fn with_model_sidecar_threshold(mut self) -> Self {
        if let Some(threshold) = load_sidecar_threshold(&self.model_path) {
            self.confidence_threshold = threshold;
        }
        self
    }
}

fn load_sidecar_threshold(model_path: &Path) -> Option<f32> {
    let metadata_path = model_path.with_extension("json");
    let content = std::fs::read_to_string(&metadata_path).ok()?;
    let payload: JsonValue = serde_json::from_str(&content).ok()?;
    threshold_from_model_metadata(&payload)
}

fn threshold_from_model_metadata(payload: &JsonValue) -> Option<f32> {
    let raw = payload
        .get("decision")
        .and_then(|decision| decision.get("malicious_threshold"))
        .or_else(|| payload.get("malicious_threshold"))
        .or_else(|| {
            payload
                .get("input_contract")
                .and_then(|contract| contract.get("threshold"))
        })?;
    let threshold = raw.as_f64()?;
    if !(0.0..=1.0).contains(&threshold) {
        return None;
    }
    Some(threshold as f32)
}

/// Statistics for the ONNX scanner
#[derive(Debug, Default, Clone)]
pub struct ScannerStats {
    /// Total scans performed
    pub total_scans: u64,
    /// Cache hits
    pub cache_hits: u64,
    /// Cache misses
    pub cache_misses: u64,
    /// Total inference time in milliseconds
    pub total_inference_time_ms: u64,
    /// Files detected as malicious
    pub malicious_detected: u64,
    /// Files too large to scan
    pub skipped_too_large: u64,
    /// Scan errors
    pub scan_errors: u64,
    /// Inference timeouts
    pub inference_timeouts: u64,
}

/// ONNX Runtime ML Scanner
///
/// Provides pre-execution malware detection using a trained ONNX model.
/// Falls back gracefully to hash-only mode if the model is not available.
/// Model loading happens asynchronously in the background to avoid blocking startup.
pub struct OnnxScanner {
    /// ONNX session (None if model failed to load or still loading)
    #[cfg(feature = "onnx")]
    session: Arc<RwLock<Option<Session>>>,
    #[cfg(not(feature = "onnx"))]
    session: Arc<RwLock<Option<()>>>,
    /// Scanner configuration
    config: OnnxScannerConfig,
    /// LRU cache for scan results (keyed by SHA256 hex)
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    /// Scanner statistics
    stats: Arc<RwLock<ScannerStats>>,
    /// Whether the scanner is operational (model loaded successfully)
    is_operational: Arc<RwLock<bool>>,
    /// Watch channel for model ready status (true when model is loaded)
    model_ready_rx: watch::Receiver<bool>,
}

impl OnnxScanner {
    /// Create a new ONNX scanner with the given configuration
    ///
    /// Model loading happens asynchronously in a background task.
    /// The scanner will return hash-based fallback results until the model is ready.
    /// Check `is_operational()` or wait on `model_ready_rx` to know when the model is loaded.
    pub fn new(config: OnnxScannerConfig) -> Self {
        let config = config.with_model_sidecar_threshold();
        let (model_ready_tx, model_ready_rx) = watch::channel(false);
        let session = Arc::new(RwLock::new(None));
        let is_operational = Arc::new(RwLock::new(false));

        // Spawn background task for async model loading
        let config_clone = config.clone();
        let session_clone = Arc::clone(&session);
        let is_operational_clone = Arc::clone(&is_operational);

        tokio::spawn(async move {
            info!(
                model_path = %config_clone.model_path.display(),
                "ONNX scanner starting async model load"
            );

            let (loaded_session, operational) = Self::load_model(&config_clone);

            *session_clone.write() = loaded_session;
            *is_operational_clone.write() = operational;

            if operational {
                info!(
                    model_path = %config_clone.model_path.display(),
                    "ONNX model loaded successfully in background"
                );
                let _ = model_ready_tx.send(true);
            } else {
                warn!(
                    model_path = %config_clone.model_path.display(),
                    "ONNX scanner in fallback mode - model not available"
                );
                let _ = model_ready_tx.send(false);
            }
        });

        info!("ONNX scanner initialized, model loading in background");

        Self {
            session,
            config,
            cache: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(ScannerStats::default())),
            is_operational,
            model_ready_rx,
        }
    }

    /// Create a scanner with default configuration
    pub fn with_defaults() -> Self {
        Self::new(OnnxScannerConfig::default())
    }

    /// Load the ONNX model
    #[cfg(feature = "onnx")]
    fn load_model(config: &OnnxScannerConfig) -> (Option<Session>, bool) {
        match std::panic::catch_unwind(|| Self::load_model_inner(config)) {
            Ok(result) => result,
            Err(payload) => {
                let reason = if let Some(message) = payload.downcast_ref::<&str>() {
                    (*message).to_string()
                } else if let Some(message) = payload.downcast_ref::<String>() {
                    message.clone()
                } else {
                    "unknown ONNX Runtime panic".to_string()
                };
                error!(
                    model_path = %config.model_path.display(),
                    reason = %reason,
                    "ONNX Runtime panicked while loading scanner model; scanner fallback enabled"
                );
                (None, false)
            }
        }
    }

    #[cfg(feature = "onnx")]
    fn load_model_inner(config: &OnnxScannerConfig) -> (Option<Session>, bool) {
        if !config.model_path.exists() {
            warn!(
                model_path = %config.model_path.display(),
                "ONNX model file not found"
            );
            return (None, false);
        }

        match Session::builder() {
            Ok(builder) => {
                // Configure session options
                let builder = match builder
                    .with_optimization_level(ort::session::builder::GraphOptimizationLevel::Disable)
                {
                    Ok(b) => b,
                    Err(e) => {
                        error!(error = %e, "Failed to set optimization level");
                        return (None, false);
                    }
                };

                // Try to set intra-op parallelism.
                let mut builder = match builder.with_intra_threads(2) {
                    Ok(b) => b,
                    Err(e) => {
                        error!(error = %e, "Failed to set intra-op threads");
                        return (None, false);
                    }
                };

                // Load the model
                match builder.commit_from_file(&config.model_path) {
                    Ok(session) => {
                        info!(
                            model_path = %config.model_path.display(),
                            "ONNX model loaded successfully"
                        );
                        (Some(session), true)
                    }
                    Err(e) => {
                        error!(
                            model_path = %config.model_path.display(),
                            error = %e,
                            "Failed to load ONNX model"
                        );
                        (None, false)
                    }
                }
            }
            Err(e) => {
                error!(error = %e, "Failed to create ONNX session builder");
                (None, false)
            }
        }
    }

    #[cfg(not(feature = "onnx"))]
    fn load_model(_config: &OnnxScannerConfig) -> (Option<()>, bool) {
        warn!("ONNX feature not enabled - scanner in fallback mode");
        (None, false)
    }

    /// Check if the scanner is operational (model loaded successfully)
    pub fn is_operational(&self) -> bool {
        *self.is_operational.read()
    }

    /// Wait for the model to finish loading (or fail to load)
    ///
    /// Returns true if the model loaded successfully, false if it failed.
    pub async fn wait_for_model_ready(&mut self) -> bool {
        self.model_ready_rx.changed().await.ok();
        *self.model_ready_rx.borrow()
    }

    /// Get scanner statistics
    pub fn get_stats(&self) -> ScannerStats {
        self.stats.read().clone()
    }

    /// Clear the scan cache
    pub fn clear_cache(&self) {
        self.cache.write().clear();
        debug!("Scan cache cleared");
    }

    /// Scan a file for malware
    ///
    /// Returns a ScanResult indicating whether the file is malicious.
    /// If the model is not available, returns a default result with is_malicious=false.
    pub async fn scan_file(&self, path: &Path) -> Result<ScanResult> {
        self.stats.write().total_scans += 1;

        // Check if operational
        if !self.is_operational() {
            debug!(
                path = %path.display(),
                "Scanner not operational, returning unknown result"
            );
            return Ok(ScanResult::default());
        }

        // Check file size
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("Failed to get metadata for {}", path.display()))?;

        if metadata.len() > self.config.max_file_size {
            debug!(
                path = %path.display(),
                size = metadata.len(),
                max_size = self.config.max_file_size,
                "File too large for scanning"
            );
            self.stats.write().skipped_too_large += 1;
            return Ok(ScanResult::default());
        }

        // Read file
        let data = tokio::fs::read(path)
            .await
            .with_context(|| format!("Failed to read file {}", path.display()))?;

        self.scan_bytes(&data).await
    }

    /// Scan raw bytes for malware
    ///
    /// This is useful for scanning in-memory data or data from other sources.
    pub async fn scan_bytes(&self, data: &[u8]) -> Result<ScanResult> {
        // Check if operational
        if !self.is_operational() {
            return Ok(ScanResult::default());
        }

        // Calculate hash for caching
        let hash_hex = {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(data);
            hex::encode(hash)
        };

        // Check cache
        if let Some(cached) = self.get_cached(&hash_hex) {
            self.stats.write().cache_hits += 1;
            return Ok(cached);
        }
        self.stats.write().cache_misses += 1;

        // Convert to image and run inference with timeout
        let start = Instant::now();
        let result = match self.run_inference_with_timeout(data).await {
            Ok(output) => output,
            Err(e) => {
                if e.to_string().contains("timeout") {
                    warn!(
                        hash = %hash_hex,
                        timeout_secs = self.config.inference_timeout_secs,
                        "Model inference timeout - returning safe default (benign)"
                    );
                    self.stats.write().inference_timeouts += 1;
                    // Return safe default result (benign) on timeout
                    return Ok(ScanResult::default());
                } else {
                    self.stats.write().scan_errors += 1;
                    return Err(e);
                }
            }
        };
        let inference_time = start.elapsed();

        // Create scan result
        let mut scan_result = self.interpret_output(result)?;
        scan_result.inference_time_ms = inference_time.as_millis() as u64;
        scan_result.from_cache = false;

        // Update stats
        {
            let mut stats = self.stats.write();
            stats.total_inference_time_ms += scan_result.inference_time_ms;
            if scan_result.is_malicious {
                stats.malicious_detected += 1;
            }
        }

        // Cache result
        self.cache_result(&hash_hex, scan_result.clone());

        debug!(
            hash = %hash_hex,
            is_malicious = scan_result.is_malicious,
            confidence = scan_result.confidence,
            family = ?scan_result.family,
            inference_ms = scan_result.inference_time_ms,
            "Scan completed"
        );

        Ok(scan_result)
    }

    /// Scan multiple files in a batch
    ///
    /// This is more efficient than scanning files one by one when the model
    /// supports batching.
    pub async fn scan_batch(
        &self,
        paths: &[PathBuf],
    ) -> Result<Vec<(PathBuf, Result<ScanResult>)>> {
        let mut results = Vec::with_capacity(paths.len());

        // For now, scan sequentially (batch inference can be added later)
        for path in paths {
            let result = self.scan_file(path).await;
            results.push((path.clone(), result));
        }

        Ok(results)
    }

    /// Get a cached result if available and not expired
    fn get_cached(&self, hash: &str) -> Option<ScanResult> {
        let cache = self.cache.read();
        if let Some(entry) = cache.get(hash) {
            let ttl = Duration::from_secs(self.config.cache_ttl_secs);
            if entry.cached_at.elapsed() < ttl {
                let mut result = entry.result.clone();
                result.from_cache = true;
                return Some(result);
            }
        }
        None
    }

    /// Cache a scan result
    fn cache_result(&self, hash: &str, result: ScanResult) {
        let mut cache = self.cache.write();

        // Evict old entries if cache is full
        if cache.len() >= self.config.max_cache_entries {
            let ttl = Duration::from_secs(self.config.cache_ttl_secs);
            cache.retain(|_, entry| entry.cached_at.elapsed() < ttl);

            // If still full, remove oldest entries
            if cache.len() >= self.config.max_cache_entries {
                let to_remove = cache.len() - self.config.max_cache_entries / 2;
                let mut entries: Vec<_> = cache
                    .iter()
                    .map(|(key, entry)| (key.clone(), entry.cached_at))
                    .collect();
                entries.sort_by_key(|(_, cached_at)| *cached_at);
                for (key, _) in entries.into_iter().take(to_remove) {
                    cache.remove(&key);
                }
            }
        }

        cache.insert(
            hash.to_string(),
            CacheEntry {
                result,
                cached_at: Instant::now(),
            },
        );
    }

    /// Convert binary data to a 64x64 RGB image tensor
    ///
    /// Uses the same conversion method as the Malware-SMELL training pipeline:
    /// - Pad or truncate to image_size * image_size bytes
    /// - Reshape to 2D grayscale image
    /// - Normalize to 0.0-1.0 range
    #[cfg(feature = "onnx")]
    fn binary_to_image(&self, data: &[u8]) -> Array4<f32> {
        let size = self.config.image_size;
        let total_pixels = size * size;

        // Create padded/truncated buffer
        let mut buffer = vec![0u8; total_pixels];
        let copy_len = data.len().min(total_pixels);
        buffer[..copy_len].copy_from_slice(&data[..copy_len]);

        // Convert to f32 tensor with NCHW format [1, 3, 64, 64].
        let mut tensor = Array4::<f32>::zeros((1, 3, size, size));
        for (i, &byte) in buffer.iter().enumerate() {
            let row = i / size;
            let col = i % size;
            let pixel = byte as f32 / 255.0;
            tensor[[0, 0, row, col]] = pixel;
            tensor[[0, 1, row, col]] = pixel;
            tensor[[0, 2, row, col]] = pixel;
        }

        tensor
    }

    /// Run inference with timeout protection
    ///
    /// Wraps the synchronous inference call with tokio::time::timeout to prevent
    /// indefinite hangs. Returns a benign result on timeout to fail safely.
    async fn run_inference_with_timeout(&self, data: &[u8]) -> Result<Vec<f32>> {
        let timeout_duration = Duration::from_secs(self.config.inference_timeout_secs);
        let data_vec = data.to_vec(); // Clone data for move into spawned task

        // Clone Arc for move into spawned task
        let session = Arc::clone(&self.session);
        let image_size = self.config.image_size;

        // Spawn blocking task for synchronous ONNX inference
        let inference_task = tokio::task::spawn_blocking(move || {
            Self::run_inference_sync(&session, &data_vec, image_size)
        });

        // Apply timeout to the blocking task
        match tokio::time::timeout(timeout_duration, inference_task).await {
            Ok(Ok(result)) => result,
            Ok(Err(e)) => Err(anyhow::anyhow!("Inference task panicked: {}", e)),
            Err(_) => Err(anyhow::anyhow!(
                "Model inference timeout after {} seconds",
                self.config.inference_timeout_secs
            )),
        }
    }

    /// Run inference on the prepared tensor (synchronous, for use in blocking task)
    #[cfg(feature = "onnx")]
    fn run_inference_sync(
        session: &Arc<RwLock<Option<Session>>>,
        data: &[u8],
        image_size: usize,
    ) -> Result<Vec<f32>> {
        let mut session_guard = session.write();
        let session = session_guard
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("ONNX session not initialized or still loading"))?;

        // Convert binary to image tensor
        let input_tensor = Self::binary_to_image_static(data, image_size);

        // Create ONNX value from ndarray
        let input_value =
            Value::from_array(input_tensor).context("Failed to create ONNX input value")?;

        // Run inference
        let outputs: SessionOutputs = session
            .run(inputs!["input" => input_value])
            .context("ONNX inference failed")?;

        // Extract output tensor
        let output = outputs
            .iter()
            .find(|(name, _)| *name == "output")
            .or_else(|| outputs.iter().next())
            .map(|(_, value)| value)
            .ok_or_else(|| anyhow::anyhow!("No output tensor found"))?;

        // Extract probabilities
        let output_tensor = output
            .try_extract_tensor::<f32>()
            .context("Failed to extract output tensor")?;

        let probabilities: Vec<f32> = output_tensor.1.iter().copied().collect();

        Ok(probabilities)
    }

    #[cfg(not(feature = "onnx"))]
    fn run_inference_sync(
        _session: &Arc<RwLock<Option<()>>>,
        _data: &[u8],
        _image_size: usize,
    ) -> Result<Vec<f32>> {
        Err(anyhow::anyhow!("ONNX feature not enabled"))
    }

    /// Convert binary data to a 64x64 RGB image tensor (static version)
    ///
    /// Uses the same conversion method as the Malware-SMELL training pipeline:
    /// - Pad or truncate to image_size * image_size bytes
    /// - Reshape to 2D grayscale image
    /// - Normalize to 0.0-1.0 range
    #[cfg(feature = "onnx")]
    fn binary_to_image_static(data: &[u8], size: usize) -> Array4<f32> {
        let total_pixels = size * size;

        // Create padded/truncated buffer
        let mut buffer = vec![0u8; total_pixels];
        let copy_len = data.len().min(total_pixels);
        buffer[..copy_len].copy_from_slice(&data[..copy_len]);

        // Convert to f32 tensor with NCHW format [1, 3, 64, 64].
        let mut tensor = Array4::<f32>::zeros((1, 3, size, size));
        for (i, &byte) in buffer.iter().enumerate() {
            let row = i / size;
            let col = i % size;
            let pixel = byte as f32 / 255.0;
            tensor[[0, 0, row, col]] = pixel;
            tensor[[0, 1, row, col]] = pixel;
            tensor[[0, 2, row, col]] = pixel;
        }

        tensor
    }

    /// Run inference on the prepared tensor (kept for backward compatibility)
    #[cfg(feature = "onnx")]
    fn run_inference(&self, data: &[u8]) -> Result<Vec<f32>> {
        Self::run_inference_sync(&self.session, data, self.config.image_size)
    }

    #[cfg(not(feature = "onnx"))]
    fn run_inference(&self, _data: &[u8]) -> Result<Vec<f32>> {
        Err(anyhow::anyhow!("ONNX feature not enabled"))
    }

    /// Interpret model output as a scan result
    fn interpret_output(&self, probabilities: Vec<f32>) -> Result<ScanResult> {
        if probabilities.is_empty() {
            return Ok(ScanResult::default());
        }

        // Find the class with highest probability
        let (max_idx, max_prob) = probabilities
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap_or((0, &0.0));

        // Apply softmax if needed (check if already normalized)
        let sum: f32 = probabilities.iter().sum();
        let normalized_probs = if (sum - 1.0).abs() > 0.01 {
            // Apply softmax
            let max_val = probabilities
                .iter()
                .cloned()
                .fold(f32::NEG_INFINITY, f32::max);
            let exp_vals: Vec<f32> = probabilities.iter().map(|x| (x - max_val).exp()).collect();
            let exp_sum: f32 = exp_vals.iter().sum();
            exp_vals.iter().map(|x| x / exp_sum).collect()
        } else {
            probabilities.clone()
        };

        // Index 0 is benign, anything else is malware
        let is_malicious = max_idx != 0 && *max_prob >= self.config.confidence_threshold;

        // Get benign probability for confidence calculation
        let benign_prob = normalized_probs.get(0).copied().unwrap_or(0.0);

        // Confidence is the probability of the malicious class (1 - benign)
        let confidence = if is_malicious {
            1.0 - benign_prob
        } else {
            benign_prob
        };

        // Get family name
        let family = if is_malicious {
            self.config.family_labels.get(max_idx).cloned()
        } else {
            None
        };

        Ok(ScanResult {
            is_malicious,
            confidence,
            family,
            family_index: max_idx,
            probabilities: normalized_probs,
            inference_time_ms: 0,
            from_cache: false,
        })
    }

    /// Reload the model from disk
    ///
    /// This happens synchronously and will block until the model is loaded.
    /// Consider using the async initialization instead for non-blocking reloads.
    pub fn reload_model(&mut self) -> Result<()> {
        let (session, is_operational) = Self::load_model(&self.config);
        *self.session.write() = session;
        *self.is_operational.write() = is_operational;

        if is_operational {
            info!("ONNX model reloaded successfully");
            Ok(())
        } else {
            Err(anyhow::anyhow!("Failed to reload ONNX model"))
        }
    }

    /// Update configuration
    pub fn update_config(&mut self, config: OnnxScannerConfig) {
        let need_reload = self.config.model_path != config.model_path;
        self.config = config;
        if need_reload {
            let _ = self.reload_model();
        }
    }

    /// Get the configured confidence threshold
    pub fn confidence_threshold(&self) -> f32 {
        self.config.confidence_threshold
    }

    /// Set the confidence threshold
    pub fn set_confidence_threshold(&mut self, threshold: f32) {
        self.config.confidence_threshold = threshold.clamp(0.0, 1.0);
    }
}

/// Check if a file is executable based on extension and magic bytes
pub fn is_executable_file(path: &Path, data: Option<&[u8]>) -> bool {
    // Check extension
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    let executable_extensions = [
        "exe", "dll", "sys", "scr", "com", "pif", // Windows
        "so", "elf", // Linux
        "dylib", "app", // macOS
        "msi", "msp", // Windows installers
        "bat", "cmd", "ps1", "vbs", "js", "wsf", // Scripts
    ];

    if executable_extensions.contains(&ext.as_str()) {
        return true;
    }

    // Check magic bytes if data provided
    if let Some(data) = data {
        // PE (Windows executable)
        if data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A {
            return true;
        }
        // ELF (Linux/Unix executable)
        if data.len() >= 4
            && data[0] == 0x7F
            && data[1] == 0x45
            && data[2] == 0x4C
            && data[3] == 0x46
        {
            return true;
        }
        // Mach-O (macOS executable)
        if data.len() >= 4 {
            let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            if magic == 0xFEEDFACE || magic == 0xFEEDFACF || magic == 0xCAFEBABE {
                return true;
            }
            let magic_le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            if magic_le == 0xFEEDFACE || magic_le == 0xFEEDFACF {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_result_default() {
        let result = ScanResult::default();
        assert!(!result.is_malicious);
        assert_eq!(result.confidence, 0.0);
        assert!(result.family.is_none());
    }

    #[test]
    fn test_config_default() {
        let config = OnnxScannerConfig::default();
        assert_eq!(config.confidence_threshold, 0.7);
        assert_eq!(config.image_size, 64);
        assert_eq!(config.family_labels[0], "benign");
    }

    #[test]
    fn test_threshold_from_model_contract_metadata() {
        let payload = serde_json::json!({
            "decision": {
                "malicious_threshold": 0.91
            },
            "malicious_threshold": 0.7
        });

        assert_eq!(threshold_from_model_metadata(&payload), Some(0.91));
    }

    #[test]
    fn test_threshold_from_legacy_sidecar_metadata() {
        let payload = serde_json::json!({
            "malicious_threshold": 0.86
        });

        assert_eq!(threshold_from_model_metadata(&payload), Some(0.86));
    }

    #[test]
    fn test_threshold_from_model_metadata_rejects_out_of_range_values() {
        let payload = serde_json::json!({
            "decision": {
                "malicious_threshold": 1.2
            }
        });

        assert_eq!(threshold_from_model_metadata(&payload), None);
    }

    #[test]
    fn test_load_sidecar_threshold_uses_model_stem_json() {
        let dir = tempfile::tempdir().unwrap();
        let model_path = dir.path().join("malware_smell.onnx");
        let metadata_path = dir.path().join("malware_smell.json");
        std::fs::write(&model_path, b"onnx").unwrap();
        std::fs::write(
            &metadata_path,
            r#"{"decision":{"malicious_threshold":0.93}}"#,
        )
        .unwrap();

        assert_eq!(load_sidecar_threshold(&model_path), Some(0.93));
    }

    #[test]
    fn test_is_executable_file() {
        assert!(is_executable_file(Path::new("test.exe"), None));
        assert!(is_executable_file(Path::new("test.dll"), None));
        assert!(is_executable_file(Path::new("test.ps1"), None));
        assert!(!is_executable_file(Path::new("test.txt"), None));
        assert!(!is_executable_file(Path::new("test.pdf"), None));

        // Test with PE magic bytes
        let pe_data = vec![0x4D, 0x5A, 0x90, 0x00];
        assert!(is_executable_file(Path::new("unknown"), Some(&pe_data)));

        // Test with ELF magic bytes
        let elf_data = vec![0x7F, 0x45, 0x4C, 0x46];
        assert!(is_executable_file(Path::new("unknown"), Some(&elf_data)));
    }

    #[test]
    fn test_scanner_without_model() {
        // Scanner should gracefully handle missing model
        let config = OnnxScannerConfig {
            model_path: PathBuf::from("/nonexistent/model.onnx"),
            ..Default::default()
        };
        let scanner = OnnxScanner::new(config);
        assert!(!scanner.is_operational());
    }

    #[test]
    fn test_interpret_output_benign() {
        let config = OnnxScannerConfig::default();
        let scanner = OnnxScanner::new(config);

        // Test benign classification (index 0 has highest prob)
        let probs = vec![0.9, 0.05, 0.03, 0.02];
        let result = scanner.interpret_output(probs).unwrap();
        assert!(!result.is_malicious);
        assert!(result.family.is_none());
    }

    #[test]
    fn test_interpret_output_malicious() {
        let mut config = OnnxScannerConfig::default();
        config.confidence_threshold = 0.5;
        let scanner = OnnxScanner::new(config);

        // Test malicious classification (index 1 has highest prob)
        let probs = vec![0.1, 0.8, 0.05, 0.05];
        let result = scanner.interpret_output(probs).unwrap();
        assert!(result.is_malicious);
        assert_eq!(result.family, Some("trojan".to_string()));
    }

    #[test]
    fn test_cache_operations() {
        let config = OnnxScannerConfig {
            cache_ttl_secs: 1,
            max_cache_entries: 10,
            ..Default::default()
        };
        let scanner = OnnxScanner::new(config);

        // Cache a result
        let result = ScanResult {
            is_malicious: true,
            confidence: 0.95,
            family: Some("trojan".to_string()),
            family_index: 1,
            probabilities: vec![0.05, 0.95],
            inference_time_ms: 50,
            from_cache: false,
        };
        scanner.cache_result("abc123", result.clone());

        // Should retrieve from cache
        let cached = scanner.get_cached("abc123");
        assert!(cached.is_some());
        let cached = cached.unwrap();
        assert!(cached.from_cache);
        assert!(cached.is_malicious);

        // Non-existent key
        let missing = scanner.get_cached("nonexistent");
        assert!(missing.is_none());
    }

    #[cfg(feature = "onnx")]
    #[test]
    fn test_binary_to_image() {
        let config = OnnxScannerConfig::default();
        let scanner = OnnxScanner::new(config);

        // Test with small data (should be padded)
        let data = vec![128u8; 100];
        let tensor = scanner.binary_to_image(&data);
        assert_eq!(tensor.shape(), &[1, 3, 64, 64]);

        // First 100 pixels should be ~0.5, rest should be 0
        assert!((tensor[[0, 0, 0, 0]] - 0.5019608).abs() < 0.001);
        assert!((tensor[[0, 1, 0, 0]] - 0.5019608).abs() < 0.001);
        assert!((tensor[[0, 2, 0, 0]] - 0.5019608).abs() < 0.001);
        assert_eq!(tensor[[0, 0, 63, 63]], 0.0);

        // Test with large data (should be truncated)
        let large_data = vec![255u8; 64 * 64 * 2];
        let tensor = scanner.binary_to_image(&large_data);
        assert_eq!(tensor.shape(), &[1, 3, 64, 64]);
    }

    #[test]
    fn test_timeout_config() {
        // Test that timeout config is properly set
        let mut config = OnnxScannerConfig::default();
        assert_eq!(config.inference_timeout_secs, 30); // Default 30 seconds

        config.inference_timeout_secs = 60;
        let scanner = OnnxScanner::new(config);
        assert_eq!(scanner.config.inference_timeout_secs, 60);
    }

    #[test]
    fn test_timeout_stats_tracking() {
        // Test that timeout stats are tracked correctly
        let config = OnnxScannerConfig::default();
        let scanner = OnnxScanner::new(config);

        let stats = scanner.get_stats();
        assert_eq!(stats.inference_timeouts, 0);

        // Simulate a timeout by incrementing the counter
        scanner.stats.write().inference_timeouts += 1;

        let updated_stats = scanner.get_stats();
        assert_eq!(updated_stats.inference_timeouts, 1);
    }
}
