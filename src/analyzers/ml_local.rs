//! On-Agent ML Inference via ONNX Runtime
//!
//! Provides local malware classification without network dependency.
//! Uses a compact ONNX model (~5-15MB) for pre-execution file analysis.
//!
//! Feature extraction pipeline:
//! 1. PE header analysis (sections, imports, exports)
//! 2. Byte entropy calculation (Shannon entropy)
//! 3. String analysis (suspicious API names, URLs)
//! 4. File structure features (size, ratios)
//!
//! This module provides a lightweight, feature-based ML classifier that
//! complements the image-based ONNX scanner (`onnx_scanner.rs`). While
//! the image scanner uses a Malware-SMELL style binary-to-image approach,
//! this module extracts 16 structural/behavioral features from PE files
//! for fast classification with minimal resource usage.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;
use tracing::{debug, info, warn};

#[cfg(feature = "ml-local")]
use ort::{session::Session, value::Value};

#[cfg(feature = "ml-local")]
use ndarray;

/// Number of features extracted from each file. The ONNX model input shape
/// must be [1, 16] to match this vector.
pub const FEATURE_COUNT: usize = 16;

/// Maximum inference time before aborting (milliseconds).
/// Used by the caller (file collector) to enforce a timeout via
/// `std::thread::Builder::spawn` or `tokio::time::timeout`.
#[allow(dead_code)]
pub const INFERENCE_TIMEOUT_MS: u64 = 500;

/// Maximum file size for in-memory loading (50MB).
/// Files larger than this will use memory-mapped or streaming access.
const MAX_IN_MEMORY_SIZE: u64 = 50 * 1024 * 1024;

/// Chunk size for streaming file operations (1MB).
const STREAMING_CHUNK_SIZE: usize = 1024 * 1024;

/// List of Windows API imports considered suspicious in the context of malware.
/// These are commonly used for process injection, memory manipulation, and
/// privilege escalation.
const SUSPICIOUS_IMPORTS: &[&str] = &[
    "VirtualAlloc",
    "VirtualAllocEx",
    "VirtualProtect",
    "VirtualProtectEx",
    "WriteProcessMemory",
    "ReadProcessMemory",
    "CreateRemoteThread",
    "CreateRemoteThreadEx",
    "NtCreateThreadEx",
    "RtlCreateUserThread",
    "NtWriteVirtualMemory",
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "LoadLibraryA",
    "LoadLibraryW",
    "LoadLibraryExA",
    "LoadLibraryExW",
    "GetProcAddress",
    "OpenProcess",
    "OpenProcessToken",
    "AdjustTokenPrivileges",
    "CreateProcessA",
    "CreateProcessW",
    "WinExec",
    "ShellExecuteA",
    "ShellExecuteW",
    "InternetOpenA",
    "InternetOpenW",
    "InternetOpenUrlA",
    "InternetOpenUrlW",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "HttpSendRequestA",
    "HttpSendRequestW",
    "RegSetValueExA",
    "RegSetValueExW",
    "CryptEncrypt",
    "CryptDecrypt",
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "SetWindowsHookExA",
    "SetWindowsHookExW",
];

/// List of string patterns considered suspicious when found in binary data.
const SUSPICIOUS_STRINGS: &[&str] = &[
    "http://",
    "https://",
    "ftp://",
    "cmd.exe",
    "powershell",
    "pwsh",
    "wscript",
    "cscript",
    "mshta",
    "regsvr32",
    "rundll32",
    "certutil",
    "bitsadmin",
    "mimikatz",
    "password",
    "credential",
    "bitcoin",
    "wallet",
    "ransom",
    "encrypt",
    "decrypt",
    "C:\\Users\\",
    "\\AppData\\",
    "\\Temp\\",
    "HKEY_",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
];

/// Result of ML classification on a single file.
#[derive(Debug, Clone)]
pub struct MLClassification {
    /// Whether the file was classified as malicious.
    pub is_malicious: bool,
    /// Confidence score from the model (0.0 = benign, 1.0 = malicious).
    pub confidence: f32,
    /// Raw malware probability output from the model.
    pub malware_probability: f32,
    /// Number of features successfully extracted.
    pub features_extracted: usize,
    /// Model version string (from ONNX metadata or file modification time).
    pub model_version: String,
    /// Wall-clock time spent on inference in milliseconds.
    pub inference_time_ms: u64,
}

/// Cache entry for previously scanned files (keyed by SHA256 hex).
struct CacheEntry {
    classification: MLClassification,
    cached_at: Instant,
}

/// On-agent ML inference engine using ONNX Runtime with PE feature extraction.
///
/// This engine is designed for low-latency, offline-capable malware detection.
/// It extracts 16 structural features from PE files and runs them through a
/// small ONNX model to produce a malicious/benign classification.
pub struct LocalMLFeatureEngine {
    /// ONNX inference session. `None` if the model failed to load.
    #[cfg(feature = "ml-local")]
    #[allow(dead_code)]
    session: Option<Session>,

    /// Placeholder when the `ml-local` feature is not compiled in.
    #[cfg(not(feature = "ml-local"))]
    #[allow(dead_code)]
    session: Option<()>,

    /// Path to the ONNX model file on disk.
    #[allow(dead_code)]
    model_path: PathBuf,

    /// Minimum confidence score to classify a file as malicious.
    confidence_threshold: f32,

    /// Whether the engine is enabled (user can disable via config).
    enabled: bool,

    /// Whether the engine is operational (model loaded successfully).
    is_operational: bool,

    /// Model version string for telemetry.
    model_version: String,

    /// SHA256-keyed result cache with TTL eviction.
    cache: Mutex<HashMap<String, CacheEntry>>,
}

impl LocalMLFeatureEngine {
    /// Create a new engine, loading the ONNX model from the path specified
    /// in the agent configuration.
    ///
    /// If the model file does not exist or fails to load, the engine enters
    /// a degraded mode where `classify_file` always returns a benign result.
    /// This ensures the agent never crashes due to a missing model.
    pub fn new(model_path: PathBuf, confidence_threshold: f32, enabled: bool) -> Self {
        if !enabled {
            info!("Local ML feature engine disabled by configuration");
            return Self {
                session: None,
                model_path,
                confidence_threshold,
                enabled: false,
                is_operational: false,
                model_version: String::new(),
                cache: Mutex::new(HashMap::new()),
            };
        }

        let (session, is_operational, model_version) = Self::load_session(&model_path);

        if is_operational {
            info!(
                model_path = %model_path.display(),
                model_version = %model_version,
                threshold = confidence_threshold,
                "Local ML feature engine initialized"
            );
        } else {
            warn!(
                model_path = %model_path.display(),
                "Local ML feature engine: model not available, running in degraded mode"
            );
        }

        Self {
            session,
            model_path,
            confidence_threshold,
            enabled,
            is_operational,
            model_version,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Create a new engine from the agent configuration struct.
    ///
    /// Reads from `config.ml_local` fields. Falls back to top-level
    /// `ml_model_path` if `ml_local.model_path` is empty.
    pub fn from_config(config: &crate::config::AgentConfig) -> Self {
        let model_path = if !config.ml_local.model_path.is_empty() {
            PathBuf::from(&config.ml_local.model_path)
        } else {
            config
                .ml_model_path
                .as_ref()
                .map(PathBuf::from)
                .unwrap_or_else(Self::default_model_path)
        };

        let threshold = config.ml_local.confidence_threshold;
        let enabled = config.ml_local.enabled;

        Self::new(model_path, threshold, enabled)
    }

    /// Platform-specific default model path.
    fn default_model_path() -> PathBuf {
        #[cfg(target_os = "windows")]
        {
            PathBuf::from("C:\\ProgramData\\Tamandua\\models\\malware_features.onnx")
        }
        #[cfg(target_os = "linux")]
        {
            PathBuf::from("/var/lib/tamandua/models/malware_features.onnx")
        }
        #[cfg(target_os = "macos")]
        {
            PathBuf::from("/Library/Application Support/Tamandua/models/malware_features.onnx")
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            PathBuf::from("./models/malware_features.onnx")
        }
    }

    /// Attempt to load the ONNX model file and create an inference session.
    #[cfg(feature = "ml-local")]
    fn load_session(model_path: &Path) -> (Option<Session>, bool, String) {
        if !model_path.exists() {
            warn!(
                model_path = %model_path.display(),
                "ML feature model file not found"
            );
            return (None, false, String::new());
        }

        // Derive a simple version string from the file's modification time.
        let model_version = std::fs::metadata(model_path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| format!("mtime:{}", d.as_secs()))
            .unwrap_or_else(|| "unknown".to_string());

        match Session::builder() {
            Ok(builder) => {
                let builder = match builder
                    .with_optimization_level(ort::session::builder::GraphOptimizationLevel::Level3)
                {
                    Ok(b) => b,
                    Err(e) => {
                        error!(error = %e, "Failed to set ONNX optimization level");
                        return (None, false, model_version);
                    }
                };

                // Use a single thread to keep resource usage minimal.
                let builder = match builder.with_intra_threads(1) {
                    Ok(b) => b,
                    Err(e) => {
                        warn!(error = %e, "Failed to set intra-op threads, continuing with defaults");
                        builder
                    }
                };

                match builder.commit_from_file(model_path) {
                    Ok(session) => {
                        info!(
                            model_path = %model_path.display(),
                            version = %model_version,
                            "ML feature model loaded"
                        );
                        (Some(session), true, model_version)
                    }
                    Err(e) => {
                        error!(
                            model_path = %model_path.display(),
                            error = %e,
                            "Failed to load ML feature model"
                        );
                        (None, false, model_version)
                    }
                }
            }
            Err(e) => {
                error!(error = %e, "Failed to create ONNX session builder");
                (None, false, model_version)
            }
        }
    }

    #[cfg(not(feature = "ml-local"))]
    fn load_session(_model_path: &Path) -> (Option<()>, bool, String) {
        debug!("ml-local feature not compiled in");
        (None, false, String::new())
    }

    /// Returns `true` if the engine is enabled AND the model loaded successfully.
    pub fn is_operational(&self) -> bool {
        self.enabled && self.is_operational
    }

    /// Classify a file at the given path.
    ///
    /// For small files (<50MB), reads the entire file into memory.
    /// For large files, uses streaming access to avoid excessive RAM usage.
    /// Results are cached by SHA256 so re-scanning the same unchanged file is essentially free.
    ///
    /// If the engine is not operational, returns a benign classification with
    /// zero confidence.
    pub fn classify_file(&self, path: &Path) -> Result<MLClassification> {
        if !self.is_operational() {
            return Ok(MLClassification {
                is_malicious: false,
                confidence: 0.0,
                malware_probability: 0.0,
                features_extracted: 0,
                model_version: self.model_version.clone(),
                inference_time_ms: 0,
            });
        }

        // Check file size for streaming decision.
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("Failed to get file metadata: {}", path.display()))?;
        let file_size = metadata.len();

        // Compute SHA256 using streaming (avoids loading entire file for hash).
        let sha256_hex = Self::calculate_sha256_streaming(path)?;

        // Check cache.
        if let Some(cached) = self.get_cached(&sha256_hex) {
            debug!(path = %path.display(), "ML feature classification cache hit");
            return Ok(cached);
        }

        // Read file data based on size.
        let data = if file_size <= MAX_IN_MEMORY_SIZE {
            // Small file: read into memory.
            std::fs::read(path).with_context(|| {
                format!(
                    "Failed to read file for ML classification: {}",
                    path.display()
                )
            })?
        } else {
            // Large file: read only what we need for feature extraction.
            // For PE files, we primarily need headers + .text section.
            // Read first 10MB which covers most executable code sections.
            debug!(
                path = %path.display(),
                size = file_size,
                "Large file detected, using partial read for feature extraction"
            );
            Self::read_file_partial(path, 10 * 1024 * 1024)?
        };

        // Extract features.
        let features = extract_features(&data);
        let features_extracted = features.len();

        // Run inference.
        let start = Instant::now();
        let malware_probability = self.run_inference(&features)?;
        let inference_time_ms = start.elapsed().as_millis() as u64;

        let is_malicious = malware_probability >= self.confidence_threshold;
        let confidence = if is_malicious {
            malware_probability
        } else {
            1.0 - malware_probability
        };

        let classification = MLClassification {
            is_malicious,
            confidence,
            malware_probability,
            features_extracted,
            model_version: self.model_version.clone(),
            inference_time_ms,
        };

        if is_malicious {
            warn!(
                path = %path.display(),
                probability = malware_probability,
                confidence = confidence,
                inference_ms = inference_time_ms,
                "ML feature engine classified file as malicious"
            );
        } else {
            debug!(
                path = %path.display(),
                probability = malware_probability,
                inference_ms = inference_time_ms,
                "ML feature engine classified file as benign"
            );
        }

        // Cache the result.
        self.cache_result(&sha256_hex, &classification);

        Ok(classification)
    }

    /// Calculate SHA256 hash of a file using streaming (chunked reads).
    ///
    /// This avoids loading the entire file into memory just for hashing.
    fn calculate_sha256_streaming(path: &Path) -> Result<String> {
        use sha2::{Digest, Sha256};

        let file = File::open(path)
            .with_context(|| format!("Failed to open file for hashing: {}", path.display()))?;
        let mut reader = BufReader::with_capacity(STREAMING_CHUNK_SIZE, file);
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; STREAMING_CHUNK_SIZE];

        loop {
            let bytes_read = reader
                .read(&mut buffer)
                .with_context(|| format!("Failed to read file for hashing: {}", path.display()))?;

            if bytes_read == 0 {
                break;
            }

            hasher.update(&buffer[..bytes_read]);
        }

        Ok(hex::encode(hasher.finalize()))
    }

    /// Read a partial segment of a file (first max_bytes).
    ///
    /// Used for large files where we only need headers and early sections
    /// for feature extraction.
    fn read_file_partial(path: &Path, max_bytes: usize) -> Result<Vec<u8>> {
        let file = File::open(path)
            .with_context(|| format!("Failed to open file for partial read: {}", path.display()))?;
        let mut reader = BufReader::with_capacity(STREAMING_CHUNK_SIZE, file);
        let mut buffer = Vec::with_capacity(max_bytes);

        let mut chunk = vec![0u8; STREAMING_CHUNK_SIZE.min(max_bytes)];
        let mut total_read = 0;

        while total_read < max_bytes {
            let to_read = (max_bytes - total_read).min(STREAMING_CHUNK_SIZE);
            let bytes_read = reader
                .read(&mut chunk[..to_read])
                .with_context(|| format!("Failed to read file: {}", path.display()))?;

            if bytes_read == 0 {
                break; // EOF
            }

            buffer.extend_from_slice(&chunk[..bytes_read]);
            total_read += bytes_read;
        }

        Ok(buffer)
    }

    /// Run ONNX inference on the extracted feature vector.
    #[cfg(feature = "ml-local")]
    fn run_inference(&self, features: &[f32]) -> Result<f32> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("ONNX session not initialized"))?;

        // Build a [1, FEATURE_COUNT] input tensor.
        let input_array =
            ndarray::Array2::<f32>::from_shape_vec((1, FEATURE_COUNT), features.to_vec())
                .context("Failed to create feature tensor")?;

        let input_value =
            Value::from_array(input_array.view()).context("Failed to create ONNX input value")?;

        // Run inference. The macro `inputs!` expects string-keyed inputs.
        let outputs = session
            .run(ort::inputs!["input" => input_value]?)
            .context("ONNX feature inference failed")?;

        // Extract output. Expected shape: [1, 1] or [1, 2].
        let output = outputs
            .get("output")
            .or_else(|| outputs.iter().next().map(|(_, v)| v))
            .ok_or_else(|| anyhow::anyhow!("No output tensor found"))?;

        let output_tensor = output
            .try_extract_tensor::<f32>()
            .context("Failed to extract output tensor")?;

        let values: Vec<f32> = output_tensor.view().iter().copied().collect();

        // Interpret output:
        // - If single value: sigmoid-style probability (0 = benign, 1 = malicious)
        // - If two values: [benign_prob, malicious_prob] (take index 1)
        let malware_prob = match values.len() {
            1 => values[0],
            2 => values[1],
            n if n > 2 => {
                // Multi-class: sum all non-benign probabilities
                let benign = values[0];
                1.0 - benign
            }
            _ => 0.0,
        };

        Ok(malware_prob.clamp(0.0, 1.0))
    }

    #[cfg(not(feature = "ml-local"))]
    fn run_inference(&self, _features: &[f32]) -> Result<f32> {
        Ok(0.0)
    }

    /// Retrieve a cached classification result if available and not expired.
    fn get_cached(&self, sha256: &str) -> Option<MLClassification> {
        let cache = match self.cache.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("ML cache lock was poisoned, recovering from panic");
                poisoned.into_inner()
            }
        };
        if let Some(entry) = cache.get(sha256) {
            // Cache entries expire after 5 minutes.
            if entry.cached_at.elapsed().as_secs() < 300 {
                return Some(entry.classification.clone());
            }
        }
        None
    }

    /// Store a classification result in the cache.
    fn cache_result(&self, sha256: &str, classification: &MLClassification) {
        let mut cache = match self.cache.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("ML cache lock was poisoned during cache_result, recovering");
                poisoned.into_inner()
            }
        };

        // Evict when cache grows too large (simple flush strategy).
        if cache.len() >= 10_000 {
            cache.clear();
        }

        cache.insert(
            sha256.to_string(),
            CacheEntry {
                classification: classification.clone(),
                cached_at: Instant::now(),
            },
        );
    }

    /// Clear the result cache. Useful after model updates.
    pub fn clear_cache(&self) {
        let mut cache = match self.cache.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("ML cache lock was poisoned during clear_cache, recovering");
                poisoned.into_inner()
            }
        };
        cache.clear();
        debug!("ML feature engine cache cleared");
    }
}

// ============================================================================
// Feature extraction
// ============================================================================

/// Extract exactly [`FEATURE_COUNT`] (16) floating-point features from raw
/// file bytes.
///
/// Features (in order):
///  0. `file_size`                -- log-normalized file size
///  1. `entropy`                  -- Shannon entropy of full file (0.0-1.0)
///  2. `pe_valid`                 -- 1.0 if valid PE, 0.0 otherwise
///  3. `section_count`            -- normalized section count
///  4. `executable_section_entropy` -- entropy of .text section (0.0-1.0)
///  5. `resource_section_ratio`   -- resource size / total size
///  6. `import_count`             -- normalized import count
///  7. `suspicious_import_count`  -- normalized suspicious import count
///  8. `export_count`             -- normalized export count
///  9. `has_debug_info`           -- 1.0 / 0.0
/// 10. `has_signature`            -- 1.0 / 0.0
/// 11. `string_suspicion_score`   -- ratio of suspicious strings found
/// 12. `header_checksum_valid`    -- 1.0 / 0.0
/// 13. `section_name_entropy`     -- average entropy of section names (0.0-1.0)
/// 14. `import_dll_count`         -- normalized DLL count
/// 15. `has_tls_callbacks`        -- 1.0 / 0.0
pub fn extract_features(data: &[u8]) -> Vec<f32> {
    let mut features = vec![0.0f32; FEATURE_COUNT];

    // Feature 0: file_size (log-normalized, cap at ~1GB)
    let size = data.len() as f64;
    features[0] = if size > 0.0 {
        ((size.ln()) / (1_000_000_000.0f64.ln())).min(1.0) as f32
    } else {
        0.0
    };

    // Feature 1: full-file Shannon entropy, normalized to 0.0-1.0
    features[1] = calculate_entropy(data) as f32 / 8.0;

    // Attempt PE parsing for the remaining features.
    if let Some(pe) = parse_pe(data) {
        features[2] = 1.0; // pe_valid

        // Feature 3: section count (normalized by 20; most PEs have < 20)
        features[3] = (pe.section_count as f32 / 20.0).min(1.0);

        // Feature 4: executable section (.text) entropy
        features[4] = (pe.text_section_entropy / 8.0).min(1.0) as f32;

        // Feature 5: resource section ratio
        features[5] = pe.resource_ratio.min(1.0) as f32;

        // Feature 6: total import count (normalized by 500)
        features[6] = (pe.total_imports as f32 / 500.0).min(1.0);

        // Feature 7: suspicious import count (normalized by SUSPICIOUS_IMPORTS len)
        features[7] = (pe.suspicious_imports as f32 / SUSPICIOUS_IMPORTS.len() as f32).min(1.0);

        // Feature 8: export count (normalized by 200)
        features[8] = (pe.export_count as f32 / 200.0).min(1.0);

        // Feature 9: has debug info
        features[9] = if pe.has_debug_info { 1.0 } else { 0.0 };

        // Feature 10: has Authenticode signature
        features[10] = if pe.has_signature { 1.0 } else { 0.0 };

        // Feature 12: header checksum valid
        features[12] = if pe.checksum_valid { 1.0 } else { 0.0 };

        // Feature 13: average section name entropy (normalized)
        features[13] = (pe.section_name_entropy / 8.0).min(1.0) as f32;

        // Feature 14: import DLL count (normalized by 50)
        features[14] = (pe.import_dll_count as f32 / 50.0).min(1.0);

        // Feature 15: TLS callbacks
        features[15] = if pe.has_tls_callbacks { 1.0 } else { 0.0 };
    }
    // If not a valid PE, features 2-10, 12-15 remain 0.0 which the model
    // should interpret as "not a PE executable".

    // Feature 11: string suspicion score (works for any file type)
    features[11] = calculate_string_suspicion(data);

    features
}

/// Calculate Shannon entropy of a byte slice.
///
/// Returns a value between 0.0 (perfectly uniform / empty) and 8.0 (maximum
/// entropy for byte data).
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let total = data.len() as f64;
    let mut entropy = 0.0f64;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Count total and suspicious imports from a list of import names.
pub fn scan_suspicious_imports(imports: &[String]) -> (usize, usize) {
    let total = imports.len();
    let suspicious = imports
        .iter()
        .filter(|name| SUSPICIOUS_IMPORTS.iter().any(|s| name.contains(s)))
        .count();
    (total, suspicious)
}

/// Calculate a suspicion score based on the ratio of suspicious string
/// patterns found in the binary data.
fn calculate_string_suspicion(data: &[u8]) -> f32 {
    if data.is_empty() || SUSPICIOUS_STRINGS.is_empty() {
        return 0.0;
    }

    // Convert to lossy string for searching (only look at ASCII-printable
    // regions to avoid false positives from random byte sequences).
    let text = String::from_utf8_lossy(data);
    let text_lower = text.to_lowercase();

    let found = SUSPICIOUS_STRINGS
        .iter()
        .filter(|pattern| text_lower.contains(&pattern.to_lowercase()))
        .count();

    (found as f32 / SUSPICIOUS_STRINGS.len() as f32).min(1.0)
}

// ============================================================================
// Minimal PE parser (no external crate dependency)
// ============================================================================

/// Extracted PE metadata relevant for feature computation.
struct PeInfo {
    section_count: usize,
    text_section_entropy: f64,
    resource_ratio: f64,
    total_imports: usize,
    suspicious_imports: usize,
    export_count: usize,
    has_debug_info: bool,
    has_signature: bool,
    checksum_valid: bool,
    section_name_entropy: f64,
    import_dll_count: usize,
    has_tls_callbacks: bool,
}

/// Parse a PE file and extract structural metadata.
///
/// This is a lightweight, read-only parser that extracts just enough
/// information for the 16-feature vector. It does NOT validate the PE
/// exhaustively -- that is not the goal.
fn parse_pe(data: &[u8]) -> Option<PeInfo> {
    // Minimum size: DOS header (64 bytes) + PE signature (4) + COFF header (20)
    if data.len() < 64 {
        return None;
    }

    // Check MZ signature.
    if data[0] != 0x4D || data[1] != 0x5A {
        return None;
    }

    // e_lfanew: offset to PE signature at offset 0x3C (little-endian u32).
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;

    if e_lfanew + 4 > data.len() {
        return None;
    }

    // Check PE\0\0 signature.
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }

    let coff_offset = e_lfanew + 4;
    if coff_offset + 20 > data.len() {
        return None;
    }

    // COFF header fields.
    let number_of_sections =
        u16::from_le_bytes([data[coff_offset + 2], data[coff_offset + 3]]) as usize;
    let size_of_optional_header =
        u16::from_le_bytes([data[coff_offset + 16], data[coff_offset + 17]]) as usize;

    let optional_offset = coff_offset + 20;
    if optional_offset + size_of_optional_header > data.len() {
        return None;
    }

    // Determine PE32 vs PE32+ from optional header magic.
    let magic = u16::from_le_bytes([data[optional_offset], data[optional_offset + 1]]);
    let is_pe32_plus = magic == 0x20B;

    // Checksum at optional header offset 64.
    let checksum_valid = if optional_offset + 68 <= data.len() {
        let stored_checksum = u32::from_le_bytes([
            data[optional_offset + 64],
            data[optional_offset + 65],
            data[optional_offset + 66],
            data[optional_offset + 67],
        ]);
        // A zero checksum is valid for many compilers; non-zero is "present".
        stored_checksum != 0
    } else {
        false
    };

    // NumberOfRvaAndSizes and Data Directory entries.
    // PE32: starts at optional_offset + 96
    // PE32+: starts at optional_offset + 112
    let dd_base = if is_pe32_plus {
        optional_offset + 112
    } else {
        optional_offset + 96
    };

    let num_rva_sizes = if dd_base >= 4 && dd_base <= data.len() {
        u32::from_le_bytes([
            data[dd_base - 4],
            data[dd_base - 3],
            data[dd_base - 2],
            data[dd_base - 1],
        ]) as usize
    } else {
        0
    };

    // Helper to read a data directory entry (RVA + Size, each u32).
    let read_dd = |index: usize| -> (u32, u32) {
        if index >= num_rva_sizes {
            return (0, 0);
        }
        let offset = dd_base + index * 8;
        if offset + 8 > data.len() {
            return (0, 0);
        }
        let rva = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let size = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        (rva, size)
    };

    // Data directory indices.
    let (_export_rva, _export_size) = read_dd(0);
    let (import_rva, _import_size) = read_dd(1);
    let (_resource_rva, resource_size) = read_dd(2);
    let (_debug_rva, debug_size) = read_dd(6);
    let (_tls_rva, tls_size) = read_dd(9);
    let (_cert_rva, cert_size) = read_dd(4); // Certificate table (Authenticode)

    let has_debug_info = debug_size > 0;
    let has_signature = cert_size > 0;
    let has_tls_callbacks = tls_size > 0;
    let resource_ratio = if data.len() > 0 {
        resource_size as f64 / data.len() as f64
    } else {
        0.0
    };

    // Parse section headers.
    let section_headers_offset = optional_offset + size_of_optional_header;
    let mut text_section_entropy = 0.0f64;
    let mut section_name_entropies = Vec::new();
    let mut rva_to_offset_map: Vec<(u32, u32, u32)> = Vec::new(); // (virtual_addr, virtual_size, raw_offset)

    for i in 0..number_of_sections {
        let sh_offset = section_headers_offset + i * 40;
        if sh_offset + 40 > data.len() {
            break;
        }

        // Section name (8 bytes, null-padded).
        let name_bytes = &data[sh_offset..sh_offset + 8];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        let name = &name_bytes[..name_end];

        // Section name entropy.
        if !name.is_empty() {
            section_name_entropies.push(calculate_entropy(name));
        }

        let virtual_size = u32::from_le_bytes([
            data[sh_offset + 8],
            data[sh_offset + 9],
            data[sh_offset + 10],
            data[sh_offset + 11],
        ]);
        let virtual_address = u32::from_le_bytes([
            data[sh_offset + 12],
            data[sh_offset + 13],
            data[sh_offset + 14],
            data[sh_offset + 15],
        ]);
        let raw_size = u32::from_le_bytes([
            data[sh_offset + 16],
            data[sh_offset + 17],
            data[sh_offset + 18],
            data[sh_offset + 19],
        ]);
        let raw_offset = u32::from_le_bytes([
            data[sh_offset + 20],
            data[sh_offset + 21],
            data[sh_offset + 22],
            data[sh_offset + 23],
        ]);

        rva_to_offset_map.push((virtual_address, virtual_size, raw_offset));

        // Compute entropy for the .text section.
        if name.starts_with(b".text") {
            let start = raw_offset as usize;
            let end = (start + raw_size as usize).min(data.len());
            if start < end && start < data.len() {
                text_section_entropy = calculate_entropy(&data[start..end]);
            }
        }
    }

    let section_name_entropy = if section_name_entropies.is_empty() {
        0.0
    } else {
        section_name_entropies.iter().sum::<f64>() / section_name_entropies.len() as f64
    };

    // Helper: convert RVA to file offset using section mapping.
    let rva_to_offset = |rva: u32| -> Option<usize> {
        for &(va, vs, raw_off) in &rva_to_offset_map {
            if rva >= va && rva < va + vs {
                return Some((raw_off + (rva - va)) as usize);
            }
        }
        None
    };

    // Count imports and DLLs by walking the import directory table.
    let (total_imports, suspicious_imports, import_dll_count) =
        count_imports(data, import_rva, &rva_to_offset);

    // Count exports from the export directory.
    let export_count = count_exports(data, _export_rva, _export_size, &rva_to_offset);

    Some(PeInfo {
        section_count: number_of_sections,
        text_section_entropy,
        resource_ratio,
        total_imports,
        suspicious_imports,
        export_count,
        has_debug_info,
        has_signature,
        checksum_valid,
        section_name_entropy,
        import_dll_count,
        has_tls_callbacks,
    })
}

/// Walk the PE import directory table and count imported functions and DLLs.
fn count_imports(
    data: &[u8],
    import_rva: u32,
    rva_to_offset: &dyn Fn(u32) -> Option<usize>,
) -> (usize, usize, usize) {
    if import_rva == 0 {
        return (0, 0, 0);
    }

    let mut total = 0usize;
    let mut suspicious = 0usize;
    let mut dll_count = 0usize;

    let Some(mut idt_offset) = rva_to_offset(import_rva) else {
        return (0, 0, 0);
    };

    // Each IMAGE_IMPORT_DESCRIPTOR is 20 bytes. Walk until a null entry.
    loop {
        if idt_offset + 20 > data.len() {
            break;
        }

        let original_first_thunk = u32::from_le_bytes([
            data[idt_offset],
            data[idt_offset + 1],
            data[idt_offset + 2],
            data[idt_offset + 3],
        ]);

        let name_rva = u32::from_le_bytes([
            data[idt_offset + 12],
            data[idt_offset + 13],
            data[idt_offset + 14],
            data[idt_offset + 15],
        ]);

        // Null entry terminates the list.
        if original_first_thunk == 0 && name_rva == 0 {
            break;
        }

        dll_count += 1;

        // Walk the Import Lookup Table (ILT) to count function names.
        if original_first_thunk != 0 {
            if let Some(mut ilt_offset) = rva_to_offset(original_first_thunk) {
                // Safety limit to prevent infinite loops on malformed PEs.
                let mut func_count = 0usize;
                loop {
                    if ilt_offset + 4 > data.len() || func_count > 5000 {
                        break;
                    }

                    let entry = u32::from_le_bytes([
                        data[ilt_offset],
                        data[ilt_offset + 1],
                        data[ilt_offset + 2],
                        data[ilt_offset + 3],
                    ]);

                    if entry == 0 {
                        break;
                    }

                    // Bit 31 set means import by ordinal; skip those.
                    if entry & 0x80000000 == 0 {
                        // Hint/Name Table entry: 2-byte hint + null-terminated name.
                        if let Some(hnt_offset) = rva_to_offset(entry) {
                            if hnt_offset + 2 < data.len() {
                                let name_start = hnt_offset + 2;
                                let name_end = data[name_start..]
                                    .iter()
                                    .position(|&b| b == 0)
                                    .map(|p| name_start + p)
                                    .unwrap_or_else(|| (name_start + 128).min(data.len()));

                                if let Ok(func_name) =
                                    std::str::from_utf8(&data[name_start..name_end])
                                {
                                    total += 1;
                                    if SUSPICIOUS_IMPORTS.iter().any(|s| func_name.contains(s)) {
                                        suspicious += 1;
                                    }
                                }
                            }
                        }
                    } else {
                        total += 1; // Count ordinal imports too.
                    }

                    ilt_offset += 4;
                    func_count += 1;
                }
            }
        }

        idt_offset += 20;

        // Safety limit on number of DLLs.
        if dll_count > 500 {
            break;
        }
    }

    (total, suspicious, dll_count)
}

/// Count the number of exported functions from the export directory.
fn count_exports(
    data: &[u8],
    export_rva: u32,
    export_size: u32,
    rva_to_offset: &dyn Fn(u32) -> Option<usize>,
) -> usize {
    if export_rva == 0 || export_size == 0 {
        return 0;
    }

    let Some(export_offset) = rva_to_offset(export_rva) else {
        return 0;
    };

    // IMAGE_EXPORT_DIRECTORY: NumberOfFunctions at offset 20.
    if export_offset + 24 > data.len() {
        return 0;
    }

    u32::from_le_bytes([
        data[export_offset + 20],
        data[export_offset + 21],
        data[export_offset + 22],
        data[export_offset + 23],
    ]) as usize
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_entropy_empty() {
        assert_eq!(calculate_entropy(&[]), 0.0);
    }

    #[test]
    fn test_calculate_entropy_uniform() {
        // All same bytes -> entropy = 0
        let data = vec![0xAA; 1024];
        assert!((calculate_entropy(&data) - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_calculate_entropy_max() {
        // Perfectly distributed -> close to 8.0
        let mut data = Vec::new();
        for _ in 0..4 {
            for b in 0..=255u8 {
                data.push(b);
            }
        }
        let entropy = calculate_entropy(&data);
        assert!((entropy - 8.0).abs() < 0.01);
    }

    #[test]
    fn test_extract_features_non_pe() {
        let data = b"This is just a text file, not a PE.";
        let features = extract_features(data);
        assert_eq!(features.len(), FEATURE_COUNT);
        // pe_valid should be 0.0 for non-PE data.
        assert_eq!(features[2], 0.0);
        // file_size should be > 0
        assert!(features[0] > 0.0);
    }

    #[test]
    fn test_extract_features_minimal_pe() {
        // Build a minimal valid PE header.
        let mut pe = vec![0u8; 512];
        // DOS header: MZ
        pe[0] = 0x4D;
        pe[1] = 0x5A;
        // e_lfanew pointing to offset 128
        pe[0x3C] = 128;
        // PE signature at offset 128
        pe[128] = b'P';
        pe[129] = b'E';
        pe[130] = 0;
        pe[131] = 0;
        // COFF header: 2 sections, optional header size = 112 (PE32)
        pe[134] = 2; // NumberOfSections low byte
        pe[135] = 0;
        pe[148] = 112; // SizeOfOptionalHeader low byte
        pe[149] = 0;
        // Optional header magic: PE32 (0x10B)
        pe[152] = 0x0B;
        pe[153] = 0x01;

        let features = extract_features(&pe);
        assert_eq!(features.len(), FEATURE_COUNT);
        assert_eq!(features[2], 1.0); // pe_valid
    }

    #[test]
    fn test_scan_suspicious_imports() {
        let imports = vec![
            "CreateFileA".to_string(),
            "VirtualAlloc".to_string(),
            "WriteProcessMemory".to_string(),
            "CloseHandle".to_string(),
        ];
        let (total, suspicious) = scan_suspicious_imports(&imports);
        assert_eq!(total, 4);
        assert_eq!(suspicious, 2);
    }

    #[test]
    fn test_feature_count_constant() {
        assert_eq!(FEATURE_COUNT, 16);
    }

    #[test]
    fn test_string_suspicion_clean() {
        let data = b"Hello World, this is a normal string with nothing suspicious.";
        let score = calculate_string_suspicion(data);
        assert!(score < 0.1);
    }

    #[test]
    fn test_string_suspicion_suspicious() {
        let data = b"http://evil.com powershell cmd.exe mimikatz ransom encrypt";
        let score = calculate_string_suspicion(data);
        assert!(score > 0.1);
    }

    #[test]
    fn test_engine_not_operational_without_model() {
        let engine = LocalMLFeatureEngine::new(PathBuf::from("/nonexistent/model.onnx"), 0.7, true);
        assert!(!engine.is_operational());
    }

    #[test]
    fn test_engine_disabled() {
        let engine =
            LocalMLFeatureEngine::new(PathBuf::from("/nonexistent/model.onnx"), 0.7, false);
        assert!(!engine.is_operational());
        // classify_file on a non-existent path should still return benign.
        let result = engine.classify_file(Path::new("/nonexistent/test.exe"));
        assert!(result.is_ok());
        assert!(!result.unwrap().is_malicious);
    }
}
