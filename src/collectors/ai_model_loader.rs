//! AI Model Loader Detection Collector
//!
//! Detects processes loading AI/ML models by correlating two signals:
//! 1. ML library loading (libtorch.so, libonnxruntime.so, etc.)
//! 2. Model file access (.gguf, .safetensors, .pt, .onnx, etc.)
//!
//! When both signals are present for a process, we emit a confirmed model load event.
//! This reduces false positives compared to monitoring either signal alone.
//!
//! # Platform Support
//!
//! - **Linux**: eBPF uprobes on dlopen (future), currently polling-based
//! - **Windows**: ETW ImageLoad events (future), currently polling-based
//! - **macOS**: Endpoint Security framework (future), currently polling-based
//!
//! # Session Tracking
//!
//! Uses DashMap for concurrent session tracking with per-process state:
//! - `ml_library_loaded`: Set when ML library detected
//! - `model_file_accessed`: Set when model file opened
//! - When both are set: emit AIModelLoadEvent
//! - Sessions expire after 300 seconds (cleanup every 30 seconds)
//!
//! # Deduplication
//!
//! (pid, model_path) pairs emit only one event per session to avoid spam.

use super::model_format::{
    detect_model_format, extract_gguf_metadata, extract_safetensors_metadata, ModelFormat,
    ModelMetadata,
};
use super::{EventPayload, EventType, Severity, TelemetryEvent};
use crate::config::AgentConfig;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::{debug, info};

// ============================================================================
// Constants
// ============================================================================

/// Session timeout in seconds (5 minutes)
const SESSION_TIMEOUT_SECONDS: u64 = 300;

/// Cleanup interval in seconds
const CLEANUP_INTERVAL_SECONDS: u64 = 30;

/// ML library name patterns to detect (cross-platform)
const ML_LIBRARIES: &[&str] = &[
    // Linux shared objects
    "libtorch",
    "libonnxruntime",
    "libtensorflow",
    "libggml",
    "libllama",
    "libcublas",
    "libcudnn",
    "libcudart",
    "libnccl",
    // Windows DLLs
    "torch_cpu",
    "torch_cuda",
    "onnxruntime",
    "tensorflow",
    "llama",
    "ggml",
    // Python extension modules
    "_C.so",      // PyTorch C extension
    "_C.cpython", // PyTorch C extension (versioned)
    "onnxruntime_pybind11_state",
];

/// Model file extensions to monitor
const MODEL_FILE_EXTENSIONS: &[&str] = &[
    ".gguf",
    ".safetensors",
    ".pt",
    ".pth",
    ".onnx",
    ".pkl",
    ".bin",
    ".ggml",
    ".llamafile",
];

// ============================================================================
// Event Types
// ============================================================================

/// Process context for model loading events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessContext {
    /// Process ID
    pub pid: u32,
    /// Process name
    pub name: String,
    /// Full executable path
    pub path: String,
    /// Command line arguments
    pub cmdline: String,
    /// User running the process
    pub user: String,
}

impl Default for ProcessContext {
    fn default() -> Self {
        Self {
            pid: 0,
            name: String::new(),
            path: String::new(),
            cmdline: String::new(),
            user: String::new(),
        }
    }
}

/// Model information for load events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    /// Full path to the model file
    pub path: String,
    /// File name only
    pub filename: String,
    /// Detected format via magic bytes
    pub format: ModelFormat,
    /// File size in bytes
    pub size_bytes: u64,
    /// SHA-256 hash (optional, computed on demand)
    pub hash_sha256: Option<String>,
    /// Model architecture (llama, mistral, gpt2, etc.)
    pub architecture: Option<String>,
    /// Parameter count (7B, 13B, etc.)
    pub parameters: Option<String>,
    /// Quantization type (Q4_K_M, Q8_0, FP16, etc.)
    pub quantization: Option<String>,
}

impl Default for ModelInfo {
    fn default() -> Self {
        Self {
            path: String::new(),
            filename: String::new(),
            format: ModelFormat::Unknown,
            size_bytes: 0,
            hash_sha256: None,
            architecture: None,
            parameters: None,
            quantization: None,
        }
    }
}

/// Method used to load the model
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadingMethod {
    /// Standard file read (open + read)
    FileRead,
    /// Memory-mapped file (mmap)
    Mmap,
    /// Network download (HTTP/HTTPS)
    Network,
}

impl Default for LoadingMethod {
    fn default() -> Self {
        LoadingMethod::FileRead
    }
}

/// AI model load event - emitted when a process loads an ML model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIModelLoadEvent {
    /// Unix timestamp in milliseconds
    pub timestamp: u64,
    /// Process that loaded the model
    pub process: ProcessContext,
    /// Model information
    pub model: ModelInfo,
    /// How the model was loaded
    pub loading_method: LoadingMethod,
    /// ML libraries loaded by the process
    pub libraries_loaded: Vec<String>,
    /// Risk indicators detected
    pub risk_indicators: Vec<String>,
}

impl Default for AIModelLoadEvent {
    fn default() -> Self {
        Self {
            timestamp: 0,
            process: ProcessContext::default(),
            model: ModelInfo::default(),
            loading_method: LoadingMethod::FileRead,
            libraries_loaded: Vec::new(),
            risk_indicators: Vec::new(),
        }
    }
}

// ============================================================================
// Session Tracking
// ============================================================================

/// In-flight model load session for request/response correlation
#[derive(Debug, Clone)]
pub struct ModelLoadSession {
    /// Process ID being tracked
    pub process_id: u32,
    /// Process name
    pub process_name: String,
    /// Process path
    pub process_path: String,
    /// Process command line
    pub cmdline: String,
    /// User running the process
    pub user: String,
    /// ML library loaded (e.g., "libtorch.so")
    pub ml_library_loaded: Option<String>,
    /// Model file accessed
    pub model_file_accessed: Option<PathBuf>,
    /// All ML libraries detected for this process
    pub all_libraries: Vec<String>,
    /// Session creation time
    pub created_at: Instant,
}

impl ModelLoadSession {
    /// Create a new session for a process
    pub fn new(pid: u32, name: String, path: String, cmdline: String, user: String) -> Self {
        Self {
            process_id: pid,
            process_name: name,
            process_path: path,
            cmdline,
            user,
            ml_library_loaded: None,
            model_file_accessed: None,
            all_libraries: Vec::new(),
            created_at: Instant::now(),
        }
    }

    /// Check if session has expired
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > Duration::from_secs(SESSION_TIMEOUT_SECONDS)
    }

    /// Check if both signals are present (ready to emit event)
    pub fn is_confirmed(&self) -> bool {
        self.ml_library_loaded.is_some() && self.model_file_accessed.is_some()
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Check if a library path matches known ML library patterns
pub fn is_ml_library(path: &Path) -> bool {
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();

    ML_LIBRARIES
        .iter()
        .any(|lib| filename.contains(&lib.to_lowercase()))
}

/// Check if a file path is a model file based on extension
pub fn is_model_file(path: &Path) -> bool {
    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| format!(".{}", e.to_lowercase()))
        .unwrap_or_default();

    MODEL_FILE_EXTENSIONS.contains(&extension.as_str())
}

/// Get current timestamp in milliseconds
fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Hash first 1MB of file for quick identification
#[allow(dead_code)]
async fn hash_file_partial(path: &Path) -> Option<String> {
    let mut file = tokio::fs::File::open(path).await.ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024]; // 64KB chunks
    let mut total_read = 0usize;
    const MAX_HASH_SIZE: usize = 1024 * 1024; // 1MB

    use tokio::io::AsyncReadExt;
    loop {
        if total_read >= MAX_HASH_SIZE {
            break;
        }
        let to_read = std::cmp::min(buffer.len(), MAX_HASH_SIZE - total_read);
        let n = file.read(&mut buffer[..to_read]).await.ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
        total_read += n;
    }

    Some(hex::encode(hasher.finalize()))
}

/// Get process context by PID
#[cfg(target_os = "linux")]
fn get_process_context(pid: u32) -> Option<ProcessContext> {
    let cmdline = std::fs::read_to_string(format!("/proc/{}/cmdline", pid))
        .ok()?
        .replace('\0', " ")
        .trim()
        .to_string();

    let exe_path = std::fs::read_link(format!("/proc/{}/exe", pid))
        .ok()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    let name = Path::new(&exe_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    // Get UID from status file
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    let uid = status
        .lines()
        .find(|l| l.starts_with("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|u| u.parse::<u32>().ok())
        .unwrap_or(u32::MAX);

    // Try to resolve username from UID (simplified)
    let user = if uid == 0 {
        "root".to_string()
    } else {
        format!("uid:{}", uid)
    };

    Some(ProcessContext {
        pid,
        name,
        path: exe_path,
        cmdline,
        user,
    })
}

#[cfg(target_os = "windows")]
fn get_process_context(pid: u32) -> Option<ProcessContext> {
    use sysinfo::{ProcessRefreshKind, RefreshKind, System};

    let system = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
    );

    let process = system.process(sysinfo::Pid::from(pid as usize))?;

    Some(ProcessContext {
        pid,
        name: process.name().to_string(),
        path: process.exe()?.to_string_lossy().to_string(),
        cmdline: process.cmd().join(" "),
        user: process.user_id()?.to_string(),
    })
}

#[cfg(target_os = "macos")]
fn get_process_context(pid: u32) -> Option<ProcessContext> {
    use sysinfo::{ProcessRefreshKind, RefreshKind, System};

    let system = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
    );

    let process = system.process(sysinfo::Pid::from(pid as usize))?;

    Some(ProcessContext {
        pid,
        name: process.name().to_string(),
        path: process.exe()?.to_string_lossy().to_string(),
        cmdline: process.cmd().join(" "),
        user: process.user_id()?.to_string(),
    })
}

/// Cleanup expired sessions
fn cleanup_expired_sessions(sessions: &DashMap<u32, ModelLoadSession>) {
    let expired_pids: Vec<u32> = sessions
        .iter()
        .filter(|entry| entry.value().is_expired())
        .map(|entry| *entry.key())
        .collect();

    for pid in expired_pids {
        if let Some((_, session)) = sessions.remove(&pid) {
            debug!(
                pid = session.process_id,
                "Cleaned up expired model load session"
            );
        }
    }
}

// ============================================================================
// AI Model Loader Collector
// ============================================================================

/// Collector for detecting AI model loading events
pub struct AIModelLoaderCollector {
    /// Active sessions per process
    sessions: Arc<DashMap<u32, ModelLoadSession>>,
    /// Confirmed loads for deduplication: (pid, model_path) -> event
    confirmed_loads: Arc<DashMap<(u32, String), AIModelLoadEvent>>,
    /// Event sender
    #[allow(dead_code)]
    event_tx: mpsc::Sender<TelemetryEvent>,
    /// Event receiver
    event_rx: mpsc::Receiver<TelemetryEvent>,
}

impl AIModelLoaderCollector {
    /// Create a new AI model loader collector
    pub fn new(config: &AgentConfig) -> Self {
        let (event_tx, event_rx) = mpsc::channel(1000);
        let sessions: Arc<DashMap<u32, ModelLoadSession>> = Arc::new(DashMap::new());
        let confirmed_loads: Arc<DashMap<(u32, String), AIModelLoadEvent>> =
            Arc::new(DashMap::new());

        let sessions_cleanup = sessions.clone();
        let _config = config.clone();

        // Spawn cleanup task
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(CLEANUP_INTERVAL_SECONDS)).await;
                cleanup_expired_sessions(&sessions_cleanup);
            }
        });

        // STUB — PLATFORM-INCOMPLETE / DESIGN-DORMANT, not production. No native
        // OS hook is spawned on any platform:
        //   - Linux: eBPF uprobe monitoring on dlopen — not implemented
        //   - Windows: ETW ImageLoad event monitoring — not implemented
        //   - macOS: Endpoint Security framework monitoring — not implemented
        // The collector is inert unless an external caller drives it via
        // on_library_load / on_file_access (intended to be fed by the FIM and
        // process collectors). Standalone, it produces no events.

        // For now, we rely on external callers to invoke on_library_load and on_file_access
        // This will be integrated with FIM collector and process collector events

        info!("AIModelLoaderCollector initialized");

        Self {
            sessions,
            confirmed_loads,
            event_tx,
            event_rx,
        }
    }

    /// Get the next telemetry event
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }

    /// Get a reference to sessions for external event injection
    pub fn sessions(&self) -> Arc<DashMap<u32, ModelLoadSession>> {
        self.sessions.clone()
    }

    /// Get a reference to confirmed loads for external checking
    pub fn confirmed_loads(&self) -> Arc<DashMap<(u32, String), AIModelLoadEvent>> {
        self.confirmed_loads.clone()
    }

    /// Called when a library load is detected
    pub fn on_library_load(&self, pid: u32, lib_path: &Path) {
        if !is_ml_library(lib_path) {
            return;
        }

        let lib_name = lib_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        debug!(pid = pid, lib = %lib_name, "ML library load detected");

        // Get or create session
        let mut session = self.sessions.entry(pid).or_insert_with(|| {
            let ctx = get_process_context(pid).unwrap_or_default();
            ModelLoadSession::new(pid, ctx.name, ctx.path, ctx.cmdline, ctx.user)
        });

        // Mark library as loaded
        if session.ml_library_loaded.is_none() {
            session.ml_library_loaded = Some(lib_name.clone());
        }
        session.all_libraries.push(lib_name);

        // Check if we should emit event
        if session.is_confirmed() {
            drop(session); // Release the lock before calling check_and_emit
            let _ = self.check_and_emit(pid);
        }
    }

    /// Called when a model file access is detected
    pub fn on_file_access(&self, pid: u32, file_path: &Path) {
        if !is_model_file(file_path) {
            return;
        }

        debug!(pid = pid, path = %file_path.display(), "Model file access detected");

        // Get or create session
        let mut session = self.sessions.entry(pid).or_insert_with(|| {
            let ctx = get_process_context(pid).unwrap_or_default();
            ModelLoadSession::new(pid, ctx.name, ctx.path, ctx.cmdline, ctx.user)
        });

        // Mark file as accessed
        session.model_file_accessed = Some(file_path.to_path_buf());

        // Check if we should emit event
        if session.is_confirmed() {
            drop(session); // Release the lock before calling check_and_emit
            let _ = self.check_and_emit(pid);
        }
    }

    /// Check if both signals are present and emit event
    fn check_and_emit(&self, pid: u32) -> Option<TelemetryEvent> {
        let session = self.sessions.get(&pid)?;

        // Both signals required
        if !session.is_confirmed() {
            return None;
        }

        let model_path = session.model_file_accessed.as_ref()?.clone();
        let model_path_str = model_path.to_string_lossy().to_string();
        let dedup_key = (pid, model_path_str.clone());

        // Check for duplicate
        if self.confirmed_loads.contains_key(&dedup_key) {
            debug!(pid = pid, path = %model_path_str, "Duplicate model load event, skipping");
            return None;
        }

        // Build the event
        let event = self.build_model_load_event(&session, &model_path);

        // Cache to prevent duplicates
        self.confirmed_loads.insert(dedup_key, event.clone());

        // Send via channel
        let telemetry = TelemetryEvent::new(
            EventType::AIModelLoad,
            determine_severity(&event),
            EventPayload::AIModelLoad(event.clone()),
        );

        // Try to send, don't block
        let _ = self.event_tx.try_send(telemetry.clone());

        info!(
            pid = pid,
            model = %event.model.filename,
            format = %event.model.format,
            "AI model load event emitted"
        );

        Some(telemetry)
    }

    /// Build a complete model load event
    fn build_model_load_event(
        &self,
        session: &dashmap::mapref::one::Ref<'_, u32, ModelLoadSession>,
        model_path: &Path,
    ) -> AIModelLoadEvent {
        let mut event = AIModelLoadEvent {
            timestamp: now_millis(),
            process: ProcessContext {
                pid: session.process_id,
                name: session.process_name.clone(),
                path: session.process_path.clone(),
                cmdline: session.cmdline.clone(),
                user: session.user.clone(),
            },
            model: ModelInfo::default(),
            loading_method: LoadingMethod::FileRead,
            libraries_loaded: session.all_libraries.clone(),
            risk_indicators: Vec::new(),
        };

        // Fill in model info
        event.model.path = model_path.to_string_lossy().to_string();
        event.model.filename = model_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        // Get file size
        if let Ok(metadata) = std::fs::metadata(model_path) {
            event.model.size_bytes = metadata.len();

            // Large model indicator
            if metadata.len() > 1_073_741_824 {
                // > 1GB
                event
                    .risk_indicators
                    .push(format!("large_model_{}GB", metadata.len() / 1_073_741_824));
            }
        }

        // Detect format via magic bytes
        event.model.format = detect_model_format(model_path).unwrap_or(ModelFormat::Unknown);

        // Extract metadata based on format
        let model_metadata: Option<ModelMetadata> = match event.model.format {
            ModelFormat::Gguf => extract_gguf_metadata(model_path).ok(),
            ModelFormat::Safetensors => extract_safetensors_metadata(model_path).ok(),
            _ => None,
        };

        if let Some(meta) = model_metadata {
            event.model.architecture = meta.architecture;
            event.model.parameters = meta.parameters;
            event.model.quantization = meta.quantization;
        }

        // Check for risk indicators
        self.add_risk_indicators(&mut event, session);

        event
    }

    /// Add risk indicators based on session and event data
    fn add_risk_indicators(
        &self,
        event: &mut AIModelLoadEvent,
        session: &dashmap::mapref::one::Ref<'_, u32, ModelLoadSession>,
    ) {
        // Check if running as root/admin
        if session.user == "root" || session.user == "Administrator" {
            event
                .risk_indicators
                .push("elevated_privileges".to_string());
        }

        // Check if model is in a temp directory
        let path_lower = event.model.path.to_lowercase();
        if path_lower.contains("/tmp/")
            || path_lower.contains("\\temp\\")
            || path_lower.contains("/var/tmp/")
        {
            event
                .risk_indicators
                .push("model_in_temp_directory".to_string());
        }

        // Check for suspicious process names
        let name_lower = session.process_name.to_lowercase();
        if name_lower.contains("python") && !path_lower.contains("site-packages") {
            // Python loading model from non-standard location
            if !path_lower.contains(".cache")
                && !path_lower.contains("models")
                && !path_lower.contains("huggingface")
            {
                event
                    .risk_indicators
                    .push("non_standard_model_location".to_string());
            }
        }

        // Check for network binding in cmdline (potential model serving)
        let cmdline_lower = session.cmdline.to_lowercase();
        if cmdline_lower.contains("0.0.0.0") || cmdline_lower.contains("--host") {
            event
                .risk_indicators
                .push("network_exposed_model_serving".to_string());
        }
    }
}

/// Determine event severity based on risk indicators
fn determine_severity(event: &AIModelLoadEvent) -> Severity {
    if event.risk_indicators.len() >= 3 {
        Severity::High
    } else if event.risk_indicators.len() >= 1 {
        Severity::Medium
    } else {
        Severity::Info
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Library Detection Tests
    // ========================================================================

    #[test]
    fn test_is_ml_library_linux() {
        assert!(is_ml_library(Path::new("/usr/lib/libtorch.so")));
        assert!(is_ml_library(Path::new("/opt/cuda/lib64/libcublas.so.12")));
        assert!(is_ml_library(Path::new(
            "/home/user/venv/lib/python3.11/site-packages/torch/_C.cpython-311-x86_64-linux-gnu.so"
        )));
        assert!(is_ml_library(Path::new("libonnxruntime.so.1.17.0")));
        assert!(is_ml_library(Path::new("libggml.so")));
        assert!(is_ml_library(Path::new("libllama.so")));
    }

    #[test]
    fn test_is_ml_library_windows() {
        assert!(is_ml_library(Path::new(
            "C:\\Python311\\Lib\\site-packages\\torch\\lib\\torch_cpu.dll"
        )));
        assert!(is_ml_library(Path::new("torch_cuda.dll")));
        assert!(is_ml_library(Path::new("onnxruntime.dll")));
        assert!(is_ml_library(Path::new("llama.dll")));
    }

    #[test]
    fn test_is_ml_library_negative() {
        assert!(!is_ml_library(Path::new("/lib/x86_64-linux-gnu/libc.so.6")));
        assert!(!is_ml_library(Path::new("kernel32.dll")));
        assert!(!is_ml_library(Path::new("libssl.so.3")));
        assert!(!is_ml_library(Path::new("random_library.so")));
    }

    // ========================================================================
    // Model File Detection Tests
    // ========================================================================

    #[test]
    fn test_is_model_file() {
        assert!(is_model_file(Path::new("model.gguf")));
        assert!(is_model_file(Path::new("model.safetensors")));
        assert!(is_model_file(Path::new("model.pt")));
        assert!(is_model_file(Path::new("model.pth")));
        assert!(is_model_file(Path::new("model.onnx")));
        assert!(is_model_file(Path::new("model.pkl")));
        assert!(is_model_file(Path::new("model.bin")));
        assert!(is_model_file(Path::new("/path/to/llama-7b-q4.gguf")));
    }

    #[test]
    fn test_is_model_file_case_insensitive() {
        assert!(is_model_file(Path::new("MODEL.GGUF")));
        assert!(is_model_file(Path::new("Model.SafeTensors")));
        assert!(is_model_file(Path::new("model.PT")));
    }

    #[test]
    fn test_is_model_file_negative() {
        assert!(!is_model_file(Path::new("model.txt")));
        assert!(!is_model_file(Path::new("model.json")));
        assert!(!is_model_file(Path::new("model.exe")));
        assert!(!is_model_file(Path::new("model")));
    }

    // ========================================================================
    // Session Tracking Tests
    // ========================================================================

    #[test]
    fn test_session_creation() {
        let session = ModelLoadSession::new(
            1234,
            "python".to_string(),
            "/usr/bin/python".to_string(),
            "python main.py".to_string(),
            "user".to_string(),
        );

        assert_eq!(session.process_id, 1234);
        assert_eq!(session.process_name, "python");
        assert!(!session.is_expired());
        assert!(!session.is_confirmed());
    }

    #[test]
    fn test_session_confirmation() {
        let mut session = ModelLoadSession::new(
            1234,
            "python".to_string(),
            "/usr/bin/python".to_string(),
            "python main.py".to_string(),
            "user".to_string(),
        );

        // Not confirmed initially
        assert!(!session.is_confirmed());

        // Add library load
        session.ml_library_loaded = Some("libtorch.so".to_string());
        assert!(!session.is_confirmed());

        // Add file access
        session.model_file_accessed = Some(PathBuf::from("/models/model.gguf"));
        assert!(session.is_confirmed());
    }

    // ========================================================================
    // Deduplication Tests
    // ========================================================================

    #[test]
    fn test_deduplication_key() {
        let key1 = (1234u32, "/models/model.gguf".to_string());
        let key2 = (1234u32, "/models/model.gguf".to_string());
        let key3 = (1234u32, "/models/other.gguf".to_string());
        let key4 = (5678u32, "/models/model.gguf".to_string());

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
        assert_ne!(key1, key4);
    }

    // ========================================================================
    // Event Structure Tests
    // ========================================================================

    #[test]
    fn test_ai_model_load_event_serialization() {
        let event = AIModelLoadEvent {
            timestamp: 1714484400000,
            process: ProcessContext {
                pid: 1234,
                name: "python".to_string(),
                path: "/usr/bin/python".to_string(),
                cmdline: "python main.py".to_string(),
                user: "user".to_string(),
            },
            model: ModelInfo {
                path: "/models/llama-7b.gguf".to_string(),
                filename: "llama-7b.gguf".to_string(),
                format: ModelFormat::Gguf,
                size_bytes: 4_000_000_000,
                hash_sha256: None,
                architecture: Some("llama".to_string()),
                parameters: Some("7B".to_string()),
                quantization: Some("Q4_K_M".to_string()),
            },
            loading_method: LoadingMethod::FileRead,
            libraries_loaded: vec!["libllama.so".to_string()],
            risk_indicators: vec![],
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"pid\":1234"));
        assert!(json.contains("\"format\":\"gguf\""));
        assert!(json.contains("\"architecture\":\"llama\""));
        assert!(json.contains("\"loading_method\":\"file_read\""));

        // Verify deserialization
        let deserialized: AIModelLoadEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.process.pid, 1234);
        assert_eq!(deserialized.model.format, ModelFormat::Gguf);
    }

    #[test]
    fn test_loading_method_serialization() {
        assert_eq!(
            serde_json::to_string(&LoadingMethod::FileRead).unwrap(),
            "\"file_read\""
        );
        assert_eq!(
            serde_json::to_string(&LoadingMethod::Mmap).unwrap(),
            "\"mmap\""
        );
        assert_eq!(
            serde_json::to_string(&LoadingMethod::Network).unwrap(),
            "\"network\""
        );
    }

    #[test]
    fn test_process_context_default() {
        let ctx = ProcessContext::default();
        assert_eq!(ctx.pid, 0);
        assert!(ctx.name.is_empty());
        assert!(ctx.path.is_empty());
    }

    // ========================================================================
    // Risk Indicator Tests
    // ========================================================================

    #[test]
    fn test_severity_determination() {
        let mut event = AIModelLoadEvent::default();

        // No indicators -> Info
        assert_eq!(determine_severity(&event), Severity::Info);

        // 1 indicator -> Medium
        event.risk_indicators.push("indicator1".to_string());
        assert_eq!(determine_severity(&event), Severity::Medium);

        // 2 indicators -> Medium
        event.risk_indicators.push("indicator2".to_string());
        assert_eq!(determine_severity(&event), Severity::Medium);

        // 3+ indicators -> High
        event.risk_indicators.push("indicator3".to_string());
        assert_eq!(determine_severity(&event), Severity::High);
    }

    // ========================================================================
    // Integration Tests
    // ========================================================================

    #[tokio::test]
    async fn test_collector_creation() {
        let config = AgentConfig::default();
        let collector = AIModelLoaderCollector::new(&config);

        // Sessions map should be empty initially
        assert!(collector.sessions.is_empty());
        assert!(collector.confirmed_loads.is_empty());
    }

    #[tokio::test]
    async fn test_on_library_load() {
        let config = AgentConfig::default();
        let collector = AIModelLoaderCollector::new(&config);

        // Inject library load event
        collector.on_library_load(1234, Path::new("/usr/lib/libtorch.so"));

        // Session should be created
        assert!(collector.sessions.contains_key(&1234));

        // Library should be recorded
        let session = collector.sessions.get(&1234).unwrap();
        assert_eq!(session.ml_library_loaded, Some("libtorch.so".to_string()));
    }

    #[tokio::test]
    async fn test_on_file_access() {
        let config = AgentConfig::default();
        let collector = AIModelLoaderCollector::new(&config);

        // Inject file access event
        collector.on_file_access(1234, Path::new("/models/model.gguf"));

        // Session should be created
        assert!(collector.sessions.contains_key(&1234));

        // File should be recorded
        let session = collector.sessions.get(&1234).unwrap();
        assert_eq!(
            session.model_file_accessed,
            Some(PathBuf::from("/models/model.gguf"))
        );
    }

    #[tokio::test]
    async fn test_dual_signal_correlation() {
        let config = AgentConfig::default();
        let collector = AIModelLoaderCollector::new(&config);

        // First signal: library load
        collector.on_library_load(1234, Path::new("/usr/lib/libtorch.so"));

        // Session not confirmed yet
        {
            let session = collector.sessions.get(&1234).unwrap();
            assert!(!session.is_confirmed());
        }

        // Second signal: file access
        collector.on_file_access(1234, Path::new("/models/model.gguf"));

        // Session should now be confirmed
        {
            let session = collector.sessions.get(&1234).unwrap();
            assert!(session.is_confirmed());
        }
    }

    #[tokio::test]
    async fn test_non_ml_library_ignored() {
        let config = AgentConfig::default();
        let collector = AIModelLoaderCollector::new(&config);

        // Inject non-ML library load
        collector.on_library_load(1234, Path::new("/lib/x86_64-linux-gnu/libc.so.6"));

        // Session should NOT be created
        assert!(!collector.sessions.contains_key(&1234));
    }

    #[tokio::test]
    async fn test_non_model_file_ignored() {
        let config = AgentConfig::default();
        let collector = AIModelLoaderCollector::new(&config);

        // Inject non-model file access
        collector.on_file_access(1234, Path::new("/etc/passwd"));

        // Session should NOT be created
        assert!(!collector.sessions.contains_key(&1234));
    }
}
