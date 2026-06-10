//! Plugin API Definitions
//!
//! This module defines the host functions and data structures that plugins can use
//! to interact with the agent. All interactions are mediated through WASM imports.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Telemetry event sent by collector plugins
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginEvent {
    /// Event type identifier
    pub event_type: String,
    /// Event timestamp (Unix epoch milliseconds)
    pub timestamp: u64,
    /// Event severity (0-10)
    pub severity: u8,
    /// Event data (JSON)
    pub data: HashMap<String, serde_json::Value>,
    /// Tags
    pub tags: Vec<String>,
}

/// Analysis result from analyzer plugins
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// Analysis verdict
    pub verdict: Verdict,
    /// Confidence score (0.0-1.0)
    pub confidence: f64,
    /// Analysis details
    pub details: String,
    /// Matched indicators
    pub indicators: Vec<String>,
    /// Recommended actions
    pub recommended_actions: Vec<String>,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Analysis verdict
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// Benign behavior
    Benign,
    /// Suspicious behavior
    Suspicious,
    /// Malicious behavior
    Malicious,
    /// Unknown/Undetermined
    Unknown,
}

/// Response action executed by response plugins
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAction {
    /// Action type
    pub action_type: String,
    /// Target (e.g., process ID, file path)
    pub target: String,
    /// Action parameters
    pub parameters: HashMap<String, serde_json::Value>,
}

/// Response action result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseResult {
    /// Whether action succeeded
    pub success: bool,
    /// Result message
    pub message: String,
    /// Actions taken
    pub actions_taken: Vec<String>,
    /// Rollback information (for recovery)
    pub rollback_info: Option<String>,
}

/// Process information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub path: String,
    pub command_line: String,
    pub username: String,
    pub start_time: u64,
    pub is_elevated: bool,
}

/// File information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub path: String,
    pub size: u64,
    pub created: u64,
    pub modified: u64,
    pub accessed: u64,
    pub hash_sha256: Option<String>,
    pub hash_md5: Option<String>,
    pub is_signed: bool,
    pub signer: Option<String>,
}

/// Network connection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub protocol: String,
    pub state: String,
    pub pid: u32,
}

/// Host API trait (implemented by agent, called by plugins)
pub trait PluginHostApi {
    /// Log message from plugin
    fn log(&self, level: LogLevel, message: &str) -> Result<()>;

    /// Send event to backend
    fn send_event(&self, event: PluginEvent) -> Result<()>;

    /// Get process information
    fn get_process_info(&self, pid: u32) -> Result<Option<ProcessInfo>>;

    /// Get file information
    fn get_file_info(&self, path: &str) -> Result<Option<FileInfo>>;

    /// List network connections
    fn list_network_connections(&self) -> Result<Vec<NetworkConnection>>;

    /// Read file content
    fn read_file(&self, path: &str, max_bytes: usize) -> Result<Vec<u8>>;

    /// Calculate file hash
    fn hash_file(&self, path: &str, algorithm: HashAlgorithm) -> Result<String>;

    /// Execute YARA scan
    fn yara_scan_file(&self, path: &str) -> Result<Vec<String>>;

    /// Execute ML inference
    fn ml_classify_file(&self, path: &str) -> Result<(Verdict, f64)>;

    /// Kill process
    fn kill_process(&self, pid: u32, force: bool) -> Result<bool>;

    /// Quarantine file
    fn quarantine_file(&self, path: &str) -> Result<String>;

    /// Get configuration value
    fn get_config(&self, key: &str) -> Result<Option<String>>;

    /// Get environment variable
    fn get_env(&self, key: &str) -> Result<Option<String>>;

    /// Make HTTP request (if network capability granted)
    fn http_request(&self, method: &str, url: &str, body: Option<Vec<u8>>) -> Result<HttpResponse>;
}

/// Log level for plugin logging
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// Hash algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    Sha256,
    Sha1,
    Md5,
}

/// HTTP response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

/// Collector plugin trait (implemented by plugins)
pub trait CollectorPlugin {
    /// Initialize the collector
    fn init(&mut self, config: HashMap<String, serde_json::Value>) -> Result<()>;

    /// Collect events (called periodically)
    fn collect(&mut self) -> Result<Vec<PluginEvent>>;

    /// Shutdown the collector
    fn shutdown(&mut self) -> Result<()>;
}

/// Analyzer plugin trait (implemented by plugins)
pub trait AnalyzerPlugin {
    /// Initialize the analyzer
    fn init(&mut self, config: HashMap<String, serde_json::Value>) -> Result<()>;

    /// Analyze an event
    fn analyze(&mut self, event: &PluginEvent) -> Result<AnalysisResult>;

    /// Shutdown the analyzer
    fn shutdown(&mut self) -> Result<()>;
}

/// Response plugin trait (implemented by plugins)
pub trait ResponsePlugin {
    /// Initialize the response plugin
    fn init(&mut self, config: HashMap<String, serde_json::Value>) -> Result<()>;

    /// Execute a response action
    fn execute(&mut self, action: &ResponseAction) -> Result<ResponseResult>;

    /// Shutdown the response plugin
    fn shutdown(&mut self) -> Result<()>;
}

/// Plugin exports structure (what plugin must export)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginExports {
    /// Plugin initialization
    pub init: String,
    /// Main function (collect/analyze/execute)
    pub main: String,
    /// Shutdown function
    pub shutdown: String,
}

impl Default for PluginExports {
    fn default() -> Self {
        Self {
            init: "plugin_init".to_string(),
            main: "plugin_main".to_string(),
            shutdown: "plugin_shutdown".to_string(),
        }
    }
}

/// Memory layout for passing data between host and plugin
///
/// Data is serialized as JSON and passed via linear memory.
/// The plugin allocates memory and returns a pointer to the host.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WasmPtr {
    pub offset: u32,
    pub length: u32,
}

impl WasmPtr {
    pub fn new(offset: u32, length: u32) -> Self {
        Self { offset, length }
    }

    pub fn null() -> Self {
        Self {
            offset: 0,
            length: 0,
        }
    }

    pub fn is_null(&self) -> bool {
        self.offset == 0 && self.length == 0
    }
}

/// Convert Rust types to/from WASM linear memory
pub mod wasm_serde {
    use super::*;
    use wasmtime::Memory;

    /// Serialize value to JSON and write to WASM memory
    pub fn write_to_memory<T: Serialize>(
        memory: &Memory,
        store: &mut impl wasmtime::AsContextMut,
        value: &T,
    ) -> Result<WasmPtr> {
        let json = serde_json::to_vec(value)?;
        let len = json.len() as u32;

        // For simplicity, we write to a pre-allocated buffer in WASM
        // In practice, the plugin should export an allocator function
        let data = memory.data_mut(store);
        let offset = 0; // Simplified: use fixed offset or proper allocator

        if offset + len as usize > data.len() {
            anyhow::bail!("Insufficient WASM memory");
        }

        data[offset..offset + len as usize].copy_from_slice(&json);

        Ok(WasmPtr::new(offset as u32, len))
    }

    /// Read value from WASM memory and deserialize from JSON
    pub fn read_from_memory<T: for<'de> Deserialize<'de>>(
        memory: &Memory,
        store: &impl wasmtime::AsContext,
        ptr: WasmPtr,
    ) -> Result<T> {
        if ptr.is_null() {
            anyhow::bail!("Null pointer");
        }

        let data = memory.data(store);
        let start = ptr.offset as usize;
        let end = start + ptr.length as usize;

        if end > data.len() {
            anyhow::bail!("Invalid memory access");
        }

        let json = &data[start..end];
        let value: T = serde_json::from_slice(json)?;

        Ok(value)
    }
}
