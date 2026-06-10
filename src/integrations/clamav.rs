//! ClamAV Integration for Linux
//!
//! Provides integration with ClamAV antivirus on Linux systems:
//! - Read ClamAV scan results
//! - Coordinate real-time scanning with clamd
//! - Leverage ClamAV signature database
//! - Avoid duplicate scanning
//!
//! ## Architecture
//!
//! ```text
//! +------------------+     +------------------+     +------------------+
//! | Tamandua Agent   |<--->| clamd Socket     |<--->| ClamAV (clamd)   |
//! |                  |     | /var/run/clamav/ |     |                  |
//! +------------------+     +------------------+     +------------------+
//!         |                                                |
//!         v                                                v
//! +------------------+                          +------------------+
//! | fanotify         |                          | Signature DB     |
//! | Coordination     |                          | /var/lib/clamav/ |
//! +------------------+                          +------------------+
//! ```
//!
//! ## Usage
//!
//! ClamAV must be installed with clamd running:
//! ```bash
//! sudo apt install clamav clamav-daemon
//! sudo systemctl enable --now clamav-daemon
//! ```

#![cfg(target_os = "linux")]

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// ClamAV scan result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClamAvResult {
    /// File is clean
    Clean,
    /// Virus found
    Virus(String),
    /// Scan error
    Error(String),
}

/// ClamAV integration configuration
#[derive(Debug, Clone)]
pub struct ClamAvConfig {
    /// Path to clamd socket
    pub socket_path: String,
    /// Connection timeout
    pub timeout: Duration,
    /// Maximum file size to scan (bytes)
    pub max_scan_size: usize,
    /// Enable stream scanning
    pub enable_streaming: bool,
    /// Cache clean file results
    pub enable_cache: bool,
    /// Cache TTL
    pub cache_ttl: Duration,
}

impl Default for ClamAvConfig {
    fn default() -> Self {
        Self {
            socket_path: "/var/run/clamav/clamd.ctl".to_string(),
            timeout: Duration::from_secs(30),
            max_scan_size: 100 * 1024 * 1024, // 100 MB
            enable_streaming: true,
            enable_cache: true,
            cache_ttl: Duration::from_secs(300),
        }
    }
}

/// ClamAV threat event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClamAvThreatEvent {
    /// File path
    pub file_path: String,
    /// Virus name
    pub virus_name: String,
    /// Scan timestamp
    pub timestamp: u64,
    /// File hash (if computed)
    pub sha256: Option<String>,
    /// File size
    pub file_size: u64,
}

/// ClamAV integration statistics
#[derive(Debug, Default)]
pub struct ClamAvStats {
    /// Total files scanned
    pub files_scanned: AtomicU64,
    /// Viruses found
    pub viruses_found: AtomicU64,
    /// Clean files
    pub clean_files: AtomicU64,
    /// Scan errors
    pub scan_errors: AtomicU64,
    /// Cache hits
    pub cache_hits: AtomicU64,
}

/// ClamAV integration handler
pub struct ClamAvIntegration {
    config: ClamAvConfig,
    stats: Arc<ClamAvStats>,
    /// Cache of recently scanned files
    cache: std::sync::RwLock<HashMap<String, (ClamAvResult, Instant)>>,
    /// Event channel
    event_tx: Option<mpsc::Sender<ClamAvThreatEvent>>,
}

impl ClamAvIntegration {
    /// Create new ClamAV integration
    pub fn new(config: ClamAvConfig) -> Result<Self> {
        Ok(Self {
            config,
            stats: Arc::new(ClamAvStats::default()),
            cache: std::sync::RwLock::new(HashMap::new()),
            event_tx: None,
        })
    }

    /// Set event channel for threat notifications
    pub fn set_event_channel(&mut self, tx: mpsc::Sender<ClamAvThreatEvent>) {
        self.event_tx = Some(tx);
    }

    /// Check if ClamAV is available
    pub fn is_available(&self) -> bool {
        Path::new(&self.config.socket_path).exists()
    }

    /// Ping clamd to check connectivity
    pub fn ping(&self) -> Result<bool> {
        let mut stream = self.connect()?;
        stream.write_all(b"PING\0")?;

        let mut response = String::new();
        stream.read_to_string(&mut response)?;

        Ok(response.trim() == "PONG")
    }

    /// Get ClamAV version
    pub fn version(&self) -> Result<String> {
        let mut stream = self.connect()?;
        stream.write_all(b"VERSION\0")?;

        let mut response = String::new();
        stream.read_to_string(&mut response)?;

        Ok(response.trim().to_string())
    }

    /// Scan a file
    pub fn scan_file(&self, path: &str) -> Result<ClamAvResult> {
        // Check cache first
        if self.config.enable_cache {
            if let Some(result) = self.get_cached(path) {
                self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Ok(result);
            }
        }

        self.stats.files_scanned.fetch_add(1, Ordering::Relaxed);

        // Connect to clamd
        let mut stream = self.connect()?;

        // Send SCAN command
        let command = format!("SCAN {}\0", path);
        stream.write_all(command.as_bytes())?;

        // Read response
        let mut response = String::new();
        stream.read_to_string(&mut response)?;

        // Parse response
        let result = self.parse_response(&response, path);

        // Update stats
        match &result {
            ClamAvResult::Clean => {
                self.stats.clean_files.fetch_add(1, Ordering::Relaxed);
            }
            ClamAvResult::Virus(name) => {
                self.stats.viruses_found.fetch_add(1, Ordering::Relaxed);

                // Send event
                if let Some(ref tx) = self.event_tx {
                    let event = ClamAvThreatEvent {
                        file_path: path.to_string(),
                        virus_name: name.clone(),
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64,
                        sha256: None,
                        file_size: std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
                    };

                    let tx = tx.clone();
                    tokio::spawn(async move {
                        let _ = tx.send(event).await;
                    });
                }
            }
            ClamAvResult::Error(_) => {
                self.stats.scan_errors.fetch_add(1, Ordering::Relaxed);
            }
        }

        // Cache result
        if self.config.enable_cache {
            self.cache_result(path, result.clone());
        }

        Ok(result)
    }

    /// Scan data stream
    pub fn scan_stream(&self, data: &[u8]) -> Result<ClamAvResult> {
        if !self.config.enable_streaming {
            return Err(anyhow!("Streaming not enabled"));
        }

        if data.len() > self.config.max_scan_size {
            return Err(anyhow!("Data exceeds maximum scan size"));
        }

        self.stats.files_scanned.fetch_add(1, Ordering::Relaxed);

        let mut stream = self.connect()?;

        // Send INSTREAM command
        stream.write_all(b"zINSTREAM\0")?;

        // Send data length (big-endian u32)
        let len = data.len() as u32;
        stream.write_all(&len.to_be_bytes())?;

        // Send data
        stream.write_all(data)?;

        // Send terminating zero-length chunk
        stream.write_all(&[0u8; 4])?;

        // Read response
        let mut response = String::new();
        stream.read_to_string(&mut response)?;

        Ok(self.parse_response(&response, "stream"))
    }

    /// Reload ClamAV database
    pub fn reload(&self) -> Result<()> {
        let mut stream = self.connect()?;
        stream.write_all(b"RELOAD\0")?;

        let mut response = String::new();
        stream.read_to_string(&mut response)?;

        if response.trim() == "RELOADING" {
            Ok(())
        } else {
            Err(anyhow!("Reload failed: {}", response))
        }
    }

    /// Get statistics
    pub fn get_stats(&self) -> &ClamAvStats {
        &self.stats
    }

    /// Get signature database info
    pub fn get_db_info(&self) -> Result<HashMap<String, String>> {
        let mut stream = self.connect()?;
        stream.write_all(b"STATS\0")?;

        let mut response = String::new();
        stream.read_to_string(&mut response)?;

        let mut info = HashMap::new();
        for line in response.lines() {
            if let Some((key, value)) = line.split_once(':') {
                info.insert(key.trim().to_string(), value.trim().to_string());
            }
        }

        Ok(info)
    }

    // ========================================================================
    // Private Implementation
    // ========================================================================

    /// Connect to clamd socket
    fn connect(&self) -> Result<UnixStream> {
        let stream = UnixStream::connect(&self.config.socket_path)
            .map_err(|e| anyhow!("Failed to connect to clamd: {}", e))?;

        stream.set_read_timeout(Some(self.config.timeout))?;
        stream.set_write_timeout(Some(self.config.timeout))?;

        Ok(stream)
    }

    /// Parse clamd response
    fn parse_response(&self, response: &str, path: &str) -> ClamAvResult {
        let response = response.trim();

        // Response format: "path: RESULT"
        if response.ends_with("OK") {
            ClamAvResult::Clean
        } else if response.contains("FOUND") {
            // Extract virus name
            // Format: "path: VirusName FOUND"
            let parts: Vec<&str> = response.split(':').collect();
            if parts.len() >= 2 {
                let result = parts[1].trim();
                if let Some(virus) = result.strip_suffix(" FOUND") {
                    return ClamAvResult::Virus(virus.to_string());
                }
            }
            ClamAvResult::Virus("Unknown".to_string())
        } else if response.contains("ERROR") {
            ClamAvResult::Error(response.to_string())
        } else {
            ClamAvResult::Error(format!("Unknown response: {}", response))
        }
    }

    /// Get cached result
    fn get_cached(&self, path: &str) -> Option<ClamAvResult> {
        let cache = self.cache.read().ok()?;
        if let Some((result, timestamp)) = cache.get(path) {
            if timestamp.elapsed() < self.config.cache_ttl {
                return Some(result.clone());
            }
        }
        None
    }

    /// Cache scan result
    fn cache_result(&self, path: &str, result: ClamAvResult) {
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(path.to_string(), (result, Instant::now()));

            // Prune old entries
            if cache.len() > 10000 {
                let now = Instant::now();
                cache.retain(|_, (_, ts)| now.duration_since(*ts) < self.config.cache_ttl);
            }
        }
    }
}

/// Monitor ClamAV logs for real-time detections
pub struct ClamAvLogMonitor {
    running: Arc<AtomicBool>,
    log_path: String,
}

impl ClamAvLogMonitor {
    pub fn new(log_path: &str) -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            log_path: log_path.to_string(),
        }
    }

    /// Start monitoring ClamAV logs
    pub async fn start<F>(&self, callback: F)
    where
        F: Fn(ClamAvThreatEvent) + Send + Sync + 'static,
    {
        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();
        let log_path = self.log_path.clone();

        tokio::spawn(async move {
            // Use inotify to watch log file
            Self::watch_log(running, log_path, callback).await;
        });
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    async fn watch_log<F>(running: Arc<AtomicBool>, log_path: String, callback: F)
    where
        F: Fn(ClamAvThreatEvent) + Send + Sync + 'static,
    {
        use std::fs::File;
        use std::io::{BufRead, BufReader, Seek, SeekFrom};

        let file = match File::open(&log_path) {
            Ok(f) => f,
            Err(e) => {
                error!(error = %e, path = %log_path, "Failed to open ClamAV log");
                return;
            }
        };

        let mut reader = BufReader::new(file);
        // Seek to end
        let _ = reader.seek(SeekFrom::End(0));

        while running.load(Ordering::SeqCst) {
            let mut line = String::new();

            match reader.read_line(&mut line) {
                Ok(0) => {
                    // No new data, wait
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Ok(_) => {
                    // Parse log line for detections
                    if line.contains("FOUND") {
                        if let Some(event) = Self::parse_log_line(&line) {
                            callback(event);
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Error reading ClamAV log");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    fn parse_log_line(line: &str) -> Option<ClamAvThreatEvent> {
        // Example: "path/to/file: Win.Malware.Agent-1234 FOUND"
        if let Some((path_part, rest)) = line.split_once(':') {
            if let Some(virus) = rest.trim().strip_suffix(" FOUND") {
                return Some(ClamAvThreatEvent {
                    file_path: path_part.trim().to_string(),
                    virus_name: virus.trim().to_string(),
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                    sha256: None,
                    file_size: 0,
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_clean_response() {
        let config = ClamAvConfig::default();
        let integration = ClamAvIntegration::new(config).unwrap();

        let result = integration.parse_response("/path/to/file: OK", "/path/to/file");
        assert!(matches!(result, ClamAvResult::Clean));
    }

    #[test]
    fn test_parse_virus_response() {
        let config = ClamAvConfig::default();
        let integration = ClamAvIntegration::new(config).unwrap();

        let result = integration.parse_response(
            "/path/to/file: Win.Malware.Agent-1234 FOUND",
            "/path/to/file",
        );

        match result {
            ClamAvResult::Virus(name) => {
                assert_eq!(name, "Win.Malware.Agent-1234");
            }
            _ => panic!("Expected virus result"),
        }
    }

    #[test]
    fn test_config_defaults() {
        let config = ClamAvConfig::default();
        assert_eq!(config.socket_path, "/var/run/clamav/clamd.ctl");
        assert!(config.enable_streaming);
    }
}
