//! Plugin Sandbox Configuration and Resource Limits
//!
//! This module defines security policies and resource constraints for plugin execution.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Sandbox configuration for plugin execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Memory limit (bytes)
    pub memory_limit_bytes: u64,

    /// CPU time limit per execution (microseconds)
    pub cpu_time_limit_us: u64,

    /// Maximum CPU usage (percentage, 0-100)
    pub max_cpu_percent: u8,

    /// Disk I/O limit (bytes per second)
    pub disk_io_limit_bps: u64,

    /// Network I/O limit (bytes per second)
    pub network_io_limit_bps: u64,

    /// Filesystem access rules
    pub filesystem_access: FilesystemAccess,

    /// Network access rules
    pub network_access: NetworkAccess,

    /// Maximum execution time per call (seconds)
    pub max_execution_time_secs: u64,

    /// Enable WASI support
    pub enable_wasi: bool,

    /// Enable networking (requires network capability)
    pub enable_networking: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            memory_limit_bytes: 64 * 1024 * 1024,  // 64 MB
            cpu_time_limit_us: 1_000_000,          // 1 second
            max_cpu_percent: 10,                   // 10% CPU
            disk_io_limit_bps: 10 * 1024 * 1024,   // 10 MB/s
            network_io_limit_bps: 5 * 1024 * 1024, // 5 MB/s
            filesystem_access: FilesystemAccess::default(),
            network_access: NetworkAccess::default(),
            max_execution_time_secs: 30,
            enable_wasi: true,
            enable_networking: false,
        }
    }
}

/// Filesystem access rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemAccess {
    /// Access mode
    pub mode: FilesystemMode,

    /// Allowed read paths (when mode is Custom)
    pub allowed_read_paths: Vec<PathBuf>,

    /// Allowed write paths (when mode is Custom)
    pub allowed_write_paths: Vec<PathBuf>,

    /// Denied paths (always denied, even if in allowed list)
    pub denied_paths: Vec<PathBuf>,
}

impl Default for FilesystemAccess {
    fn default() -> Self {
        Self {
            mode: FilesystemMode::ReadOnly,
            allowed_read_paths: vec![],
            allowed_write_paths: vec![],
            denied_paths: vec![
                // Always deny sensitive paths
                PathBuf::from("/etc/shadow"),
                PathBuf::from("/etc/passwd"),
                PathBuf::from("C:\\Windows\\System32\\config"),
                PathBuf::from("/root/.ssh"),
                PathBuf::from("C:\\Users\\*\\.ssh"),
            ],
        }
    }
}

/// Filesystem access mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemMode {
    /// No filesystem access
    Disabled,
    /// Read-only access to all non-sensitive paths
    ReadOnly,
    /// Read-write access to all non-sensitive paths
    ReadWrite,
    /// Custom access rules (use allowed_read_paths/allowed_write_paths)
    Custom,
}

/// Network access rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAccess {
    /// Access mode
    pub mode: NetworkMode,

    /// Allowed domains/IPs (when mode is Allowlist)
    pub allowlist: Vec<String>,

    /// Denied domains/IPs (when mode is Denylist)
    pub denylist: Vec<String>,

    /// Allowed ports
    pub allowed_ports: Option<Vec<u16>>,
}

impl Default for NetworkAccess {
    fn default() -> Self {
        Self {
            mode: NetworkMode::Disabled,
            allowlist: vec![],
            denylist: vec![],
            allowed_ports: None,
        }
    }
}

/// Network access mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// No network access
    Disabled,
    /// Allow all network access
    Unrestricted,
    /// Allow only specific domains/IPs
    Allowlist,
    /// Deny specific domains/IPs, allow others
    Denylist,
}

/// Resource usage tracker
pub struct ResourceTracker {
    /// Memory usage (bytes)
    pub memory_bytes: u64,

    /// CPU time used (microseconds)
    pub cpu_time_us: u64,

    /// Disk I/O (bytes)
    pub disk_io_bytes: u64,

    /// Network I/O (bytes)
    pub network_io_bytes: u64,

    /// Start time
    start_time: std::time::Instant,
}

impl ResourceTracker {
    /// Create new resource tracker
    pub fn new() -> Self {
        Self {
            memory_bytes: 0,
            cpu_time_us: 0,
            disk_io_bytes: 0,
            network_io_bytes: 0,
            start_time: std::time::Instant::now(),
        }
    }

    /// Record memory allocation
    pub fn record_memory(&mut self, bytes: u64) {
        self.memory_bytes = self.memory_bytes.saturating_add(bytes);
    }

    /// Record CPU time
    pub fn record_cpu_time(&mut self, duration: Duration) {
        self.cpu_time_us = self.cpu_time_us.saturating_add(duration.as_micros() as u64);
    }

    /// Record disk I/O
    pub fn record_disk_io(&mut self, bytes: u64) {
        self.disk_io_bytes = self.disk_io_bytes.saturating_add(bytes);
    }

    /// Record network I/O
    pub fn record_network_io(&mut self, bytes: u64) {
        self.network_io_bytes = self.network_io_bytes.saturating_add(bytes);
    }

    /// Get elapsed time
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Check if limits are exceeded
    pub fn check_limits(&self, config: &SandboxConfig) -> Result<()> {
        if self.memory_bytes > config.memory_limit_bytes {
            anyhow::bail!(
                "Memory limit exceeded: {} > {}",
                self.memory_bytes,
                config.memory_limit_bytes
            );
        }

        if self.cpu_time_us > config.cpu_time_limit_us {
            anyhow::bail!(
                "CPU time limit exceeded: {} > {}",
                self.cpu_time_us,
                config.cpu_time_limit_us
            );
        }

        let elapsed_secs = self.elapsed().as_secs();
        if elapsed_secs > config.max_execution_time_secs {
            anyhow::bail!(
                "Execution time limit exceeded: {} > {}",
                elapsed_secs,
                config.max_execution_time_secs
            );
        }

        Ok(())
    }

    /// Reset tracker
    pub fn reset(&mut self) {
        self.memory_bytes = 0;
        self.cpu_time_us = 0;
        self.disk_io_bytes = 0;
        self.network_io_bytes = 0;
        self.start_time = std::time::Instant::now();
    }
}

/// Validate filesystem access
pub fn validate_filesystem_access(
    path: &str,
    write: bool,
    config: &FilesystemAccess,
) -> Result<bool> {
    let path = PathBuf::from(path);

    // Check denied paths first
    for denied in &config.denied_paths {
        if path.starts_with(denied) || path_matches_glob(&path, denied) {
            return Ok(false);
        }
    }

    match config.mode {
        FilesystemMode::Disabled => Ok(false),
        FilesystemMode::ReadOnly => Ok(!write),
        FilesystemMode::ReadWrite => Ok(true),
        FilesystemMode::Custom => {
            if write {
                // Check write paths
                for allowed in &config.allowed_write_paths {
                    if path.starts_with(allowed) || path_matches_glob(&path, allowed) {
                        return Ok(true);
                    }
                }
                Ok(false)
            } else {
                // Check read paths
                for allowed in &config.allowed_read_paths {
                    if path.starts_with(allowed) || path_matches_glob(&path, allowed) {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
        }
    }
}

/// Validate network access
pub fn validate_network_access(host: &str, port: u16, config: &NetworkAccess) -> Result<bool> {
    // Check port restriction
    if let Some(ref allowed_ports) = config.allowed_ports {
        if !allowed_ports.contains(&port) {
            return Ok(false);
        }
    }

    match config.mode {
        NetworkMode::Disabled => Ok(false),
        NetworkMode::Unrestricted => Ok(true),
        NetworkMode::Allowlist => {
            for allowed in &config.allowlist {
                if host_matches(host, allowed) {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        NetworkMode::Denylist => {
            for denied in &config.denylist {
                if host_matches(host, denied) {
                    return Ok(false);
                }
            }
            Ok(true)
        }
    }
}

/// Check if path matches glob pattern
fn path_matches_glob(path: &PathBuf, pattern: &PathBuf) -> bool {
    // Simple glob matching (supports * wildcard)
    let path_str = path.to_string_lossy();
    let pattern_str = pattern.to_string_lossy();

    if !pattern_str.contains('*') {
        return path_str == pattern_str;
    }

    // Convert to regex pattern
    let regex_pattern = pattern_str.replace('*', ".*");
    if let Ok(re) = regex::Regex::new(&regex_pattern) {
        re.is_match(&path_str)
    } else {
        false
    }
}

/// Check if host matches pattern (supports wildcards)
fn host_matches(host: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if !pattern.contains('*') {
        return host == pattern;
    }

    // Convert to regex pattern
    let regex_pattern = pattern.replace('.', r"\.").replace('*', ".*");
    if let Ok(re) = regex::Regex::new(&format!("^{}$", regex_pattern)) {
        re.is_match(host)
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_matching() {
        assert!(host_matches("example.com", "example.com"));
        assert!(host_matches("api.example.com", "*.example.com"));
        assert!(host_matches("anything", "*"));
        assert!(!host_matches("example.com", "other.com"));
        assert!(!host_matches("example.com", "*.other.com"));
    }

    #[test]
    fn test_resource_limits() {
        let config = SandboxConfig::default();
        let mut tracker = ResourceTracker::new();

        // Within limits
        tracker.record_memory(1024);
        tracker.record_cpu_time(Duration::from_micros(100));
        assert!(tracker.check_limits(&config).is_ok());

        // Exceed memory limit
        tracker.record_memory(config.memory_limit_bytes + 1);
        assert!(tracker.check_limits(&config).is_err());
    }

    #[test]
    fn test_filesystem_access_validation() {
        let mut config = FilesystemAccess::default();
        config.mode = FilesystemMode::Custom;
        config.allowed_read_paths = vec![PathBuf::from("/tmp")];
        config.allowed_write_paths = vec![PathBuf::from("/var/log/plugin")];

        // Read access to allowed path
        assert!(validate_filesystem_access("/tmp/test.txt", false, &config).unwrap());

        // Write access to allowed path
        assert!(validate_filesystem_access("/var/log/plugin/out.log", true, &config).unwrap());

        // Write access to read-only path
        assert!(!validate_filesystem_access("/tmp/test.txt", true, &config).unwrap());

        // Access to denied path
        config.denied_paths.push(PathBuf::from("/tmp/secret"));
        assert!(!validate_filesystem_access("/tmp/secret/data.txt", false, &config).unwrap());
    }

    #[test]
    fn test_network_access_validation() {
        let mut config = NetworkAccess::default();
        config.mode = NetworkMode::Allowlist;
        config.allowlist = vec!["api.example.com".to_string(), "*.trusted.com".to_string()];
        config.allowed_ports = Some(vec![443, 80]);

        // Allowed host and port
        assert!(validate_network_access("api.example.com", 443, &config).unwrap());

        // Allowed wildcard host
        assert!(validate_network_access("service.trusted.com", 80, &config).unwrap());

        // Denied host
        assert!(!validate_network_access("evil.com", 443, &config).unwrap());

        // Denied port
        assert!(!validate_network_access("api.example.com", 22, &config).unwrap());
    }
}
