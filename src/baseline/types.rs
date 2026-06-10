//! Baseline type definitions

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Anomaly detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    /// Anomaly type
    pub anomaly_type: AnomalyType,
    /// Anomaly score (0-100)
    pub score: f64,
    /// Baseline that was violated
    pub baseline_name: String,
    /// Description of the anomaly
    pub description: String,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
    /// Z-score (standard deviations from mean)
    pub z_score: f64,
    /// Expected value (from baseline)
    pub expected: f64,
    /// Observed value
    pub observed: f64,
    /// Timestamp of the anomaly
    pub timestamp: i64,
}

/// Anomaly types
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AnomalyType {
    /// Process memory usage anomaly
    ProcessMemory,
    /// Process CPU usage anomaly
    ProcessCpu,
    /// Process network connection anomaly
    ProcessNetwork,
    /// User login time anomaly
    UserLoginTime,
    /// User workstation anomaly
    UserWorkstation,
    /// User application anomaly
    UserApplication,
    /// Network destination anomaly
    NetworkDestination,
    /// Network port anomaly
    NetworkPort,
    /// Network protocol anomaly
    NetworkProtocol,
    /// File access anomaly
    FileAccess,
    /// Registry access anomaly (Windows only)
    RegistryAccess,
    /// Process count anomaly
    ProcessCount,
    /// Unknown anomaly type
    Unknown,
}

impl std::fmt::Display for AnomalyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProcessMemory => write!(f, "process_memory"),
            Self::ProcessCpu => write!(f, "process_cpu"),
            Self::ProcessNetwork => write!(f, "process_network"),
            Self::UserLoginTime => write!(f, "user_login_time"),
            Self::UserWorkstation => write!(f, "user_workstation"),
            Self::UserApplication => write!(f, "user_application"),
            Self::NetworkDestination => write!(f, "network_destination"),
            Self::NetworkPort => write!(f, "network_port"),
            Self::NetworkProtocol => write!(f, "network_protocol"),
            Self::FileAccess => write!(f, "file_access"),
            Self::RegistryAccess => write!(f, "registry_access"),
            Self::ProcessCount => write!(f, "process_count"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Process baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessBaseline {
    /// Process name (e.g., "chrome.exe")
    pub process_name: String,
    /// Average memory usage in MB
    pub avg_memory_mb: f64,
    /// Standard deviation of memory usage
    pub stddev_memory_mb: f64,
    /// Average CPU percent (0-100)
    pub avg_cpu_percent: f64,
    /// Standard deviation of CPU percent
    pub stddev_cpu_percent: f64,
    /// Common network destinations (IP:port)
    pub common_network_destinations: HashMap<String, u32>,
    /// Common file access patterns (file path -> access count)
    pub common_file_access: HashMap<String, u32>,
    /// Number of learning samples collected
    pub learning_samples: u32,
    /// First seen timestamp
    pub first_seen: i64,
    /// Last updated timestamp
    pub last_updated: i64,
    /// Baseline version (for tracking changes)
    pub version: u32,
}

impl ProcessBaseline {
    pub fn new(process_name: String) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            process_name,
            avg_memory_mb: 0.0,
            stddev_memory_mb: 0.0,
            avg_cpu_percent: 0.0,
            stddev_cpu_percent: 0.0,
            common_network_destinations: HashMap::new(),
            common_file_access: HashMap::new(),
            learning_samples: 0,
            first_seen: now,
            last_updated: now,
            version: 1,
        }
    }
}

/// User baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserBaseline {
    /// Username
    pub username: String,
    /// Common login hour histogram (0-23)
    pub login_hours: Vec<u32>,
    /// Common workstations (hostname -> count)
    pub common_workstations: HashMap<String, u32>,
    /// Common applications (process name -> count)
    pub common_applications: HashMap<String, u32>,
    /// Number of learning samples
    pub learning_samples: u32,
    /// First seen timestamp
    pub first_seen: i64,
    /// Last updated timestamp
    pub last_updated: i64,
    /// Baseline version
    pub version: u32,
}

impl UserBaseline {
    pub fn new(username: String) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            username,
            login_hours: vec![0; 24],
            common_workstations: HashMap::new(),
            common_applications: HashMap::new(),
            learning_samples: 0,
            first_seen: now,
            last_updated: now,
            version: 1,
        }
    }
}

/// Network connection baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkBaseline {
    /// Baseline key (e.g., "chrome.exe" or "system-wide")
    pub key: String,
    /// Common destinations (IP/hostname)
    pub common_destinations: HashMap<String, u32>,
    /// Common ports
    pub common_ports: HashMap<u16, u32>,
    /// Common protocols
    pub common_protocols: HashMap<String, u32>,
    /// Number of learning samples
    pub learning_samples: u32,
    /// First seen timestamp
    pub first_seen: i64,
    /// Last updated timestamp
    pub last_updated: i64,
    /// Baseline version
    pub version: u32,
}

impl NetworkBaseline {
    pub fn new(key: String) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            key,
            common_destinations: HashMap::new(),
            common_ports: HashMap::new(),
            common_protocols: HashMap::new(),
            learning_samples: 0,
            first_seen: now,
            last_updated: now,
            version: 1,
        }
    }
}

/// File access baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAccessBaseline {
    /// Process name
    pub process_name: String,
    /// Common file paths accessed
    pub common_paths: HashMap<String, u32>,
    /// Common file extensions
    pub common_extensions: HashMap<String, u32>,
    /// Number of learning samples
    pub learning_samples: u32,
    /// First seen timestamp
    pub first_seen: i64,
    /// Last updated timestamp
    pub last_updated: i64,
    /// Baseline version
    pub version: u32,
}

impl FileAccessBaseline {
    pub fn new(process_name: String) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            process_name,
            common_paths: HashMap::new(),
            common_extensions: HashMap::new(),
            learning_samples: 0,
            first_seen: now,
            last_updated: now,
            version: 1,
        }
    }
}

/// Registry access baseline (Windows only)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryBaseline {
    /// Process name
    pub process_name: String,
    /// Common registry keys accessed
    pub common_keys: HashMap<String, u32>,
    /// Number of learning samples
    pub learning_samples: u32,
    /// First seen timestamp
    pub first_seen: i64,
    /// Last updated timestamp
    pub last_updated: i64,
    /// Baseline version
    pub version: u32,
}

impl RegistryBaseline {
    pub fn new(process_name: String) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            process_name,
            common_keys: HashMap::new(),
            learning_samples: 0,
            first_seen: now,
            last_updated: now,
            version: 1,
        }
    }
}

/// Baseline statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineStatistics {
    /// Number of process baselines
    pub process_baselines: usize,
    /// Number of user baselines
    pub user_baselines: usize,
    /// Number of network baselines
    pub network_baselines: usize,
    /// Number of file access baselines
    pub file_access_baselines: usize,
    /// Number of registry baselines
    pub registry_baselines: usize,
    /// Total learning samples
    pub total_samples: u64,
    /// Oldest baseline timestamp
    pub oldest_baseline: Option<i64>,
    /// Newest baseline timestamp
    pub newest_baseline: Option<i64>,
    /// Database size in bytes
    pub database_size_bytes: u64,
}

impl Default for BaselineStatistics {
    fn default() -> Self {
        Self {
            process_baselines: 0,
            user_baselines: 0,
            network_baselines: 0,
            file_access_baselines: 0,
            registry_baselines: 0,
            total_samples: 0,
            oldest_baseline: None,
            newest_baseline: None,
            database_size_bytes: 0,
        }
    }
}

/// Baseline drift detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineDrift {
    /// Baseline name
    pub baseline_name: String,
    /// Drift percentage (0-100)
    pub drift_percent: f64,
    /// Drift direction (increasing or decreasing)
    pub direction: DriftDirection,
    /// Description
    pub description: String,
    /// Timestamp
    pub timestamp: i64,
}

/// Drift direction
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DriftDirection {
    Increasing,
    Decreasing,
    Stable,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_baseline_creation() {
        let baseline = ProcessBaseline::new("chrome.exe".to_string());
        assert_eq!(baseline.process_name, "chrome.exe");
        assert_eq!(baseline.learning_samples, 0);
        assert_eq!(baseline.version, 1);
    }

    #[test]
    fn test_user_baseline_creation() {
        let baseline = UserBaseline::new("alice".to_string());
        assert_eq!(baseline.username, "alice");
        assert_eq!(baseline.login_hours.len(), 24);
        assert_eq!(baseline.learning_samples, 0);
    }

    #[test]
    fn test_anomaly_type_display() {
        assert_eq!(AnomalyType::ProcessMemory.to_string(), "process_memory");
        assert_eq!(
            AnomalyType::NetworkDestination.to_string(),
            "network_destination"
        );
    }
}
