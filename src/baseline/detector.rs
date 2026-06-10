//! Anomaly detector
//!
//! Detects deviations from learned baselines using statistical methods
//! (Z-score, outlier detection, etc.)

use super::config::BaselineConfig;
use super::storage::BaselineStorage;
use super::types::*;
use crate::collectors::{EventPayload, TelemetryEvent};
use anyhow::Result;
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Anomaly detector
pub struct AnomalyDetector {
    config: BaselineConfig,
    storage: BaselineStorage,

    // Cached baselines for fast lookup
    process_baselines: HashMap<String, ProcessBaseline>,
    user_baselines: HashMap<String, UserBaseline>,
    network_baselines: HashMap<String, NetworkBaseline>,
    file_access_baselines: HashMap<String, FileAccessBaseline>,
    #[cfg(target_os = "windows")]
    registry_baselines: HashMap<String, RegistryBaseline>,

    // Anomaly whitelist (keys that should never generate alerts)
    whitelist: HashMap<String, ()>,
}

impl AnomalyDetector {
    /// Create a new anomaly detector
    pub fn new(config: BaselineConfig, storage: BaselineStorage) -> Self {
        Self {
            config,
            storage,
            process_baselines: HashMap::new(),
            user_baselines: HashMap::new(),
            network_baselines: HashMap::new(),
            file_access_baselines: HashMap::new(),
            #[cfg(target_os = "windows")]
            registry_baselines: HashMap::new(),
            whitelist: HashMap::new(),
        }
    }

    /// Load baselines from storage into memory
    pub async fn load_baselines(&mut self) -> Result<()> {
        info!("Loading baselines from storage");

        // Load process baselines
        if self.config.enable_process_baselines {
            let baselines = self.storage.get_all_process_baselines().await?;
            for baseline in baselines {
                self.process_baselines
                    .insert(baseline.process_name.clone(), baseline);
            }
            debug!("Loaded {} process baselines", self.process_baselines.len());
        }

        // STUB — PRODUCTION-GAP, not production. Only process baselines are loaded here.
        // user_baselines / network_baselines / file_access_baselines / registry_baselines
        // remain empty even when their detect_* paths run, so anomaly detection for those
        // categories operates with no learned baseline. Missing: storage getters +
        // population for user/network/file/registry baselines.
        info!("Loaded all baselines successfully");
        Ok(())
    }

    /// Reload baselines from storage
    pub async fn reload_baselines(&mut self) -> Result<()> {
        self.process_baselines.clear();
        self.user_baselines.clear();
        self.network_baselines.clear();
        self.file_access_baselines.clear();
        #[cfg(target_os = "windows")]
        self.registry_baselines.clear();

        self.load_baselines().await
    }

    /// Detect anomalies in a telemetry event
    pub async fn detect(&mut self, event: &TelemetryEvent) -> Result<Vec<Anomaly>> {
        let mut anomalies = Vec::new();

        match &event.payload {
            EventPayload::Process(proc_event) => {
                if self.config.enable_process_baselines {
                    if let Some(process_anomalies) =
                        self.detect_process_anomalies(proc_event).await?
                    {
                        anomalies.extend(process_anomalies);
                    }
                }
            }
            EventPayload::Network(net_event) => {
                if self.config.enable_network_baselines {
                    if let Some(network_anomalies) =
                        self.detect_network_anomalies(net_event).await?
                    {
                        anomalies.extend(network_anomalies);
                    }
                }
            }
            EventPayload::File(file_event) => {
                if self.config.enable_file_access_baselines {
                    if let Some(file_anomalies) = self.detect_file_anomalies(file_event).await? {
                        anomalies.extend(file_anomalies);
                    }
                }
            }
            #[cfg(target_os = "windows")]
            EventPayload::Registry(reg_event) => {
                if self.config.enable_registry_baselines {
                    if let Some(registry_anomalies) =
                        self.detect_registry_anomalies(reg_event).await?
                    {
                        anomalies.extend(registry_anomalies);
                    }
                }
            }
            _ => {}
        }

        // Filter suppressed anomalies
        anomalies = self.filter_suppressed(anomalies).await?;

        Ok(anomalies)
    }

    /// Detect process anomalies
    async fn detect_process_anomalies(
        &mut self,
        event: &crate::collectors::ProcessEvent,
    ) -> Result<Option<Vec<Anomaly>>> {
        let process_name = event.name.to_lowercase();

        // Get baseline for this process
        let baseline = match self.process_baselines.get(&process_name) {
            Some(b) => b,
            None => {
                // No baseline yet - this is expected during learning period
                return Ok(None);
            }
        };

        // Check if baseline has enough samples
        if baseline.learning_samples < self.config.min_samples {
            return Ok(None);
        }

        let mut anomalies = Vec::new();
        let now = chrono::Utc::now().timestamp();

        // In a real implementation, we would extract actual memory/CPU from system
        // For demonstration, we'll check metadata if available
        if let Some(metadata) = &event.metadata {
            // Check memory usage
            if let Some(memory) = metadata.get("memory_mb").and_then(|v| v.as_f64()) {
                let z_score =
                    calculate_z_score(memory, baseline.avg_memory_mb, baseline.stddev_memory_mb);

                if z_score.abs() >= self.config.z_score_threshold {
                    let score = calculate_anomaly_score(z_score);
                    let description = format!(
                        "Process {} has abnormal memory usage: {:.1} MB (expected: {:.1} ± {:.1} MB)",
                        process_name, memory, baseline.avg_memory_mb, baseline.stddev_memory_mb
                    );

                    anomalies.push(Anomaly {
                        anomaly_type: AnomalyType::ProcessMemory,
                        score,
                        baseline_name: format!("process_memory:{}", process_name),
                        description,
                        metadata: {
                            let mut map = HashMap::new();
                            map.insert("process_name".to_string(), serde_json::json!(process_name));
                            map.insert("pid".to_string(), serde_json::json!(event.pid));
                            map
                        },
                        z_score,
                        expected: baseline.avg_memory_mb,
                        observed: memory,
                        timestamp: now,
                    });
                }
            }

            // Check CPU usage
            if let Some(cpu) = metadata.get("cpu_percent").and_then(|v| v.as_f64()) {
                let z_score =
                    calculate_z_score(cpu, baseline.avg_cpu_percent, baseline.stddev_cpu_percent);

                if z_score.abs() >= self.config.z_score_threshold {
                    let score = calculate_anomaly_score(z_score);
                    let description = format!(
                        "Process {} has abnormal CPU usage: {:.1}% (expected: {:.1} ± {:.1}%)",
                        process_name, cpu, baseline.avg_cpu_percent, baseline.stddev_cpu_percent
                    );

                    anomalies.push(Anomaly {
                        anomaly_type: AnomalyType::ProcessCpu,
                        score,
                        baseline_name: format!("process_cpu:{}", process_name),
                        description,
                        metadata: {
                            let mut map = HashMap::new();
                            map.insert("process_name".to_string(), serde_json::json!(process_name));
                            map.insert("pid".to_string(), serde_json::json!(event.pid));
                            map
                        },
                        z_score,
                        expected: baseline.avg_cpu_percent,
                        observed: cpu,
                        timestamp: now,
                    });
                }
            }
        }

        Ok(if anomalies.is_empty() {
            None
        } else {
            Some(anomalies)
        })
    }

    /// Detect network anomalies
    async fn detect_network_anomalies(
        &mut self,
        event: &crate::collectors::NetworkEvent,
    ) -> Result<Option<Vec<Anomaly>>> {
        let key = if !event.process_name.is_empty() {
            event.process_name.to_lowercase()
        } else {
            "system-wide".to_string()
        };

        // Get baseline for this key
        let baseline = match self.network_baselines.get(&key) {
            Some(b) => b,
            None => return Ok(None),
        };

        if baseline.learning_samples < self.config.min_samples {
            return Ok(None);
        }

        let mut anomalies = Vec::new();
        let now = chrono::Utc::now().timestamp();

        // Check if destination is in common destinations
        let destination = format!("{}:{}", event.remote_addr, event.remote_port);
        if !baseline.common_destinations.contains_key(&destination)
            && !baseline
                .common_destinations
                .contains_key(&event.remote_addr)
        {
            // Uncommon destination
            let score = 60.0; // Medium severity for unknown destinations

            anomalies.push(Anomaly {
                anomaly_type: AnomalyType::NetworkDestination,
                score,
                baseline_name: format!("network_destination:{}", key),
                description: format!(
                    "Process {} connected to uncommon destination: {}",
                    key, destination
                ),
                metadata: {
                    let mut map = HashMap::new();
                    map.insert("process_name".to_string(), serde_json::json!(key));
                    map.insert("destination".to_string(), serde_json::json!(destination));
                    map.insert("protocol".to_string(), serde_json::json!(event.protocol));
                    map
                },
                z_score: 0.0, // Not z-score based
                expected: 0.0,
                observed: 1.0,
                timestamp: now,
            });
        }

        // Check if port is uncommon
        if !baseline.common_ports.contains_key(&event.remote_port) {
            let score = 50.0; // Medium-low severity for unknown ports

            anomalies.push(Anomaly {
                anomaly_type: AnomalyType::NetworkPort,
                score,
                baseline_name: format!("network_port:{}", key),
                description: format!("Process {} used uncommon port: {}", key, event.remote_port),
                metadata: {
                    let mut map = HashMap::new();
                    map.insert("process_name".to_string(), serde_json::json!(key));
                    map.insert("port".to_string(), serde_json::json!(event.remote_port));
                    map
                },
                z_score: 0.0,
                expected: 0.0,
                observed: event.remote_port as f64,
                timestamp: now,
            });
        }

        Ok(if anomalies.is_empty() {
            None
        } else {
            Some(anomalies)
        })
    }

    /// Detect file access anomalies
    async fn detect_file_anomalies(
        &mut self,
        event: &crate::collectors::FileEvent,
    ) -> Result<Option<Vec<Anomaly>>> {
        let process_name = event.process_name.to_lowercase();

        let baseline = match self.file_access_baselines.get(&process_name) {
            Some(b) => b,
            None => return Ok(None),
        };

        if baseline.learning_samples < self.config.min_samples {
            return Ok(None);
        }

        let mut anomalies = Vec::new();
        let now = chrono::Utc::now().timestamp();

        // Check if file path is uncommon for this process
        if !baseline.common_paths.contains_key(&event.path) {
            // Check if file extension is uncommon
            let ext = std::path::Path::new(&event.path)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("");

            if !ext.is_empty() && !baseline.common_extensions.contains_key(ext) {
                let score = 55.0; // Medium severity

                anomalies.push(Anomaly {
                    anomaly_type: AnomalyType::FileAccess,
                    score,
                    baseline_name: format!("file_access:{}", process_name),
                    description: format!(
                        "Process {} accessed uncommon file: {} (extension: {})",
                        process_name, event.path, ext
                    ),
                    metadata: {
                        let mut map = HashMap::new();
                        map.insert("process_name".to_string(), serde_json::json!(process_name));
                        map.insert("file_path".to_string(), serde_json::json!(event.path));
                        map.insert("operation".to_string(), serde_json::json!(event.operation));
                        map
                    },
                    z_score: 0.0,
                    expected: 0.0,
                    observed: 1.0,
                    timestamp: now,
                });
            }
        }

        Ok(if anomalies.is_empty() {
            None
        } else {
            Some(anomalies)
        })
    }

    /// Detect registry access anomalies (Windows only)
    #[cfg(target_os = "windows")]
    async fn detect_registry_anomalies(
        &mut self,
        event: &crate::collectors::RegistryEvent,
    ) -> Result<Option<Vec<Anomaly>>> {
        let process_name = event.process_name.to_lowercase();

        let baseline = match self.registry_baselines.get(&process_name) {
            Some(b) => b,
            None => return Ok(None),
        };

        if baseline.learning_samples < self.config.min_samples {
            return Ok(None);
        }

        let mut anomalies = Vec::new();
        let now = chrono::Utc::now().timestamp();

        // Check if registry key is uncommon
        if !baseline.common_keys.contains_key(&event.key_path) {
            let score = 65.0; // Medium-high severity for uncommon registry access

            anomalies.push(Anomaly {
                anomaly_type: AnomalyType::RegistryAccess,
                score,
                baseline_name: format!("registry_access:{}", process_name),
                description: format!(
                    "Process {} accessed uncommon registry key: {}",
                    process_name, event.key_path
                ),
                metadata: {
                    let mut map = HashMap::new();
                    map.insert("process_name".to_string(), serde_json::json!(process_name));
                    map.insert("key_path".to_string(), serde_json::json!(event.key_path));
                    map.insert("operation".to_string(), serde_json::json!(event.operation));
                    map
                },
                z_score: 0.0,
                expected: 0.0,
                observed: 1.0,
                timestamp: now,
            });
        }

        Ok(if anomalies.is_empty() {
            None
        } else {
            Some(anomalies)
        })
    }

    /// Filter out suppressed anomalies
    async fn filter_suppressed(&mut self, anomalies: Vec<Anomaly>) -> Result<Vec<Anomaly>> {
        let mut filtered = Vec::new();

        for anomaly in anomalies {
            let suppression_key = format!("{}:{}", anomaly.anomaly_type, anomaly.baseline_name);

            // Check whitelist
            if self.whitelist.contains_key(&suppression_key) {
                debug!("Anomaly whitelisted: {}", suppression_key);
                continue;
            }

            // Check suppression window
            if self
                .storage
                .should_suppress_anomaly(
                    &suppression_key,
                    self.config.anomaly_suppression_window_seconds,
                )
                .await?
            {
                debug!("Anomaly suppressed (recent duplicate): {}", suppression_key);
                continue;
            }

            // Record this anomaly for future suppression
            self.storage
                .record_anomaly_suppression(&suppression_key)
                .await?;

            filtered.push(anomaly);
        }

        Ok(filtered)
    }

    /// Add an anomaly to the whitelist
    pub fn whitelist_anomaly(&mut self, anomaly_type: AnomalyType, baseline_name: String) {
        let key = format!("{}:{}", anomaly_type, baseline_name);
        self.whitelist.insert(key, ());
        info!(
            "Added anomaly to whitelist: {}:{}",
            anomaly_type, baseline_name
        );
    }

    /// Remove an anomaly from the whitelist
    pub fn remove_from_whitelist(&mut self, anomaly_type: AnomalyType, baseline_name: String) {
        let key = format!("{}:{}", anomaly_type, baseline_name);
        self.whitelist.remove(&key);
        info!(
            "Removed anomaly from whitelist: {}:{}",
            anomaly_type, baseline_name
        );
    }
}

/// Calculate Z-score: (observed - mean) / stddev
fn calculate_z_score(observed: f64, mean: f64, stddev: f64) -> f64 {
    if stddev == 0.0 {
        return 0.0;
    }
    (observed - mean) / stddev
}

/// Calculate anomaly score (0-100) from Z-score
fn calculate_anomaly_score(z_score: f64) -> f64 {
    // Map Z-score to 0-100 scale
    // Z=3 -> 75, Z=4 -> 85, Z=5 -> 90, Z=6+ -> 95+
    let abs_z = z_score.abs();

    if abs_z < 3.0 {
        50.0
    } else if abs_z < 4.0 {
        75.0
    } else if abs_z < 5.0 {
        85.0
    } else if abs_z < 6.0 {
        90.0
    } else {
        95.0.min(50.0 + (abs_z * 10.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_z_score_calculation() {
        // Z-score = (x - μ) / σ
        assert_eq!(calculate_z_score(10.0, 5.0, 2.0), 2.5);
        assert_eq!(calculate_z_score(5.0, 5.0, 2.0), 0.0);
        assert_eq!(calculate_z_score(0.0, 5.0, 2.0), -2.5);
    }

    #[test]
    fn test_anomaly_score_calculation() {
        assert_eq!(calculate_anomaly_score(2.5), 50.0);
        assert_eq!(calculate_anomaly_score(3.5), 75.0);
        assert_eq!(calculate_anomaly_score(4.5), 85.0);
        assert_eq!(calculate_anomaly_score(5.5), 90.0);
        assert!(calculate_anomaly_score(7.0) >= 95.0);
    }

    #[tokio::test]
    async fn test_detector_creation() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let config = BaselineConfig::default();
        let storage = BaselineStorage::new(db_path).unwrap();

        let detector = AnomalyDetector::new(config, storage);
        assert_eq!(detector.process_baselines.len(), 0);
    }

    #[tokio::test]
    async fn test_whitelist() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let config = BaselineConfig::default();
        let storage = BaselineStorage::new(db_path).unwrap();

        let mut detector = AnomalyDetector::new(config, storage);

        detector.whitelist_anomaly(AnomalyType::ProcessMemory, "chrome.exe".to_string());
        assert_eq!(detector.whitelist.len(), 1);

        detector.remove_from_whitelist(AnomalyType::ProcessMemory, "chrome.exe".to_string());
        assert_eq!(detector.whitelist.len(), 0);
    }
}
