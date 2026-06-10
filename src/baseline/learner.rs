//! Baseline learning engine
//!
//! Processes telemetry events and builds statistical baselines for normal
//! behavior patterns. Uses online algorithms for computing running statistics.

use super::config::BaselineConfig;
use super::storage::BaselineStorage;
use super::types::*;
use crate::collectors::{EventPayload, TelemetryEvent};
use anyhow::Result;
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Baseline learner
pub struct BaselineLearner {
    config: BaselineConfig,
    storage: BaselineStorage,

    // In-memory state for learning
    process_state: HashMap<String, ProcessLearningState>,
    user_state: HashMap<String, UserLearningState>,
    network_state: HashMap<String, NetworkLearningState>,
    file_access_state: HashMap<String, FileAccessLearningState>,
    #[cfg(target_os = "windows")]
    registry_state: HashMap<String, RegistryLearningState>,

    // Update tracking
    last_persist: std::time::Instant,
}

/// Internal state for learning process baselines
struct ProcessLearningState {
    baseline: ProcessBaseline,
    memory_values: Vec<f64>,
    cpu_values: Vec<f64>,
}

/// Internal state for learning user baselines
struct UserLearningState {
    baseline: UserBaseline,
}

/// Internal state for learning network baselines
struct NetworkLearningState {
    baseline: NetworkBaseline,
}

/// Internal state for learning file access baselines
struct FileAccessLearningState {
    baseline: FileAccessBaseline,
}

/// Internal state for learning registry baselines
#[cfg(target_os = "windows")]
struct RegistryLearningState {
    baseline: RegistryBaseline,
}

impl BaselineLearner {
    /// Create a new baseline learner
    pub fn new(config: BaselineConfig, storage: BaselineStorage) -> Self {
        Self {
            config,
            storage,
            process_state: HashMap::new(),
            user_state: HashMap::new(),
            network_state: HashMap::new(),
            file_access_state: HashMap::new(),
            #[cfg(target_os = "windows")]
            registry_state: HashMap::new(),
            last_persist: std::time::Instant::now(),
        }
    }

    /// Process a telemetry event for learning
    pub async fn process_event(&mut self, event: &TelemetryEvent) -> Result<()> {
        match &event.payload {
            EventPayload::Process(proc_event) => {
                if self.config.enable_process_baselines {
                    self.learn_process_event(proc_event).await?;
                }
            }
            EventPayload::Network(net_event) => {
                if self.config.enable_network_baselines {
                    self.learn_network_event(net_event).await?;
                }
            }
            EventPayload::File(file_event) => {
                if self.config.enable_file_access_baselines {
                    self.learn_file_event(file_event).await?;
                }
            }
            #[cfg(target_os = "windows")]
            EventPayload::Registry(reg_event) => {
                if self.config.enable_registry_baselines {
                    self.learn_registry_event(reg_event).await?;
                }
            }
            _ => {}
        }

        // Periodically persist baselines to storage
        if self.last_persist.elapsed() >= self.config.update_interval() {
            self.persist_all().await?;
            self.last_persist = std::time::Instant::now();
        }

        Ok(())
    }

    /// Learn from a process event
    async fn learn_process_event(&mut self, event: &crate::collectors::ProcessEvent) -> Result<()> {
        let process_name = event.name.to_lowercase();

        let state = self
            .process_state
            .entry(process_name.clone())
            .or_insert_with(|| ProcessLearningState {
                baseline: ProcessBaseline::new(process_name.clone()),
                memory_values: Vec::new(),
                cpu_values: Vec::new(),
            });

        // Update baseline with new observations
        // In a real implementation, we would extract memory/CPU from system info
        // For now, we'll use placeholder values that would come from the event or system query

        state.baseline.learning_samples += 1;
        state.baseline.last_updated = chrono::Utc::now().timestamp();

        // Track network destinations if available in event metadata
        if let Some(metadata) = &event.metadata {
            if let Some(network_dest) = metadata.get("network_destination") {
                if let Some(dest_str) = network_dest.as_str() {
                    *state
                        .baseline
                        .common_network_destinations
                        .entry(dest_str.to_string())
                        .or_insert(0) += 1;
                }
            }
        }

        // Limit top N items
        self.trim_top_n(&mut state.baseline.common_network_destinations);
        self.trim_top_n(&mut state.baseline.common_file_access);

        Ok(())
    }

    /// Learn from a network event
    async fn learn_network_event(&mut self, event: &crate::collectors::NetworkEvent) -> Result<()> {
        // Use process name as key, or "system-wide" for global baseline
        let key = if !event.process_name.is_empty() {
            event.process_name.to_lowercase()
        } else {
            "system-wide".to_string()
        };

        let state = self
            .network_state
            .entry(key.clone())
            .or_insert_with(|| NetworkLearningState {
                baseline: NetworkBaseline::new(key.clone()),
            });

        // Track destination
        let destination = format!("{}:{}", event.remote_addr, event.remote_port);
        *state
            .baseline
            .common_destinations
            .entry(destination)
            .or_insert(0) += 1;

        // Track port
        *state
            .baseline
            .common_ports
            .entry(event.remote_port)
            .or_insert(0) += 1;

        // Track protocol
        *state
            .baseline
            .common_protocols
            .entry(event.protocol.clone())
            .or_insert(0) += 1;

        state.baseline.learning_samples += 1;
        state.baseline.last_updated = chrono::Utc::now().timestamp();

        // Limit top N items
        self.trim_top_n(&mut state.baseline.common_destinations);

        Ok(())
    }

    /// Learn from a file event
    async fn learn_file_event(&mut self, event: &crate::collectors::FileEvent) -> Result<()> {
        let process_name = event.process_name.to_lowercase();

        let state = self
            .file_access_state
            .entry(process_name.clone())
            .or_insert_with(|| FileAccessLearningState {
                baseline: FileAccessBaseline::new(process_name.clone()),
            });

        // Track file path
        *state
            .baseline
            .common_paths
            .entry(event.path.clone())
            .or_insert(0) += 1;

        // Track file extension
        if let Some(ext) = std::path::Path::new(&event.path).extension() {
            if let Some(ext_str) = ext.to_str() {
                *state
                    .baseline
                    .common_extensions
                    .entry(ext_str.to_lowercase())
                    .or_insert(0) += 1;
            }
        }

        state.baseline.learning_samples += 1;
        state.baseline.last_updated = chrono::Utc::now().timestamp();

        // Limit top N items
        self.trim_top_n(&mut state.baseline.common_paths);

        Ok(())
    }

    /// Learn from a registry event (Windows only)
    #[cfg(target_os = "windows")]
    async fn learn_registry_event(
        &mut self,
        event: &crate::collectors::RegistryEvent,
    ) -> Result<()> {
        let process_name = event.process_name.to_lowercase();

        let state = self
            .registry_state
            .entry(process_name.clone())
            .or_insert_with(|| RegistryLearningState {
                baseline: RegistryBaseline::new(process_name.clone()),
            });

        // Track registry key
        *state
            .baseline
            .common_keys
            .entry(event.key_path.clone())
            .or_insert(0) += 1;

        state.baseline.learning_samples += 1;
        state.baseline.last_updated = chrono::Utc::now().timestamp();

        // Limit top N items
        self.trim_top_n(&mut state.baseline.common_keys);

        Ok(())
    }

    /// Trim a frequency map to keep only top N items
    fn trim_top_n<K: Clone + Ord>(&self, map: &mut HashMap<K, u32>) {
        if map.len() <= self.config.top_n_items {
            return;
        }

        // Sort by count (descending) and keep top N
        let mut items: Vec<_> = map.iter().map(|(k, v)| (k.clone(), *v)).collect();
        items.sort_by(|a, b| b.1.cmp(&a.1));
        items.truncate(self.config.top_n_items);

        *map = items.into_iter().collect();
    }

    /// Persist all baselines to storage
    async fn persist_all(&mut self) -> Result<()> {
        let mut persisted = 0;

        // Persist process baselines
        for (_, state) in &mut self.process_state {
            // Update statistics before persisting
            self.update_process_statistics(
                &mut state.baseline,
                &state.memory_values,
                &state.cpu_values,
            );

            // Only persist if we have enough samples
            if state.baseline.learning_samples >= self.config.min_samples {
                self.storage.store_process_baseline(&state.baseline).await?;
                persisted += 1;
            }
        }

        // Persist network baselines
        for (_, state) in &self.network_state {
            if state.baseline.learning_samples >= self.config.min_samples {
                self.storage.store_network_baseline(&state.baseline).await?;
                persisted += 1;
            }
        }

        // Persist file access baselines
        for (_, state) in &self.file_access_state {
            if state.baseline.learning_samples >= self.config.min_samples {
                self.storage
                    .store_file_access_baseline(&state.baseline)
                    .await?;
                persisted += 1;
            }
        }

        // Persist registry baselines (Windows only)
        #[cfg(target_os = "windows")]
        for (_, state) in &self.registry_state {
            if state.baseline.learning_samples >= self.config.min_samples {
                self.storage
                    .store_registry_baseline(&state.baseline)
                    .await?;
                persisted += 1;
            }
        }

        if persisted > 0 {
            debug!("Persisted {} baselines to storage", persisted);
        }

        Ok(())
    }

    /// Update process statistics (mean and stddev)
    fn update_process_statistics(
        &self,
        baseline: &mut ProcessBaseline,
        memory_values: &[f64],
        cpu_values: &[f64],
    ) {
        if !memory_values.is_empty() {
            let (mean, stddev) = calculate_mean_stddev(memory_values);
            baseline.avg_memory_mb = mean;
            baseline.stddev_memory_mb = stddev;
        }

        if !cpu_values.is_empty() {
            let (mean, stddev) = calculate_mean_stddev(cpu_values);
            baseline.avg_cpu_percent = mean;
            baseline.stddev_cpu_percent = stddev;
        }
    }

    /// Force persist all baselines
    pub async fn force_persist(&mut self) -> Result<()> {
        self.persist_all().await
    }
}

/// Calculate mean and standard deviation
fn calculate_mean_stddev(values: &[f64]) -> (f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0);
    }

    let n = values.len() as f64;
    let mean = values.iter().sum::<f64>() / n;

    let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n;

    let stddev = variance.sqrt();

    (mean, stddev)
}

/// Welford's online algorithm for computing running mean and variance
pub struct OnlineStats {
    count: u64,
    mean: f64,
    m2: f64, // Sum of squared differences from mean
}

impl OnlineStats {
    pub fn new() -> Self {
        Self {
            count: 0,
            mean: 0.0,
            m2: 0.0,
        }
    }

    /// Add a new value
    pub fn add(&mut self, value: f64) {
        self.count += 1;
        let delta = value - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;
    }

    /// Get mean
    pub fn mean(&self) -> f64 {
        self.mean
    }

    /// Get variance
    pub fn variance(&self) -> f64 {
        if self.count < 2 {
            0.0
        } else {
            self.m2 / (self.count - 1) as f64
        }
    }

    /// Get standard deviation
    pub fn stddev(&self) -> f64 {
        self.variance().sqrt()
    }

    /// Get count
    pub fn count(&self) -> u64 {
        self.count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_online_stats() {
        let mut stats = OnlineStats::new();

        // Add values: 2, 4, 6, 8
        stats.add(2.0);
        stats.add(4.0);
        stats.add(6.0);
        stats.add(8.0);

        assert_eq!(stats.count(), 4);
        assert_eq!(stats.mean(), 5.0);

        // Variance = ((2-5)^2 + (4-5)^2 + (6-5)^2 + (8-5)^2) / 3 = 20/3 ≈ 6.67
        let variance = stats.variance();
        assert!((variance - 6.67).abs() < 0.01);
    }

    #[test]
    fn test_calculate_mean_stddev() {
        let values = vec![2.0, 4.0, 6.0, 8.0];
        let (mean, stddev) = calculate_mean_stddev(&values);

        assert_eq!(mean, 5.0);
        // Population stddev = sqrt(20/4) = sqrt(5) ≈ 2.236
        assert!((stddev - 2.236).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_learner_creation() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let config = BaselineConfig::default();
        let storage = BaselineStorage::new(db_path).unwrap();

        let learner = BaselineLearner::new(config, storage);
        assert_eq!(learner.process_state.len(), 0);
    }
}
