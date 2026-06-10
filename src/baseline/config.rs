//! Baseline configuration

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Baseline learning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineConfig {
    /// Learning period in days (7-30)
    pub learning_period_days: u32,

    /// Minimum samples required before baseline is considered valid
    pub min_samples: u32,

    /// Z-score threshold for anomaly detection (typically 3.0)
    pub z_score_threshold: f64,

    /// Enable process baselines
    pub enable_process_baselines: bool,

    /// Enable user baselines
    pub enable_user_baselines: bool,

    /// Enable network baselines
    pub enable_network_baselines: bool,

    /// Enable file access baselines
    pub enable_file_access_baselines: bool,

    /// Enable registry baselines (Windows only)
    pub enable_registry_baselines: bool,

    /// Baseline update interval in seconds
    pub update_interval_seconds: u64,

    /// Baseline TTL in days (expire old baselines)
    pub baseline_ttl_days: u32,

    /// Maximum baselines to keep per type
    pub max_baselines_per_type: usize,

    /// Drift detection threshold (percentage change)
    pub drift_threshold_percent: f64,

    /// Sync interval with backend in seconds
    pub sync_interval_seconds: u64,

    /// Enable baseline compression for sync
    pub enable_compression: bool,

    /// Anomaly suppression window in seconds
    pub anomaly_suppression_window_seconds: u64,

    /// Top N items to track in frequency maps (destinations, files, etc.)
    pub top_n_items: usize,
}

impl Default for BaselineConfig {
    fn default() -> Self {
        Self {
            learning_period_days: 14,
            min_samples: 100,
            z_score_threshold: 3.0,
            enable_process_baselines: true,
            enable_user_baselines: true,
            enable_network_baselines: true,
            enable_file_access_baselines: true,
            enable_registry_baselines: cfg!(target_os = "windows"),
            update_interval_seconds: 300, // 5 minutes
            baseline_ttl_days: 90,
            max_baselines_per_type: 10000,
            drift_threshold_percent: 50.0,
            sync_interval_seconds: 3600, // 1 hour
            enable_compression: true,
            anomaly_suppression_window_seconds: 3600, // 1 hour
            top_n_items: 100,
        }
    }
}

impl BaselineConfig {
    /// Get learning period as Duration
    pub fn learning_period(&self) -> Duration {
        Duration::from_secs(self.learning_period_days as u64 * 24 * 3600)
    }

    /// Get update interval as Duration
    pub fn update_interval(&self) -> Duration {
        Duration::from_secs(self.update_interval_seconds)
    }

    /// Get sync interval as Duration
    pub fn sync_interval(&self) -> Duration {
        Duration::from_secs(self.sync_interval_seconds)
    }

    /// Get baseline TTL as Duration
    pub fn baseline_ttl(&self) -> Duration {
        Duration::from_secs(self.baseline_ttl_days as u64 * 24 * 3600)
    }

    /// Get anomaly suppression window as Duration
    pub fn anomaly_suppression_window(&self) -> Duration {
        Duration::from_secs(self.anomaly_suppression_window_seconds)
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.learning_period_days < 7 || self.learning_period_days > 30 {
            return Err("learning_period_days must be between 7 and 30".to_string());
        }

        if self.min_samples == 0 {
            return Err("min_samples must be greater than 0".to_string());
        }

        if self.z_score_threshold < 1.0 || self.z_score_threshold > 10.0 {
            return Err("z_score_threshold must be between 1.0 and 10.0".to_string());
        }

        if self.drift_threshold_percent < 10.0 || self.drift_threshold_percent > 100.0 {
            return Err("drift_threshold_percent must be between 10.0 and 100.0".to_string());
        }

        if self.top_n_items == 0 || self.top_n_items > 10000 {
            return Err("top_n_items must be between 1 and 10000".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = BaselineConfig::default();
        assert_eq!(config.learning_period_days, 14);
        assert_eq!(config.min_samples, 100);
        assert_eq!(config.z_score_threshold, 3.0);
    }

    #[test]
    fn test_config_validation() {
        let mut config = BaselineConfig::default();
        assert!(config.validate().is_ok());

        config.learning_period_days = 5;
        assert!(config.validate().is_err());

        config.learning_period_days = 14;
        config.z_score_threshold = 0.5;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_duration_conversions() {
        let config = BaselineConfig::default();
        assert_eq!(config.learning_period().as_secs(), 14 * 24 * 3600);
        assert_eq!(config.update_interval().as_secs(), 300);
        assert_eq!(config.sync_interval().as_secs(), 3600);
    }
}
