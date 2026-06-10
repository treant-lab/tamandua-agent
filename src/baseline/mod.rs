//! Behavioral Baseline Learning Module
//!
//! This module implements agent-side behavioral baseline learning and local
//! anomaly detection for Tamandua EDR. It learns normal behavior patterns
//! over a configurable learning period (7-30 days) and detects deviations.
//!
//! ## Architecture
//!
//! - **Learner**: Collects telemetry events and builds statistical baselines
//! - **Detector**: Compares new events against baselines to detect anomalies
//! - **Storage**: Persists baselines to local SQLite database
//! - **Sync**: Synchronizes baselines with backend server
//!
//! ## Baseline Types
//!
//! 1. **Process Baselines**: Normal memory usage, CPU, network connections
//! 2. **User Baselines**: Typical login times, workstations, applications
//! 3. **Network Baselines**: Common destinations, ports, protocols
//! 4. **File Access Baselines**: Which processes access which files
//! 5. **Registry Baselines**: Registry access patterns (Windows only)
//!
//! ## Anomaly Detection
//!
//! Uses Z-score based detection (>3σ = anomaly) with statistical outlier
//! detection. Supports anomaly suppression and whitelisting.

pub mod config;
pub mod detector;
pub mod learner;
pub mod storage;
pub mod sync;
pub mod types;

#[cfg(test)]
mod tests;

pub use config::BaselineConfig;
pub use detector::AnomalyDetector;
pub use learner::BaselineLearner;
pub use storage::BaselineStorage;
pub use sync::BaselineSync;
pub use types::*;

use anyhow::Result;
use std::path::PathBuf;
use tracing::{debug, error, info, warn};

/// Baseline learning engine that orchestrates all baseline components
pub struct BaselineEngine {
    learner: BaselineLearner,
    detector: AnomalyDetector,
    storage: BaselineStorage,
    sync: BaselineSync,
    config: BaselineConfig,
}

impl BaselineEngine {
    /// Create a new baseline engine
    pub fn new(db_path: PathBuf, config: BaselineConfig) -> Result<Self> {
        let storage = BaselineStorage::new(db_path)?;
        let learner = BaselineLearner::new(config.clone(), storage.clone());
        let detector = AnomalyDetector::new(config.clone(), storage.clone());
        let sync = BaselineSync::new(config.clone(), storage.clone());

        Ok(Self {
            learner,
            detector,
            storage,
            sync,
            config,
        })
    }

    /// Start the baseline engine
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting baseline learning engine");

        // Load existing baselines from storage
        self.detector.load_baselines().await?;

        // Start sync task
        self.sync.start_sync_task().await?;

        info!("Baseline engine started successfully");
        Ok(())
    }

    /// Process a telemetry event for baseline learning
    pub async fn learn_event(&mut self, event: &crate::collectors::TelemetryEvent) -> Result<()> {
        self.learner.process_event(event).await
    }

    /// Detect anomalies in a telemetry event
    pub async fn detect_anomalies(
        &mut self,
        event: &crate::collectors::TelemetryEvent,
    ) -> Result<Vec<Anomaly>> {
        self.detector.detect(event).await
    }

    /// Get baseline statistics
    pub async fn get_statistics(&self) -> Result<BaselineStatistics> {
        self.storage.get_statistics().await
    }

    /// Force a baseline sync with the backend
    pub async fn force_sync(&mut self) -> Result<()> {
        self.sync.sync_now().await
    }

    /// Export baselines for the backend
    pub async fn export_baselines(&self) -> Result<Vec<u8>> {
        self.storage.export_baselines().await
    }

    /// Import baselines from the backend
    pub async fn import_baselines(&mut self, data: Vec<u8>) -> Result<()> {
        self.storage.import_baselines(data).await?;
        self.detector.reload_baselines().await
    }

    /// Clear all baselines (for testing or reset)
    pub async fn clear_all_baselines(&mut self) -> Result<()> {
        warn!("Clearing all baselines");
        self.storage.clear_all().await?;
        self.detector.reload_baselines().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_baseline_engine_creation() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("baselines.db");
        let config = BaselineConfig::default();

        let engine = BaselineEngine::new(db_path, config);
        assert!(engine.is_ok());
    }

    #[tokio::test]
    async fn test_baseline_engine_start() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("baselines.db");
        let config = BaselineConfig::default();

        let mut engine = BaselineEngine::new(db_path, config).unwrap();
        let result = engine.start().await;
        assert!(result.is_ok());
    }
}
