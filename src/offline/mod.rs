//! Offline mode for Tamandua agent.
//!
//! When the agent loses connectivity to the backend, it transitions to offline
//! mode where:
//! - Local YARA and Sigma rules continue detecting threats
//! - Detections are queued to SQLite for later sync
//! - ML inference falls back to local ONNX model (if available)
//! - Telemetry is buffered with bounded capacity
//!
//! On reconnection, queued detections are synced to the backend.

pub mod local_rules;
pub mod sync_queue;

use crate::collectors::Detection;
use anyhow::{Context, Result};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info};

pub use local_rules::LocalRuleEngine;
pub use sync_queue::{QueuedDetection, SyncQueue};

/// Offline mode state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineState {
    /// Connected to backend, normal operation
    Online,
    /// Lost connection, operating offline
    Offline,
    /// Reconnecting, syncing queued data
    Syncing,
}

impl std::fmt::Display for OfflineState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Online => write!(f, "online"),
            Self::Offline => write!(f, "offline"),
            Self::Syncing => write!(f, "syncing"),
        }
    }
}

/// Offline mode configuration.
#[derive(Debug, Clone)]
pub struct OfflineConfig {
    /// Path to SQLite database for sync queue
    pub queue_db_path: String,
    /// Maximum queued detections before dropping oldest
    pub max_queue_size: usize,
    /// Interval for connectivity checks while offline
    pub reconnect_check_interval: Duration,
    /// Path to local YARA rules directory
    pub local_yara_rules_dir: String,
    /// Path to local Sigma rules directory
    pub local_sigma_rules_dir: String,
    /// Enable local ML inference (requires ONNX model)
    pub enable_local_ml: bool,
}

impl Default for OfflineConfig {
    fn default() -> Self {
        #[cfg(target_os = "windows")]
        let base_path =
            std::env::var("PROGRAMDATA").unwrap_or_else(|_| "C:\\ProgramData".to_string());

        #[cfg(not(target_os = "windows"))]
        let base_path = "/var/lib".to_string();

        Self {
            queue_db_path: format!("{}/tamandua/offline_queue.db", base_path),
            max_queue_size: 100_000,
            reconnect_check_interval: Duration::from_secs(30),
            local_yara_rules_dir: format!("{}/tamandua/rules/yara", base_path),
            local_sigma_rules_dir: format!("{}/tamandua/rules/sigma", base_path),
            enable_local_ml: true,
        }
    }
}

/// Offline mode manager.
pub struct OfflineMode {
    state: AtomicBool, // true = offline
    config: OfflineConfig,
    sync_queue: Arc<SyncQueue>,
    local_rules: Arc<LocalRuleEngine>,
    last_online: parking_lot::RwLock<Option<Instant>>,
    offline_since: parking_lot::RwLock<Option<Instant>>,
    syncing: AtomicBool,
}

impl OfflineMode {
    /// Create new offline mode manager.
    pub async fn new(config: OfflineConfig) -> Result<Self> {
        info!(
            queue_db = %config.queue_db_path,
            max_queue = config.max_queue_size,
            "Initializing offline mode"
        );

        let sync_queue = Arc::new(
            SyncQueue::new(&config.queue_db_path, config.max_queue_size)
                .context("Failed to initialize sync queue")?,
        );

        let local_rules = Arc::new(
            LocalRuleEngine::new(&config.local_yara_rules_dir, &config.local_sigma_rules_dir).await,
        );

        Ok(Self {
            state: AtomicBool::new(false),
            config,
            sync_queue,
            local_rules,
            last_online: parking_lot::RwLock::new(Some(Instant::now())),
            offline_since: parking_lot::RwLock::new(None),
            syncing: AtomicBool::new(false),
        })
    }

    /// Check if currently offline.
    pub fn is_offline(&self) -> bool {
        self.state.load(Ordering::Relaxed)
    }

    /// Check if currently syncing.
    pub fn is_syncing(&self) -> bool {
        self.syncing.load(Ordering::Relaxed)
    }

    /// Get current state.
    pub fn get_state(&self) -> OfflineState {
        if self.is_syncing() {
            OfflineState::Syncing
        } else if self.is_offline() {
            OfflineState::Offline
        } else {
            OfflineState::Online
        }
    }

    /// Transition to offline mode.
    pub fn go_offline(&self) {
        if !self.state.swap(true, Ordering::SeqCst) {
            *self.offline_since.write() = Some(Instant::now());
            info!("Transitioned to offline mode");
        }
    }

    /// Transition to online mode.
    pub fn go_online(&self) {
        if self.state.swap(false, Ordering::SeqCst) {
            *self.last_online.write() = Some(Instant::now());
            let offline_duration = self
                .offline_since
                .read()
                .map(|t| t.elapsed())
                .unwrap_or_default();
            *self.offline_since.write() = None;
            info!(
                offline_duration_secs = offline_duration.as_secs(),
                queued_detections = self.sync_queue.len(),
                "Transitioned back to online mode"
            );
        }
    }

    /// Begin sync operation (called during reconnection).
    pub fn begin_sync(&self) {
        self.syncing.store(true, Ordering::SeqCst);
        info!("Beginning offline detection sync");
    }

    /// End sync operation.
    pub fn end_sync(&self) {
        self.syncing.store(false, Ordering::SeqCst);
        info!("Completed offline detection sync");
    }

    /// Duration spent offline (if currently offline).
    pub fn offline_duration(&self) -> Option<Duration> {
        self.offline_since.read().map(|t| t.elapsed())
    }

    /// Time since last online.
    pub fn time_since_online(&self) -> Option<Duration> {
        self.last_online.read().map(|t| t.elapsed())
    }

    /// Queue a detection for later sync.
    pub fn queue_detection(&self, detection: QueuedDetection) -> Result<()> {
        self.sync_queue.push(detection)
    }

    /// Queue multiple detections.
    pub fn queue_detections(&self, detections: Vec<QueuedDetection>) -> Result<()> {
        for detection in detections {
            self.sync_queue.push(detection)?;
        }
        Ok(())
    }

    /// Drain all queued detections for sync.
    ///
    /// Prefer `read_batch_for_replay` plus `ack_replayed_ids` for new replay
    /// paths so detections are removed only after backend acceptance.
    pub fn drain_queue(&self) -> Vec<QueuedDetection> {
        self.sync_queue.drain_all()
    }

    /// Drain a batch of queued detections.
    ///
    /// Prefer `read_batch_for_replay` plus `ack_replayed_ids` for ACK-safe
    /// replay.
    pub fn drain_batch(&self, limit: usize) -> Vec<QueuedDetection> {
        self.sync_queue.drain_batch(limit)
    }

    /// Read a replay batch without removing it from the queue.
    pub fn read_batch_for_replay(&self, limit: usize) -> Result<Vec<QueuedDetection>> {
        self.sync_queue.try_read_batch(limit)
    }

    /// Acknowledge replayed detections after backend acceptance.
    pub fn ack_replayed_ids(&self, ids: &[&str]) -> Result<usize> {
        self.sync_queue.try_ack_ids(ids)
    }

    /// Get queued detection count.
    pub fn queue_len(&self) -> usize {
        self.sync_queue.len()
    }

    /// Check if queue is empty.
    pub fn queue_is_empty(&self) -> bool {
        self.sync_queue.is_empty()
    }

    /// Analyze a file using local rules (offline detection).
    pub async fn analyze_file(&self, path: &Path) -> Vec<Detection> {
        self.local_rules.analyze_file(path).await
    }

    /// Analyze bytes using local rules.
    pub async fn analyze_bytes(&self, data: &[u8], label: &str) -> Vec<Detection> {
        self.local_rules.analyze_bytes(data, label).await
    }

    /// Check a command line against local Sigma patterns.
    pub fn check_command_line(&self, cmd: &str) -> Vec<Detection> {
        self.local_rules.check_command_line(cmd)
    }

    /// Get local rules engine reference.
    pub fn local_rules(&self) -> &Arc<LocalRuleEngine> {
        &self.local_rules
    }

    /// Get sync queue reference.
    pub fn sync_queue(&self) -> &Arc<SyncQueue> {
        &self.sync_queue
    }

    /// Get offline configuration.
    pub fn config(&self) -> &OfflineConfig {
        &self.config
    }

    /// Get statistics.
    pub fn stats(&self) -> OfflineStats {
        let (files_scanned, detections_found) = self.local_rules.stats();
        let (yara_rules, sigma_rules) = self.local_rules.rule_counts();

        OfflineStats {
            state: self.get_state(),
            offline_duration: self.offline_duration(),
            queued_detections: self.queue_len(),
            files_scanned,
            detections_found,
            yara_rules_loaded: yara_rules,
            sigma_patterns_loaded: sigma_rules,
        }
    }
}

/// Statistics for offline mode.
#[derive(Debug, Clone)]
pub struct OfflineStats {
    pub state: OfflineState,
    pub offline_duration: Option<Duration>,
    pub queued_detections: usize,
    pub files_scanned: u64,
    pub detections_found: u64,
    pub yara_rules_loaded: usize,
    pub sigma_patterns_loaded: usize,
}

/// Check if backend is reachable.
pub async fn check_connectivity(backend_url: &str) -> bool {
    let health_url = backend_url
        .replace("wss://", "https://")
        .replace("ws://", "http://")
        .replace("/socket/agent", "/api/health");

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            debug!(error = %e, "Failed to build HTTP client for connectivity check");
            return false;
        }
    };

    match client.head(&health_url).send().await {
        Ok(resp) => {
            let success = resp.status().is_success();
            debug!(
                url = %health_url,
                status = resp.status().as_u16(),
                reachable = success,
                "Backend connectivity check"
            );
            success
        }
        Err(e) => {
            debug!(url = %health_url, error = %e, "Backend unreachable");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_offline_config_default() {
        let config = OfflineConfig::default();
        assert_eq!(config.max_queue_size, 100_000);
        assert_eq!(config.reconnect_check_interval, Duration::from_secs(30));
        assert!(config.enable_local_ml);
    }

    #[test]
    fn test_offline_state_display() {
        assert_eq!(format!("{}", OfflineState::Online), "online");
        assert_eq!(format!("{}", OfflineState::Offline), "offline");
        assert_eq!(format!("{}", OfflineState::Syncing), "syncing");
    }

    #[tokio::test]
    async fn test_offline_mode_transitions() {
        let config = OfflineConfig {
            queue_db_path: ":memory:".to_string(),
            max_queue_size: 100,
            reconnect_check_interval: Duration::from_secs(1),
            local_yara_rules_dir: "/nonexistent".to_string(),
            local_sigma_rules_dir: "/nonexistent".to_string(),
            enable_local_ml: false,
        };

        let offline = OfflineMode::new(config).await.unwrap();

        // Start online
        assert!(!offline.is_offline());
        assert_eq!(offline.get_state(), OfflineState::Online);

        // Go offline
        offline.go_offline();
        assert!(offline.is_offline());
        assert_eq!(offline.get_state(), OfflineState::Offline);
        assert!(offline.offline_duration().is_some());

        // Begin sync
        offline.begin_sync();
        assert_eq!(offline.get_state(), OfflineState::Syncing);

        // End sync
        offline.end_sync();
        assert_eq!(offline.get_state(), OfflineState::Offline);

        // Go online
        offline.go_online();
        assert!(!offline.is_offline());
        assert_eq!(offline.get_state(), OfflineState::Online);
        assert!(offline.offline_duration().is_none());
    }
}
