//! Plugin Monitoring and Health Tracking
//!
//! This module monitors plugin resource usage, health, and performance metrics.

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, warn};

use super::PluginMetrics;

/// Plugin health status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    /// Plugin is healthy
    Healthy,
    /// Plugin is degraded (high resource usage)
    Degraded,
    /// Plugin is unhealthy (crashed or unresponsive)
    Unhealthy,
}

/// Plugin health information
#[derive(Debug, Clone)]
pub struct PluginHealth {
    /// Health status
    pub status: HealthStatus,
    /// Last update time
    pub last_update: Instant,
    /// Consecutive errors
    pub consecutive_errors: u32,
    /// Total crashes
    pub total_crashes: u32,
    /// Average CPU usage (percentage)
    pub avg_cpu_percent: f64,
    /// Average memory usage (bytes)
    pub avg_memory_bytes: u64,
}

impl Default for PluginHealth {
    fn default() -> Self {
        Self {
            status: HealthStatus::Healthy,
            last_update: Instant::now(),
            consecutive_errors: 0,
            total_crashes: 0,
            avg_cpu_percent: 0.0,
            avg_memory_bytes: 0,
        }
    }
}

/// Plugin monitor
pub struct PluginMonitor {
    /// Plugin health tracking
    health: Arc<RwLock<HashMap<String, PluginHealth>>>,
}

impl PluginMonitor {
    /// Create new plugin monitor
    pub fn new() -> Self {
        Self {
            health: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Start monitoring a plugin
    pub fn start_monitoring(&self, plugin_id: &str) {
        let plugin_id = plugin_id.to_string();
        let health = Arc::clone(&self.health);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));

            loop {
                interval.tick().await;

                let mut health_map = health.write().await;
                if let Some(plugin_health) = health_map.get_mut(&plugin_id) {
                    plugin_health.last_update = Instant::now();
                    debug!(plugin_id = %plugin_id, "Plugin health check");
                } else {
                    // Plugin stopped
                    break;
                }
            }
        });
    }

    /// Stop monitoring a plugin
    pub fn stop_monitoring(&self, plugin_id: &str) {
        let health = Arc::clone(&self.health);
        let plugin_id = plugin_id.to_string();

        tokio::spawn(async move {
            let mut health_map = health.write().await;
            health_map.remove(&plugin_id);
        });
    }

    /// Update plugin metrics
    pub async fn update_metrics(&self, plugin_id: &str, metrics: &PluginMetrics) {
        let mut health_map = self.health.write().await;

        let health = health_map
            .entry(plugin_id.to_string())
            .or_insert_with(PluginHealth::default);

        health.last_update = Instant::now();

        // Update averages (simple moving average)
        let alpha = 0.3; // Smoothing factor
        health.avg_memory_bytes = (health.avg_memory_bytes as f64 * (1.0 - alpha)
            + metrics.memory_bytes as f64 * alpha) as u64;

        // Determine health status based on resource usage
        if metrics.memory_bytes > 128 * 1024 * 1024 {
            // >128MB
            health.status = HealthStatus::Degraded;
            warn!(
                plugin_id = %plugin_id,
                memory_mb = metrics.memory_bytes / (1024 * 1024),
                "Plugin using high memory"
            );
        } else if health.consecutive_errors >= 5 {
            health.status = HealthStatus::Unhealthy;
            warn!(
                plugin_id = %plugin_id,
                consecutive_errors = health.consecutive_errors,
                "Plugin has too many consecutive errors"
            );
        } else {
            health.status = HealthStatus::Healthy;
        }
    }

    /// Record plugin error
    pub async fn record_error(&self, plugin_id: &str) {
        let mut health_map = self.health.write().await;

        let health = health_map
            .entry(plugin_id.to_string())
            .or_insert_with(PluginHealth::default);

        health.consecutive_errors += 1;
        health.last_update = Instant::now();

        if health.consecutive_errors >= 5 {
            health.status = HealthStatus::Unhealthy;
            warn!(
                plugin_id = %plugin_id,
                consecutive_errors = health.consecutive_errors,
                "Plugin health degraded due to errors"
            );
        }
    }

    /// Record plugin crash
    pub async fn record_crash(&self, plugin_id: &str) {
        let mut health_map = self.health.write().await;

        let health = health_map
            .entry(plugin_id.to_string())
            .or_insert_with(PluginHealth::default);

        health.total_crashes += 1;
        health.status = HealthStatus::Unhealthy;
        health.last_update = Instant::now();

        warn!(
            plugin_id = %plugin_id,
            total_crashes = health.total_crashes,
            "Plugin crashed"
        );
    }

    /// Reset error counter (after successful execution)
    pub async fn reset_errors(&self, plugin_id: &str) {
        let mut health_map = self.health.write().await;

        if let Some(health) = health_map.get_mut(plugin_id) {
            health.consecutive_errors = 0;
            if health.status == HealthStatus::Unhealthy && health.total_crashes == 0 {
                health.status = HealthStatus::Healthy;
            }
        }
    }

    /// Get plugin health
    pub async fn get_health(&self, plugin_id: &str) -> Option<PluginHealth> {
        let health_map = self.health.read().await;
        health_map.get(plugin_id).cloned()
    }

    /// Get all plugin health statuses
    pub async fn get_all_health(&self) -> HashMap<String, PluginHealth> {
        let health_map = self.health.read().await;
        health_map.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_monitoring() {
        let monitor = PluginMonitor::new();
        let plugin_id = "test-plugin";

        // Start monitoring
        monitor.start_monitoring(plugin_id);

        // Check initial health
        let health = monitor.get_health(plugin_id).await;
        assert!(health.is_none());

        // Record error
        monitor.record_error(plugin_id).await;
        let health = monitor.get_health(plugin_id).await.unwrap();
        assert_eq!(health.consecutive_errors, 1);
        assert_eq!(health.status, HealthStatus::Healthy);

        // Record multiple errors
        for _ in 0..5 {
            monitor.record_error(plugin_id).await;
        }

        let health = monitor.get_health(plugin_id).await.unwrap();
        assert_eq!(health.consecutive_errors, 6);
        assert_eq!(health.status, HealthStatus::Unhealthy);

        // Reset errors
        monitor.reset_errors(plugin_id).await;
        let health = monitor.get_health(plugin_id).await.unwrap();
        assert_eq!(health.consecutive_errors, 0);
        assert_eq!(health.status, HealthStatus::Healthy);
    }

    #[tokio::test]
    async fn test_crash_tracking() {
        let monitor = PluginMonitor::new();
        let plugin_id = "test-plugin";

        monitor.record_crash(plugin_id).await;

        let health = monitor.get_health(plugin_id).await.unwrap();
        assert_eq!(health.total_crashes, 1);
        assert_eq!(health.status, HealthStatus::Unhealthy);
    }
}
