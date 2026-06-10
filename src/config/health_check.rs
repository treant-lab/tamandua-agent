//! Health check system for automatic config rollback.
//!
//! Monitors agent health after config changes and triggers automatic rollback if:
//! - Agent cannot connect to server within 30 seconds
//! - Critical collectors panic
//! - Memory usage exceeds safe thresholds
//! - CPU usage is abnormally high

use anyhow::Result;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

/// Health check status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    /// Health check not started
    Pending,
    /// Health check in progress
    InProgress,
    /// Health check passed
    Healthy,
    /// Health check failed
    Unhealthy,
}

/// Reasons for health check failure
#[derive(Debug, Clone)]
pub enum FailureReason {
    /// Cannot connect to server
    ConnectionFailure(String),
    /// Collector panic detected
    CollectorPanic(String),
    /// Memory usage too high
    MemoryExhaustion { current_mb: u64, threshold_mb: u64 },
    /// CPU usage too high
    CpuOverload {
        current_percent: f32,
        threshold_percent: f32,
    },
    /// Config validation failed during runtime
    RuntimeValidationFailure(String),
    /// Timeout waiting for health check to complete
    Timeout,
}

impl std::fmt::Display for FailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConnectionFailure(msg) => write!(f, "Connection failure: {}", msg),
            Self::CollectorPanic(msg) => write!(f, "Collector panic: {}", msg),
            Self::MemoryExhaustion {
                current_mb,
                threshold_mb,
            } => {
                write!(
                    f,
                    "Memory exhaustion: {} MB / {} MB threshold",
                    current_mb, threshold_mb
                )
            }
            Self::CpuOverload {
                current_percent,
                threshold_percent,
            } => {
                write!(
                    f,
                    "CPU overload: {:.1}% / {:.1}% threshold",
                    current_percent, threshold_percent
                )
            }
            Self::RuntimeValidationFailure(msg) => write!(f, "Runtime validation failure: {}", msg),
            Self::Timeout => write!(f, "Health check timeout"),
        }
    }
}

/// Health check configuration
#[derive(Debug, Clone)]
pub struct HealthCheckConfig {
    /// Duration to wait before starting health check after config change
    pub delay: Duration,
    /// Timeout for health check to complete
    pub timeout: Duration,
    /// Memory threshold in MB
    pub memory_threshold_mb: u64,
    /// CPU threshold percentage
    pub cpu_threshold_percent: f32,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            delay: Duration::from_secs(30),
            timeout: Duration::from_secs(120),
            memory_threshold_mb: 1024, // 1 GB
            cpu_threshold_percent: 80.0,
        }
    }
}

/// Health check state shared across threads
#[derive(Debug, Clone)]
pub struct HealthCheckState {
    pub status: HealthStatus,
    pub last_check: Option<Instant>,
    pub failure_reason: Option<FailureReason>,
    pub connection_healthy: bool,
    pub collectors_healthy: bool,
}

impl Default for HealthCheckState {
    fn default() -> Self {
        Self {
            status: HealthStatus::Pending,
            last_check: None,
            failure_reason: None,
            connection_healthy: false,
            collectors_healthy: true,
        }
    }
}

/// Health checker for post-config-update validation
#[derive(Clone)]
pub struct HealthChecker {
    config: HealthCheckConfig,
    state: Arc<RwLock<HealthCheckState>>,
}

impl HealthChecker {
    /// Create a new health checker
    pub fn new(config: HealthCheckConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(HealthCheckState::default())),
        }
    }

    /// Get shared state handle
    pub fn state(&self) -> Arc<RwLock<HealthCheckState>> {
        self.state.clone()
    }

    /// Get the current health checker configuration
    pub fn config(&self) -> &HealthCheckConfig {
        &self.config
    }

    /// Mark connection as healthy
    pub async fn mark_connection_healthy(&self) {
        let mut state = self.state.write().await;
        state.connection_healthy = true;
        debug!("Connection health check passed");
    }

    /// Mark connection as unhealthy
    pub async fn mark_connection_unhealthy(&self, reason: String) {
        let mut state = self.state.write().await;
        state.connection_healthy = false;
        state.failure_reason = Some(FailureReason::ConnectionFailure(reason));
        warn!("Connection health check failed");
    }

    /// Report collector panic
    pub async fn report_collector_panic(&self, collector_name: String) {
        let mut state = self.state.write().await;
        state.collectors_healthy = false;
        state.failure_reason = Some(FailureReason::CollectorPanic(collector_name));
        error!("Collector panic detected");
    }

    /// Check system resource usage
    async fn check_resources(&self) -> Result<()> {
        use sysinfo::System;

        let mut sys = System::new_all();
        sys.refresh_all();

        // Get current process
        let pid = sysinfo::get_current_pid()
            .map_err(|e| anyhow::anyhow!("Failed to get current PID: {}", e))?;

        if let Some(process) = sys.process(pid) {
            // Check memory usage
            let memory_mb = process.memory() / 1024 / 1024;
            if memory_mb > self.config.memory_threshold_mb {
                let mut state = self.state.write().await;
                state.failure_reason = Some(FailureReason::MemoryExhaustion {
                    current_mb: memory_mb,
                    threshold_mb: self.config.memory_threshold_mb,
                });
                state.status = HealthStatus::Unhealthy;
                return Ok(());
            }

            // Check CPU usage
            let cpu_percent = process.cpu_usage();
            if cpu_percent > self.config.cpu_threshold_percent {
                let mut state = self.state.write().await;
                state.failure_reason = Some(FailureReason::CpuOverload {
                    current_percent: cpu_percent,
                    threshold_percent: self.config.cpu_threshold_percent,
                });
                state.status = HealthStatus::Unhealthy;
                return Ok(());
            }

            debug!(
                memory_mb = memory_mb,
                cpu_percent = %cpu_percent,
                "Resource usage healthy"
            );
        }

        Ok(())
    }

    /// Run health check after config update
    pub async fn run_health_check(&self) -> Result<bool> {
        info!(
            delay_secs = self.config.delay.as_secs(),
            timeout_secs = self.config.timeout.as_secs(),
            "Starting post-config health check"
        );

        {
            let mut state = self.state.write().await;
            state.status = HealthStatus::InProgress;
            state.last_check = Some(Instant::now());
        }

        // Wait for the configured delay before checking
        sleep(self.config.delay).await;

        // Run health checks with timeout
        let check_start = Instant::now();
        let timeout = self.config.timeout;

        while check_start.elapsed() < timeout {
            // Check connection health
            let state = self.state.read().await;
            let connection_ok = state.connection_healthy;
            let collectors_ok = state.collectors_healthy;
            drop(state);

            if !collectors_ok {
                error!("Health check failed: collectors unhealthy");
                let mut state = self.state.write().await;
                state.status = HealthStatus::Unhealthy;
                return Ok(false);
            }

            // Check resource usage
            if let Err(e) = self.check_resources().await {
                warn!(error = %e, "Failed to check resource usage");
            }

            let state = self.state.read().await;
            if state.status == HealthStatus::Unhealthy {
                error!(reason = ?state.failure_reason, "Health check failed: resource issues");
                return Ok(false);
            }
            drop(state);

            if connection_ok {
                // All checks passed
                let mut state = self.state.write().await;
                state.status = HealthStatus::Healthy;
                info!("Health check passed");
                return Ok(true);
            }

            // Wait a bit before next check, but never sleep past the remaining
            // timeout window. Using a poll interval capped at the time left keeps
            // the loop responsive for short timeouts instead of overshooting.
            let remaining = timeout.saturating_sub(check_start.elapsed());
            if remaining.is_zero() {
                break;
            }
            sleep(remaining.min(Duration::from_millis(100))).await;
        }

        // Timeout - connection never became healthy
        error!("Health check timeout: connection not established");
        let mut state = self.state.write().await;
        state.status = HealthStatus::Unhealthy;
        state.failure_reason = Some(FailureReason::Timeout);

        Ok(false)
    }

    /// Reset health check state (call before applying new config)
    pub async fn reset(&self) {
        let mut state = self.state.write().await;
        *state = HealthCheckState::default();
        debug!("Health check state reset");
    }

    /// Get current health status
    pub async fn get_status(&self) -> HealthStatus {
        let state = self.state.read().await;
        state.status
    }

    /// Get failure reason if unhealthy
    pub async fn get_failure_reason(&self) -> Option<FailureReason> {
        let state = self.state.read().await;
        state.failure_reason.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_check_connection() {
        let config = HealthCheckConfig {
            delay: Duration::from_millis(100),
            // Use a generous timeout because check_resources() calls
            // System::new_all() / refresh_all() inside the loop, which can be
            // slow when many tokio tests run in parallel.
            timeout: Duration::from_secs(10),
            // Use high thresholds so the test runner's resource usage does not
            // trip MemoryExhaustion/CpuOverload during the assertion.
            memory_threshold_mb: u64::MAX,
            cpu_threshold_percent: f32::INFINITY,
        };

        let checker = HealthChecker::new(config);

        // Mark connection healthy BEFORE spawning the check. The check's own
        // 100ms `delay` already provides time for the spawned task to start.
        // This removes the race against `tokio::spawn` scheduling under heavy
        // parallel test load, which was the prior source of flakiness.
        checker.mark_connection_healthy().await;

        // Spawn health check
        let checker_clone = checker.clone();
        let check_handle = tokio::spawn(async move { checker_clone.run_health_check().await });

        // Health check should pass
        let result = check_handle.await.unwrap().unwrap();
        assert!(result);
        assert_eq!(checker.get_status().await, HealthStatus::Healthy);
    }

    #[tokio::test]
    async fn test_health_check_timeout() {
        let config = HealthCheckConfig {
            delay: Duration::from_millis(100),
            timeout: Duration::from_millis(500),
            // Use high thresholds so the test runner's resource usage does not
            // trip MemoryExhaustion/CpuOverload before the timeout fires.
            memory_threshold_mb: u64::MAX,
            cpu_threshold_percent: f32::INFINITY,
        };

        let checker = HealthChecker::new(config);

        // Run health check without marking connection healthy
        let result = checker.run_health_check().await.unwrap();

        // Should fail due to timeout
        assert!(!result);
        assert_eq!(checker.get_status().await, HealthStatus::Unhealthy);

        let reason = checker.get_failure_reason().await;
        assert!(matches!(reason, Some(FailureReason::Timeout)));
    }

    #[tokio::test]
    async fn test_collector_panic() {
        let checker = HealthChecker::new(HealthCheckConfig::default());

        checker
            .report_collector_panic("test_collector".to_string())
            .await;

        let state = checker.state.read().await;
        assert!(!state.collectors_healthy);
        assert!(matches!(
            &state.failure_reason,
            Some(FailureReason::CollectorPanic(name)) if name == "test_collector"
        ));
    }

    #[tokio::test]
    async fn test_reset() {
        let checker = HealthChecker::new(HealthCheckConfig::default());

        checker.mark_connection_unhealthy("test".to_string()).await;
        assert!(!checker.state.read().await.connection_healthy);

        checker.reset().await;
        assert!(!checker.state.read().await.connection_healthy); // Should be false after reset
        assert!(checker.state.read().await.failure_reason.is_none());
    }
}
