//! Per-collector resource management and budgeting.
//!
//! This module provides fine-grained resource budgets for individual collectors,
//! complementing the global resource governor with per-collector enforcement.
//!
//! ## Architecture
//!
//! - **ResourceManager**: Central coordinator that tracks all collectors and
//!   enforces their individual budgets.
//! - **CollectorBudget**: Resource limits for a single collector (CPU, memory,
//!   disk I/O, event rate).
//! - **CollectorMonitor**: Real-time resource usage tracking per collector.
//! - **CollectorThrottler**: Enforces budgets via backpressure and pausing.
//!
//! ## Usage Flow
//!
//! ```text
//! 1. Collector registers with ResourceManager
//! 2. Manager creates Monitor + Throttler for the collector
//! 3. Collector checks throttler before doing expensive work
//! 4. Monitor tracks actual usage (CPU, memory, I/O, events/sec)
//! 5. Manager compares usage vs budget and signals throttler
//! 6. Throttler applies backpressure (delays, pauses)
//! 7. Manager publishes usage snapshots for health reporting
//! ```
//!
//! ## Integration with Global Governor
//!
//! The global `ResourceGovernor` enforces agent-wide CPU/memory limits and
//! sets the `PressureLevel` that all collectors multiply their intervals by.
//!
//! Per-collector budgets add an **additional layer** of enforcement:
//! - A collector may be under global pressure (e.g., Light = 2x interval)
//! - But if that specific collector exceeds its own CPU budget, it gets
//!   individually throttled or paused regardless of global pressure.
//!
//! This prevents a single misbehaving collector from monopolizing resources
//! while staying compliant with the global resource governor.

pub mod budget;
pub mod monitor;
pub mod throttler;

#[cfg(test)]
mod integration_example;

use anyhow::Result;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

pub use budget::{CollectorBudget, CollectorBudgetConfig, CollectorPriority};
pub use monitor::{CollectorMonitor, CollectorUsageSnapshot};
pub use throttler::{CollectorThrottler, ThrottleAction};

// ---------------------------------------------------------------------------
// Resource Manager Configuration
// ---------------------------------------------------------------------------

/// Configuration for the per-collector resource manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ResourceManagerConfig {
    /// Enable per-collector resource budgeting (default: true).
    pub enabled: bool,

    /// Monitoring interval in seconds (default: 2).
    /// How often the manager checks each collector's resource usage.
    pub monitor_interval_secs: u64,

    /// Global default budgets for all collectors.
    /// Individual collectors can override these in `collector_budgets`.
    pub default_budget: CollectorBudgetConfig,

    /// Per-collector budget overrides, keyed by collector name.
    /// Example: "process" -> { cpu_percent_max: 5.0, ... }
    #[serde(default)]
    pub collector_budgets: HashMap<String, CollectorBudgetConfig>,

    /// Enable dynamic budget adjustment based on system load (default: true).
    /// When system CPU >80%, reduce all collector budgets by 50%.
    pub dynamic_budget_enabled: bool,

    /// Priority-based resource allocation (default: true).
    /// High-priority collectors (process, network) get more resources under
    /// pressure than low-priority ones (clipboard, software_inventory).
    pub priority_allocation_enabled: bool,

    /// Percentage of budget to reclaim from low-priority collectors when
    /// a high-priority collector needs more resources (default: 30.0).
    pub priority_reclaim_percent: f32,
}

impl Default for ResourceManagerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            monitor_interval_secs: 2,
            default_budget: CollectorBudgetConfig::default(),
            collector_budgets: HashMap::new(),
            dynamic_budget_enabled: true,
            priority_allocation_enabled: true,
            priority_reclaim_percent: 30.0,
        }
    }
}

// ---------------------------------------------------------------------------
// Collector Registration
// ---------------------------------------------------------------------------

/// Registration info for a collector with the resource manager.
#[derive(Debug, Clone)]
pub struct CollectorRegistration {
    /// Collector name (e.g., "process", "network", "memory").
    pub name: String,
    /// Optional PID override for tracking (default: agent's own PID).
    /// Used when a collector spawns a separate process.
    pub pid: Option<u32>,
    /// Priority level for this collector.
    pub priority: CollectorPriority,
}

// ---------------------------------------------------------------------------
// Resource Manager Runtime
// ---------------------------------------------------------------------------

/// Shared handle to a registered collector's throttler.
/// Collectors use this to check if they should throttle or pause.
pub type CollectorHandle = Arc<CollectorThrottler>;

/// Central resource manager for all collectors.
pub struct ResourceManager {
    config: ResourceManagerConfig,
    /// Registered collectors: name -> (monitor, throttler).
    collectors: Arc<RwLock<HashMap<String, (CollectorMonitor, Arc<CollectorThrottler>)>>>,
    /// Channel for publishing usage snapshots (for health reporting).
    snapshot_tx: mpsc::UnboundedSender<CollectorUsageSnapshot>,
    /// System-wide CPU usage tracker (for dynamic budget adjustment).
    system: Arc<RwLock<sysinfo::System>>,
}

impl ResourceManager {
    /// Create a new resource manager.
    ///
    /// Returns:
    /// - `ResourceManager`: The manager instance (spawn with `run()`).
    /// - `mpsc::UnboundedReceiver<CollectorUsageSnapshot>`: Channel for receiving
    ///   per-collector usage snapshots for health reporting.
    pub fn new(
        config: ResourceManagerConfig,
    ) -> (Self, mpsc::UnboundedReceiver<CollectorUsageSnapshot>) {
        let (snapshot_tx, snapshot_rx) = mpsc::unbounded_channel();
        let system = Arc::new(RwLock::new(sysinfo::System::new_all()));

        let manager = Self {
            config,
            collectors: Arc::new(RwLock::new(HashMap::new())),
            snapshot_tx,
            system,
        };

        (manager, snapshot_rx)
    }

    /// Register a collector and return its throttle handle.
    ///
    /// The collector should check the handle before expensive operations:
    /// ```rust,ignore
    /// let handle = manager.register(CollectorRegistration {
    ///     name: "process".to_string(),
    ///     pid: None,
    ///     priority: CollectorPriority::High,
    /// });
    ///
    /// loop {
    ///     // Check if we should throttle or pause
    ///     if let Some(delay) = handle.should_throttle() {
    ///         tokio::time::sleep(delay).await;
    ///     }
    ///     if handle.is_paused() {
    ///         handle.wait_for_resume().await;
    ///     }
    ///
    ///     // Do work...
    /// }
    /// ```
    pub fn register(&self, registration: CollectorRegistration) -> CollectorHandle {
        let name = registration.name.clone();

        // Get budget config for this collector (specific override or default)
        let budget_config = self
            .config
            .collector_budgets
            .get(&name)
            .cloned()
            .unwrap_or_else(|| self.config.default_budget.clone());

        let budget = CollectorBudget::new(budget_config, registration.priority);
        let monitor = CollectorMonitor::new(name.clone(), registration.pid);
        let throttler = Arc::new(CollectorThrottler::new(name.clone()));

        self.collectors
            .write()
            .insert(name.clone(), (monitor, Arc::clone(&throttler)));

        info!(
            collector = %name,
            cpu_max = format!("{:.1}%", budget.cpu_percent_max),
            mem_max_mb = budget.memory_mb_max,
            priority = ?registration.priority,
            "Collector registered with resource manager"
        );

        throttler
    }

    /// Unregister a collector (called when collector is stopped).
    pub fn unregister(&self, name: &str) {
        if self.collectors.write().remove(name).is_some() {
            debug!(collector = %name, "Collector unregistered from resource manager");
        }
    }

    /// Run the resource manager monitoring loop.
    /// This should be spawned as a tokio task.
    pub async fn run(self: Arc<Self>) {
        if !self.config.enabled {
            info!("Per-collector resource manager disabled");
            return;
        }

        let interval = Duration::from_secs(self.config.monitor_interval_secs.max(1));
        info!(
            interval_secs = interval.as_secs(),
            dynamic_budget = self.config.dynamic_budget_enabled,
            priority_allocation = self.config.priority_allocation_enabled,
            "Per-collector resource manager started"
        );

        loop {
            tokio::time::sleep(interval).await;
            self.monitor_cycle().await;
        }
    }

    /// Execute one monitoring cycle: check all collectors, enforce budgets.
    async fn monitor_cycle(&self) {
        // Refresh system-wide CPU for dynamic budget adjustment
        if self.config.dynamic_budget_enabled {
            self.system.write().refresh_cpu();
        }

        let system_cpu = if self.config.dynamic_budget_enabled {
            self.system.read().global_cpu_info().cpu_usage()
        } else {
            0.0
        };

        // Dynamic budget multiplier: reduce budgets when system is under load
        let budget_multiplier = if self.config.dynamic_budget_enabled && system_cpu > 80.0 {
            0.5 // Cut all budgets in half when system CPU >80%
        } else {
            1.0
        };

        // Collect usage snapshots and enforce budgets in a tight scope so the
        // non-Send `RwLockReadGuard` is dropped before any `.await` below. This
        // is required for the enclosing future to be `Send` (see
        // `tokio::spawn` bound) when used from `integration_example.rs`.
        let snapshots: Vec<CollectorUsageSnapshot> = {
            let collectors = self.collectors.read();
            let mut snapshots = Vec::with_capacity(collectors.len());

            for (name, (monitor, throttler)) in collectors.iter() {
                // Get budget for this collector
                let budget_config = self
                    .config
                    .collector_budgets
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| self.config.default_budget.clone());
                let mut budget = CollectorBudget::new(budget_config, monitor.priority());

                // Apply dynamic budget scaling
                budget.apply_multiplier(budget_multiplier);

                // Take usage snapshot
                let snapshot = monitor.snapshot();
                snapshots.push(snapshot.clone());

                // Enforce budget
                let action = budget.check_budget(&snapshot);
                throttler.apply_action(action);

                // Publish snapshot for health reporting
                let _ = self.snapshot_tx.send(snapshot);
            }

            snapshots
        };

        // Priority-based resource reallocation
        if self.config.priority_allocation_enabled {
            self.reallocate_priority_resources(&snapshots).await;
        }
    }

    /// Reallocate resources from low-priority to high-priority collectors
    /// when high-priority collectors exceed their budgets.
    async fn reallocate_priority_resources(&self, snapshots: &[CollectorUsageSnapshot]) {
        // Find high-priority collectors that are over budget
        let high_priority_over_budget: Vec<_> = snapshots
            .iter()
            .filter(|s| {
                matches!(
                    s.priority,
                    CollectorPriority::Critical | CollectorPriority::High
                ) && s.budget_utilization_percent > 100.0
            })
            .collect();

        if high_priority_over_budget.is_empty() {
            return; // All critical collectors are within budget
        }

        // Find low-priority collectors to throttle
        let low_priority_targets: Vec<_> = snapshots
            .iter()
            .filter(|s| matches!(s.priority, CollectorPriority::Low))
            .collect();

        if low_priority_targets.is_empty() {
            return; // No low-priority collectors to throttle
        }

        // Apply additional throttling to low-priority collectors
        let collectors = self.collectors.read();
        for target in low_priority_targets {
            if let Some((_, throttler)) = collectors.get(&target.collector_name) {
                throttler.apply_action(ThrottleAction::Throttle {
                    delay: Duration::from_millis(500),
                });
                debug!(
                    collector = %target.collector_name,
                    "Throttling low-priority collector to free resources for critical collectors"
                );
            }
        }
    }

    /// Get a snapshot of all collector resource usage for health reporting.
    pub fn get_all_snapshots(&self) -> Vec<CollectorUsageSnapshot> {
        let collectors = self.collectors.read();
        collectors
            .iter()
            .map(|(_, (monitor, _))| monitor.snapshot())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_collector_registration() {
        let config = ResourceManagerConfig::default();
        let (manager, _rx) = ResourceManager::new(config);

        let handle = manager.register(CollectorRegistration {
            name: "test_collector".to_string(),
            pid: None,
            priority: CollectorPriority::Normal,
        });

        assert_eq!(manager.collectors.read().len(), 1);
        assert!(!handle.is_paused());
    }

    #[tokio::test]
    async fn test_collector_unregister() {
        let config = ResourceManagerConfig::default();
        let (manager, _rx) = ResourceManager::new(config);

        manager.register(CollectorRegistration {
            name: "test_collector".to_string(),
            pid: None,
            priority: CollectorPriority::Normal,
        });

        manager.unregister("test_collector");
        assert_eq!(manager.collectors.read().len(), 0);
    }

    #[tokio::test]
    async fn test_dynamic_budget_adjustment() {
        let config = ResourceManagerConfig {
            dynamic_budget_enabled: true,
            ..Default::default()
        };
        let (manager, _rx) = ResourceManager::new(config);
        let manager = Arc::new(manager);

        manager.register(CollectorRegistration {
            name: "test".to_string(),
            pid: None,
            priority: CollectorPriority::Normal,
        });

        // One monitoring cycle
        manager.monitor_cycle().await;

        // Verify no panics and collectors still registered
        assert_eq!(manager.collectors.read().len(), 1);
    }
}
