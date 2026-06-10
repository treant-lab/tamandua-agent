//! Resource budget definitions and enforcement logic.

use super::monitor::CollectorUsageSnapshot;
use super::throttler::ThrottleAction;
use serde::{Deserialize, Serialize};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Collector Priority
// ---------------------------------------------------------------------------

/// Priority level for resource allocation.
///
/// When resources are scarce, high-priority collectors get more budget than
/// low-priority ones. Critical collectors are never paused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectorPriority {
    /// Never pause, always allow to run (process, network, file).
    Critical,
    /// Important collectors with higher resource allocation.
    High,
    /// Standard priority.
    Normal,
    /// Can be heavily throttled or paused under pressure.
    Low,
}

impl Default for CollectorPriority {
    fn default() -> Self {
        Self::Normal
    }
}

// ---------------------------------------------------------------------------
// Budget Configuration
// ---------------------------------------------------------------------------

/// Per-collector resource budget configuration.
///
/// These are the **limits** a collector should stay within. If it exceeds
/// them, the resource manager will throttle or pause the collector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorBudgetConfig {
    /// Maximum CPU usage for this collector (0.0-100.0).
    /// Default: 5.0% per collector.
    #[serde(default = "default_cpu_max")]
    pub cpu_percent_max: f32,

    /// Maximum memory usage in MB.
    /// Default: 50 MB per collector.
    #[serde(default = "default_memory_max")]
    pub memory_mb_max: u64,

    /// Maximum disk I/O bytes per second.
    /// Default: 10 MB/s per collector.
    #[serde(default = "default_disk_io_max")]
    pub disk_io_bytes_per_sec_max: u64,

    /// Maximum event emission rate (events/sec).
    /// Default: 100 events/sec per collector.
    #[serde(default = "default_event_rate_max")]
    pub event_rate_per_sec_max: u32,

    /// Soft threshold percentage before throttling (0-100).
    /// When usage exceeds this % of the max budget, apply light throttling.
    /// Default: 80%
    #[serde(default = "default_soft_threshold")]
    pub soft_threshold_percent: f32,

    /// Hard threshold percentage before pausing (0-100).
    /// When usage exceeds this % of the max budget, pause the collector.
    /// Default: 100% (only pause when budget exceeded)
    #[serde(default = "default_hard_threshold")]
    pub hard_threshold_percent: f32,

    /// Throttle delay in milliseconds when soft threshold exceeded.
    /// Default: 100ms
    #[serde(default = "default_throttle_delay_ms")]
    pub throttle_delay_ms: u64,

    /// How long to pause when hard threshold exceeded (milliseconds).
    /// Default: 1000ms (1 second)
    #[serde(default = "default_pause_duration_ms")]
    pub pause_duration_ms: u64,
}

fn default_cpu_max() -> f32 {
    5.0
}
fn default_memory_max() -> u64 {
    50
}
fn default_disk_io_max() -> u64 {
    10 * 1024 * 1024
} // 10 MB/s
fn default_event_rate_max() -> u32 {
    100
}
fn default_soft_threshold() -> f32 {
    80.0
}
fn default_hard_threshold() -> f32 {
    100.0
}
fn default_throttle_delay_ms() -> u64 {
    100
}
fn default_pause_duration_ms() -> u64 {
    1000
}

impl Default for CollectorBudgetConfig {
    fn default() -> Self {
        Self {
            cpu_percent_max: default_cpu_max(),
            memory_mb_max: default_memory_max(),
            disk_io_bytes_per_sec_max: default_disk_io_max(),
            event_rate_per_sec_max: default_event_rate_max(),
            soft_threshold_percent: default_soft_threshold(),
            hard_threshold_percent: default_hard_threshold(),
            throttle_delay_ms: default_throttle_delay_ms(),
            pause_duration_ms: default_pause_duration_ms(),
        }
    }
}

// ---------------------------------------------------------------------------
// Budget Enforcement
// ---------------------------------------------------------------------------

/// Runtime budget enforcer for a collector.
pub struct CollectorBudget {
    pub cpu_percent_max: f32,
    pub memory_mb_max: u64,
    pub disk_io_bytes_per_sec_max: u64,
    pub event_rate_per_sec_max: u32,
    pub soft_threshold_percent: f32,
    pub hard_threshold_percent: f32,
    pub throttle_delay: Duration,
    pub pause_duration: Duration,
    pub priority: CollectorPriority,
}

impl CollectorBudget {
    /// Create a new budget from config and priority.
    pub fn new(config: CollectorBudgetConfig, priority: CollectorPriority) -> Self {
        Self {
            cpu_percent_max: config.cpu_percent_max,
            memory_mb_max: config.memory_mb_max,
            disk_io_bytes_per_sec_max: config.disk_io_bytes_per_sec_max,
            event_rate_per_sec_max: config.event_rate_per_sec_max,
            soft_threshold_percent: config.soft_threshold_percent,
            hard_threshold_percent: config.hard_threshold_percent,
            throttle_delay: Duration::from_millis(config.throttle_delay_ms),
            pause_duration: Duration::from_millis(config.pause_duration_ms),
            priority,
        }
    }

    /// Apply a multiplier to all budget limits (for dynamic adjustment).
    /// Example: multiplier=0.5 cuts all limits in half.
    pub fn apply_multiplier(&mut self, multiplier: f32) {
        self.cpu_percent_max *= multiplier;
        self.memory_mb_max = ((self.memory_mb_max as f32) * multiplier) as u64;
        self.disk_io_bytes_per_sec_max =
            ((self.disk_io_bytes_per_sec_max as f32) * multiplier) as u64;
        self.event_rate_per_sec_max = ((self.event_rate_per_sec_max as f32) * multiplier) as u32;
    }

    /// Check current usage against budget and return the appropriate action.
    pub fn check_budget(&self, snapshot: &CollectorUsageSnapshot) -> ThrottleAction {
        // Critical collectors are never paused
        if self.priority == CollectorPriority::Critical {
            // But still throttle if way over budget
            if snapshot.cpu_percent > self.cpu_percent_max * 2.0 {
                return ThrottleAction::Throttle {
                    delay: self.throttle_delay,
                };
            }
            return ThrottleAction::None;
        }

        // Check CPU budget
        let cpu_utilization = (snapshot.cpu_percent / self.cpu_percent_max) * 100.0;
        if cpu_utilization >= self.hard_threshold_percent {
            return ThrottleAction::Pause {
                duration: self.pause_duration,
            };
        }
        if cpu_utilization >= self.soft_threshold_percent {
            return ThrottleAction::Throttle {
                delay: self.throttle_delay,
            };
        }

        // Check memory budget
        let mem_utilization =
            ((snapshot.memory_bytes / (1024 * 1024)) as f32 / self.memory_mb_max as f32) * 100.0;
        if mem_utilization >= self.hard_threshold_percent {
            return ThrottleAction::Pause {
                duration: self.pause_duration,
            };
        }
        if mem_utilization >= self.soft_threshold_percent {
            return ThrottleAction::Throttle {
                delay: self.throttle_delay,
            };
        }

        // Check disk I/O budget
        let disk_utilization =
            (snapshot.disk_io_bytes_per_sec as f32 / self.disk_io_bytes_per_sec_max as f32) * 100.0;
        if disk_utilization >= self.hard_threshold_percent {
            return ThrottleAction::Pause {
                duration: self.pause_duration,
            };
        }
        if disk_utilization >= self.soft_threshold_percent {
            return ThrottleAction::Throttle {
                delay: self.throttle_delay,
            };
        }

        // Check event rate budget
        let event_utilization =
            (snapshot.events_per_sec as f32 / self.event_rate_per_sec_max as f32) * 100.0;
        if event_utilization >= self.hard_threshold_percent {
            return ThrottleAction::Pause {
                duration: self.pause_duration,
            };
        }
        if event_utilization >= self.soft_threshold_percent {
            return ThrottleAction::Throttle {
                delay: self.throttle_delay,
            };
        }

        ThrottleAction::None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_budget_no_throttle() {
        let config = CollectorBudgetConfig::default();
        let budget = CollectorBudget::new(config, CollectorPriority::Normal);

        let snapshot = CollectorUsageSnapshot {
            collector_name: "test".to_string(),
            cpu_percent: 2.0,                   // Under 5% max
            memory_bytes: 10 * 1024 * 1024,     // 10 MB, under 50 MB max
            disk_io_bytes_per_sec: 1024 * 1024, // 1 MB/s, under 10 MB/s max
            events_per_sec: 10,                 // Under 100/sec max
            budget_utilization_percent: 40.0,
            is_throttled: false,
            is_paused: false,
            timestamp_ms: 0,
            priority: CollectorPriority::Normal,
        };

        let action = budget.check_budget(&snapshot);
        assert!(matches!(action, ThrottleAction::None));
    }

    #[test]
    fn test_budget_soft_throttle() {
        let config = CollectorBudgetConfig::default();
        let budget = CollectorBudget::new(config, CollectorPriority::Normal);

        let snapshot = CollectorUsageSnapshot {
            collector_name: "test".to_string(),
            cpu_percent: 4.5, // 90% of 5% max -> above 80% soft threshold
            memory_bytes: 10 * 1024 * 1024,
            disk_io_bytes_per_sec: 0,
            events_per_sec: 0,
            budget_utilization_percent: 90.0,
            is_throttled: false,
            is_paused: false,
            timestamp_ms: 0,
            priority: CollectorPriority::Normal,
        };

        let action = budget.check_budget(&snapshot);
        assert!(matches!(action, ThrottleAction::Throttle { .. }));
    }

    #[test]
    fn test_budget_hard_pause() {
        let config = CollectorBudgetConfig::default();
        let budget = CollectorBudget::new(config, CollectorPriority::Normal);

        let snapshot = CollectorUsageSnapshot {
            collector_name: "test".to_string(),
            cpu_percent: 6.0, // 120% of 5% max -> above 100% hard threshold
            memory_bytes: 10 * 1024 * 1024,
            disk_io_bytes_per_sec: 0,
            events_per_sec: 0,
            budget_utilization_percent: 120.0,
            is_throttled: false,
            is_paused: false,
            timestamp_ms: 0,
            priority: CollectorPriority::Normal,
        };

        let action = budget.check_budget(&snapshot);
        assert!(matches!(action, ThrottleAction::Pause { .. }));
    }

    #[test]
    fn test_critical_priority_never_paused() {
        let config = CollectorBudgetConfig::default();
        let budget = CollectorBudget::new(config, CollectorPriority::Critical);

        let snapshot = CollectorUsageSnapshot {
            collector_name: "critical".to_string(),
            cpu_percent: 8.0,                        // Way over budget
            memory_bytes: 100 * 1024 * 1024,         // Over budget
            disk_io_bytes_per_sec: 50 * 1024 * 1024, // Over budget
            events_per_sec: 200,                     // Over budget
            budget_utilization_percent: 160.0,
            is_throttled: false,
            is_paused: false,
            timestamp_ms: 0,
            priority: CollectorPriority::Critical,
        };

        let action = budget.check_budget(&snapshot);
        // Critical collectors never get Pause action, but may get Throttle
        assert!(!matches!(action, ThrottleAction::Pause { .. }));
    }

    #[test]
    fn test_budget_multiplier() {
        let config = CollectorBudgetConfig::default();
        let mut budget = CollectorBudget::new(config, CollectorPriority::Normal);

        let original_cpu_max = budget.cpu_percent_max;
        budget.apply_multiplier(0.5);

        assert_eq!(budget.cpu_percent_max, original_cpu_max * 0.5);
    }
}
