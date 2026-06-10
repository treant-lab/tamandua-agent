//! Resource Governor — enforces CPU, memory, and disk limits on the agent.
//!
//! The governor runs as a background task that periodically samples the agent
//! process's resource usage and takes corrective action:
//!
//! - **CPU**: Tracks per-sample CPU usage. When sustained usage exceeds the
//!   configured threshold, it signals collectors to widen their poll intervals
//!   (via an `Arc<AtomicU8>` pressure level).
//! - **Memory**: Tracks RSS. When a soft limit is exceeded, it drops low-priority
//!   cached data (e.g. behavioral baselines, entropy caches). When the hard limit
//!   is exceeded, it disables non-critical collectors.
//! - **Disk**: Monitors the offline event queue size. When the configured quota
//!   is exceeded, it evicts oldest events.
//!
//! Collectors read the `pressure_level` atomic and multiply their sleep intervals
//! by the corresponding factor. This provides back-pressure without explicit
//! cross-task message passing.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Pressure levels (read by collectors to self-throttle)
// ---------------------------------------------------------------------------

/// Pressure levels communicated to collectors via `Arc<AtomicU8>`.
///
/// Collectors multiply their base sleep interval by the factor corresponding
/// to the current level.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PressureLevel {
    /// Normal operation — no throttling.
    None = 0,
    /// Light pressure — increase intervals by 2x.
    Light = 1,
    /// Moderate pressure — increase intervals by 4x, drop caches.
    Moderate = 2,
    /// Heavy pressure — increase intervals by 8x, disable non-critical collectors.
    Heavy = 3,
    /// Critical — only heartbeat and self-protection remain active.
    Critical = 4,
}

impl PressureLevel {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::None,
            1 => Self::Light,
            2 => Self::Moderate,
            3 => Self::Heavy,
            _ => Self::Critical,
        }
    }

    /// Interval multiplier that collectors should apply.
    pub fn multiplier(self) -> f32 {
        match self {
            Self::None => 1.0,
            Self::Light => 2.0,
            Self::Moderate => 4.0,
            Self::Heavy => 8.0,
            Self::Critical => 16.0,
        }
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Resource governor configuration.
///
/// Nested under `[resource_governor]` in `agent.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ResourceGovernorConfig {
    /// Enable the resource governor (default: true).
    pub enabled: bool,

    /// Sampling interval in seconds (default: 5).
    pub sample_interval_secs: u64,

    /// Sustained CPU threshold (%) to enter Light pressure (default: 10.0).
    pub cpu_light_threshold: f32,

    /// Sustained CPU threshold (%) to enter Moderate pressure (default: 20.0).
    pub cpu_moderate_threshold: f32,

    /// Sustained CPU threshold (%) to enter Heavy pressure (default: 35.0).
    pub cpu_heavy_threshold: f32,

    /// Sustained CPU threshold (%) to enter Critical pressure (default: 50.0).
    pub cpu_critical_threshold: f32,

    /// Number of consecutive samples above threshold before escalating (default: 3).
    pub escalation_samples: u32,

    /// Number of consecutive samples below threshold before de-escalating (default: 5).
    pub de_escalation_samples: u32,

    /// Memory soft limit in MB. When RSS exceeds this, caches are dropped (default: 200).
    pub memory_soft_limit_mb: u64,

    /// Memory hard limit in MB. When RSS exceeds this, non-critical collectors
    /// are disabled (default: 400).
    pub memory_hard_limit_mb: u64,

    /// Disk quota for the offline event queue in MB (default: 100).
    pub disk_quota_mb: u64,
}

impl Default for ResourceGovernorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sample_interval_secs: 5,
            cpu_light_threshold: 10.0,
            cpu_moderate_threshold: 20.0,
            cpu_heavy_threshold: 35.0,
            cpu_critical_threshold: 50.0,
            escalation_samples: 3,
            de_escalation_samples: 5,
            memory_soft_limit_mb: 200,
            memory_hard_limit_mb: 400,
            disk_quota_mb: 100,
        }
    }
}

// ---------------------------------------------------------------------------
// Metrics snapshot (exposed for health reporting)
// ---------------------------------------------------------------------------

/// A snapshot of current resource usage, published each sample cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSnapshot {
    /// Agent process CPU usage (0.0 – 100.0).
    pub cpu_percent: f32,
    /// Agent process RSS in bytes.
    pub memory_rss_bytes: u64,
    /// Offline queue disk usage in bytes.
    pub disk_queue_bytes: u64,
    /// Current pressure level.
    pub pressure_level: u8,
    /// Timestamp (ms since epoch).
    pub timestamp_ms: u64,
}

// ---------------------------------------------------------------------------
// Governor runtime
// ---------------------------------------------------------------------------

/// Shared handle that collectors use to read the current pressure level.
#[derive(Clone)]
pub struct GovernorHandle {
    pressure: Arc<AtomicU8>,
}

impl GovernorHandle {
    /// Read the current pressure level.
    pub fn pressure_level(&self) -> PressureLevel {
        PressureLevel::from_u8(self.pressure.load(Ordering::Relaxed))
    }

    /// Convenience: return the interval multiplier collectors should apply.
    pub fn interval_multiplier(&self) -> f32 {
        self.pressure_level().multiplier()
    }
}

/// The resource governor background task.
pub struct ResourceGovernor {
    config: ResourceGovernorConfig,
    pressure: Arc<AtomicU8>,
    /// Ring buffer of recent CPU samples for smoothing.
    cpu_samples: Vec<f32>,
    /// How many consecutive samples have been above/below the current threshold.
    above_count: u32,
    below_count: u32,
    current_level: PressureLevel,
    /// Path to the offline queue directory (for disk quota enforcement).
    queue_path: Option<std::path::PathBuf>,
    /// sysinfo handle for process metrics.
    system: sysinfo::System,
    own_pid: sysinfo::Pid,
    /// Max CPU percent from the performance profile (for compliance tracking).
    /// If agent CPU exceeds this, log a warning but don't fail.
    max_cpu_percent_from_profile: f32,
    /// Track if we've already warned about profile compliance.
    profile_compliance_warned: bool,
}

impl ResourceGovernor {
    /// Create a new governor and return its shared handle.
    ///
    /// `max_cpu_percent_from_profile`: The configured max CPU % from the agent's
    /// performance profile (e.g., 20.0 for Aggressive, 15.0 for Balanced, 5.0 for Lightweight).
    /// The governor will log compliance warnings if actual usage exceeds this + 5% buffer.
    pub fn new(
        config: ResourceGovernorConfig,
        queue_path: Option<std::path::PathBuf>,
        max_cpu_percent_from_profile: f32,
    ) -> (Self, GovernorHandle) {
        let pressure = Arc::new(AtomicU8::new(0));
        let handle = GovernorHandle {
            pressure: Arc::clone(&pressure),
        };

        let own_pid = sysinfo::Pid::from_u32(std::process::id());
        let mut system = sysinfo::System::new();
        system.refresh_process(own_pid);

        let gov = Self {
            config,
            pressure,
            cpu_samples: Vec::with_capacity(16),
            above_count: 0,
            below_count: 0,
            current_level: PressureLevel::None,
            queue_path,
            system,
            own_pid,
            max_cpu_percent_from_profile,
            profile_compliance_warned: false,
        };

        (gov, handle)
    }

    /// Run the governor loop. This is meant to be spawned as a tokio task.
    pub async fn run(mut self) {
        if !self.config.enabled {
            info!("Resource governor disabled");
            return;
        }

        let interval = Duration::from_secs(self.config.sample_interval_secs.max(1));
        info!(
            interval_secs = interval.as_secs(),
            cpu_thresholds = %format!(
                "light={:.0}% moderate={:.0}% heavy={:.0}% critical={:.0}%",
                self.config.cpu_light_threshold,
                self.config.cpu_moderate_threshold,
                self.config.cpu_heavy_threshold,
                self.config.cpu_critical_threshold,
            ),
            mem_soft_mb = self.config.memory_soft_limit_mb,
            mem_hard_mb = self.config.memory_hard_limit_mb,
            disk_quota_mb = self.config.disk_quota_mb,
            "Resource governor started"
        );

        loop {
            tokio::time::sleep(interval).await;
            self.sample();
        }
    }

    /// Take one sample and update pressure level.
    fn sample(&mut self) {
        // Refresh only our own process to minimise overhead.
        self.system.refresh_process(self.own_pid);

        let (cpu, rss) = self
            .system
            .process(self.own_pid)
            .map(|p| (normalize_process_cpu_percent(p.cpu_usage()), p.memory()))
            .unwrap_or((0.0, 0));

        // Push CPU sample for smoothing (keep last 8).
        self.cpu_samples.push(cpu);
        if self.cpu_samples.len() > 8 {
            self.cpu_samples.remove(0);
        }
        let avg_cpu: f32 = self.cpu_samples.iter().sum::<f32>() / self.cpu_samples.len() as f32;

        // Determine target pressure from CPU.
        let cpu_target = if avg_cpu >= self.config.cpu_critical_threshold {
            PressureLevel::Critical
        } else if avg_cpu >= self.config.cpu_heavy_threshold {
            PressureLevel::Heavy
        } else if avg_cpu >= self.config.cpu_moderate_threshold {
            PressureLevel::Moderate
        } else if avg_cpu >= self.config.cpu_light_threshold {
            PressureLevel::Light
        } else {
            PressureLevel::None
        };

        // Determine target pressure from memory.
        let mem_mb = rss / (1024 * 1024);
        let mem_target = if mem_mb >= self.config.memory_hard_limit_mb {
            PressureLevel::Heavy
        } else if mem_mb >= self.config.memory_soft_limit_mb {
            PressureLevel::Moderate
        } else {
            PressureLevel::None
        };

        // Determine target pressure from disk.
        let disk_target = self.check_disk_pressure();

        // Take the worst (highest) pressure across all dimensions.
        let target = [cpu_target, mem_target, disk_target]
            .into_iter()
            .max_by_key(|p| *p as u8)
            .unwrap_or(PressureLevel::None);

        // Hysteresis: require consecutive samples before changing level.
        if (target as u8) > (self.current_level as u8) {
            self.below_count = 0;
            self.above_count += 1;
            if self.above_count >= self.config.escalation_samples {
                self.set_level(target, avg_cpu, mem_mb);
                self.above_count = 0;
            }
        } else if (target as u8) < (self.current_level as u8) {
            self.above_count = 0;
            self.below_count += 1;
            if self.below_count >= self.config.de_escalation_samples {
                self.set_level(target, avg_cpu, mem_mb);
                self.below_count = 0;
            }
        } else {
            // Stable — reset counters.
            self.above_count = 0;
            self.below_count = 0;
        }

        debug!(
            avg_cpu = format!("{avg_cpu:.1}%"),
            rss_mb = mem_mb,
            pressure = ?self.current_level,
            "resource governor sample"
        );
    }

    fn set_level(&mut self, level: PressureLevel, cpu: f32, mem_mb: u64) {
        // Check profile compliance: warn if CPU exceeds max + 5% buffer
        if cpu > self.max_cpu_percent_from_profile + 5.0 && !self.profile_compliance_warned {
            warn!(
                current_cpu = format!("{cpu:.1}%"),
                profile_max = format!("{:.1}%", self.max_cpu_percent_from_profile),
                buffer = "5%",
                pressure = ?level,
                "WARNING: Agent CPU exceeds performance profile limit. \
                 Consider switching to a lighter profile or reducing collector scope."
            );
            self.profile_compliance_warned = true;
        }

        // Reset warning flag when CPU drops back below limit
        if cpu <= self.max_cpu_percent_from_profile {
            self.profile_compliance_warned = false;
        }

        if level != self.current_level {
            let prev = self.current_level;
            self.current_level = level;
            self.pressure.store(level as u8, Ordering::Relaxed);

            if (level as u8) > (prev as u8) {
                warn!(
                    from = ?prev,
                    to = ?level,
                    cpu = format!("{cpu:.1}%"),
                    profile_max = format!("{:.1}%", self.max_cpu_percent_from_profile),
                    rss_mb = mem_mb,
                    multiplier = level.multiplier(),
                    "Resource pressure ESCALATED — collectors will throttle"
                );
            } else {
                info!(
                    from = ?prev,
                    to = ?level,
                    cpu = format!("{cpu:.1}%"),
                    profile_max = format!("{:.1}%", self.max_cpu_percent_from_profile),
                    rss_mb = mem_mb,
                    "Resource pressure de-escalated"
                );
            }
        }
    }

    fn check_disk_pressure(&self) -> PressureLevel {
        let Some(ref path) = self.queue_path else {
            return PressureLevel::None;
        };

        // Best-effort directory size check.
        let size_bytes = dir_size(path);
        let size_mb = size_bytes / (1024 * 1024);
        let quota = self.config.disk_quota_mb;

        if quota == 0 {
            return PressureLevel::None;
        }

        let usage_pct = (size_mb as f64 / quota as f64) * 100.0;
        if usage_pct >= 95.0 {
            PressureLevel::Heavy
        } else if usage_pct >= 80.0 {
            PressureLevel::Moderate
        } else if usage_pct >= 60.0 {
            PressureLevel::Light
        } else {
            PressureLevel::None
        }
    }
}

/// Recursively sum file sizes in a directory. Best-effort, ignores errors.
fn dir_size(path: &std::path::Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    entries
        .filter_map(|e| e.ok())
        .map(|e| {
            let meta = e.metadata().unwrap_or_else(|_| {
                // Fallback: zero-size if metadata unavailable
                std::fs::metadata(e.path()).unwrap_or_else(|_| {
                    // Should not happen, but safety
                    return std::fs::metadata(".").unwrap();
                })
            });
            if meta.is_dir() {
                dir_size(&e.path())
            } else {
                meta.len()
            }
        })
        .sum()
}

fn normalize_process_cpu_percent(raw_cpu: f32) -> f32 {
    let logical_cpus = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .max(1) as f32;

    (raw_cpu / logical_cpus).clamp(0.0, 100.0)
}
