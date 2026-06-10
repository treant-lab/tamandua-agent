// Tamandua EDR Agent - Performance Profiling Module
//
// Provides comprehensive profiling capabilities:
// - CPU profiling with pprof (flame graphs)
// - Memory profiling with jemalloc
// - Lock contention analysis
// - Per-collector performance breakdown
// - Continuous profiling with Pyroscope integration
// - On-demand profiling via API

use anyhow::{Context, Result};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

#[cfg(feature = "jemalloc")]
use tikv_jemallocator::Jemalloc;

#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

pub mod cpu;
pub mod memory;
pub mod locks;
pub mod metrics;
pub mod pyroscope;

/// Profiling configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProfilingConfig {
    /// Enable continuous CPU profiling
    pub cpu_profiling_enabled: bool,

    /// CPU profiling sample frequency (Hz)
    pub cpu_sample_frequency: u32,

    /// Enable memory profiling
    pub memory_profiling_enabled: bool,

    /// Memory profiling sample rate (1 in N allocations)
    pub memory_sample_rate: u32,

    /// Enable lock contention profiling
    pub lock_profiling_enabled: bool,

    /// Enable per-collector metrics
    pub collector_metrics_enabled: bool,

    /// Pyroscope server URL (optional)
    pub pyroscope_url: Option<String>,

    /// Pyroscope application name
    pub pyroscope_app_name: String,

    /// Pyroscope tags
    pub pyroscope_tags: HashMap<String, String>,

    /// Enable on-demand profiling API
    pub api_enabled: bool,

    /// API listen address
    pub api_listen: String,
}

impl Default for ProfilingConfig {
    fn default() -> Self {
        Self {
            cpu_profiling_enabled: false,
            cpu_sample_frequency: 99, // Standard profiling frequency
            memory_profiling_enabled: false,
            memory_sample_rate: 512 * 1024, // Sample 1 in 512KB
            lock_profiling_enabled: false,
            collector_metrics_enabled: true,
            pyroscope_url: None,
            pyroscope_app_name: "tamandua-agent".to_string(),
            pyroscope_tags: HashMap::new(),
            api_enabled: false,
            api_listen: "127.0.0.1:6060".to_string(),
        }
    }
}

/// Profiler manager - coordinates all profiling activities
pub struct Profiler {
    config: ProfilingConfig,
    cpu_profiler: Option<cpu::CpuProfiler>,
    memory_profiler: Option<memory::MemoryProfiler>,
    lock_profiler: Option<locks::LockProfiler>,
    collector_metrics: Arc<RwLock<metrics::CollectorMetrics>>,
    pyroscope_client: Option<pyroscope::PyroscopeClient>,
}

impl Profiler {
    /// Create a new profiler instance
    pub fn new(config: ProfilingConfig) -> Result<Self> {
        info!("Initializing profiler with config: {:?}", config);

        // Initialize CPU profiler
        let cpu_profiler = if config.cpu_profiling_enabled {
            Some(cpu::CpuProfiler::new(config.cpu_sample_frequency)?)
        } else {
            None
        };

        // Initialize memory profiler
        let memory_profiler = if config.memory_profiling_enabled {
            Some(memory::MemoryProfiler::new(config.memory_sample_rate)?)
        } else {
            None
        };

        // Initialize lock profiler
        let lock_profiler = if config.lock_profiling_enabled {
            Some(locks::LockProfiler::new()?)
        } else {
            None
        };

        // Initialize collector metrics
        let collector_metrics = Arc::new(RwLock::new(metrics::CollectorMetrics::new()));

        // Initialize Pyroscope client
        let pyroscope_client = if let Some(url) = &config.pyroscope_url {
            Some(pyroscope::PyroscopeClient::new(
                url,
                &config.pyroscope_app_name,
                config.pyroscope_tags.clone(),
            )?)
        } else {
            None
        };

        Ok(Self {
            config,
            cpu_profiler,
            memory_profiler,
            lock_profiler,
            collector_metrics,
            pyroscope_client,
        })
    }

    /// Start continuous profiling
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting profiler");

        // Start CPU profiling
        if let Some(cpu_profiler) = &mut self.cpu_profiler {
            cpu_profiler.start()?;
            info!("CPU profiling started");
        }

        // Start memory profiling
        if let Some(memory_profiler) = &mut self.memory_profiler {
            memory_profiler.start()?;
            info!("Memory profiling started");
        }

        // Start lock profiling
        if let Some(lock_profiler) = &mut self.lock_profiler {
            lock_profiler.start()?;
            info!("Lock contention profiling started");
        }

        // Start Pyroscope client
        if let Some(pyroscope_client) = &mut self.pyroscope_client {
            pyroscope_client.start().await?;
            info!("Pyroscope client started");
        }

        Ok(())
    }

    /// Stop continuous profiling
    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping profiler");

        // Stop Pyroscope client
        if let Some(pyroscope_client) = &mut self.pyroscope_client {
            pyroscope_client.stop().await?;
        }

        // Stop lock profiling
        if let Some(lock_profiler) = &mut self.lock_profiler {
            lock_profiler.stop()?;
        }

        // Stop memory profiling
        if let Some(memory_profiler) = &mut self.memory_profiler {
            memory_profiler.stop()?;
        }

        // Stop CPU profiling
        if let Some(cpu_profiler) = &mut self.cpu_profiler {
            cpu_profiler.stop()?;
        }

        Ok(())
    }

    /// Trigger on-demand CPU profile
    pub fn profile_cpu(&self, duration: Duration) -> Result<Vec<u8>> {
        info!("Starting on-demand CPU profile for {:?}", duration);
        cpu::profile_cpu(duration)
    }

    /// Trigger on-demand memory profile
    pub fn profile_memory(&self) -> Result<Vec<u8>> {
        info!("Capturing memory profile");
        memory::profile_memory()
    }

    /// Get lock contention statistics
    pub fn lock_stats(&self) -> Result<locks::LockStats> {
        if let Some(lock_profiler) = &self.lock_profiler {
            Ok(lock_profiler.stats())
        } else {
            anyhow::bail!("Lock profiling not enabled")
        }
    }

    /// Record collector timing
    pub fn record_collector_timing(&self, collector_name: &str, duration: Duration) {
        if self.config.collector_metrics_enabled {
            let mut metrics = self.collector_metrics.write();
            metrics.record_timing(collector_name, duration);
        }
    }

    /// Get collector metrics
    pub fn collector_metrics(&self) -> metrics::CollectorMetricsSnapshot {
        let metrics = self.collector_metrics.read();
        metrics.snapshot()
    }

    /// Export flame graph (SVG format)
    pub fn export_flamegraph(&self) -> Result<String> {
        if let Some(cpu_profiler) = &self.cpu_profiler {
            cpu_profiler.export_flamegraph()
        } else {
            anyhow::bail!("CPU profiling not enabled")
        }
    }
}

/// Profiling guard for automatic timing measurement
pub struct ProfileGuard {
    collector_name: String,
    start: Instant,
    profiler: Arc<Profiler>,
}

impl ProfileGuard {
    pub fn new(profiler: Arc<Profiler>, collector_name: String) -> Self {
        Self {
            collector_name,
            start: Instant::now(),
            profiler,
        }
    }
}

impl Drop for ProfileGuard {
    fn drop(&mut self) {
        let duration = self.start.elapsed();
        self.profiler.record_collector_timing(&self.collector_name, duration);
    }
}

/// Global profiler instance (optional)
static GLOBAL_PROFILER: once_cell::sync::OnceCell<Arc<RwLock<Option<Profiler>>>> = once_cell::sync::OnceCell::new();

/// Initialize global profiler
pub fn init_global_profiler(config: ProfilingConfig) -> Result<()> {
    let profiler = Profiler::new(config)?;
    GLOBAL_PROFILER.get_or_init(|| Arc::new(RwLock::new(Some(profiler))));
    Ok(())
}

/// Get global profiler
pub fn global_profiler() -> Option<Arc<RwLock<Option<Profiler>>>> {
    GLOBAL_PROFILER.get().cloned()
}

/// Start global profiler
pub async fn start_global_profiler() -> Result<()> {
    if let Some(profiler_lock) = GLOBAL_PROFILER.get() {
        if let Some(profiler) = profiler_lock.write().as_mut() {
            profiler.start().await?;
        }
    }
    Ok(())
}

/// Stop global profiler
pub async fn stop_global_profiler() -> Result<()> {
    if let Some(profiler_lock) = GLOBAL_PROFILER.get() {
        if let Some(profiler) = profiler_lock.write().as_mut() {
            profiler.stop().await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_profiler_lifecycle() {
        let config = ProfilingConfig {
            cpu_profiling_enabled: true,
            memory_profiling_enabled: true,
            lock_profiling_enabled: true,
            collector_metrics_enabled: true,
            ..Default::default()
        };

        let mut profiler = Profiler::new(config).unwrap();
        profiler.start().await.unwrap();

        // Simulate some work
        tokio::time::sleep(Duration::from_millis(100)).await;

        profiler.stop().await.unwrap();
    }
}
