//! Enhanced Health Metrics Collector
//!
//! Collects detailed performance metrics for agent health monitoring:
//! - CPU usage per collector
//! - Memory usage breakdown
//! - Network bandwidth
//! - Disk I/O
//! - Event processing rate
//! - Detection latency
//! - Error rates by component

// This module enumerates per-component health metrics (CPU, memory, network,
// disk, latency, error rates) and baselines. Reserved fields and helper
// state are kept exhaustive for downstream health reporting even when not
// all paths are dispatched yet.
#![allow(dead_code, unused_variables)]

use super::super::collectors::{EventPayload, EventType, Severity, TelemetryEvent};
use crate::collectors::CollectorCapabilityStatus;
use crate::config::AgentConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use sysinfo::{Disks, Pid, System};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

/// Detailed health metrics snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedHealthMetrics {
    /// Timestamp of metrics collection (Unix epoch milliseconds)
    pub timestamp: u64,

    /// CPU metrics
    pub cpu: CpuMetrics,

    /// Memory metrics
    pub memory: MemoryMetrics,

    /// Disk metrics
    pub disk: DiskMetrics,

    /// Network metrics
    pub network: NetworkMetrics,

    /// Collector performance metrics
    pub collectors: HashMap<String, CollectorMetrics>,

    /// Event processing metrics
    pub event_processing: EventProcessingMetrics,

    /// Detection engine metrics
    pub detection: DetectionMetrics,

    /// Error tracking
    pub errors: ErrorMetrics,

    /// Collector capability/config/policy status snapshot.
    pub collector_status: CollectorCapabilityStatus,

    /// Agent uptime in seconds
    pub uptime_seconds: u64,
}

/// CPU usage metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuMetrics {
    /// Overall CPU usage percentage (0.0 - 100.0)
    pub overall_usage: f32,

    /// Per-core CPU usage
    pub per_core: Vec<f32>,

    /// Agent process CPU usage
    pub agent_process_usage: f32,

    /// CPU usage by collector
    pub collector_usage: HashMap<String, f32>,

    /// Number of CPU cores
    pub core_count: usize,

    /// Load average (1min, 5min, 15min) - Unix only
    pub load_average: Option<(f64, f64, f64)>,
}

/// Memory usage metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryMetrics {
    /// Total system memory in bytes
    pub total: u64,

    /// Used system memory in bytes
    pub used: u64,

    /// Available system memory in bytes
    pub available: u64,

    /// Memory usage percentage
    pub usage_percent: f32,

    /// Agent process memory usage in bytes
    pub agent_process_usage: u64,

    /// Agent process memory percentage
    pub agent_process_percent: f32,

    /// Memory breakdown by collector
    pub collector_usage: HashMap<String, u64>,

    /// Swap memory usage
    pub swap_total: u64,
    pub swap_used: u64,
}

/// Disk I/O metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskMetrics {
    /// Total disk space in bytes
    pub total: u64,

    /// Used disk space in bytes
    pub used: u64,

    /// Disk usage percentage
    pub usage_percent: f32,

    /// Disk read bytes per second
    pub read_bytes_per_sec: u64,

    /// Disk write bytes per second
    pub write_bytes_per_sec: u64,

    /// I/O operations per second
    pub iops: u64,

    /// Per-disk metrics
    pub disks: Vec<DiskInfo>,
}

/// Individual disk information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskInfo {
    pub name: String,
    pub mount_point: String,
    pub total: u64,
    pub available: u64,
    pub usage_percent: f32,
}

/// Network bandwidth metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetrics {
    /// Bytes received per second
    pub rx_bytes_per_sec: u64,

    /// Bytes transmitted per second
    pub tx_bytes_per_sec: u64,

    /// Packets received per second
    pub rx_packets_per_sec: u64,

    /// Packets transmitted per second
    pub tx_packets_per_sec: u64,

    /// Network errors per second
    pub errors_per_sec: u64,

    /// Active connections count
    pub active_connections: u64,

    /// WebSocket connection latency (ms)
    pub websocket_latency_ms: Option<u64>,
}

/// Collector performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorMetrics {
    /// Collector name
    pub name: String,

    /// Events generated in last interval
    pub events_generated: u64,

    /// Events per second rate
    pub events_per_sec: f64,

    /// Average event processing time (microseconds)
    pub avg_processing_time_us: u64,

    /// CPU usage percentage
    pub cpu_usage: f32,

    /// Memory usage in bytes
    pub memory_usage: u64,

    /// Error count in last interval
    pub error_count: u64,

    /// Last error timestamp
    pub last_error: Option<u64>,

    /// Is collector enabled
    pub enabled: bool,
}

/// Event processing metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventProcessingMetrics {
    /// Total events processed in last interval
    pub events_processed: u64,

    /// Events per second
    pub events_per_sec: f64,

    /// Events queued
    pub events_queued: u64,

    /// Average event size in bytes
    pub avg_event_size: u64,

    /// Event processing latency (p50, p95, p99) in microseconds
    pub latency_p50_us: u64,
    pub latency_p95_us: u64,
    pub latency_p99_us: u64,

    /// Events dropped due to queue overflow
    pub events_dropped: u64,
}

/// Detection engine metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionMetrics {
    /// YARA scans performed
    pub yara_scans: u64,

    /// Sigma rule evaluations
    pub sigma_evaluations: u64,

    /// Local ML inferences
    pub ml_inferences: u64,

    /// Average detection latency (microseconds)
    pub avg_detection_latency_us: u64,

    /// Detections triggered
    pub detections_triggered: u64,

    /// False positives marked
    pub false_positives: u64,
}

/// Error tracking metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMetrics {
    /// Total errors in last interval
    pub total_errors: u64,

    /// Errors per minute
    pub errors_per_min: f64,

    /// Errors by component
    pub by_component: HashMap<String, u64>,

    /// Errors by severity (warn, error, critical)
    pub by_severity: HashMap<String, u64>,

    /// Recent error samples
    pub recent_errors: Vec<ErrorSample>,
}

/// Error sample for tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorSample {
    pub timestamp: u64,
    pub component: String,
    pub severity: String,
    pub message: String,
}

/// Enhanced metrics collector state
pub struct EnhancedMetricsCollector {
    event_tx: mpsc::Sender<TelemetryEvent>,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    metrics_state: Arc<RwLock<MetricsState>>,
    start_time: Instant,
}

/// Internal metrics tracking state
struct MetricsState {
    collector_stats: HashMap<String, CollectorStats>,
    event_stats: EventStats,
    detection_stats: DetectionStats,
    error_tracker: ErrorTracker,
    network_baseline: NetworkBaseline,
    disk_baseline: DiskBaseline,
}

struct CollectorStats {
    events_count: u64,
    total_processing_time_us: u64,
    error_count: u64,
    last_error_time: Option<Instant>,
    /// Timestamp when the interval started (for rate calculation)
    interval_start: Instant,
}

impl Default for CollectorStats {
    fn default() -> Self {
        Self {
            events_count: 0,
            total_processing_time_us: 0,
            error_count: 0,
            last_error_time: None,
            interval_start: Instant::now(),
        }
    }
}

struct EventStats {
    processed: u64,
    queued: u64,
    dropped: u64,
    total_size: u64,
    latencies_us: Vec<u64>,
    /// Timestamp when the interval started (for rate calculation)
    interval_start: Instant,
}

impl Default for EventStats {
    fn default() -> Self {
        Self {
            processed: 0,
            queued: 0,
            dropped: 0,
            total_size: 0,
            latencies_us: Vec::new(),
            interval_start: Instant::now(),
        }
    }
}

#[derive(Default)]
struct DetectionStats {
    yara_scans: u64,
    sigma_evals: u64,
    ml_inferences: u64,
    total_latency_us: u64,
    detections: u64,
    false_positives: u64,
}

struct ErrorTracker {
    total: u64,
    by_component: HashMap<String, u64>,
    by_severity: HashMap<String, u64>,
    samples: Vec<ErrorSample>,
    /// Timestamp when the interval started (for rate calculation)
    interval_start: Instant,
}

impl Default for ErrorTracker {
    fn default() -> Self {
        Self {
            total: 0,
            by_component: HashMap::new(),
            by_severity: HashMap::new(),
            samples: Vec::new(),
            interval_start: Instant::now(),
        }
    }
}

#[derive(Default)]
struct NetworkBaseline {
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,
    errors: u64,
    last_update: Option<Instant>,
}

#[derive(Default)]
struct DiskBaseline {
    read_bytes: u64,
    write_bytes: u64,
    operations: u64,
    last_update: Option<Instant>,
}

impl EnhancedMetricsCollector {
    /// Create a new enhanced metrics collector
    pub fn new(config: &AgentConfig) -> Self {
        let (event_tx, event_rx) = mpsc::channel(128);

        let interval_secs = if config.health_interval_seconds > 0 {
            config.health_interval_seconds
        } else {
            30 // Default to 30 seconds for detailed metrics
        };

        let metrics_state = Arc::new(RwLock::new(MetricsState {
            collector_stats: HashMap::new(),
            event_stats: EventStats::default(),
            detection_stats: DetectionStats::default(),
            error_tracker: ErrorTracker::default(),
            network_baseline: NetworkBaseline::default(),
            disk_baseline: DiskBaseline::default(),
        }));

        let tx = event_tx.clone();
        let state = metrics_state.clone();
        let start_time = Instant::now();

        let collector_status = CollectorCapabilityStatus::from_config(config);

        tokio::spawn(Self::collection_loop(
            tx,
            state,
            interval_secs,
            start_time,
            collector_status,
        ));

        info!(
            interval_seconds = interval_secs,
            "Enhanced metrics collector initialized"
        );

        Self {
            event_tx,
            event_rx,
            metrics_state,
            start_time,
        }
    }

    /// Main collection loop
    async fn collection_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        state: Arc<RwLock<MetricsState>>,
        interval_secs: u32,
        start_time: Instant,
        collector_status: CollectorCapabilityStatus,
    ) {
        let mut sys = System::new_all();
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs as u64));

        // Allow initial CPU measurement to settle
        sys.refresh_cpu_usage();
        tokio::time::sleep(Duration::from_secs(1)).await;

        loop {
            interval.tick().await;

            // Refresh system info
            sys.refresh_all();

            // Collect all metrics
            let metrics =
                match Self::collect_metrics(&sys, &state, start_time, &collector_status).await {
                    Ok(m) => m,
                    Err(e) => {
                        warn!("Failed to collect metrics: {}", e);
                        continue;
                    }
                };

            debug!(
                cpu = %format!("{:.1}%", metrics.cpu.overall_usage),
                mem = %format!("{:.1}%", metrics.memory.usage_percent),
                events_per_sec = %format!("{:.1}", metrics.event_processing.events_per_sec),
                "Enhanced health metrics collected"
            );

            let event = TelemetryEvent::new(
                EventType::SystemHealth,
                Severity::Info,
                EventPayload::EnhancedHealth(metrics),
            );

            if tx.send(event).await.is_err() {
                warn!("Metrics event channel closed");
                return;
            }
        }
    }

    /// Collect comprehensive metrics
    async fn collect_metrics(
        sys: &System,
        state: &Arc<RwLock<MetricsState>>,
        start_time: Instant,
        collector_status: &CollectorCapabilityStatus,
    ) -> anyhow::Result<DetailedHealthMetrics> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis() as u64;

        let uptime_seconds = start_time.elapsed().as_secs();

        // CPU metrics
        let cpu = Self::collect_cpu_metrics(sys)?;

        // Memory metrics
        let memory = Self::collect_memory_metrics(sys)?;

        // Disk metrics
        let disk = Self::collect_disk_metrics(state).await?;

        // Network metrics
        let network = Self::collect_network_metrics(state).await?;

        // Get collector metrics from state
        let mut state_lock = state.write().await;
        let collectors = Self::build_collector_metrics(&mut state_lock);
        let event_processing = Self::build_event_metrics(&mut state_lock);
        let detection = Self::build_detection_metrics(&mut state_lock);
        let errors = Self::build_error_metrics(&mut state_lock);
        drop(state_lock);

        Ok(DetailedHealthMetrics {
            timestamp,
            cpu,
            memory,
            disk,
            network,
            collectors,
            event_processing,
            detection,
            errors,
            collector_status: collector_status.clone(),
            uptime_seconds,
        })
    }

    fn collect_cpu_metrics(sys: &System) -> anyhow::Result<CpuMetrics> {
        let overall_usage = sys.global_cpu_info().cpu_usage();

        let per_core: Vec<f32> = sys.cpus().iter().map(|cpu| cpu.cpu_usage()).collect();

        let core_count = sys.cpus().len();

        // Get agent process CPU usage via current process ID
        let agent_process_usage = {
            let pid = Pid::from_u32(std::process::id());
            sys.process(pid).map(|p| p.cpu_usage()).unwrap_or(0.0)
        };

        let collector_usage = HashMap::new(); // Per-collector tracking requires thread-level instrumentation

        // Load average (Unix only)
        #[cfg(target_family = "unix")]
        let load_average = {
            let la = System::load_average();
            Some((la.one, la.five, la.fifteen))
        };

        #[cfg(not(target_family = "unix"))]
        let load_average: Option<(f64, f64, f64)> = None;

        Ok(CpuMetrics {
            overall_usage,
            per_core,
            agent_process_usage,
            collector_usage,
            core_count,
            load_average,
        })
    }

    fn collect_memory_metrics(sys: &System) -> anyhow::Result<MemoryMetrics> {
        let total = sys.total_memory();
        let used = sys.used_memory();
        let available = sys.available_memory();
        let usage_percent = if total > 0 {
            (used as f64 / total as f64 * 100.0) as f32
        } else {
            0.0
        };

        // Get agent process memory usage via current process ID
        let (agent_process_usage, agent_process_percent) = {
            let pid = Pid::from_u32(std::process::id());
            match sys.process(pid) {
                Some(p) => {
                    let mem = p.memory();
                    let percent = if total > 0 {
                        (mem as f64 / total as f64 * 100.0) as f32
                    } else {
                        0.0
                    };
                    (mem, percent)
                }
                None => (0, 0.0),
            }
        };

        let collector_usage = HashMap::new(); // Per-collector tracking requires thread-level instrumentation

        let swap_total = sys.total_swap();
        let swap_used = sys.used_swap();

        Ok(MemoryMetrics {
            total,
            used,
            available,
            usage_percent,
            agent_process_usage,
            agent_process_percent,
            collector_usage,
            swap_total,
            swap_used,
        })
    }

    async fn collect_disk_metrics(
        state: &Arc<RwLock<MetricsState>>,
    ) -> anyhow::Result<DiskMetrics> {
        let disks_obj = Disks::new_with_refreshed_list();

        let mut total: u64 = 0;
        let mut used: u64 = 0;
        let mut disks_info = Vec::new();

        for disk in disks_obj.list() {
            let disk_total = disk.total_space();
            let disk_available = disk.available_space();
            let disk_used = disk_total - disk_available;

            total += disk_total;
            used += disk_used;

            let usage_percent = if disk_total > 0 {
                (disk_used as f64 / disk_total as f64 * 100.0) as f32
            } else {
                0.0
            };

            disks_info.push(DiskInfo {
                name: disk.name().to_string_lossy().to_string(),
                mount_point: disk.mount_point().to_string_lossy().to_string(),
                total: disk_total,
                available: disk_available,
                usage_percent,
            });
        }

        let usage_percent = if total > 0 {
            (used as f64 / total as f64 * 100.0) as f32
        } else {
            0.0
        };

        // I/O metrics (simplified - would need platform-specific tracking)
        let read_bytes_per_sec = 0;
        let write_bytes_per_sec = 0;
        let iops = 0;

        Ok(DiskMetrics {
            total,
            used,
            usage_percent,
            read_bytes_per_sec,
            write_bytes_per_sec,
            iops,
            disks: disks_info,
        })
    }

    async fn collect_network_metrics(
        state: &Arc<RwLock<MetricsState>>,
    ) -> anyhow::Result<NetworkMetrics> {
        // Network metrics (simplified - would need platform-specific tracking)
        Ok(NetworkMetrics {
            rx_bytes_per_sec: 0,
            tx_bytes_per_sec: 0,
            rx_packets_per_sec: 0,
            tx_packets_per_sec: 0,
            errors_per_sec: 0,
            active_connections: 0,
            websocket_latency_ms: None,
        })
    }

    fn build_collector_metrics(state: &mut MetricsState) -> HashMap<String, CollectorMetrics> {
        let mut result = HashMap::new();

        for (name, stats) in state.collector_stats.iter_mut() {
            let avg_processing_time_us = if stats.events_count > 0 {
                stats.total_processing_time_us / stats.events_count
            } else {
                0
            };

            // Calculate events per second based on elapsed time since interval start
            let elapsed_secs = stats.interval_start.elapsed().as_secs_f64();
            let events_per_sec = if elapsed_secs > 0.0 {
                stats.events_count as f64 / elapsed_secs
            } else {
                0.0
            };

            let metrics = CollectorMetrics {
                name: name.clone(),
                events_generated: stats.events_count,
                events_per_sec,
                avg_processing_time_us,
                cpu_usage: 0.0, // Per-collector CPU tracking requires thread-level instrumentation
                memory_usage: 0, // Per-collector memory tracking requires allocator hooks
                error_count: stats.error_count,
                last_error: stats.last_error_time.map(|t| t.elapsed().as_secs()),
                enabled: true,
            };

            result.insert(name.clone(), metrics);

            // Reset counters for next interval
            stats.events_count = 0;
            stats.total_processing_time_us = 0;
            stats.error_count = 0;
            stats.interval_start = Instant::now();
        }

        result
    }

    fn build_event_metrics(state: &mut MetricsState) -> EventProcessingMetrics {
        let stats = &mut state.event_stats;

        // Calculate percentiles
        stats.latencies_us.sort_unstable();
        let len = stats.latencies_us.len();

        let latency_p50_us = if len > 0 {
            stats.latencies_us[len / 2]
        } else {
            0
        };

        let latency_p95_us = if len > 0 {
            stats.latencies_us[(len * 95) / 100]
        } else {
            0
        };

        let latency_p99_us = if len > 0 {
            stats.latencies_us[(len * 99) / 100]
        } else {
            0
        };

        let avg_event_size = if stats.processed > 0 {
            stats.total_size / stats.processed
        } else {
            0
        };

        // Calculate events per second based on elapsed time since interval start
        let elapsed_secs = stats.interval_start.elapsed().as_secs_f64();
        let events_per_sec = if elapsed_secs > 0.0 {
            stats.processed as f64 / elapsed_secs
        } else {
            0.0
        };

        let metrics = EventProcessingMetrics {
            events_processed: stats.processed,
            events_per_sec,
            events_queued: stats.queued,
            avg_event_size,
            latency_p50_us,
            latency_p95_us,
            latency_p99_us,
            events_dropped: stats.dropped,
        };

        // Reset for next interval
        stats.latencies_us.clear();
        stats.processed = 0;
        stats.total_size = 0;
        stats.dropped = 0;
        stats.interval_start = Instant::now();

        metrics
    }

    fn build_detection_metrics(state: &mut MetricsState) -> DetectionMetrics {
        let stats = &state.detection_stats;

        let avg_detection_latency_us = if stats.yara_scans + stats.sigma_evals + stats.ml_inferences
            > 0
        {
            stats.total_latency_us / (stats.yara_scans + stats.sigma_evals + stats.ml_inferences)
        } else {
            0
        };

        DetectionMetrics {
            yara_scans: stats.yara_scans,
            sigma_evaluations: stats.sigma_evals,
            ml_inferences: stats.ml_inferences,
            avg_detection_latency_us,
            detections_triggered: stats.detections,
            false_positives: stats.false_positives,
        }
    }

    fn build_error_metrics(state: &mut MetricsState) -> ErrorMetrics {
        let tracker = &mut state.error_tracker;

        // Keep only last 100 error samples
        let recent_errors: Vec<ErrorSample> =
            tracker.samples.iter().rev().take(100).cloned().collect();

        // Calculate errors per minute based on elapsed time since interval start
        let elapsed_mins = tracker.interval_start.elapsed().as_secs_f64() / 60.0;
        let errors_per_min = if elapsed_mins > 0.0 {
            tracker.total as f64 / elapsed_mins
        } else {
            0.0
        };

        let metrics = ErrorMetrics {
            total_errors: tracker.total,
            errors_per_min,
            by_component: tracker.by_component.clone(),
            by_severity: tracker.by_severity.clone(),
            recent_errors,
        };

        // Reset for next interval (keep samples for historical tracking)
        tracker.total = 0;
        tracker.by_component.clear();
        tracker.by_severity.clear();
        tracker.interval_start = Instant::now();

        metrics
    }

    /// Record a collector event
    pub async fn record_collector_event(&self, collector_name: &str, processing_time_us: u64) {
        let mut state = self.metrics_state.write().await;
        let stats = state
            .collector_stats
            .entry(collector_name.to_string())
            .or_insert_with(CollectorStats::default);

        stats.events_count += 1;
        stats.total_processing_time_us += processing_time_us;
    }

    /// Record an error
    pub async fn record_error(&self, component: &str, severity: &str, message: String) {
        let mut state = self.metrics_state.write().await;
        let tracker = &mut state.error_tracker;

        tracker.total += 1;
        *tracker
            .by_component
            .entry(component.to_string())
            .or_insert(0) += 1;
        *tracker.by_severity.entry(severity.to_string()).or_insert(0) += 1;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        tracker.samples.push(ErrorSample {
            timestamp,
            component: component.to_string(),
            severity: severity.to_string(),
            message,
        });

        // Keep only last 1000 samples
        if tracker.samples.len() > 1000 {
            tracker.samples.drain(0..tracker.samples.len() - 1000);
        }
    }

    /// Get next event
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }
}
