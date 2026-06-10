//! Real-time resource usage monitoring for collectors.

use super::budget::CollectorPriority;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

// ---------------------------------------------------------------------------
// Usage Tracking
// ---------------------------------------------------------------------------

/// Real-time resource usage tracker for a single collector.
#[derive(Debug)]
pub struct CollectorMonitor {
    /// Collector name
    name: String,
    /// Process ID to monitor (None = use agent's own PID)
    pid: Option<u32>,
    /// Priority level
    priority: CollectorPriority,
    /// Accumulated CPU time tracking
    cpu_tracker: Arc<RwLock<CpuTracker>>,
    /// Memory usage tracking
    memory_bytes: Arc<AtomicU64>,
    /// Disk I/O tracking
    disk_tracker: Arc<RwLock<DiskIoTracker>>,
    /// Event rate tracking
    event_tracker: Arc<RwLock<EventRateTracker>>,
    /// sysinfo System handle for process metrics
    system: Arc<RwLock<sysinfo::System>>,
    /// Our PID (for per-collector CPU tracking)
    own_pid: sysinfo::Pid,
    /// Collector start time
    start_time: Instant,
}

/// CPU usage tracker (smoothed over time windows).
#[derive(Debug)]
struct CpuTracker {
    /// Recent CPU samples (last 10 samples)
    samples: Vec<f32>,
    /// Last sample time
    last_sample: Instant,
}

impl CpuTracker {
    fn new() -> Self {
        Self {
            samples: Vec::with_capacity(10),
            last_sample: Instant::now(),
        }
    }

    fn add_sample(&mut self, cpu_percent: f32) {
        self.samples.push(cpu_percent);
        if self.samples.len() > 10 {
            self.samples.remove(0);
        }
        self.last_sample = Instant::now();
    }

    fn average(&self) -> f32 {
        if self.samples.is_empty() {
            return 0.0;
        }
        self.samples.iter().sum::<f32>() / self.samples.len() as f32
    }
}

/// Disk I/O tracker (bytes/sec calculation).
#[derive(Debug)]
struct DiskIoTracker {
    /// Total bytes read/written since start
    total_bytes: u64,
    /// Last measurement
    last_total: u64,
    /// Last measurement time
    last_time: Instant,
}

impl DiskIoTracker {
    fn new() -> Self {
        Self {
            total_bytes: 0,
            last_total: 0,
            last_time: Instant::now(),
        }
    }

    fn record_io(&mut self, bytes: u64) {
        self.total_bytes += bytes;
    }

    fn bytes_per_sec(&mut self) -> u64 {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_time).as_secs_f64();
        if elapsed < 0.1 {
            return 0; // Too soon, return 0
        }

        let delta_bytes = self.total_bytes.saturating_sub(self.last_total);
        let rate = (delta_bytes as f64 / elapsed) as u64;

        self.last_total = self.total_bytes;
        self.last_time = now;

        rate
    }
}

/// Event rate tracker (events/sec calculation).
#[derive(Debug)]
struct EventRateTracker {
    /// Total events emitted since start
    total_events: u64,
    /// Last measurement
    last_total: u64,
    /// Last measurement time
    last_time: Instant,
}

impl EventRateTracker {
    fn new() -> Self {
        Self {
            total_events: 0,
            last_total: 0,
            last_time: Instant::now(),
        }
    }

    fn record_event(&mut self) {
        self.total_events += 1;
    }

    fn record_events(&mut self, count: u64) {
        self.total_events += count;
    }

    fn events_per_sec(&mut self) -> u32 {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_time).as_secs_f64();
        if elapsed < 0.1 {
            return 0; // Too soon, return 0
        }

        let delta_events = self.total_events.saturating_sub(self.last_total);
        let rate = (delta_events as f64 / elapsed) as u32;

        self.last_total = self.total_events;
        self.last_time = now;

        rate
    }
}

impl CollectorMonitor {
    /// Create a new monitor for a collector.
    pub fn new(name: String, pid: Option<u32>) -> Self {
        let own_pid = sysinfo::Pid::from_u32(std::process::id());
        let mut system = sysinfo::System::new();
        system.refresh_process(own_pid);

        Self {
            name,
            pid,
            priority: CollectorPriority::Normal,
            cpu_tracker: Arc::new(RwLock::new(CpuTracker::new())),
            memory_bytes: Arc::new(AtomicU64::new(0)),
            disk_tracker: Arc::new(RwLock::new(DiskIoTracker::new())),
            event_tracker: Arc::new(RwLock::new(EventRateTracker::new())),
            system: Arc::new(RwLock::new(system)),
            own_pid,
            start_time: Instant::now(),
        }
    }

    /// Set the priority level for this collector.
    pub fn set_priority(&mut self, priority: CollectorPriority) {
        self.priority = priority;
    }

    /// Get the priority level.
    pub fn priority(&self) -> CollectorPriority {
        self.priority
    }

    /// Record an event emission (for event rate tracking).
    pub fn record_event(&self) {
        self.event_tracker.write().record_event();
    }

    /// Record multiple event emissions at once.
    pub fn record_events(&self, count: u64) {
        self.event_tracker.write().record_events(count);
    }

    /// Record disk I/O activity (bytes read or written).
    pub fn record_disk_io(&self, bytes: u64) {
        self.disk_tracker.write().record_io(bytes);
    }

    /// Update memory usage (bytes).
    pub fn update_memory(&self, bytes: u64) {
        self.memory_bytes.store(bytes, Ordering::Relaxed);
    }

    /// Take a snapshot of current resource usage.
    pub fn snapshot(&self) -> CollectorUsageSnapshot {
        // Refresh process metrics
        let mut system = self.system.write();
        system.refresh_process(self.own_pid);

        let (cpu_percent, memory_bytes) = if let Some(process) = system.process(self.own_pid) {
            (process.cpu_usage(), process.memory())
        } else {
            (0.0, 0)
        };

        // Update CPU tracker
        self.cpu_tracker.write().add_sample(cpu_percent);
        let avg_cpu = self.cpu_tracker.read().average();

        // Update memory tracking
        self.memory_bytes.store(memory_bytes, Ordering::Relaxed);

        // Calculate rates
        let disk_io_bytes_per_sec = self.disk_tracker.write().bytes_per_sec();
        let events_per_sec = self.event_tracker.write().events_per_sec();

        // Calculate overall budget utilization (simplified: just use CPU)
        // In a real implementation, this would be a weighted average of all dimensions
        let budget_utilization_percent = avg_cpu * 20.0; // Assume 5% CPU budget -> 100% utilization

        CollectorUsageSnapshot {
            collector_name: self.name.clone(),
            cpu_percent: avg_cpu,
            memory_bytes,
            disk_io_bytes_per_sec,
            events_per_sec,
            budget_utilization_percent,
            is_throttled: false, // Set by throttler
            is_paused: false,    // Set by throttler
            timestamp_ms: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            priority: self.priority,
        }
    }

    /// Get collector uptime.
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }
}

// ---------------------------------------------------------------------------
// Usage Snapshot (published for health reporting)
// ---------------------------------------------------------------------------

/// A snapshot of a collector's current resource usage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorUsageSnapshot {
    /// Collector name
    pub collector_name: String,

    /// CPU usage (0.0-100.0)
    pub cpu_percent: f32,

    /// Memory usage in bytes
    pub memory_bytes: u64,

    /// Disk I/O rate (bytes/sec)
    pub disk_io_bytes_per_sec: u64,

    /// Event emission rate (events/sec)
    pub events_per_sec: u32,

    /// Overall budget utilization percentage (0-100+)
    /// >100% means over budget
    pub budget_utilization_percent: f32,

    /// Whether collector is currently throttled
    pub is_throttled: bool,

    /// Whether collector is currently paused
    pub is_paused: bool,

    /// Timestamp in milliseconds since UNIX epoch
    pub timestamp_ms: u64,

    /// Priority level
    pub priority: CollectorPriority,
}

// ---------------------------------------------------------------------------
// Helper: Collector-specific usage handles
// ---------------------------------------------------------------------------

/// A handle for collectors to report their resource usage.
///
/// Collectors receive this handle when registering and use it to:
/// - Report event emissions
/// - Report disk I/O operations
/// - Update memory usage
#[derive(Clone)]
pub struct CollectorUsageHandle {
    monitor: Arc<CollectorMonitor>,
}

impl CollectorUsageHandle {
    /// Create a new usage handle.
    pub fn new(monitor: Arc<CollectorMonitor>) -> Self {
        Self { monitor }
    }

    /// Record that an event was emitted.
    pub fn record_event(&self) {
        self.monitor.record_event();
    }

    /// Record multiple events emitted at once.
    pub fn record_events(&self, count: u64) {
        self.monitor.record_events(count);
    }

    /// Record disk I/O activity (bytes).
    pub fn record_disk_io(&self, bytes: u64) {
        self.monitor.record_disk_io(bytes);
    }

    /// Update memory usage (bytes).
    pub fn update_memory(&self, bytes: u64) {
        self.monitor.update_memory(bytes);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_tracker() {
        let mut tracker = CpuTracker::new();
        tracker.add_sample(5.0);
        tracker.add_sample(10.0);
        tracker.add_sample(15.0);

        assert_eq!(tracker.average(), 10.0);
    }

    #[test]
    fn test_event_rate_tracker() {
        let mut tracker = EventRateTracker::new();
        tracker.record_events(100);

        std::thread::sleep(Duration::from_millis(200));
        let rate = tracker.events_per_sec();

        // Should be approximately 500 events/sec (100 events in 0.2 sec)
        // Allow for timing variance
        assert!(rate >= 400 && rate <= 600);
    }

    #[test]
    fn test_disk_io_tracker() {
        let mut tracker = DiskIoTracker::new();
        tracker.record_io(1024 * 1024); // 1 MB

        std::thread::sleep(Duration::from_millis(200));
        let rate = tracker.bytes_per_sec();

        // Should be approximately 5 MB/sec (1 MB in 0.2 sec)
        // Allow for timing variance
        assert!(rate >= 4_000_000 && rate <= 6_000_000);
    }

    #[test]
    fn test_collector_monitor_snapshot() {
        let monitor = CollectorMonitor::new("test".to_string(), None);
        monitor.record_events(10);
        monitor.update_memory(100 * 1024 * 1024); // 100 MB

        let snapshot = monitor.snapshot();
        assert_eq!(snapshot.collector_name, "test");
        assert!(snapshot.memory_bytes > 0);
    }
}
