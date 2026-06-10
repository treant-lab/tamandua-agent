//! Performance Metrics Collection
//!
//! Track performance metrics for allocations, lock contention, CPU usage, and memory usage.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Performance metrics collector
#[derive(Clone)]
pub struct PerformanceMetrics {
    inner: Arc<MetricsInner>,
}

struct MetricsInner {
    // Memory metrics
    total_allocations: AtomicUsize,
    total_deallocations: AtomicUsize,
    total_bytes_allocated: AtomicU64,
    current_bytes: AtomicU64,
    peak_bytes: AtomicU64,

    // Queue metrics
    events_enqueued: AtomicU64,
    events_dequeued: AtomicU64,
    events_dropped: AtomicU64,

    // CPU metrics per collector
    process_cpu_time_us: AtomicU64,
    network_cpu_time_us: AtomicU64,
    file_cpu_time_us: AtomicU64,
    dns_cpu_time_us: AtomicU64,
    registry_cpu_time_us: AtomicU64,

    // Lock contention metrics
    lock_acquisitions: AtomicU64,
    lock_contentions: AtomicU64,
    lock_wait_time_us: AtomicU64,

    // Timing metrics
    start_time: Instant,
}

impl PerformanceMetrics {
    /// Create a new performance metrics collector
    pub fn new() -> Self {
        Self {
            inner: Arc::new(MetricsInner {
                total_allocations: AtomicUsize::new(0),
                total_deallocations: AtomicUsize::new(0),
                total_bytes_allocated: AtomicU64::new(0),
                current_bytes: AtomicU64::new(0),
                peak_bytes: AtomicU64::new(0),
                events_enqueued: AtomicU64::new(0),
                events_dequeued: AtomicU64::new(0),
                events_dropped: AtomicU64::new(0),
                process_cpu_time_us: AtomicU64::new(0),
                network_cpu_time_us: AtomicU64::new(0),
                file_cpu_time_us: AtomicU64::new(0),
                dns_cpu_time_us: AtomicU64::new(0),
                registry_cpu_time_us: AtomicU64::new(0),
                lock_acquisitions: AtomicU64::new(0),
                lock_contentions: AtomicU64::new(0),
                lock_wait_time_us: AtomicU64::new(0),
                start_time: Instant::now(),
            }),
        }
    }

    // Memory tracking
    pub fn record_allocation(&self, size: usize) {
        self.inner.total_allocations.fetch_add(1, Ordering::Relaxed);
        self.inner
            .total_bytes_allocated
            .fetch_add(size as u64, Ordering::Relaxed);

        let current = self
            .inner
            .current_bytes
            .fetch_add(size as u64, Ordering::Relaxed)
            + size as u64;

        // Update peak if necessary
        let mut peak = self.inner.peak_bytes.load(Ordering::Relaxed);
        while current > peak {
            match self.inner.peak_bytes.compare_exchange_weak(
                peak,
                current,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(p) => peak = p,
            }
        }
    }

    pub fn record_deallocation(&self, size: usize) {
        self.inner
            .total_deallocations
            .fetch_add(1, Ordering::Relaxed);
        self.inner
            .current_bytes
            .fetch_sub(size as u64, Ordering::Relaxed);
    }

    // Queue metrics
    pub fn record_event_enqueued(&self) {
        self.inner.events_enqueued.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_event_dequeued(&self) {
        self.inner.events_dequeued.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_event_dropped(&self) {
        self.inner.events_dropped.fetch_add(1, Ordering::Relaxed);
    }

    // CPU time tracking
    pub fn record_collector_cpu_time(&self, collector: &str, duration: Duration) {
        let micros = duration.as_micros() as u64;
        match collector {
            "process" => self
                .inner
                .process_cpu_time_us
                .fetch_add(micros, Ordering::Relaxed),
            "network" => self
                .inner
                .network_cpu_time_us
                .fetch_add(micros, Ordering::Relaxed),
            "file" => self
                .inner
                .file_cpu_time_us
                .fetch_add(micros, Ordering::Relaxed),
            "dns" => self
                .inner
                .dns_cpu_time_us
                .fetch_add(micros, Ordering::Relaxed),
            "registry" => self
                .inner
                .registry_cpu_time_us
                .fetch_add(micros, Ordering::Relaxed),
            _ => 0,
        };
    }

    // Lock contention tracking
    pub fn record_lock_acquisition(&self, contested: bool, wait_time: Duration) {
        self.inner.lock_acquisitions.fetch_add(1, Ordering::Relaxed);
        if contested {
            self.inner.lock_contentions.fetch_add(1, Ordering::Relaxed);
            self.inner
                .lock_wait_time_us
                .fetch_add(wait_time.as_micros() as u64, Ordering::Relaxed);
        }
    }

    /// Get current snapshot of metrics
    pub fn snapshot(&self) -> MetricsSnapshot {
        let uptime = self.inner.start_time.elapsed();

        MetricsSnapshot {
            uptime_secs: uptime.as_secs(),
            total_allocations: self.inner.total_allocations.load(Ordering::Relaxed),
            total_deallocations: self.inner.total_deallocations.load(Ordering::Relaxed),
            total_bytes_allocated: self.inner.total_bytes_allocated.load(Ordering::Relaxed),
            current_bytes: self.inner.current_bytes.load(Ordering::Relaxed),
            peak_bytes: self.inner.peak_bytes.load(Ordering::Relaxed),
            events_enqueued: self.inner.events_enqueued.load(Ordering::Relaxed),
            events_dequeued: self.inner.events_dequeued.load(Ordering::Relaxed),
            events_dropped: self.inner.events_dropped.load(Ordering::Relaxed),
            process_cpu_time_ms: self.inner.process_cpu_time_us.load(Ordering::Relaxed) / 1000,
            network_cpu_time_ms: self.inner.network_cpu_time_us.load(Ordering::Relaxed) / 1000,
            file_cpu_time_ms: self.inner.file_cpu_time_us.load(Ordering::Relaxed) / 1000,
            dns_cpu_time_ms: self.inner.dns_cpu_time_us.load(Ordering::Relaxed) / 1000,
            registry_cpu_time_ms: self.inner.registry_cpu_time_us.load(Ordering::Relaxed) / 1000,
            lock_acquisitions: self.inner.lock_acquisitions.load(Ordering::Relaxed),
            lock_contentions: self.inner.lock_contentions.load(Ordering::Relaxed),
            lock_wait_time_ms: self.inner.lock_wait_time_us.load(Ordering::Relaxed) / 1000,
        }
    }

    /// Reset all metrics
    pub fn reset(&self) {
        self.inner.total_allocations.store(0, Ordering::Relaxed);
        self.inner.total_deallocations.store(0, Ordering::Relaxed);
        self.inner.total_bytes_allocated.store(0, Ordering::Relaxed);
        self.inner.current_bytes.store(0, Ordering::Relaxed);
        self.inner.peak_bytes.store(0, Ordering::Relaxed);
        self.inner.events_enqueued.store(0, Ordering::Relaxed);
        self.inner.events_dequeued.store(0, Ordering::Relaxed);
        self.inner.events_dropped.store(0, Ordering::Relaxed);
        self.inner.process_cpu_time_us.store(0, Ordering::Relaxed);
        self.inner.network_cpu_time_us.store(0, Ordering::Relaxed);
        self.inner.file_cpu_time_us.store(0, Ordering::Relaxed);
        self.inner.dns_cpu_time_us.store(0, Ordering::Relaxed);
        self.inner.registry_cpu_time_us.store(0, Ordering::Relaxed);
        self.inner.lock_acquisitions.store(0, Ordering::Relaxed);
        self.inner.lock_contentions.store(0, Ordering::Relaxed);
        self.inner.lock_wait_time_us.store(0, Ordering::Relaxed);
    }
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub uptime_secs: u64,
    pub total_allocations: usize,
    pub total_deallocations: usize,
    pub total_bytes_allocated: u64,
    pub current_bytes: u64,
    pub peak_bytes: u64,
    pub events_enqueued: u64,
    pub events_dequeued: u64,
    pub events_dropped: u64,
    pub process_cpu_time_ms: u64,
    pub network_cpu_time_ms: u64,
    pub file_cpu_time_ms: u64,
    pub dns_cpu_time_ms: u64,
    pub registry_cpu_time_ms: u64,
    pub lock_acquisitions: u64,
    pub lock_contentions: u64,
    pub lock_wait_time_ms: u64,
}

impl MetricsSnapshot {
    /// Calculate allocation rate (per second)
    pub fn allocation_rate(&self) -> f64 {
        if self.uptime_secs == 0 {
            0.0
        } else {
            self.total_allocations as f64 / self.uptime_secs as f64
        }
    }

    /// Calculate event throughput (events per second)
    pub fn event_throughput(&self) -> f64 {
        if self.uptime_secs == 0 {
            0.0
        } else {
            self.events_dequeued as f64 / self.uptime_secs as f64
        }
    }

    /// Calculate event drop rate (percentage)
    pub fn event_drop_rate(&self) -> f64 {
        if self.events_enqueued == 0 {
            0.0
        } else {
            (self.events_dropped as f64 / self.events_enqueued as f64) * 100.0
        }
    }

    /// Calculate lock contention rate (percentage)
    pub fn lock_contention_rate(&self) -> f64 {
        if self.lock_acquisitions == 0 {
            0.0
        } else {
            (self.lock_contentions as f64 / self.lock_acquisitions as f64) * 100.0
        }
    }

    /// Calculate average lock wait time (milliseconds)
    pub fn avg_lock_wait_time(&self) -> f64 {
        if self.lock_contentions == 0 {
            0.0
        } else {
            self.lock_wait_time_ms as f64 / self.lock_contentions as f64
        }
    }

    /// Get total CPU time across all collectors
    pub fn total_cpu_time_ms(&self) -> u64 {
        self.process_cpu_time_ms
            + self.network_cpu_time_ms
            + self.file_cpu_time_ms
            + self.dns_cpu_time_ms
            + self.registry_cpu_time_ms
    }

    /// Format as human-readable string
    pub fn format(&self) -> String {
        format!(
            "Performance Metrics:\n\
             Uptime: {}s\n\
             Memory: current={:.2}MB, peak={:.2}MB, allocated={:.2}MB\n\
             Allocations: {}, rate={:.2}/s\n\
             Events: enqueued={}, dequeued={}, dropped={} ({:.2}%)\n\
             Throughput: {:.2} events/s\n\
             CPU Time: process={}ms, network={}ms, file={}ms, dns={}ms, registry={}ms (total={}ms)\n\
             Locks: acquisitions={}, contentions={} ({:.2}%), avg_wait={:.2}ms",
            self.uptime_secs,
            self.current_bytes as f64 / (1024.0 * 1024.0),
            self.peak_bytes as f64 / (1024.0 * 1024.0),
            self.total_bytes_allocated as f64 / (1024.0 * 1024.0),
            self.total_allocations,
            self.allocation_rate(),
            self.events_enqueued,
            self.events_dequeued,
            self.events_dropped,
            self.event_drop_rate(),
            self.event_throughput(),
            self.process_cpu_time_ms,
            self.network_cpu_time_ms,
            self.file_cpu_time_ms,
            self.dns_cpu_time_ms,
            self.registry_cpu_time_ms,
            self.total_cpu_time_ms(),
            self.lock_acquisitions,
            self.lock_contentions,
            self.lock_contention_rate(),
            self.avg_lock_wait_time(),
        )
    }
}

/// RAII guard for timing operations
pub struct TimingGuard<'a> {
    metrics: &'a PerformanceMetrics,
    collector: String,
    start: Instant,
}

impl<'a> TimingGuard<'a> {
    pub fn new(metrics: &'a PerformanceMetrics, collector: impl Into<String>) -> Self {
        Self {
            metrics,
            collector: collector.into(),
            start: Instant::now(),
        }
    }
}

impl<'a> Drop for TimingGuard<'a> {
    fn drop(&mut self) {
        let duration = self.start.elapsed();
        self.metrics
            .record_collector_cpu_time(&self.collector, duration);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_memory_metrics() {
        let metrics = PerformanceMetrics::new();

        metrics.record_allocation(1024);
        metrics.record_allocation(2048);
        metrics.record_deallocation(512);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.total_allocations, 2);
        assert_eq!(snapshot.total_deallocations, 1);
        assert_eq!(snapshot.current_bytes, 3072 - 512);
        assert_eq!(snapshot.peak_bytes, 3072);
    }

    #[test]
    fn test_queue_metrics() {
        let metrics = PerformanceMetrics::new();

        for _ in 0..10 {
            metrics.record_event_enqueued();
        }

        for _ in 0..8 {
            metrics.record_event_dequeued();
        }

        for _ in 0..2 {
            metrics.record_event_dropped();
        }

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.events_enqueued, 10);
        assert_eq!(snapshot.events_dequeued, 8);
        assert_eq!(snapshot.events_dropped, 2);
        assert_eq!(snapshot.event_drop_rate(), 20.0);
    }

    #[test]
    fn test_cpu_time() {
        let metrics = PerformanceMetrics::new();

        metrics.record_collector_cpu_time("process", Duration::from_millis(100));
        metrics.record_collector_cpu_time("network", Duration::from_millis(50));

        let snapshot = metrics.snapshot();
        assert!(snapshot.process_cpu_time_ms >= 100);
        assert!(snapshot.network_cpu_time_ms >= 50);
        assert!(snapshot.total_cpu_time_ms() >= 150);
    }

    #[test]
    fn test_lock_contention() {
        let metrics = PerformanceMetrics::new();

        metrics.record_lock_acquisition(false, Duration::from_micros(10));
        metrics.record_lock_acquisition(true, Duration::from_millis(5));
        metrics.record_lock_acquisition(true, Duration::from_millis(3));

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.lock_acquisitions, 3);
        assert_eq!(snapshot.lock_contentions, 2);
        assert_eq!(snapshot.lock_contention_rate(), 200.0 / 3.0);
    }

    #[test]
    fn test_timing_guard() {
        let metrics = PerformanceMetrics::new();

        {
            let _guard = TimingGuard::new(&metrics, "process");
            thread::sleep(Duration::from_millis(10));
        }

        let snapshot = metrics.snapshot();
        assert!(snapshot.process_cpu_time_ms >= 10);
    }

    #[test]
    fn test_metrics_reset() {
        let metrics = PerformanceMetrics::new();

        metrics.record_allocation(1024);
        metrics.record_event_enqueued();

        let snapshot = metrics.snapshot();
        assert!(snapshot.total_allocations > 0);

        metrics.reset();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.total_allocations, 0);
        assert_eq!(snapshot.events_enqueued, 0);
    }

    #[test]
    fn test_snapshot_format() {
        let metrics = PerformanceMetrics::new();
        metrics.record_allocation(1024 * 1024);
        metrics.record_event_enqueued();
        metrics.record_event_dequeued();

        let snapshot = metrics.snapshot();
        let formatted = snapshot.format();
        assert!(formatted.contains("Performance Metrics"));
        assert!(formatted.contains("Uptime"));
        assert!(formatted.contains("Memory"));
    }
}
