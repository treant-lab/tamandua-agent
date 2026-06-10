// Collector Performance Metrics
//
// Tracks per-collector performance:
// - Event processing latency
// - Throughput (events/sec)
// - Error rates
// - Resource usage

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Collector performance metrics
pub struct CollectorMetrics {
    collectors: HashMap<String, CollectorStats>,
}

impl CollectorMetrics {
    pub fn new() -> Self {
        Self {
            collectors: HashMap::new(),
        }
    }

    /// Record timing for a collector
    pub fn record_timing(&mut self, collector_name: &str, duration: Duration) {
        let stats = self.collectors
            .entry(collector_name.to_string())
            .or_insert_with(CollectorStats::default);

        stats.event_count += 1;
        stats.total_duration += duration;

        if duration > stats.max_duration {
            stats.max_duration = duration;
        }

        if stats.min_duration == Duration::ZERO || duration < stats.min_duration {
            stats.min_duration = duration;
        }

        // Update histogram
        let bucket_index = duration_to_bucket_index(duration);
        if bucket_index < stats.histogram.len() {
            stats.histogram[bucket_index] += 1;
        }
    }

    /// Record an error for a collector
    pub fn record_error(&mut self, collector_name: &str) {
        let stats = self.collectors
            .entry(collector_name.to_string())
            .or_insert_with(CollectorStats::default);
        stats.error_count += 1;
    }

    /// Get snapshot of all metrics
    pub fn snapshot(&self) -> CollectorMetricsSnapshot {
        CollectorMetricsSnapshot {
            collectors: self.collectors.clone(),
        }
    }
}

/// Collector statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CollectorStats {
    pub event_count: u64,
    pub error_count: u64,
    pub total_duration: Duration,
    pub min_duration: Duration,
    pub max_duration: Duration,
    pub histogram: Vec<u64>,
}

impl CollectorStats {
    fn default() -> Self {
        Self {
            event_count: 0,
            error_count: 0,
            total_duration: Duration::ZERO,
            min_duration: Duration::ZERO,
            max_duration: Duration::ZERO,
            histogram: vec![0; 10], // 10 buckets
        }
    }

    /// Average duration per event
    pub fn avg_duration(&self) -> Duration {
        if self.event_count == 0 {
            Duration::ZERO
        } else {
            self.total_duration / self.event_count as u32
        }
    }

    /// Error rate (0.0 to 1.0)
    pub fn error_rate(&self) -> f64 {
        if self.event_count == 0 {
            0.0
        } else {
            self.error_count as f64 / self.event_count as f64
        }
    }

    /// Events per second (requires time window tracking)
    pub fn events_per_second(&self) -> f64 {
        if self.total_duration.is_zero() {
            0.0
        } else {
            self.event_count as f64 / self.total_duration.as_secs_f64()
        }
    }

    /// Get percentile from histogram
    pub fn percentile(&self, p: f64) -> Duration {
        if self.event_count == 0 {
            return Duration::ZERO;
        }

        let target_count = (self.event_count as f64 * p) as u64;
        let mut cumulative = 0u64;

        for (i, &count) in self.histogram.iter().enumerate() {
            cumulative += count;
            if cumulative >= target_count {
                return bucket_index_to_duration(i);
            }
        }

        self.max_duration
    }
}

/// Snapshot of collector metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorMetricsSnapshot {
    pub collectors: HashMap<String, CollectorStats>,
}

impl CollectorMetricsSnapshot {
    /// Get top N slowest collectors
    pub fn slowest_collectors(&self, n: usize) -> Vec<(String, Duration)> {
        let mut collectors: Vec<_> = self.collectors
            .iter()
            .map(|(name, stats)| (name.clone(), stats.avg_duration()))
            .collect();

        collectors.sort_by(|a, b| b.1.cmp(&a.1));
        collectors.truncate(n);
        collectors
    }

    /// Get collectors with highest error rates
    pub fn error_prone_collectors(&self, n: usize) -> Vec<(String, f64)> {
        let mut collectors: Vec<_> = self.collectors
            .iter()
            .map(|(name, stats)| (name.clone(), stats.error_rate()))
            .filter(|(_, rate)| *rate > 0.0)
            .collect();

        collectors.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        collectors.truncate(n);
        collectors
    }
}

/// Convert duration to histogram bucket index
fn duration_to_bucket_index(duration: Duration) -> usize {
    let micros = duration.as_micros();

    // Logarithmic buckets
    // 0: < 1ms
    // 1: 1-10ms
    // 2: 10-100ms
    // 3: 100ms-1s
    // 4: 1s-10s
    // 5: 10s+
    match micros {
        0..=999 => 0,
        1_000..=9_999 => 1,
        10_000..=99_999 => 2,
        100_000..=999_999 => 3,
        1_000_000..=9_999_999 => 4,
        _ => 5,
    }
}

/// Convert histogram bucket index to representative duration
fn bucket_index_to_duration(index: usize) -> Duration {
    match index {
        0 => Duration::from_micros(500),
        1 => Duration::from_micros(5_000),
        2 => Duration::from_micros(50_000),
        3 => Duration::from_micros(500_000),
        4 => Duration::from_micros(5_000_000),
        _ => Duration::from_secs(10),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collector_metrics() {
        let mut metrics = CollectorMetrics::new();

        metrics.record_timing("test_collector", Duration::from_millis(10));
        metrics.record_timing("test_collector", Duration::from_millis(20));
        metrics.record_error("test_collector");

        let snapshot = metrics.snapshot();
        let stats = snapshot.collectors.get("test_collector").unwrap();

        assert_eq!(stats.event_count, 2);
        assert_eq!(stats.error_count, 1);
        assert_eq!(stats.avg_duration(), Duration::from_millis(15));
        assert_eq!(stats.error_rate(), 0.5);
    }

    #[test]
    fn test_slowest_collectors() {
        let mut metrics = CollectorMetrics::new();

        metrics.record_timing("fast", Duration::from_millis(1));
        metrics.record_timing("slow", Duration::from_millis(100));
        metrics.record_timing("medium", Duration::from_millis(10));

        let snapshot = metrics.snapshot();
        let slowest = snapshot.slowest_collectors(2);

        assert_eq!(slowest[0].0, "slow");
        assert_eq!(slowest[1].0, "medium");
    }
}
