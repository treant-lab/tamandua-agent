// Lock Contention Profiling
//
// Tracks mutex and RwLock contention:
// - Lock acquisition time
// - Lock hold time
// - Contention statistics
// - Deadlock detection hints

use anyhow::Result;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Lock profiler implementation
pub struct LockProfiler {
    stats: Arc<RwLock<HashMap<String, LockContentionStats>>>,
}

impl LockProfiler {
    /// Create a new lock profiler
    pub fn new() -> Result<Self> {
        Ok(Self {
            stats: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Start lock profiling
    pub fn start(&mut self) -> Result<()> {
        info!("Starting lock contention profiler");
        Ok(())
    }

    /// Stop lock profiling
    pub fn stop(&mut self) -> Result<()> {
        info!("Stopping lock contention profiler");
        Ok(())
    }

    /// Record lock acquisition
    pub fn record_acquisition(&self, lock_name: &str, wait_time: Duration, hold_time: Duration) {
        let mut stats = self.stats.write();
        let entry = stats.entry(lock_name.to_string()).or_insert_with(LockContentionStats::default);

        entry.acquisitions += 1;
        entry.total_wait_time += wait_time;
        entry.total_hold_time += hold_time;

        if wait_time > entry.max_wait_time {
            entry.max_wait_time = wait_time;
        }

        if hold_time > entry.max_hold_time {
            entry.max_hold_time = hold_time;
        }
    }

    /// Get lock statistics
    pub fn stats(&self) -> LockStats {
        let stats = self.stats.read();
        LockStats {
            locks: stats.clone(),
        }
    }
}

/// Lock contention statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LockContentionStats {
    pub acquisitions: u64,
    pub total_wait_time: Duration,
    pub total_hold_time: Duration,
    pub max_wait_time: Duration,
    pub max_hold_time: Duration,
}

impl LockContentionStats {
    /// Average wait time
    pub fn avg_wait_time(&self) -> Duration {
        if self.acquisitions == 0 {
            Duration::ZERO
        } else {
            self.total_wait_time / self.acquisitions as u32
        }
    }

    /// Average hold time
    pub fn avg_hold_time(&self) -> Duration {
        if self.acquisitions == 0 {
            Duration::ZERO
        } else {
            self.total_hold_time / self.acquisitions as u32
        }
    }
}

/// Lock statistics snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockStats {
    pub locks: HashMap<String, LockContentionStats>,
}

/// Profiled lock guard
pub struct ProfiledLockGuard<T> {
    lock_name: String,
    start: Instant,
    acquired_at: Instant,
    profiler: Arc<LockProfiler>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> ProfiledLockGuard<T> {
    pub fn new(lock_name: String, profiler: Arc<LockProfiler>, start: Instant) -> Self {
        Self {
            lock_name,
            start,
            acquired_at: Instant::now(),
            profiler,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T> Drop for ProfiledLockGuard<T> {
    fn drop(&mut self) {
        let wait_time = self.acquired_at.duration_since(self.start);
        let hold_time = self.acquired_at.elapsed();
        self.profiler.record_acquisition(&self.lock_name, wait_time, hold_time);
    }
}

/// Global lock profiler
static GLOBAL_LOCK_PROFILER: once_cell::sync::OnceCell<Arc<LockProfiler>> = once_cell::sync::OnceCell::new();

/// Initialize global lock profiler
pub fn init_global_lock_profiler() -> Result<()> {
    let profiler = LockProfiler::new()?;
    GLOBAL_LOCK_PROFILER.get_or_init(|| Arc::new(profiler));
    Ok(())
}

/// Get global lock profiler
pub fn global_lock_profiler() -> Option<Arc<LockProfiler>> {
    GLOBAL_LOCK_PROFILER.get().cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lock_profiler() {
        let profiler = LockProfiler::new().unwrap();
        profiler.record_acquisition("test_lock", Duration::from_millis(10), Duration::from_millis(5));

        let stats = profiler.stats();
        assert_eq!(stats.locks.get("test_lock").unwrap().acquisitions, 1);
    }

    #[test]
    fn test_lock_stats_averages() {
        let mut stats = LockContentionStats::default();
        stats.acquisitions = 2;
        stats.total_wait_time = Duration::from_millis(20);
        stats.total_hold_time = Duration::from_millis(10);

        assert_eq!(stats.avg_wait_time(), Duration::from_millis(10));
        assert_eq!(stats.avg_hold_time(), Duration::from_millis(5));
    }
}
