//! Performance Optimization Module
//!
//! This module provides advanced performance optimizations for the Tamandua EDR agent:
//! - CPU affinity and NUMA-aware core pinning
//! - Lock-free data structures
//! - Zero-copy telemetry serialization
//! - Memory pooling
//! - SIMD optimizations
//! - Jemalloc integration

pub mod allocator;
pub mod config;
pub mod cpu_affinity;
pub mod lockfree_queue;
pub mod memory_pool;
pub mod metrics;
pub mod simd_hash;

#[cfg(test)]
mod integration_test;

#[cfg(test)]
mod example_collector;

pub use config::PerformanceConfig;
pub use cpu_affinity::{set_thread_affinity, CollectorType, CpuAffinity};
pub use lockfree_queue::{LockFreeQueue, TelemetryQueue};
pub use memory_pool::{BufferPool, EventPool};
pub use metrics::PerformanceMetrics;
pub use simd_hash::{hash_file_simd, SimdHasher};

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Global performance optimization state
static PERFORMANCE_ENABLED: AtomicBool = AtomicBool::new(false);

/// Initialize performance optimizations
pub fn initialize(config: &PerformanceConfig) -> anyhow::Result<()> {
    tracing::info!("Initializing performance optimizations");

    if config.use_jemalloc {
        tracing::info!("Jemalloc allocator enabled (configured via global allocator)");
    }

    if config.use_lockfree_queues {
        tracing::info!("Lock-free queues enabled");
    }

    if config.use_simd {
        let simd_available = simd_hash::detect_simd_features();
        tracing::info!(
            "SIMD optimizations: requested={}, available={}",
            config.use_simd,
            simd_available
        );
    }

    if config.use_cpu_affinity {
        tracing::info!(
            "CPU affinity enabled with {} mappings",
            config.cpu_affinity_map.len()
        );
    }

    PERFORMANCE_ENABLED.store(true, Ordering::SeqCst);

    Ok(())
}

/// Check if performance optimizations are enabled
pub fn is_enabled() -> bool {
    PERFORMANCE_ENABLED.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialization() {
        let config = PerformanceConfig::default();
        assert!(initialize(&config).is_ok());
        assert!(is_enabled());
    }
}
