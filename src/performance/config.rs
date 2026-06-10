//! Performance configuration

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Performance optimization configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Enable CPU affinity for collectors
    #[serde(default = "default_true")]
    pub use_cpu_affinity: bool,

    /// CPU affinity mapping: collector -> core(s)
    #[serde(default)]
    pub cpu_affinity_map: HashMap<String, CpuAffinityMapping>,

    /// Enable jemalloc allocator
    #[serde(default = "default_true")]
    pub use_jemalloc: bool,

    /// Enable lock-free queues
    #[serde(default = "default_true")]
    pub use_lockfree_queues: bool,

    /// Enable SIMD optimizations
    #[serde(default = "default_true")]
    pub use_simd: bool,

    /// Event pool size (pre-allocated events)
    #[serde(default = "default_pool_size")]
    pub event_pool_size: usize,

    /// Buffer pool size (I/O buffers)
    #[serde(default = "default_buffer_pool_size")]
    pub buffer_pool_size: usize,

    /// Telemetry queue capacity
    #[serde(default = "default_queue_capacity")]
    pub telemetry_queue_capacity: usize,

    /// Enable zero-copy serialization
    #[serde(default = "default_true")]
    pub zero_copy_serialization: bool,

    /// Enable performance metrics collection
    #[serde(default = "default_true")]
    pub enable_metrics: bool,
}

/// CPU affinity mapping for a collector
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CpuAffinityMapping {
    /// Single core
    Single(usize),
    /// Multiple cores
    Multiple(Vec<usize>),
}

impl CpuAffinityMapping {
    pub fn cores(&self) -> Vec<usize> {
        match self {
            CpuAffinityMapping::Single(core) => vec![*core],
            CpuAffinityMapping::Multiple(cores) => cores.clone(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_pool_size() -> usize {
    1024
}

fn default_buffer_pool_size() -> usize {
    512
}

fn default_queue_capacity() -> usize {
    10000
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        let mut cpu_affinity_map = HashMap::new();

        // Default CPU affinity mappings
        cpu_affinity_map.insert("process".to_string(), CpuAffinityMapping::Single(0));
        cpu_affinity_map.insert("network".to_string(), CpuAffinityMapping::Single(1));
        cpu_affinity_map.insert("file".to_string(), CpuAffinityMapping::Multiple(vec![2, 3]));
        cpu_affinity_map.insert("dns".to_string(), CpuAffinityMapping::Single(4));
        cpu_affinity_map.insert("registry".to_string(), CpuAffinityMapping::Single(5));

        Self {
            use_cpu_affinity: true,
            cpu_affinity_map,
            use_jemalloc: true,
            use_lockfree_queues: true,
            use_simd: true,
            event_pool_size: 1024,
            buffer_pool_size: 512,
            telemetry_queue_capacity: 10000,
            zero_copy_serialization: true,
            enable_metrics: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = PerformanceConfig::default();
        assert!(config.use_cpu_affinity);
        assert!(config.use_jemalloc);
        assert!(config.use_lockfree_queues);
        assert!(config.use_simd);
        assert_eq!(config.event_pool_size, 1024);
    }

    #[test]
    fn test_cpu_affinity_mapping() {
        let single = CpuAffinityMapping::Single(2);
        assert_eq!(single.cores(), vec![2]);

        let multiple = CpuAffinityMapping::Multiple(vec![2, 3, 4]);
        assert_eq!(multiple.cores(), vec![2, 3, 4]);
    }
}
