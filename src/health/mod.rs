//! Health monitoring module
//!
//! Provides comprehensive health metrics collection for the agent.

pub mod metrics_collector;

pub use metrics_collector::{
    CollectorMetrics, CpuMetrics, DetailedHealthMetrics, DetectionMetrics, DiskInfo, DiskMetrics,
    EnhancedMetricsCollector, ErrorMetrics, ErrorSample, EventProcessingMetrics, MemoryMetrics,
    NetworkMetrics,
};
