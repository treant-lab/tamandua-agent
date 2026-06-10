//! Prometheus metrics instrumentation for Tamandua EDR Agent
//!
//! This module provides comprehensive metrics collection across all agent components:
//! - Collector metrics (events/sec, processing latency)
//! - Transport metrics (WebSocket connectivity, message rates)
//! - Response action metrics (execution time, success/failure rates)
//! - Resource usage metrics (CPU, memory, disk I/O per collector)
//!
//! Metrics are exposed via HTTP endpoint on port 9090 for Prometheus scraping.

use lazy_static::lazy_static;
use prometheus::{
    register_counter_vec, register_gauge_vec, register_histogram_vec, register_int_counter_vec,
    register_int_gauge_vec, CounterVec, Encoder, GaugeVec, HistogramVec, IntCounterVec,
    IntGaugeVec, TextEncoder,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

pub mod server;

lazy_static! {
    // ============================================================================
    // COLLECTOR METRICS (30+ metrics)
    // ============================================================================

    /// Total number of telemetry events collected by each collector
    /// Labels: collector (process, file, network, dns, registry, etc.)
    pub static ref COLLECTOR_EVENTS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "tamandua_collector_events_total",
        "Total number of telemetry events collected by each collector",
        &["collector"]
    ).unwrap();

    /// Current rate of events per second for each collector
    /// Labels: collector
    pub static ref COLLECTOR_EVENTS_RATE: GaugeVec = register_gauge_vec!(
        "tamandua_collector_events_per_second",
        "Current rate of events per second for each collector",
        &["collector"]
    ).unwrap();

    /// Processing latency histogram for each collector (in seconds)
    /// Labels: collector
    /// Buckets: 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0
    pub static ref COLLECTOR_PROCESSING_DURATION: HistogramVec = register_histogram_vec!(
        "tamandua_collector_processing_duration_seconds",
        "Processing latency histogram for each collector",
        &["collector"],
        vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0]
    ).unwrap();

    /// Number of errors encountered by each collector
    /// Labels: collector, error_type
    pub static ref COLLECTOR_ERRORS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "tamandua_collector_errors_total",
        "Total number of errors encountered by each collector",
        &["collector", "error_type"]
    ).unwrap();

    /// CPU usage percentage for each collector
    /// Labels: collector
    pub static ref COLLECTOR_CPU_USAGE: GaugeVec = register_gauge_vec!(
        "tamandua_collector_cpu_usage_percent",
        "CPU usage percentage for each collector",
        &["collector"]
    ).unwrap();

    /// Memory usage in bytes for each collector
    /// Labels: collector
    pub static ref COLLECTOR_MEMORY_BYTES: GaugeVec = register_gauge_vec!(
        "tamandua_collector_memory_bytes",
        "Memory usage in bytes for each collector",
        &["collector"]
    ).unwrap();

    /// Disk I/O read bytes for each collector
    /// Labels: collector
    pub static ref COLLECTOR_DISK_READ_BYTES: IntCounterVec = register_int_counter_vec!(
        "tamandua_collector_disk_read_bytes_total",
        "Total disk read bytes for each collector",
        &["collector"]
    ).unwrap();

    /// Disk I/O write bytes for each collector
    /// Labels: collector
    pub static ref COLLECTOR_DISK_WRITE_BYTES: IntCounterVec = register_int_counter_vec!(
        "tamandua_collector_disk_write_bytes_total",
        "Total disk write bytes for each collector",
        &["collector"]
    ).unwrap();

    /// Queue depth for buffered events in each collector
    /// Labels: collector
    pub static ref COLLECTOR_QUEUE_DEPTH: IntGaugeVec = register_int_gauge_vec!(
        "tamandua_collector_queue_depth",
        "Queue depth for buffered events in each collector",
        &["collector"]
    ).unwrap();

    /// Number of dropped events due to queue overflow
    /// Labels: collector
    pub static ref COLLECTOR_EVENTS_DROPPED: IntCounterVec = register_int_counter_vec!(
        "tamandua_collector_events_dropped_total",
        "Total number of dropped events due to queue overflow",
        &["collector"]
    ).unwrap();

    /// Collector status (1 = running, 0 = stopped)
    /// Labels: collector
    pub static ref COLLECTOR_STATUS: IntGaugeVec = register_int_gauge_vec!(
        "tamandua_collector_status",
        "Collector status (1 = running, 0 = stopped)",
        &["collector"]
    ).unwrap();

    /// Number of hot-reloads performed for each collector
    /// Labels: collector
    pub static ref COLLECTOR_RELOADS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "tamandua_collector_reloads_total",
        "Total number of hot-reloads performed for each collector",
        &["collector"]
    ).unwrap();

    // ============================================================================
    // TRANSPORT METRICS (15+ metrics)
    // ============================================================================

    /// WebSocket connection status (1 = connected, 0 = disconnected)
    pub static ref TRANSPORT_WEBSOCKET_CONNECTED: IntGaugeVec = register_int_gauge_vec!(
        "tamandua_transport_websocket_connected",
        "WebSocket connection status (1 = connected, 0 = disconnected)",
        &["server"]
    ).unwrap();

    /// Total number of WebSocket reconnection attempts
    /// Labels: server
    pub static ref TRANSPORT_RECONNECTIONS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "tamandua_transport_reconnections_total",
        "Total number of WebSocket reconnection attempts",
        &["server"]
    ).unwrap();

    /// Total messages sent via WebSocket
    /// Labels: message_type (telemetry, heartbeat, command_response)
    pub static ref TRANSPORT_MESSAGES_SENT_TOTAL: IntCounterVec = register_int_counter_vec!(
        "tamandua_transport_messages_sent_total",
        "Total number of messages sent via WebSocket",
        &["message_type"]
    ).unwrap();

    /// Total messages received via WebSocket
    /// Labels: message_type (command, config_update, rule_update)
    pub static ref TRANSPORT_MESSAGES_RECEIVED_TOTAL: IntCounterVec = register_int_counter_vec!(
        "tamandua_transport_messages_received_total",
        "Total number of messages received via WebSocket",
        &["message_type"]
    ).unwrap();

    /// Message send rate (messages per second)
    pub static ref TRANSPORT_SEND_RATE: GaugeVec = register_gauge_vec!(
        "tamandua_transport_send_rate_per_second",
        "Message send rate (messages per second)",
        &["message_type"]
    ).unwrap();

    /// Message receive rate (messages per second)
    pub static ref TRANSPORT_RECEIVE_RATE: GaugeVec = register_gauge_vec!(
        "tamandua_transport_receive_rate_per_second",
        "Message receive rate (messages per second)",
        &["message_type"]
    ).unwrap();

    /// Total bytes sent via WebSocket
    pub static ref TRANSPORT_BYTES_SENT_TOTAL: IntCounterVec = register_int_counter_vec!(
        "tamandua_transport_bytes_sent_total",
        "Total bytes sent via WebSocket",
        &["message_type"]
    ).unwrap();

    /// Total bytes received via WebSocket
    pub static ref TRANSPORT_BYTES_RECEIVED_TOTAL: IntCounterVec = register_int_counter_vec!(
        "tamandua_transport_bytes_received_total",
        "Total bytes received via WebSocket",
        &["message_type"]
    ).unwrap();

    /// Message send latency (time from queue to send)
    /// Labels: message_type
    pub static ref TRANSPORT_SEND_DURATION: HistogramVec = register_histogram_vec!(
        "tamandua_transport_send_duration_seconds",
        "Message send latency (time from queue to send)",
        &["message_type"],
        vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0]
    ).unwrap();

    /// Transport errors by type
    /// Labels: error_type (connection_failed, send_failed, receive_failed, timeout)
    pub static ref TRANSPORT_ERRORS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "tamandua_transport_errors_total",
        "Total number of transport errors by type",
        &["error_type"]
    ).unwrap();

    /// Current WebSocket outbound queue depth
    pub static ref TRANSPORT_QUEUE_DEPTH: IntGaugeVec = register_int_gauge_vec!(
        "tamandua_transport_queue_depth",
        "Current WebSocket outbound queue depth",
        &["queue_type"]
    ).unwrap();

    /// Messages dropped due to queue overflow
    pub static ref TRANSPORT_MESSAGES_DROPPED: IntCounterVec = register_int_counter_vec!(
        "tamandua_transport_messages_dropped_total",
        "Total number of messages dropped due to queue overflow",
        &["message_type"]
    ).unwrap();

    /// WebSocket ping latency
    pub static ref TRANSPORT_PING_DURATION: HistogramVec = register_histogram_vec!(
        "tamandua_transport_ping_duration_seconds",
        "WebSocket ping latency",
        &["server"],
        vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]
    ).unwrap();

    /// Connection uptime in seconds
    pub static ref TRANSPORT_UPTIME_SECONDS: GaugeVec = register_gauge_vec!(
        "tamandua_transport_uptime_seconds",
        "Connection uptime in seconds",
        &["server"]
    ).unwrap();

    // ============================================================================
    // RESPONSE ACTION METRICS (15+ metrics)
    // ============================================================================

    /// Total number of response actions executed
    /// Labels: action_type (kill_process, quarantine_file, isolate_endpoint, etc.)
    pub static ref RESPONSE_ACTIONS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "tamandua_response_actions_total",
        "Total number of response actions executed",
        &["action_type"]
    ).unwrap();

    /// Response actions success count
    /// Labels: action_type
    pub static ref RESPONSE_ACTIONS_SUCCESS: IntCounterVec = register_int_counter_vec!(
        "tamandua_response_actions_success_total",
        "Total number of successful response actions",
        &["action_type"]
    ).unwrap();

    /// Response actions failure count
    /// Labels: action_type, error_type
    pub static ref RESPONSE_ACTIONS_FAILED: IntCounterVec = register_int_counter_vec!(
        "tamandua_response_actions_failed_total",
        "Total number of failed response actions",
        &["action_type", "error_type"]
    ).unwrap();

    /// Response action execution time
    /// Labels: action_type
    pub static ref RESPONSE_ACTION_DURATION: HistogramVec = register_histogram_vec!(
        "tamandua_response_action_duration_seconds",
        "Response action execution time",
        &["action_type"],
        vec![0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0]
    ).unwrap();

    /// Currently executing response actions
    /// Labels: action_type
    pub static ref RESPONSE_ACTIONS_IN_PROGRESS: IntGaugeVec = register_int_gauge_vec!(
        "tamandua_response_actions_in_progress",
        "Number of currently executing response actions",
        &["action_type"]
    ).unwrap();

    /// Total number of processes killed
    pub static ref RESPONSE_PROCESSES_KILLED: IntCounterVec = register_int_counter_vec!(
        "tamandua_response_processes_killed_total",
        "Total number of processes killed",
        &["reason"]
    ).unwrap();

    /// Total number of files quarantined
    pub static ref RESPONSE_FILES_QUARANTINED: IntCounterVec = register_int_counter_vec!(
        "tamandua_response_files_quarantined_total",
        "Total number of files quarantined",
        &["file_type"]
    ).unwrap();

    /// Total number of endpoints isolated
    pub static ref RESPONSE_ENDPOINTS_ISOLATED: IntCounterVec = register_int_counter_vec!(
        "tamandua_response_endpoints_isolated_total",
        "Total number of endpoints isolated",
        &["isolation_type"]
    ).unwrap();

    /// Total number of rollback operations
    pub static ref RESPONSE_ROLLBACKS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "tamandua_response_rollbacks_total",
        "Total number of rollback operations",
        &["rollback_type"]
    ).unwrap();

    /// Files restored from quarantine
    pub static ref RESPONSE_FILES_RESTORED: IntCounterVec = register_int_counter_vec!(
        "tamandua_response_files_restored_total",
        "Total number of files restored from quarantine",
        &["reason"]
    ).unwrap();

    /// Autonomous response actions (no human intervention)
    pub static ref RESPONSE_AUTONOMOUS_ACTIONS: IntCounterVec = register_int_counter_vec!(
        "tamandua_response_autonomous_actions_total",
        "Total number of autonomous response actions",
        &["action_type", "confidence_level"]
    ).unwrap();

    // ============================================================================
    // RESOURCE USAGE METRICS (10+ metrics)
    // ============================================================================

    /// Agent CPU usage percentage
    pub static ref AGENT_CPU_USAGE: GaugeVec = register_gauge_vec!(
        "tamandua_agent_cpu_usage_percent",
        "Agent CPU usage percentage",
        &["component"]
    ).unwrap();

    /// Agent memory usage in bytes
    pub static ref AGENT_MEMORY_BYTES: GaugeVec = register_gauge_vec!(
        "tamandua_agent_memory_bytes",
        "Agent memory usage in bytes",
        &["component"]
    ).unwrap();

    /// Agent disk I/O read bytes
    pub static ref AGENT_DISK_READ_BYTES: IntCounterVec = register_int_counter_vec!(
        "tamandua_agent_disk_read_bytes_total",
        "Total agent disk read bytes",
        &["component"]
    ).unwrap();

    /// Agent disk I/O write bytes
    pub static ref AGENT_DISK_WRITE_BYTES: IntCounterVec = register_int_counter_vec!(
        "tamandua_agent_disk_write_bytes_total",
        "Total agent disk write bytes",
        &["component"]
    ).unwrap();

    /// Agent network bytes sent
    pub static ref AGENT_NETWORK_SENT_BYTES: IntCounterVec = register_int_counter_vec!(
        "tamandua_agent_network_sent_bytes_total",
        "Total agent network bytes sent",
        &["destination"]
    ).unwrap();

    /// Agent network bytes received
    pub static ref AGENT_NETWORK_RECEIVED_BYTES: IntCounterVec = register_int_counter_vec!(
        "tamandua_agent_network_received_bytes_total",
        "Total agent network bytes received",
        &["source"]
    ).unwrap();

    /// Thread count by component
    pub static ref AGENT_THREAD_COUNT: IntGaugeVec = register_int_gauge_vec!(
        "tamandua_agent_thread_count",
        "Number of threads by component",
        &["component"]
    ).unwrap();

    /// File handles open
    pub static ref AGENT_FILE_HANDLES: IntGaugeVec = register_int_gauge_vec!(
        "tamandua_agent_file_handles",
        "Number of open file handles",
        &["component"]
    ).unwrap();

    /// Agent uptime in seconds
    pub static ref AGENT_UPTIME_SECONDS: GaugeVec = register_gauge_vec!(
        "tamandua_agent_uptime_seconds",
        "Agent uptime in seconds",
        &[]
    ).unwrap();

    /// Resource governor throttle events
    /// Labels: collector, reason
    pub static ref AGENT_THROTTLE_EVENTS: IntCounterVec = register_int_counter_vec!(
        "tamandua_agent_throttle_events_total",
        "Total number of resource governor throttle events",
        &["collector", "reason"]
    ).unwrap();

    // ============================================================================
    // DETECTION & ANALYSIS METRICS (15+ metrics)
    // ============================================================================

    /// YARA rule scans performed
    pub static ref YARA_SCANS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "tamandua_yara_scans_total",
        "Total number of YARA scans performed",
        &["scan_type"]
    ).unwrap();

    /// YARA rule matches
    /// Labels: rule_name, severity
    pub static ref YARA_MATCHES_TOTAL: IntCounterVec = register_int_counter_vec!(
        "tamandua_yara_matches_total",
        "Total number of YARA rule matches",
        &["rule_name", "severity"]
    ).unwrap();

    /// YARA scan duration
    pub static ref YARA_SCAN_DURATION: HistogramVec = register_histogram_vec!(
        "tamandua_yara_scan_duration_seconds",
        "YARA scan duration",
        &["scan_type"],
        vec![0.001, 0.01, 0.1, 0.5, 1.0, 5.0, 10.0]
    ).unwrap();

    /// ML inference requests
    pub static ref ML_INFERENCE_TOTAL: IntCounterVec = register_int_counter_vec!(
        "tamandua_ml_inference_total",
        "Total number of ML inference requests",
        &["model_type"]
    ).unwrap();

    /// ML inference latency
    pub static ref ML_INFERENCE_DURATION: HistogramVec = register_histogram_vec!(
        "tamandua_ml_inference_duration_seconds",
        "ML inference latency",
        &["model_type"],
        vec![0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0]
    ).unwrap();

    /// ML predictions by verdict
    /// Labels: verdict (malicious, benign, suspicious)
    pub static ref ML_PREDICTIONS: IntCounterVec = register_int_counter_vec!(
        "tamandua_ml_predictions_total",
        "Total number of ML predictions by verdict",
        &["verdict", "model_type"]
    ).unwrap();

    /// ML confidence scores
    pub static ref ML_CONFIDENCE: HistogramVec = register_histogram_vec!(
        "tamandua_ml_confidence_score",
        "ML prediction confidence scores",
        &["verdict", "model_type"],
        vec![0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
    ).unwrap();

    /// Threat intelligence lookups
    /// Labels: source (virustotal, alienvault, etc.)
    pub static ref THREAT_INTEL_LOOKUPS: IntCounterVec = register_int_counter_vec!(
        "tamandua_threat_intel_lookups_total",
        "Total number of threat intelligence lookups",
        &["source", "indicator_type"]
    ).unwrap();

    /// Threat intelligence hits
    pub static ref THREAT_INTEL_HITS: IntCounterVec = register_int_counter_vec!(
        "tamandua_threat_intel_hits_total",
        "Total number of threat intelligence hits",
        &["source", "indicator_type", "severity"]
    ).unwrap();

    /// Deception events (honeyfile/honeytoken access)
    /// Labels: deception_type
    pub static ref DECEPTION_EVENTS: IntCounterVec = register_int_counter_vec!(
        "tamandua_deception_events_total",
        "Total number of deception events",
        &["deception_type"]
    ).unwrap();

    // ============================================================================
    // AGENT INFO & STATUS METRICS (5+ metrics)
    // ============================================================================

    /// Agent version info (gauge set to 1 with labels)
    /// Labels: version, os, arch
    pub static ref AGENT_INFO: IntGaugeVec = register_int_gauge_vec!(
        "tamandua_agent_info",
        "Agent version and system information",
        &["version", "os", "arch", "agent_id"]
    ).unwrap();

    /// Last successful heartbeat timestamp
    pub static ref AGENT_LAST_HEARTBEAT: GaugeVec = register_gauge_vec!(
        "tamandua_agent_last_heartbeat_timestamp_seconds",
        "Last successful heartbeat timestamp",
        &[]
    ).unwrap();

    /// Config version currently loaded
    pub static ref AGENT_CONFIG_VERSION: IntGaugeVec = register_int_gauge_vec!(
        "tamandua_agent_config_version",
        "Config version currently loaded",
        &["config_type"]
    ).unwrap();

    /// Number of loaded YARA rules
    pub static ref AGENT_YARA_RULES_LOADED: IntGaugeVec = register_int_gauge_vec!(
        "tamandua_agent_yara_rules_loaded",
        "Number of loaded YARA rules",
        &[]
    ).unwrap();

    /// Number of loaded Sigma rules
    pub static ref AGENT_SIGMA_RULES_LOADED: IntGaugeVec = register_int_gauge_vec!(
        "tamandua_agent_sigma_rules_loaded",
        "Number of loaded Sigma rules",
        &[]
    ).unwrap();
}

/// Metrics aggregator for calculating rates and tracking state
pub struct MetricsAggregator {
    start_time: std::time::Instant,
}

impl MetricsAggregator {
    pub fn new() -> Self {
        Self {
            start_time: std::time::Instant::now(),
        }
    }

    /// Update agent uptime metric
    pub fn update_uptime(&self) {
        let uptime = self.start_time.elapsed().as_secs_f64();
        AGENT_UPTIME_SECONDS.with_label_values(&[]).set(uptime);
    }

    /// Record collector event
    pub fn record_collector_event(&self, collector: &str) {
        COLLECTOR_EVENTS_TOTAL
            .with_label_values(&[collector])
            .inc();
    }

    /// Record collector processing time
    pub fn record_collector_duration(&self, collector: &str, duration: f64) {
        COLLECTOR_PROCESSING_DURATION
            .with_label_values(&[collector])
            .observe(duration);
    }

    /// Record collector error
    pub fn record_collector_error(&self, collector: &str, error_type: &str) {
        COLLECTOR_ERRORS_TOTAL
            .with_label_values(&[collector, error_type])
            .inc();
    }

    /// Record transport message sent
    pub fn record_message_sent(&self, message_type: &str, bytes: u64) {
        TRANSPORT_MESSAGES_SENT_TOTAL
            .with_label_values(&[message_type])
            .inc();
        TRANSPORT_BYTES_SENT_TOTAL
            .with_label_values(&[message_type])
            .inc_by(bytes);
    }

    /// Record transport message received
    pub fn record_message_received(&self, message_type: &str, bytes: u64) {
        TRANSPORT_MESSAGES_RECEIVED_TOTAL
            .with_label_values(&[message_type])
            .inc();
        TRANSPORT_BYTES_RECEIVED_TOTAL
            .with_label_values(&[message_type])
            .inc_by(bytes);
    }

    /// Record response action
    pub fn record_response_action(
        &self,
        action_type: &str,
        duration: f64,
        success: bool,
        error_type: Option<&str>,
    ) {
        RESPONSE_ACTIONS_TOTAL
            .with_label_values(&[action_type])
            .inc();

        if success {
            RESPONSE_ACTIONS_SUCCESS
                .with_label_values(&[action_type])
                .inc();
        } else {
            RESPONSE_ACTIONS_FAILED
                .with_label_values(&[action_type, error_type.unwrap_or("unknown")])
                .inc();
        }

        RESPONSE_ACTION_DURATION
            .with_label_values(&[action_type])
            .observe(duration);
    }

    /// Record YARA scan
    pub fn record_yara_scan(&self, scan_type: &str, duration: f64, matches: usize) {
        YARA_SCANS_TOTAL.with_label_values(&[scan_type]).inc();
        YARA_SCAN_DURATION
            .with_label_values(&[scan_type])
            .observe(duration);
    }

    /// Record YARA match
    pub fn record_yara_match(&self, rule_name: &str, severity: &str) {
        YARA_MATCHES_TOTAL
            .with_label_values(&[rule_name, severity])
            .inc();
    }

    /// Record ML inference
    pub fn record_ml_inference(
        &self,
        model_type: &str,
        duration: f64,
        verdict: &str,
        confidence: f64,
    ) {
        ML_INFERENCE_TOTAL.with_label_values(&[model_type]).inc();
        ML_INFERENCE_DURATION
            .with_label_values(&[model_type])
            .observe(duration);
        ML_PREDICTIONS
            .with_label_values(&[verdict, model_type])
            .inc();
        ML_CONFIDENCE
            .with_label_values(&[verdict, model_type])
            .observe(confidence);
    }

    /// Gather all metrics for Prometheus export
    pub fn gather(&self) -> anyhow::Result<String> {
        let encoder = TextEncoder::new();
        let metric_families = prometheus::gather();
        let mut buffer = Vec::new();
        encoder
            .encode(&metric_families, &mut buffer)
            .map_err(|e| anyhow::anyhow!("Failed to encode metrics: {}", e))?;
        String::from_utf8(buffer)
            .map_err(|e| anyhow::anyhow!("Failed to convert metrics to UTF-8: {}", e))
    }
}

impl Default for MetricsAggregator {
    fn default() -> Self {
        Self::new()
    }
}

/// Global metrics instance
pub static METRICS: once_cell::sync::Lazy<Arc<RwLock<MetricsAggregator>>> =
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(MetricsAggregator::new())));

/// Initialize metrics subsystem
pub async fn init_metrics(agent_id: &str, version: &str) -> anyhow::Result<()> {
    info!("Initializing Prometheus metrics instrumentation");

    // Set agent info metric
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    AGENT_INFO
        .with_label_values(&[version, os, arch, agent_id])
        .set(1);

    // Initialize collector status metrics (all stopped initially)
    for collector in &[
        "process",
        "file",
        "network",
        "dns",
        "registry",
        "etw",
        "ebpf",
        "memory",
        "injection",
        "persistence",
        "firmware",
        "container",
        "cloud",
    ] {
        COLLECTOR_STATUS.with_label_values(&[collector]).set(0);
    }

    info!("Prometheus metrics initialized successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_initialization() {
        let result = init_metrics("test-agent-123", "0.1.0").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_collector_metrics() {
        let aggregator = MetricsAggregator::new();
        aggregator.record_collector_event("process");
        aggregator.record_collector_duration("process", 0.015);
        aggregator.record_collector_error("process", "permission_denied");

        let metrics = aggregator.gather().unwrap();
        assert!(metrics.contains("tamandua_collector_events_total"));
        assert!(metrics.contains("tamandua_collector_processing_duration_seconds"));
    }

    #[tokio::test]
    async fn test_transport_metrics() {
        let aggregator = MetricsAggregator::new();
        aggregator.record_message_sent("telemetry", 1024);
        aggregator.record_message_received("command", 256);

        let metrics = aggregator.gather().unwrap();
        assert!(metrics.contains("tamandua_transport_messages_sent_total"));
        assert!(metrics.contains("tamandua_transport_bytes_sent_total"));
    }

    #[tokio::test]
    async fn test_response_metrics() {
        let aggregator = MetricsAggregator::new();
        aggregator.record_response_action("kill_process", 0.5, true, None);
        aggregator.record_response_action("quarantine_file", 1.2, false, Some("access_denied"));

        let metrics = aggregator.gather().unwrap();
        assert!(metrics.contains("tamandua_response_actions_total"));
        assert!(metrics.contains("tamandua_response_action_duration_seconds"));
    }

    #[tokio::test]
    async fn test_yara_metrics() {
        let aggregator = MetricsAggregator::new();
        aggregator.record_yara_scan("file", 0.25, 2);
        aggregator.record_yara_match("emotet_payload", "critical");

        let metrics = aggregator.gather().unwrap();
        assert!(metrics.contains("tamandua_yara_scans_total"));
        assert!(metrics.contains("tamandua_yara_matches_total"));
    }

    #[tokio::test]
    async fn test_ml_metrics() {
        let aggregator = MetricsAggregator::new();
        aggregator.record_ml_inference("malware_smell", 0.15, "malicious", 0.95);

        let metrics = aggregator.gather().unwrap();
        assert!(metrics.contains("tamandua_ml_inference_total"));
        assert!(metrics.contains("tamandua_ml_confidence_score"));
    }
}
