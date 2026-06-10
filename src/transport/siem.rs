//! SIEM/Log Forwarding Integration Module
//!
//! Provides configurable log forwarding to various SIEM platforms:
//! - Syslog (RFC 5424, CEF, LEEF)
//! - Splunk (HTTP Event Collector)
//! - Elastic/ELK (Bulk API, Filebeat JSON)
//! - Microsoft Sentinel (Log Analytics API, DCR)
//! - QRadar (LEEF, Universal DSM)
//! - CrowdStrike Falcon LogScale (HEC)
//! - Generic Webhook

use crate::collectors::{EventType, Severity, TelemetryEvent};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error, info, warn};

// ============================================================================
// Configuration Types
// ============================================================================

/// SIEM forwarder configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemConfig {
    /// Enable SIEM forwarding
    pub enabled: bool,

    /// Destinations to forward to
    pub destinations: Vec<DestinationConfig>,

    /// Global event filtering
    #[serde(default)]
    pub global_filters: EventFilters,

    /// Local queue settings
    #[serde(default)]
    pub queue: QueueConfig,

    /// Compression settings
    #[serde(default)]
    pub compression: CompressionConfig,

    /// Field mapping configuration
    #[serde(default)]
    pub field_mapping: FieldMappingConfig,
}

impl Default for SiemConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            destinations: Vec::new(),
            global_filters: EventFilters::default(),
            queue: QueueConfig::default(),
            compression: CompressionConfig::default(),
            field_mapping: FieldMappingConfig::default(),
        }
    }
}

/// Destination configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestinationConfig {
    /// Unique destination identifier
    pub id: String,

    /// Destination type
    pub destination_type: DestinationType,

    /// Enable this destination
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Destination-specific event filters
    #[serde(default)]
    pub filters: EventFilters,

    /// Batch settings for this destination
    #[serde(default)]
    pub batch: BatchConfig,

    /// Retry settings
    #[serde(default)]
    pub retry: RetryConfig,
}

fn default_true() -> bool {
    true
}

/// Destination types with their specific configurations
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DestinationType {
    /// Syslog (RFC 5424) output
    Syslog(SyslogConfig),
    /// Splunk HTTP Event Collector
    Splunk(SplunkConfig),
    /// Elasticsearch/ELK
    Elastic(ElasticConfig),
    /// Microsoft Sentinel
    Sentinel(SentinelConfig),
    /// IBM QRadar
    QRadar(QRadarConfig),
    /// CrowdStrike Falcon LogScale (Humio)
    FalconLogScale(FalconLogScaleConfig),
    /// Generic Webhook
    Webhook(WebhookConfig),
}

/// Event filters for routing
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventFilters {
    /// Include only these event types (empty = all)
    #[serde(default)]
    pub include_event_types: Vec<String>,

    /// Exclude these event types
    #[serde(default)]
    pub exclude_event_types: Vec<String>,

    /// Minimum severity level
    #[serde(default)]
    pub min_severity: Option<String>,

    /// Only include events with detections
    #[serde(default)]
    pub detections_only: bool,
}

/// Queue configuration for delivery guarantees
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueConfig {
    /// Maximum queue size in events
    pub max_size: usize,

    /// Persist queue to disk
    pub persistent: bool,

    /// Disk queue path
    pub path: Option<String>,

    /// Flush interval in milliseconds
    pub flush_interval_ms: u64,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            max_size: 10000,
            persistent: false,
            path: None,
            flush_interval_ms: 1000,
        }
    }
}

/// Batch configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchConfig {
    /// Maximum batch size in events
    pub max_events: usize,

    /// Maximum batch size in bytes
    pub max_bytes: usize,

    /// Maximum wait time in milliseconds
    pub max_wait_ms: u64,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_events: 100,
            max_bytes: 1024 * 1024, // 1MB
            max_wait_ms: 5000,
        }
    }
}

/// Retry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum retry attempts
    pub max_attempts: u32,

    /// Initial retry delay in milliseconds
    pub initial_delay_ms: u64,

    /// Maximum retry delay in milliseconds
    pub max_delay_ms: u64,

    /// Exponential backoff multiplier
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay_ms: 1000,
            max_delay_ms: 30000,
            backoff_multiplier: 2.0,
        }
    }
}

/// Compression configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionConfig {
    /// Enable compression
    pub enabled: bool,

    /// Compression algorithm
    pub algorithm: CompressionAlgorithm,

    /// Compression level (1-9)
    pub level: u32,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            algorithm: CompressionAlgorithm::Gzip,
            level: 6,
        }
    }
}

/// Compression algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CompressionAlgorithm {
    Gzip,
    Zstd,
    Lz4,
}

/// Field mapping configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldMappingConfig {
    /// Normalization schema
    pub schema: NormalizationSchema,

    /// Custom field mappings
    #[serde(default)]
    pub custom_mappings: HashMap<String, String>,

    /// Timestamp format
    pub timestamp_format: TimestampFormat,
}

impl Default for FieldMappingConfig {
    fn default() -> Self {
        Self {
            schema: NormalizationSchema::Native,
            custom_mappings: HashMap::new(),
            timestamp_format: TimestampFormat::Iso8601,
        }
    }
}

/// Normalization schemas
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NormalizationSchema {
    /// No normalization (native format)
    Native,
    /// Elastic Common Schema
    Ecs,
    /// Open Cybersecurity Schema Framework
    Ocsf,
}

/// Timestamp formats
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampFormat {
    Iso8601,
    UnixMs,
    UnixSec,
    Rfc3339,
    Custom(String),
}

// ============================================================================
// Syslog Configuration
// ============================================================================

/// Syslog configuration (RFC 5424)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyslogConfig {
    /// Syslog server host
    pub host: String,

    /// Syslog server port
    pub port: u16,

    /// Transport protocol
    pub transport: SyslogTransport,

    /// Message format
    pub format: SyslogFormat,

    /// Syslog facility
    #[serde(default = "default_syslog_facility")]
    pub facility: u8,

    /// Application name
    #[serde(default = "default_app_name")]
    pub app_name: String,

    /// TLS configuration for TCP/TLS
    #[serde(default)]
    pub tls: Option<SyslogTlsConfig>,
}

fn default_syslog_facility() -> u8 {
    1 // LOG_USER
}

fn default_app_name() -> String {
    "tamandua-agent".to_string()
}

/// Syslog transport protocols
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SyslogTransport {
    #[default]
    Udp,
    Tcp,
    Tls,
}

/// Syslog message formats
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SyslogFormat {
    /// RFC 5424 format
    Rfc5424,
    /// Common Event Format (ArcSight)
    Cef,
    /// Log Event Extended Format (QRadar)
    Leef,
}

/// Syslog TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyslogTlsConfig {
    /// Skip certificate verification
    pub skip_verify: bool,

    /// CA certificate path
    pub ca_path: Option<String>,

    /// Client certificate path
    pub cert_path: Option<String>,

    /// Client key path
    pub key_path: Option<String>,
}

// ============================================================================
// Splunk Configuration
// ============================================================================

/// Splunk HTTP Event Collector configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplunkConfig {
    /// HEC endpoint URL
    pub url: String,

    /// HEC token
    pub token: String,

    /// Default index
    #[serde(default)]
    pub index: Option<String>,

    /// Source
    #[serde(default)]
    pub source: Option<String>,

    /// Sourcetype
    #[serde(default)]
    pub sourcetype: Option<String>,

    /// Index routing rules
    #[serde(default)]
    pub index_routing: HashMap<String, String>,

    /// Skip TLS verification
    #[serde(default)]
    pub skip_verify: bool,

    /// Raw mode (bypass JSON parsing)
    #[serde(default)]
    pub raw_mode: bool,
}

// ============================================================================
// Elasticsearch Configuration
// ============================================================================

/// Elasticsearch/ELK configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElasticConfig {
    /// Elasticsearch URLs (for failover)
    pub urls: Vec<String>,

    /// Authentication
    #[serde(default)]
    pub auth: Option<ElasticAuth>,

    /// Index name pattern (supports date placeholders)
    #[serde(default = "default_elastic_index")]
    pub index: String,

    /// Output format
    #[serde(default)]
    pub format: ElasticFormat,

    /// Index template name
    #[serde(default)]
    pub template_name: Option<String>,

    /// Skip TLS verification
    #[serde(default)]
    pub skip_verify: bool,

    /// Use data streams
    #[serde(default)]
    pub use_data_streams: bool,
}

fn default_elastic_index() -> String {
    "tamandua-events-%Y.%m.%d".to_string()
}

/// Elasticsearch authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ElasticAuth {
    Basic { username: String, password: String },
    ApiKey { id: String, api_key: String },
    Bearer { token: String },
}

/// Elasticsearch output format
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ElasticFormat {
    /// Bulk API format
    #[default]
    Bulk,
    /// Filebeat-compatible JSON
    Filebeat,
    /// Single document API
    Single,
}

// ============================================================================
// Microsoft Sentinel Configuration
// ============================================================================

/// Microsoft Sentinel configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelConfig {
    /// Log Analytics Workspace ID
    pub workspace_id: String,

    /// Shared key (primary or secondary)
    pub shared_key: String,

    /// Custom log table name
    #[serde(default = "default_sentinel_table")]
    pub table_name: String,

    /// Use DCR-based ingestion
    #[serde(default)]
    pub use_dcr: bool,

    /// DCR endpoint (for DCR-based ingestion)
    #[serde(default)]
    pub dcr_endpoint: Option<String>,

    /// DCR ID
    #[serde(default)]
    pub dcr_id: Option<String>,

    /// Azure AD tenant ID (for DCR)
    #[serde(default)]
    pub tenant_id: Option<String>,

    /// Azure AD client ID (for DCR)
    #[serde(default)]
    pub client_id: Option<String>,

    /// Azure AD client secret (for DCR)
    #[serde(default)]
    pub client_secret: Option<String>,
}

fn default_sentinel_table() -> String {
    "TamanduaEvents_CL".to_string()
}

// ============================================================================
// QRadar Configuration
// ============================================================================

/// IBM QRadar configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QRadarConfig {
    /// QRadar syslog host
    pub host: String,

    /// QRadar syslog port
    #[serde(default = "default_qradar_port")]
    pub port: u16,

    /// Transport protocol
    #[serde(default)]
    pub transport: SyslogTransport,

    /// Log source identifier
    #[serde(default = "default_qradar_source")]
    pub log_source_identifier: String,

    /// Device vendor (for LEEF)
    #[serde(default = "default_vendor")]
    pub device_vendor: String,

    /// Device product (for LEEF)
    #[serde(default = "default_product")]
    pub device_product: String,

    /// Device version
    #[serde(default = "default_version")]
    pub device_version: String,
}

fn default_qradar_port() -> u16 {
    514
}

fn default_qradar_source() -> String {
    "tamandua-agent".to_string()
}

fn default_vendor() -> String {
    "Tamandua".to_string()
}

fn default_product() -> String {
    "EDR Agent".to_string()
}

fn default_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// ============================================================================
// Falcon LogScale (Humio) Configuration
// ============================================================================

/// CrowdStrike Falcon LogScale configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalconLogScaleConfig {
    /// Ingest endpoint URL
    pub url: String,

    /// Ingest token
    pub token: String,

    /// Parser to use
    #[serde(default)]
    pub parser: Option<String>,

    /// Tags to add
    #[serde(default)]
    pub tags: HashMap<String, String>,

    /// Skip TLS verification
    #[serde(default)]
    pub skip_verify: bool,
}

// ============================================================================
// Webhook Configuration
// ============================================================================

/// Generic webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Webhook URL
    pub url: String,

    /// HTTP method
    #[serde(default = "default_http_method")]
    pub method: String,

    /// Custom headers
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// Authentication
    #[serde(default)]
    pub auth: Option<WebhookAuth>,

    /// Payload template (Go template syntax)
    #[serde(default)]
    pub template: Option<String>,

    /// Content type
    #[serde(default = "default_content_type")]
    pub content_type: String,

    /// Skip TLS verification
    #[serde(default)]
    pub skip_verify: bool,

    /// Timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

fn default_http_method() -> String {
    "POST".to_string()
}

fn default_content_type() -> String {
    "application/json".to_string()
}

fn default_timeout() -> u64 {
    30
}

/// Webhook authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WebhookAuth {
    Basic { username: String, password: String },
    Bearer { token: String },
    ApiKey { header: String, key: String },
}

// ============================================================================
// Event Formatting
// ============================================================================

/// Formatted event for SIEM output
#[derive(Debug, Clone, Serialize)]
struct FormattedEvent {
    /// Original event
    #[serde(flatten)]
    event: TelemetryEvent,

    /// Agent hostname
    agent_hostname: String,

    /// Agent ID
    agent_id: String,

    /// Formatted timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    formatted_timestamp: Option<String>,
}

/// Event formatter for different SIEM formats
pub struct EventFormatter {
    agent_id: String,
    hostname: String,
    config: FieldMappingConfig,
}

impl EventFormatter {
    pub fn new(agent_id: String, hostname: String, config: FieldMappingConfig) -> Self {
        Self {
            agent_id,
            hostname,
            config,
        }
    }

    /// Format event to JSON
    pub fn to_json(&self, event: &TelemetryEvent) -> Result<String> {
        let formatted = FormattedEvent {
            event: event.clone(),
            agent_hostname: self.hostname.clone(),
            agent_id: self.agent_id.clone(),
            formatted_timestamp: Some(self.format_timestamp(event.timestamp)),
        };

        match self.config.schema {
            NormalizationSchema::Native => {
                serde_json::to_string(&formatted).context("Failed to serialize event to JSON")
            }
            NormalizationSchema::Ecs => self.to_ecs(event),
            NormalizationSchema::Ocsf => self.to_ocsf(event),
        }
    }

    /// Format timestamp according to configuration
    fn format_timestamp(&self, timestamp_ms: u64) -> String {
        match &self.config.timestamp_format {
            TimestampFormat::Iso8601 | TimestampFormat::Rfc3339 => {
                let datetime = chrono::DateTime::from_timestamp_millis(timestamp_ms as i64)
                    .unwrap_or_else(|| chrono::Utc::now());
                datetime.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
            }
            TimestampFormat::UnixMs => timestamp_ms.to_string(),
            TimestampFormat::UnixSec => (timestamp_ms / 1000).to_string(),
            TimestampFormat::Custom(fmt) => {
                let datetime = chrono::DateTime::from_timestamp_millis(timestamp_ms as i64)
                    .unwrap_or_else(|| chrono::Utc::now());
                datetime.format(fmt).to_string()
            }
        }
    }

    /// Convert to Elastic Common Schema (ECS)
    fn to_ecs(&self, event: &TelemetryEvent) -> Result<String> {
        let mut ecs = serde_json::json!({
            "@timestamp": self.format_timestamp(event.timestamp),
            "event": {
                "id": event.event_id,
                "kind": "event",
                "category": self.event_type_to_ecs_category(&event.event_type),
                "type": self.event_type_to_ecs_type(&event.event_type),
                "severity": self.severity_to_number(&event.severity),
                "original": serde_json::to_string(&event.payload)?,
            },
            "agent": {
                "id": self.agent_id,
                "name": "tamandua-agent",
                "type": "edr",
                "version": env!("CARGO_PKG_VERSION"),
            },
            "host": {
                "hostname": self.hostname,
            },
            "tamandua": {
                "event_type": format!("{:?}", event.event_type),
                "severity": format!("{:?}", event.severity),
                "detections": event.detections,
                "metadata": event.metadata,
            }
        });

        // Add payload-specific ECS fields
        self.add_ecs_payload_fields(&mut ecs, event)?;

        serde_json::to_string(&ecs).context("Failed to serialize ECS event")
    }

    fn add_ecs_payload_fields(
        &self,
        ecs: &mut serde_json::Value,
        event: &TelemetryEvent,
    ) -> Result<()> {
        use crate::collectors::EventPayload;

        match &event.payload {
            EventPayload::Process(p) => {
                ecs["process"] = serde_json::json!({
                    "pid": p.pid,
                    "parent": { "pid": p.ppid },
                    "name": p.name,
                    "executable": p.path,
                    "command_line": p.cmdline,
                    "hash": { "sha256": hex::encode(&p.sha256) },
                });
                ecs["user"] = serde_json::json!({ "name": p.user });
            }
            EventPayload::File(f) => {
                ecs["file"] = serde_json::json!({
                    "path": f.path,
                    "hash": { "sha256": hex::encode(&f.sha256) },
                    "size": f.size,
                    "type": f.file_type,
                });
                ecs["process"] = serde_json::json!({
                    "pid": f.pid,
                    "name": f.process_name,
                });
            }
            EventPayload::Network(n) => {
                ecs["source"] = serde_json::json!({
                    "ip": n.local_ip,
                    "port": n.local_port,
                });
                ecs["destination"] = serde_json::json!({
                    "ip": n.remote_ip,
                    "port": n.remote_port,
                });
                ecs["network"] = serde_json::json!({
                    "transport": n.protocol.to_lowercase(),
                    "direction": n.direction,
                });
                ecs["process"] = serde_json::json!({
                    "pid": n.pid,
                    "name": n.process_name,
                });
            }
            EventPayload::Dns(d) => {
                ecs["dns"] = serde_json::json!({
                    "question": {
                        "name": d.query,
                        "type": d.query_type,
                    },
                    "answers": d.responses.iter().map(|r| serde_json::json!({"data": r})).collect::<Vec<_>>(),
                });
                ecs["process"] = serde_json::json!({
                    "pid": d.pid,
                    "name": d.process_name,
                });
            }
            EventPayload::Registry(r) => {
                ecs["registry"] = serde_json::json!({
                    "path": r.key_path,
                    "value": r.value_name,
                    "data": { "strings": r.value_data },
                });
                ecs["process"] = serde_json::json!({
                    "pid": r.pid,
                    "name": r.process_name,
                });
            }
            _ => {}
        }

        Ok(())
    }

    fn event_type_to_ecs_category(&self, event_type: &EventType) -> Vec<&'static str> {
        match event_type {
            EventType::ProcessCreate | EventType::ProcessTerminate | EventType::ProcessInject => {
                vec!["process"]
            }
            EventType::FileCreate
            | EventType::FileModify
            | EventType::FileDelete
            | EventType::FileRename
            | EventType::FileExecute => vec!["file"],
            EventType::NetworkConnect | EventType::NetworkListen | EventType::NetworkClose => {
                vec!["network"]
            }
            EventType::DnsQuery => vec!["network"],
            EventType::RegistryCreate | EventType::RegistrySetValue | EventType::RegistryDelete => {
                vec!["registry"]
            }
            EventType::AuthLogin | EventType::AuthLogout | EventType::AuthFailed => {
                vec!["authentication"]
            }
            EventType::HoneyfileAccess => vec!["intrusion_detection"],
            EventType::DriverLoad | EventType::ModuleLoad => vec!["driver"],
            _ => vec!["host"],
        }
    }

    fn event_type_to_ecs_type(&self, event_type: &EventType) -> Vec<&'static str> {
        match event_type {
            EventType::ProcessCreate => vec!["start"],
            EventType::ProcessTerminate => vec!["end"],
            EventType::FileCreate => vec!["creation"],
            EventType::FileModify => vec!["change"],
            EventType::FileDelete => vec!["deletion"],
            EventType::NetworkConnect => vec!["connection", "start"],
            EventType::NetworkClose => vec!["connection", "end"],
            EventType::AuthLogin => vec!["start"],
            EventType::AuthLogout => vec!["end"],
            EventType::AuthFailed => vec!["start"],
            _ => vec!["info"],
        }
    }

    fn severity_to_number(&self, severity: &Severity) -> u8 {
        match severity {
            Severity::Info => 1,
            Severity::Low => 3,
            Severity::Medium => 5,
            Severity::High => 7,
            Severity::Critical => 9,
        }
    }

    /// Convert to OCSF format
    fn to_ocsf(&self, event: &TelemetryEvent) -> Result<String> {
        let ocsf = serde_json::json!({
            "metadata": {
                "version": "1.0.0",
                "product": {
                    "name": "Tamandua EDR",
                    "vendor_name": "Tamandua",
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "uid": event.event_id,
            },
            "time": event.timestamp,
            "severity_id": self.severity_to_ocsf(&event.severity),
            "severity": format!("{:?}", event.severity),
            "class_uid": self.event_type_to_ocsf_class(&event.event_type),
            "type_uid": self.event_type_to_ocsf_type(&event.event_type),
            "activity_id": 1,
            "status": "Success",
            "device": {
                "hostname": self.hostname,
                "agent_list": [{
                    "name": "tamandua-agent",
                    "uid": self.agent_id,
                    "type": "EDR",
                    "version": env!("CARGO_PKG_VERSION"),
                }],
            },
            "unmapped": {
                "tamandua_payload": event.payload,
                "tamandua_detections": event.detections,
                "tamandua_metadata": event.metadata,
            },
        });

        serde_json::to_string(&ocsf).context("Failed to serialize OCSF event")
    }

    fn severity_to_ocsf(&self, severity: &Severity) -> u8 {
        match severity {
            Severity::Info => 1,
            Severity::Low => 2,
            Severity::Medium => 3,
            Severity::High => 4,
            Severity::Critical => 5,
        }
    }

    fn event_type_to_ocsf_class(&self, event_type: &EventType) -> u32 {
        match event_type {
            EventType::ProcessCreate | EventType::ProcessTerminate => 1007, // Process Activity
            EventType::FileCreate | EventType::FileModify | EventType::FileDelete => 1001, // File Activity
            EventType::NetworkConnect | EventType::NetworkListen => 4001, // Network Activity
            EventType::DnsQuery => 4003,                                  // DNS Activity
            EventType::RegistryCreate | EventType::RegistrySetValue => 201001, // Registry Activity
            EventType::AuthLogin | EventType::AuthLogout | EventType::AuthFailed => 3001, // Authentication
            _ => 1, // Base Event
        }
    }

    fn event_type_to_ocsf_type(&self, event_type: &EventType) -> u32 {
        match event_type {
            EventType::ProcessCreate => 100701,
            EventType::ProcessTerminate => 100702,
            EventType::FileCreate => 100101,
            EventType::FileModify => 100102,
            EventType::FileDelete => 100104,
            _ => 0,
        }
    }

    /// Format to RFC 5424 syslog
    pub fn to_rfc5424(
        &self,
        event: &TelemetryEvent,
        facility: u8,
        app_name: &str,
    ) -> Result<String> {
        let priority = facility * 8 + self.severity_to_syslog(&event.severity);
        let timestamp = self.format_timestamp(event.timestamp);
        let msg = self.to_json(event)?;

        Ok(format!(
            "<{}>1 {} {} {} - {} - {}",
            priority, timestamp, self.hostname, app_name, event.event_id, msg
        ))
    }

    /// Format to CEF (Common Event Format)
    pub fn to_cef(&self, event: &TelemetryEvent) -> Result<String> {
        let severity = self.severity_to_cef(&event.severity);
        let name = format!("{:?}", event.event_type);
        let event_id = self.event_type_to_cef_id(&event.event_type);

        let mut extensions = vec![
            format!("rt={}", event.timestamp),
            format!("dhost={}", self.hostname),
            format!("eventId={}", event.event_id),
        ];

        // Add payload-specific extensions
        self.add_cef_extensions(&mut extensions, event);

        Ok(format!(
            "CEF:0|Tamandua|EDR Agent|{}|{}|{}|{}|{}",
            env!("CARGO_PKG_VERSION"),
            event_id,
            name,
            severity,
            extensions.join(" ")
        ))
    }

    fn add_cef_extensions(&self, ext: &mut Vec<String>, event: &TelemetryEvent) {
        use crate::collectors::EventPayload;

        match &event.payload {
            EventPayload::Process(p) => {
                ext.push(format!("sproc={}", p.name));
                ext.push(format!("spid={}", p.pid));
                ext.push(format!("suser={}", p.user));
                ext.push(format!("filePath={}", p.path.replace('\\', "\\\\")));
                ext.push(format!("cs1={}", p.cmdline.replace('=', "\\=")));
                ext.push(format!("cs1Label=CommandLine"));
                ext.push(format!("fileHash={}", hex::encode(&p.sha256)));
            }
            EventPayload::File(f) => {
                ext.push(format!("fname={}", f.path.replace('\\', "\\\\")));
                ext.push(format!("fsize={}", f.size));
                ext.push(format!("fileHash={}", hex::encode(&f.sha256)));
                ext.push(format!("sproc={}", f.process_name));
                ext.push(format!("spid={}", f.pid));
            }
            EventPayload::Network(n) => {
                ext.push(format!("src={}", n.local_ip));
                ext.push(format!("spt={}", n.local_port));
                ext.push(format!("dst={}", n.remote_ip));
                ext.push(format!("dpt={}", n.remote_port));
                ext.push(format!("proto={}", n.protocol));
                ext.push(format!("sproc={}", n.process_name));
                ext.push(format!("spid={}", n.pid));
            }
            EventPayload::Dns(d) => {
                ext.push(format!("dhost={}", d.query));
                ext.push(format!("cs2={}", d.query_type));
                ext.push(format!("cs2Label=QueryType"));
                ext.push(format!("sproc={}", d.process_name));
                ext.push(format!("spid={}", d.pid));
            }
            _ => {}
        }
    }

    fn event_type_to_cef_id(&self, event_type: &EventType) -> u32 {
        match event_type {
            EventType::ProcessCreate => 1001,
            EventType::ProcessTerminate => 1002,
            EventType::ProcessInject => 1003,
            EventType::FileCreate => 2001,
            EventType::FileModify => 2002,
            EventType::FileDelete => 2003,
            EventType::FileRename => 2004,
            EventType::FileExecute => 2005,
            EventType::NetworkConnect => 3001,
            EventType::NetworkListen => 3002,
            EventType::NetworkClose => 3003,
            EventType::DnsQuery => 4001,
            EventType::RegistryCreate => 5001,
            EventType::RegistrySetValue => 5002,
            EventType::RegistryDelete => 5003,
            EventType::HoneyfileAccess => 9001,
            _ => 9999,
        }
    }

    fn severity_to_syslog(&self, severity: &Severity) -> u8 {
        match severity {
            Severity::Info => 6,     // Informational
            Severity::Low => 5,      // Notice
            Severity::Medium => 4,   // Warning
            Severity::High => 3,     // Error
            Severity::Critical => 2, // Critical
        }
    }

    fn severity_to_cef(&self, severity: &Severity) -> u8 {
        match severity {
            Severity::Info => 1,
            Severity::Low => 3,
            Severity::Medium => 5,
            Severity::High => 8,
            Severity::Critical => 10,
        }
    }

    /// Format to LEEF (Log Event Extended Format)
    pub fn to_leef(
        &self,
        event: &TelemetryEvent,
        vendor: &str,
        product: &str,
        version: &str,
    ) -> Result<String> {
        let event_id = format!("{:?}", event.event_type);

        let mut attrs = vec![
            format!("devTime={}", self.format_timestamp(event.timestamp)),
            format!("devTimeFormat=yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"),
            format!("cat={:?}", event.event_type),
            format!("sev={}", self.severity_to_leef(&event.severity)),
            format!("identHostName={}", self.hostname),
        ];

        // Add payload-specific attributes
        self.add_leef_attributes(&mut attrs, event);

        Ok(format!(
            "LEEF:2.0|{}|{}|{}|{}|{}",
            vendor,
            product,
            version,
            event_id,
            attrs.join("\t")
        ))
    }

    fn add_leef_attributes(&self, attrs: &mut Vec<String>, event: &TelemetryEvent) {
        use crate::collectors::EventPayload;

        match &event.payload {
            EventPayload::Process(p) => {
                attrs.push(format!("srcProcName={}", p.name));
                attrs.push(format!("srcProcId={}", p.pid));
                attrs.push(format!("usrName={}", p.user));
                attrs.push(format!("srcFilePath={}", p.path));
                attrs.push(format!("srcCmdLine={}", p.cmdline));
                attrs.push(format!("srcFileHash={}", hex::encode(&p.sha256)));
            }
            EventPayload::File(f) => {
                attrs.push(format!("fileName={}", f.path));
                attrs.push(format!("fileSize={}", f.size));
                attrs.push(format!("fileHash={}", hex::encode(&f.sha256)));
                attrs.push(format!("srcProcName={}", f.process_name));
                attrs.push(format!("srcProcId={}", f.pid));
            }
            EventPayload::Network(n) => {
                attrs.push(format!("src={}", n.local_ip));
                attrs.push(format!("srcPort={}", n.local_port));
                attrs.push(format!("dst={}", n.remote_ip));
                attrs.push(format!("dstPort={}", n.remote_port));
                attrs.push(format!("proto={}", n.protocol));
                attrs.push(format!("srcProcName={}", n.process_name));
                attrs.push(format!("srcProcId={}", n.pid));
            }
            EventPayload::Dns(d) => {
                attrs.push(format!("domain={}", d.query));
                attrs.push(format!("queryType={}", d.query_type));
                attrs.push(format!("srcProcName={}", d.process_name));
                attrs.push(format!("srcProcId={}", d.pid));
            }
            _ => {}
        }
    }

    fn severity_to_leef(&self, severity: &Severity) -> u8 {
        match severity {
            Severity::Info => 1,
            Severity::Low => 3,
            Severity::Medium => 5,
            Severity::High => 7,
            Severity::Critical => 10,
        }
    }

    /// Format for Splunk HEC
    pub fn to_splunk_hec(&self, event: &TelemetryEvent, config: &SplunkConfig) -> Result<String> {
        let index = config
            .index_routing
            .get(&format!("{:?}", event.event_type))
            .or(config.index.as_ref());

        let hec_event = serde_json::json!({
            "time": event.timestamp / 1000, // Splunk expects seconds
            "host": self.hostname,
            "source": config.source.as_deref().unwrap_or("tamandua-agent"),
            "sourcetype": config.sourcetype.as_deref().unwrap_or("tamandua:events"),
            "index": index,
            "event": {
                "event_id": event.event_id,
                "event_type": format!("{:?}", event.event_type),
                "severity": format!("{:?}", event.severity),
                "timestamp": event.timestamp,
                "payload": event.payload,
                "detections": event.detections,
                "metadata": event.metadata,
                "agent_id": self.agent_id,
            }
        });

        serde_json::to_string(&hec_event).context("Failed to serialize Splunk HEC event")
    }

    /// Format for Elasticsearch bulk API
    pub fn to_elastic_bulk(&self, events: &[TelemetryEvent], index: &str) -> Result<String> {
        let mut lines = Vec::new();
        let index_name = self.expand_index_name(index);

        for event in events {
            // Action line
            let action = serde_json::json!({
                "index": {
                    "_index": index_name,
                    "_id": event.event_id,
                }
            });
            lines.push(serde_json::to_string(&action)?);

            // Document line
            let doc = match self.config.schema {
                NormalizationSchema::Ecs => serde_json::from_str(&self.to_ecs(event)?)?,
                _ => serde_json::json!({
                    "@timestamp": self.format_timestamp(event.timestamp),
                    "event_id": event.event_id,
                    "event_type": format!("{:?}", event.event_type),
                    "severity": format!("{:?}", event.severity),
                    "payload": event.payload,
                    "detections": event.detections,
                    "metadata": event.metadata,
                    "agent": {
                        "id": self.agent_id,
                        "hostname": self.hostname,
                    }
                }),
            };
            lines.push(serde_json::to_string(&doc)?);
        }

        // Bulk format requires newline after each line, including the last one
        Ok(lines.join("\n") + "\n")
    }

    fn expand_index_name(&self, pattern: &str) -> String {
        let now = chrono::Utc::now();
        pattern
            .replace("%Y", &now.format("%Y").to_string())
            .replace("%m", &now.format("%m").to_string())
            .replace("%d", &now.format("%d").to_string())
    }

    /// Format for Microsoft Sentinel Log Analytics
    pub fn to_sentinel(&self, events: &[TelemetryEvent]) -> Result<String> {
        let records: Vec<serde_json::Value> = events
            .iter()
            .map(|event| {
                serde_json::json!({
                    "TimeGenerated": self.format_timestamp(event.timestamp),
                    "EventId": event.event_id,
                    "EventType": format!("{:?}", event.event_type),
                    "Severity": format!("{:?}", event.severity),
                    "Payload": serde_json::to_string(&event.payload).unwrap_or_default(),
                    "Detections": serde_json::to_string(&event.detections).unwrap_or_default(),
                    "Metadata": serde_json::to_string(&event.metadata).unwrap_or_default(),
                    "AgentId": self.agent_id,
                    "AgentHostname": self.hostname,
                })
            })
            .collect();

        serde_json::to_string(&records).context("Failed to serialize Sentinel events")
    }

    /// Format for Falcon LogScale
    pub fn to_falcon_logscale(
        &self,
        events: &[TelemetryEvent],
        config: &FalconLogScaleConfig,
    ) -> Result<String> {
        let records: Vec<serde_json::Value> = events
            .iter()
            .map(|event| {
                let mut record = serde_json::json!({
                    "timestamp": event.timestamp,
                    "rawstring": serde_json::to_string(&event).unwrap_or_default(),
                    "kvparse": true,
                    "attributes": {
                        "event_id": event.event_id,
                        "event_type": format!("{:?}", event.event_type),
                        "severity": format!("{:?}", event.severity),
                        "agent_id": self.agent_id,
                        "agent_hostname": self.hostname,
                    }
                });

                // Add tags
                if !config.tags.is_empty() {
                    record["tags"] = serde_json::json!(config.tags);
                }

                // Add parser if specified
                if let Some(parser) = &config.parser {
                    record["parser"] = serde_json::json!(parser);
                }

                record
            })
            .collect();

        serde_json::to_string(&records).context("Failed to serialize Falcon LogScale events")
    }
}

// ============================================================================
// Queue and Delivery System
// ============================================================================

/// Queued event for delivery
#[derive(Debug, Clone)]
pub struct QueuedEvent {
    event: TelemetryEvent,
    destination_id: String,
    #[allow(dead_code)]
    enqueued_at: u64,
    retry_count: u32,
}

/// Local event queue for delivery guarantees
pub struct EventQueue {
    queue: Arc<Mutex<VecDeque<QueuedEvent>>>,
    config: QueueConfig,
}

impl EventQueue {
    pub fn new(config: QueueConfig) -> Self {
        Self {
            queue: Arc::new(Mutex::new(VecDeque::new())),
            config,
        }
    }

    pub async fn enqueue(&self, event: TelemetryEvent, destination_id: &str) -> Result<()> {
        let mut queue = self.queue.lock().await;

        // Check queue size limit
        if queue.len() >= self.config.max_size {
            // Drop oldest event (or could return error for backpressure)
            queue.pop_front();
            warn!("Queue full, dropping oldest event");
        }

        let queued = QueuedEvent {
            event,
            destination_id: destination_id.to_string(),
            enqueued_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            retry_count: 0,
        };

        queue.push_back(queued);
        Ok(())
    }

    pub async fn dequeue_batch(&self, destination_id: &str, max_size: usize) -> Vec<QueuedEvent> {
        let mut queue = self.queue.lock().await;
        let mut batch = Vec::new();

        let mut i = 0;
        while i < queue.len() && batch.len() < max_size {
            if queue[i].destination_id == destination_id {
                if let Some(item) = queue.remove(i) {
                    batch.push(item);
                }
            } else {
                i += 1;
            }
        }

        batch
    }

    pub async fn requeue(&self, mut event: QueuedEvent) -> Result<()> {
        event.retry_count += 1;
        let mut queue = self.queue.lock().await;
        queue.push_front(event);
        Ok(())
    }

    pub async fn len(&self) -> usize {
        self.queue.lock().await.len()
    }
}

// ============================================================================
// SIEM Forwarder
// ============================================================================

/// SIEM forwarder that manages multiple destinations
pub struct SiemForwarder {
    config: SiemConfig,
    formatter: Arc<EventFormatter>,
    queue: Arc<EventQueue>,
    http_client: reqwest::Client,
    running: Arc<RwLock<bool>>,
}

impl SiemForwarder {
    pub fn new(config: SiemConfig, agent_id: String, hostname: String) -> Result<Self> {
        let formatter = Arc::new(EventFormatter::new(
            agent_id,
            hostname,
            config.field_mapping.clone(),
        ));

        let queue = Arc::new(EventQueue::new(config.queue.clone()));

        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(true) // Will be controlled per-destination
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            config,
            formatter,
            queue,
            http_client,
            running: Arc::new(RwLock::new(false)),
        })
    }

    /// Check if SIEM forwarding is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled && !self.config.destinations.is_empty()
    }

    /// Forward events to all configured destinations
    pub async fn forward(&self, events: &[TelemetryEvent]) -> Result<()> {
        if !self.is_enabled() {
            return Ok(());
        }

        for dest in &self.config.destinations {
            if !dest.enabled {
                continue;
            }

            // Filter events for this destination
            let filtered: Vec<_> = events
                .iter()
                .filter(|e| self.should_forward(e, &dest.filters))
                .cloned()
                .collect();

            if filtered.is_empty() {
                continue;
            }

            // Queue events for delivery
            for event in filtered {
                if let Err(e) = self.queue.enqueue(event, &dest.id).await {
                    warn!(destination = %dest.id, error = %e, "Failed to queue event");
                }
            }
        }

        Ok(())
    }

    /// Check if event should be forwarded based on filters
    fn should_forward(&self, event: &TelemetryEvent, filters: &EventFilters) -> bool {
        // Check global filters first
        if !self.passes_filters(event, &self.config.global_filters) {
            return false;
        }

        // Check destination-specific filters
        self.passes_filters(event, filters)
    }

    fn passes_filters(&self, event: &TelemetryEvent, filters: &EventFilters) -> bool {
        let event_type_str = format!("{:?}", event.event_type).to_lowercase();

        // Include filter (if specified, only include these types)
        if !filters.include_event_types.is_empty() {
            if !filters
                .include_event_types
                .iter()
                .any(|t| t.to_lowercase() == event_type_str)
            {
                return false;
            }
        }

        // Exclude filter
        if filters
            .exclude_event_types
            .iter()
            .any(|t| t.to_lowercase() == event_type_str)
        {
            return false;
        }

        // Minimum severity
        if let Some(min_sev) = &filters.min_severity {
            let min_level = self.severity_level(min_sev);
            let event_level = match event.severity {
                Severity::Info => 0,
                Severity::Low => 1,
                Severity::Medium => 2,
                Severity::High => 3,
                Severity::Critical => 4,
            };
            if event_level < min_level {
                return false;
            }
        }

        // Detections only
        if filters.detections_only && event.detections.is_empty() {
            return false;
        }

        true
    }

    fn severity_level(&self, severity: &str) -> u8 {
        match severity.to_lowercase().as_str() {
            "info" => 0,
            "low" => 1,
            "medium" => 2,
            "high" => 3,
            "critical" => 4,
            _ => 0,
        }
    }

    /// Start background delivery tasks
    pub async fn start(&self) -> Result<()> {
        {
            let mut running = self.running.write().await;
            if *running {
                return Ok(());
            }
            *running = true;
        }

        info!(
            "Starting SIEM forwarder with {} destinations",
            self.config.destinations.len()
        );

        for dest in &self.config.destinations {
            if !dest.enabled {
                continue;
            }

            let dest = dest.clone();
            let queue = self.queue.clone();
            let formatter = self.formatter.clone();
            let http_client = self.http_client.clone();
            let running = self.running.clone();
            let flush_interval = self.config.queue.flush_interval_ms;

            tokio::spawn(async move {
                Self::delivery_task(dest, queue, formatter, http_client, running, flush_interval)
                    .await;
            });
        }

        Ok(())
    }

    async fn delivery_task(
        dest: DestinationConfig,
        queue: Arc<EventQueue>,
        formatter: Arc<EventFormatter>,
        http_client: reqwest::Client,
        running: Arc<RwLock<bool>>,
        flush_interval: u64,
    ) {
        let mut interval = tokio::time::interval(Duration::from_millis(flush_interval));

        loop {
            interval.tick().await;

            if !*running.read().await {
                break;
            }

            let batch = queue.dequeue_batch(&dest.id, dest.batch.max_events).await;
            if batch.is_empty() {
                continue;
            }

            let events: Vec<_> = batch.iter().map(|q| q.event.clone()).collect();
            debug!(
                destination = %dest.id,
                count = events.len(),
                "Sending batch to SIEM"
            );

            let result = match &dest.destination_type {
                DestinationType::Syslog(config) => {
                    Self::send_syslog(&events, config, &formatter).await
                }
                DestinationType::Splunk(config) => {
                    Self::send_splunk(&events, config, &formatter, &http_client).await
                }
                DestinationType::Elastic(config) => {
                    Self::send_elastic(&events, config, &formatter, &http_client).await
                }
                DestinationType::Sentinel(config) => {
                    Self::send_sentinel(&events, config, &formatter, &http_client).await
                }
                DestinationType::QRadar(config) => {
                    Self::send_qradar(&events, config, &formatter).await
                }
                DestinationType::FalconLogScale(config) => {
                    Self::send_falcon_logscale(&events, config, &formatter, &http_client).await
                }
                DestinationType::Webhook(config) => {
                    Self::send_webhook(&events, config, &formatter, &http_client).await
                }
            };

            if let Err(e) = result {
                warn!(
                    destination = %dest.id,
                    error = %e,
                    "Failed to send batch to SIEM"
                );

                // Requeue failed events
                for queued in batch {
                    if queued.retry_count < dest.retry.max_attempts {
                        if let Err(e) = queue.requeue(queued).await {
                            error!(error = %e, "Failed to requeue event");
                        }
                    } else {
                        warn!("Event dropped after max retries");
                    }
                }
            } else {
                debug!(
                    destination = %dest.id,
                    count = events.len(),
                    "Successfully sent batch to SIEM"
                );
            }
        }
    }

    // ========================================================================
    // Syslog Sender
    // ========================================================================

    async fn send_syslog(
        events: &[TelemetryEvent],
        config: &SyslogConfig,
        formatter: &EventFormatter,
    ) -> Result<()> {
        match config.transport {
            SyslogTransport::Udp => Self::send_syslog_udp(events, config, formatter).await,
            SyslogTransport::Tcp => Self::send_syslog_tcp(events, config, formatter, false).await,
            SyslogTransport::Tls => Self::send_syslog_tcp(events, config, formatter, true).await,
        }
    }

    async fn send_syslog_udp(
        events: &[TelemetryEvent],
        config: &SyslogConfig,
        formatter: &EventFormatter,
    ) -> Result<()> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let addr = format!("{}:{}", config.host, config.port);

        for event in events {
            let message = match config.format {
                SyslogFormat::Rfc5424 => {
                    formatter.to_rfc5424(event, config.facility, &config.app_name)?
                }
                SyslogFormat::Cef => formatter.to_cef(event)?,
                SyslogFormat::Leef => {
                    formatter.to_leef(event, "Tamandua", "EDR Agent", env!("CARGO_PKG_VERSION"))?
                }
            };

            socket.send_to(message.as_bytes(), &addr).await?;
        }

        Ok(())
    }

    async fn send_syslog_tcp(
        events: &[TelemetryEvent],
        config: &SyslogConfig,
        formatter: &EventFormatter,
        use_tls: bool,
    ) -> Result<()> {
        let addr = format!("{}:{}", config.host, config.port);

        if use_tls {
            // TLS connection
            let tcp_stream = TcpStream::connect(&addr).await?;
            let tls_config = config.tls.as_ref();

            let connector = native_tls::TlsConnector::builder()
                .danger_accept_invalid_certs(tls_config.map_or(false, |c| c.skip_verify))
                .build()?;
            let connector = tokio_native_tls::TlsConnector::from(connector);

            let mut stream = connector.connect(&config.host, tcp_stream).await?;

            for event in events {
                let message = match config.format {
                    SyslogFormat::Rfc5424 => {
                        formatter.to_rfc5424(event, config.facility, &config.app_name)?
                    }
                    SyslogFormat::Cef => formatter.to_cef(event)?,
                    SyslogFormat::Leef => formatter.to_leef(
                        event,
                        "Tamandua",
                        "EDR Agent",
                        env!("CARGO_PKG_VERSION"),
                    )?,
                };

                // Syslog over TCP uses octet counting (RFC 6587)
                let framed = format!("{} {}\n", message.len(), message);
                stream.write_all(framed.as_bytes()).await?;
            }

            stream.flush().await?;
        } else {
            // Plain TCP
            let mut stream = TcpStream::connect(&addr).await?;

            for event in events {
                let message = match config.format {
                    SyslogFormat::Rfc5424 => {
                        formatter.to_rfc5424(event, config.facility, &config.app_name)?
                    }
                    SyslogFormat::Cef => formatter.to_cef(event)?,
                    SyslogFormat::Leef => formatter.to_leef(
                        event,
                        "Tamandua",
                        "EDR Agent",
                        env!("CARGO_PKG_VERSION"),
                    )?,
                };

                let framed = format!("{} {}\n", message.len(), message);
                stream.write_all(framed.as_bytes()).await?;
            }

            stream.flush().await?;
        }

        Ok(())
    }

    // ========================================================================
    // Splunk HEC Sender
    // ========================================================================

    async fn send_splunk(
        events: &[TelemetryEvent],
        config: &SplunkConfig,
        formatter: &EventFormatter,
        client: &reqwest::Client,
    ) -> Result<()> {
        let mut body = String::new();

        for event in events {
            let hec_event = formatter.to_splunk_hec(event, config)?;
            body.push_str(&hec_event);
            body.push('\n');
        }

        let response = client
            .post(&config.url)
            .header("Authorization", format!("Splunk {}", config.token))
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .context("Failed to send to Splunk HEC")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Splunk HEC error: {} - {}", status, body);
        }

        Ok(())
    }

    // ========================================================================
    // Elasticsearch Sender
    // ========================================================================

    async fn send_elastic(
        events: &[TelemetryEvent],
        config: &ElasticConfig,
        formatter: &EventFormatter,
        client: &reqwest::Client,
    ) -> Result<()> {
        let url = format!(
            "{}/_bulk",
            config
                .urls
                .first()
                .context("No Elasticsearch URLs configured")?
        );
        let body = formatter.to_elastic_bulk(events, &config.index)?;

        let mut request = client
            .post(&url)
            .header("Content-Type", "application/x-ndjson");

        // Add authentication
        if let Some(auth) = &config.auth {
            request = match auth {
                ElasticAuth::Basic { username, password } => {
                    request.basic_auth(username, Some(password))
                }
                ElasticAuth::ApiKey { id, api_key } => {
                    let credentials = base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        format!("{}:{}", id, api_key),
                    );
                    request.header("Authorization", format!("ApiKey {}", credentials))
                }
                ElasticAuth::Bearer { token } => request.bearer_auth(token),
            };
        }

        let response = request
            .body(body)
            .send()
            .await
            .context("Failed to send to Elasticsearch")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Elasticsearch error: {} - {}", status, body);
        }

        // Check for partial failures in bulk response
        let resp_body: serde_json::Value = response.json().await?;
        if resp_body
            .get("errors")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            warn!("Elasticsearch bulk request had partial failures");
        }

        Ok(())
    }

    // ========================================================================
    // Microsoft Sentinel Sender
    // ========================================================================

    async fn send_sentinel(
        events: &[TelemetryEvent],
        config: &SentinelConfig,
        formatter: &EventFormatter,
        client: &reqwest::Client,
    ) -> Result<()> {
        if config.use_dcr {
            return Self::send_sentinel_dcr(events, config, formatter, client).await;
        }

        // Log Analytics Data Collector API
        let body = formatter.to_sentinel(events)?;
        let date = chrono::Utc::now()
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();

        // Build signature
        let content_length = body.len();
        let string_to_sign = format!(
            "POST\n{}\napplication/json\nx-ms-date:{}\n/api/logs",
            content_length, date
        );

        let decoded_key = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &config.shared_key,
        )?;

        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(&decoded_key).context("Invalid key length")?;
        mac.update(string_to_sign.as_bytes());
        let signature = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            mac.finalize().into_bytes(),
        );

        let authorization = format!("SharedKey {}:{}", config.workspace_id, signature);

        let url = format!(
            "https://{}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01",
            config.workspace_id
        );

        let response = client
            .post(&url)
            .header("Authorization", authorization)
            .header("Content-Type", "application/json")
            .header("Log-Type", &config.table_name)
            .header("x-ms-date", date)
            .body(body)
            .send()
            .await
            .context("Failed to send to Sentinel")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Sentinel error: {} - {}", status, body);
        }

        Ok(())
    }

    async fn send_sentinel_dcr(
        events: &[TelemetryEvent],
        config: &SentinelConfig,
        formatter: &EventFormatter,
        client: &reqwest::Client,
    ) -> Result<()> {
        // Get OAuth token
        let tenant_id = config
            .tenant_id
            .as_ref()
            .context("tenant_id required for DCR")?;
        let client_id = config
            .client_id
            .as_ref()
            .context("client_id required for DCR")?;
        let client_secret = config
            .client_secret
            .as_ref()
            .context("client_secret required for DCR")?;
        let dcr_endpoint = config
            .dcr_endpoint
            .as_ref()
            .context("dcr_endpoint required for DCR")?;
        let dcr_id = config.dcr_id.as_ref().context("dcr_id required for DCR")?;

        let token_url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            tenant_id
        );

        let token_response = client
            .post(&token_url)
            .form(&[
                ("client_id", client_id.as_str()),
                ("client_secret", client_secret.as_str()),
                ("scope", "https://monitor.azure.com//.default"),
                ("grant_type", "client_credentials"),
            ])
            .send()
            .await
            .context("Failed to get OAuth token")?;

        let token_body: serde_json::Value = token_response.json().await?;
        let access_token = token_body["access_token"]
            .as_str()
            .context("No access token in response")?;

        // Send to DCR endpoint
        let body = formatter.to_sentinel(events)?;
        let url = format!(
            "{}/dataCollectionRules/{}/streams/Custom-{}?api-version=2023-01-01",
            dcr_endpoint, dcr_id, config.table_name
        );

        let response = client
            .post(&url)
            .bearer_auth(access_token)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .context("Failed to send to Sentinel DCR")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Sentinel DCR error: {} - {}", status, body);
        }

        Ok(())
    }

    // ========================================================================
    // QRadar Sender
    // ========================================================================

    async fn send_qradar(
        events: &[TelemetryEvent],
        config: &QRadarConfig,
        formatter: &EventFormatter,
    ) -> Result<()> {
        // QRadar uses LEEF format over syslog
        let syslog_config = SyslogConfig {
            host: config.host.clone(),
            port: config.port,
            transport: config.transport.clone(),
            format: SyslogFormat::Leef,
            facility: 1, // LOG_USER
            app_name: config.log_source_identifier.clone(),
            tls: None,
        };

        // Send as LEEF format
        match config.transport {
            SyslogTransport::Udp => {
                let socket = UdpSocket::bind("0.0.0.0:0").await?;
                let addr = format!("{}:{}", config.host, config.port);

                for event in events {
                    let message = formatter.to_leef(
                        event,
                        &config.device_vendor,
                        &config.device_product,
                        &config.device_version,
                    )?;
                    socket.send_to(message.as_bytes(), &addr).await?;
                }
            }
            _ => {
                // TCP/TLS
                Self::send_syslog_tcp(
                    events,
                    &syslog_config,
                    formatter,
                    matches!(config.transport, SyslogTransport::Tls),
                )
                .await?;
            }
        }

        Ok(())
    }

    // ========================================================================
    // Falcon LogScale Sender
    // ========================================================================

    async fn send_falcon_logscale(
        events: &[TelemetryEvent],
        config: &FalconLogScaleConfig,
        formatter: &EventFormatter,
        client: &reqwest::Client,
    ) -> Result<()> {
        let body = formatter.to_falcon_logscale(events, config)?;

        let response = client
            .post(&config.url)
            .header("Authorization", format!("Bearer {}", config.token))
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .context("Failed to send to Falcon LogScale")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Falcon LogScale error: {} - {}", status, body);
        }

        Ok(())
    }

    // ========================================================================
    // Generic Webhook Sender
    // ========================================================================

    async fn send_webhook(
        events: &[TelemetryEvent],
        config: &WebhookConfig,
        _formatter: &EventFormatter,
        client: &reqwest::Client,
    ) -> Result<()> {
        // Build request body
        let body = if let Some(template) = &config.template {
            // Simple template substitution (could be enhanced with a proper template engine)
            let events_json = serde_json::to_string(events)?;
            template.replace("{{events}}", &events_json)
        } else {
            // Default: send events as JSON array
            serde_json::to_string(
                &events
                    .iter()
                    .map(|e| {
                        serde_json::json!({
                            "event_id": e.event_id,
                            "event_type": format!("{:?}", e.event_type),
                            "timestamp": e.timestamp,
                            "severity": format!("{:?}", e.severity),
                            "payload": e.payload,
                            "detections": e.detections,
                            "metadata": e.metadata,
                        })
                    })
                    .collect::<Vec<_>>(),
            )?
        };

        let mut request = match config.method.to_uppercase().as_str() {
            "POST" => client.post(&config.url),
            "PUT" => client.put(&config.url),
            "PATCH" => client.patch(&config.url),
            _ => client.post(&config.url),
        };

        // Add custom headers
        for (key, value) in &config.headers {
            request = request.header(key, value);
        }

        // Add authentication
        if let Some(auth) = &config.auth {
            request = match auth {
                WebhookAuth::Basic { username, password } => {
                    request.basic_auth(username, Some(password))
                }
                WebhookAuth::Bearer { token } => request.bearer_auth(token),
                WebhookAuth::ApiKey { header, key } => request.header(header, key),
            };
        }

        let response = request
            .header("Content-Type", &config.content_type)
            .timeout(Duration::from_secs(config.timeout_seconds))
            .body(body)
            .send()
            .await
            .context("Failed to send to webhook")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Webhook error: {} - {}", status, body);
        }

        Ok(())
    }

    /// Stop the forwarder
    pub async fn stop(&self) {
        let mut running = self.running.write().await;
        *running = false;
        info!("SIEM forwarder stopped");
    }

    /// Get queue length
    pub async fn queue_len(&self) -> usize {
        self.queue.len().await
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::{EventPayload, ProcessEvent};

    fn create_test_event() -> TelemetryEvent {
        TelemetryEvent {
            event_id: "test-123".to_string(),
            event_type: EventType::ProcessCreate,
            timestamp: 1700000000000,
            severity: Severity::Medium,
            payload: EventPayload::Process(ProcessEvent {
                pid: 1234,
                ppid: 1,
                name: "test.exe".to_string(),
                path: "C:\\test\\test.exe".to_string(),
                cmdline: "test.exe --arg1".to_string(),
                user: "SYSTEM".to_string(),
                sha256: vec![0u8; 32],
                entropy: 5.5,
                is_elevated: false,
                parent_name: Some("parent.exe".to_string()),
                parent_path: Some("C:\\parent.exe".to_string()),
                is_signed: false,
                signer: None,
                start_time: 1700000000000,
                cpu_usage: 0.0,
                memory_bytes: 0,
                company_name: None,
                file_description: None,
                product_name: None,
                file_version: None,
                environment: None,
            }),
            detections: vec![],
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_cef_format() {
        let formatter = EventFormatter::new(
            "agent-123".to_string(),
            "testhost".to_string(),
            FieldMappingConfig::default(),
        );

        let event = create_test_event();
        let cef = formatter.to_cef(&event).unwrap();

        assert!(cef.starts_with("CEF:0|Tamandua|EDR Agent|"));
        assert!(cef.contains("ProcessCreate"));
        assert!(cef.contains("sproc=test.exe"));
        assert!(cef.contains("spid=1234"));
    }

    #[test]
    fn test_leef_format() {
        let formatter = EventFormatter::new(
            "agent-123".to_string(),
            "testhost".to_string(),
            FieldMappingConfig::default(),
        );

        let event = create_test_event();
        let leef = formatter.to_leef(&event, "Tamandua", "EDR", "1.0").unwrap();

        assert!(leef.starts_with("LEEF:2.0|Tamandua|EDR|1.0|"));
        assert!(leef.contains("srcProcName=test.exe"));
        assert!(leef.contains("srcProcId=1234"));
    }

    #[test]
    fn test_rfc5424_format() {
        let formatter = EventFormatter::new(
            "agent-123".to_string(),
            "testhost".to_string(),
            FieldMappingConfig::default(),
        );

        let event = create_test_event();
        let syslog = formatter.to_rfc5424(&event, 1, "tamandua-agent").unwrap();

        assert!(syslog.starts_with("<")); // Priority
        assert!(syslog.contains("testhost"));
        assert!(syslog.contains("tamandua-agent"));
    }

    #[test]
    fn test_ecs_format() {
        let formatter = EventFormatter::new(
            "agent-123".to_string(),
            "testhost".to_string(),
            FieldMappingConfig {
                schema: NormalizationSchema::Ecs,
                ..Default::default()
            },
        );

        let event = create_test_event();
        let ecs = formatter.to_ecs(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&ecs).unwrap();

        assert!(parsed.get("@timestamp").is_some());
        assert!(parsed.get("event").is_some());
        assert!(parsed.get("agent").is_some());
        assert!(parsed.get("process").is_some());
    }

    #[test]
    fn test_event_filters() {
        let forwarder = SiemForwarder::new(
            SiemConfig::default(),
            "agent-123".to_string(),
            "testhost".to_string(),
        )
        .unwrap();

        let event = create_test_event();

        // Default filters should pass
        let filters = EventFilters::default();
        assert!(forwarder.passes_filters(&event, &filters));

        // Include filter
        let filters = EventFilters {
            include_event_types: vec!["ProcessCreate".to_string()],
            ..Default::default()
        };
        assert!(forwarder.passes_filters(&event, &filters));

        // Exclude filter
        let filters = EventFilters {
            exclude_event_types: vec!["ProcessCreate".to_string()],
            ..Default::default()
        };
        assert!(!forwarder.passes_filters(&event, &filters));

        // Min severity
        let filters = EventFilters {
            min_severity: Some("high".to_string()),
            ..Default::default()
        };
        assert!(!forwarder.passes_filters(&event, &filters));
    }
}
