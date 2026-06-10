//! Real-time log forwarding to backend server
//!
//! Captures tracing logs, buffers them, and forwards to the backend
//! via WebSocket for real-time log streaming.

use super::buffer::LogBuffer;
use super::parser::{LogLevel, StructuredLog};
use crate::transport::BackendClient;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

/// Log entry to be forwarded to the backend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Timestamp in milliseconds since epoch
    pub timestamp: u64,
    /// Log level (debug, info, warn, error)
    pub level: String,
    /// Component that generated the log (collector, transport, response, etc.)
    pub component: String,
    /// Log message
    pub message: String,
    /// Structured fields (optional)
    pub fields: Option<serde_json::Value>,
    /// File name
    pub file: Option<String>,
    /// Line number
    pub line: Option<u32>,
    /// Thread name
    pub thread: Option<String>,
}

/// Configuration for log forwarding
#[derive(Debug, Clone)]
pub struct LogForwarderConfig {
    /// Enable log forwarding
    pub enabled: bool,
    /// Minimum log level to forward (debug, info, warn, error)
    pub min_level: LogLevel,
    /// Maximum buffer size (entries)
    pub max_buffer_size: usize,
    /// Batch size for forwarding
    pub batch_size: usize,
    /// Batch timeout in seconds
    pub batch_timeout_secs: u64,
    /// Components to include (empty = all)
    pub include_components: Vec<String>,
    /// Components to exclude
    pub exclude_components: Vec<String>,
}

impl Default for LogForwarderConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_level: LogLevel::Info,
            max_buffer_size: 10_000,
            batch_size: 100,
            batch_timeout_secs: 5,
            include_components: vec![],
            exclude_components: vec![],
        }
    }
}

/// Log forwarder that captures and sends logs to backend
pub struct LogForwarder {
    config: Arc<RwLock<LogForwarderConfig>>,
    buffer: Arc<LogBuffer>,
    tx: mpsc::UnboundedSender<LogEntry>,
}

impl LogForwarder {
    /// Create a new log forwarder
    pub fn new(config: LogForwarderConfig) -> (Self, mpsc::UnboundedReceiver<LogEntry>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let buffer = Arc::new(LogBuffer::new(config.max_buffer_size));

        let forwarder = Self {
            config: Arc::new(RwLock::new(config)),
            buffer,
            tx,
        };

        (forwarder, rx)
    }

    /// Start the log forwarder background task
    pub async fn start(
        config: LogForwarderConfig,
        backend_client: Arc<BackendClient>,
    ) -> Result<()> {
        let (forwarder, mut rx) = Self::new(config.clone());
        let buffer = forwarder.buffer.clone();
        let forwarder_config = forwarder.config.clone();

        // Spawn log collection task
        tokio::spawn(async move {
            while let Some(log_entry) = rx.recv().await {
                buffer.push(log_entry).await;
            }
        });

        // Spawn log forwarding task
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(config.batch_timeout_secs));

            loop {
                ticker.tick().await;

                let config = forwarder_config.read().await;
                if !config.enabled {
                    continue;
                }

                let batch_size = config.batch_size;
                drop(config);

                // Drain logs from buffer
                let logs = buffer.drain(batch_size).await;
                if logs.is_empty() {
                    continue;
                }

                // Send batch to backend
                match Self::forward_batch(&backend_client, &logs).await {
                    Ok(_) => {
                        debug!("Forwarded {} log entries to backend", logs.len());
                    }
                    Err(e) => {
                        warn!("Failed to forward logs: {}", e);
                        // Re-queue logs if send failed
                        for log in logs {
                            buffer.push(log).await;
                        }
                    }
                }
            }
        });

        Ok(())
    }

    /// Forward a batch of logs to the backend
    async fn forward_batch(
        backend_client: &BackendClient,
        logs: &[LogEntry],
    ) -> Result<()> {
        let payload = serde_json::json!({
            "logs": logs,
            "count": logs.len(),
        });

        backend_client.send_logs(payload).await
    }

    /// Create a tracing layer for log capture
    pub fn create_tracing_layer(
        tx: mpsc::UnboundedSender<LogEntry>,
    ) -> LogCaptureLayer {
        LogCaptureLayer { tx }
    }

    /// Update configuration at runtime
    pub async fn update_config(&self, new_config: LogForwarderConfig) {
        let mut config = self.config.write().await;
        *config = new_config;
        info!("Log forwarder configuration updated");
    }

    /// Get current buffer size
    pub async fn buffer_size(&self) -> usize {
        self.buffer.len().await
    }
}

/// Tracing layer that captures logs and forwards them
pub struct LogCaptureLayer {
    tx: mpsc::UnboundedSender<LogEntry>,
}

impl<S> Layer<S> for LogCaptureLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: Context<'_, S>,
    ) {
        // Extract log level
        let level = match *event.metadata().level() {
            tracing::Level::TRACE => "trace",
            tracing::Level::DEBUG => "debug",
            tracing::Level::INFO => "info",
            tracing::Level::WARN => "warn",
            tracing::Level::ERROR => "error",
        };

        // Extract component from target
        let target = event.metadata().target();
        let component = extract_component(target);

        // Extract message and fields
        let mut visitor = LogVisitor::default();
        event.record(&mut visitor);

        let log_entry = LogEntry {
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            level: level.to_string(),
            component,
            message: visitor.message.unwrap_or_else(|| "".to_string()),
            fields: if visitor.fields.is_empty() {
                None
            } else {
                Some(serde_json::json!(visitor.fields))
            },
            file: event.metadata().file().map(|s| s.to_string()),
            line: event.metadata().line(),
            thread: std::thread::current().name().map(|s| s.to_string()),
        };

        // Send to forwarder (non-blocking)
        let _ = self.tx.send(log_entry);
    }
}

/// Extract component name from tracing target
fn extract_component(target: &str) -> String {
    // Extract module name: "tamandua_agent::collectors::process" -> "collectors"
    if let Some(idx) = target.find("::") {
        let parts: Vec<&str> = target[idx + 2..].split("::").collect();
        if !parts.is_empty() {
            return parts[0].to_string();
        }
    }

    // Fallback to full target
    target.to_string()
}

/// Visitor to extract message and fields from tracing events
#[derive(Default)]
struct LogVisitor {
    message: Option<String>,
    fields: std::collections::HashMap<String, serde_json::Value>,
}

impl tracing::field::Visit for LogVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{:?}", value));
        } else {
            self.fields.insert(
                field.name().to_string(),
                serde_json::json!(format!("{:?}", value)),
            );
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        } else {
            self.fields.insert(
                field.name().to_string(),
                serde_json::json!(value),
            );
        }
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::json!(value),
        );
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::json!(value),
        );
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::json!(value),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_component() {
        assert_eq!(extract_component("tamandua_agent::collectors::process"), "collectors");
        assert_eq!(extract_component("tamandua_agent::transport"), "transport");
        assert_eq!(extract_component("unknown"), "unknown");
    }

    #[tokio::test]
    async fn test_log_buffer() {
        let (forwarder, _rx) = LogForwarder::new(LogForwarderConfig::default());

        let log = LogEntry {
            timestamp: 1234567890,
            level: "info".to_string(),
            component: "test".to_string(),
            message: "test message".to_string(),
            fields: None,
            file: None,
            line: None,
            thread: None,
        };

        forwarder.buffer.push(log).await;
        assert_eq!(forwarder.buffer.len().await, 1);

        let logs = forwarder.buffer.drain(10).await;
        assert_eq!(logs.len(), 1);
        assert_eq!(forwarder.buffer.len().await, 0);
    }
}
