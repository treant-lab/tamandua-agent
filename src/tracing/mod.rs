//! OpenTelemetry distributed tracing for Tamandua Agent
//!
//! This module provides:
//! - OTLP/gRPC exporter to Jaeger
//! - Trace context propagation via WebSocket headers
//! - Sampling strategy (always sample errors, 1% success)
//! - Span creation for all major operations

use anyhow::Result;
use opentelemetry::{
    global,
    trace::{FutureExt, SpanKind, TraceContextExt, Tracer, TracerProvider as _},
    Context, KeyValue,
};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    runtime,
    trace::{RandomIdGenerator, Sampler, TracerProvider},
    Resource,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Tracing configuration
#[derive(Debug, Clone, Deserialize)]
pub struct TracingConfig {
    /// Enable distributed tracing
    pub enabled: bool,
    /// OTLP exporter endpoint (e.g., "http://localhost:4317")
    pub otlp_endpoint: String,
    /// Service name for traces
    pub service_name: String,
    /// Service version
    pub service_version: String,
    /// Sample rate for successful operations (0.0-1.0)
    pub sample_rate_success: f64,
    /// Always sample errors
    pub always_sample_errors: bool,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            otlp_endpoint: "http://localhost:4317".to_string(),
            service_name: "tamandua-agent".to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            sample_rate_success: 0.01, // 1% sampling for success
            always_sample_errors: true,
        }
    }
}

/// Trace context for cross-service propagation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceContext {
    /// Trace ID (hex string)
    pub trace_id: String,
    /// Span ID (hex string)
    pub span_id: String,
    /// Trace flags (01 = sampled, 00 = not sampled)
    pub trace_flags: String,
}

impl TraceContext {
    /// Create from current OpenTelemetry context
    pub fn from_current() -> Option<Self> {
        let context = Context::current();
        let span = context.span();
        let span_context = span.span_context();

        if span_context.is_valid() {
            Some(Self {
                trace_id: format!("{:032x}", span_context.trace_id()),
                span_id: format!("{:016x}", span_context.span_id()),
                trace_flags: format!("{:02x}", span_context.trace_flags()),
            })
        } else {
            None
        }
    }

    /// Create traceparent header value (W3C Trace Context format)
    /// Format: 00-<trace-id>-<span-id>-<trace-flags>
    pub fn to_traceparent(&self) -> String {
        format!("00-{}-{}-{}", self.trace_id, self.span_id, self.trace_flags)
    }

    /// Parse from traceparent header
    pub fn from_traceparent(traceparent: &str) -> Option<Self> {
        let parts: Vec<&str> = traceparent.split('-').collect();
        if parts.len() != 4 || parts[0] != "00" {
            return None;
        }

        Some(Self {
            trace_id: parts[1].to_string(),
            span_id: parts[2].to_string(),
            trace_flags: parts[3].to_string(),
        })
    }

    /// Inject into headers map
    pub fn inject_headers(&self, headers: &mut HashMap<String, String>) {
        headers.insert("traceparent".to_string(), self.to_traceparent());
    }
}

/// Initialize OpenTelemetry tracing
pub fn init_tracing(config: &TracingConfig, agent_id: String) -> Result<()> {
    if !config.enabled {
        info!("Distributed tracing disabled");
        return Ok(());
    }

    info!(
        "Initializing distributed tracing: endpoint={}, service={}, sample_rate={}",
        config.otlp_endpoint, config.service_name, config.sample_rate_success
    );

    // The OTLP/OpenTelemetry stack in this branch is version-skewed.
    // Keep the tracing API surface available, but degrade to no-op initialization
    // until the dependency set is aligned.
    let _ = (config, agent_id);
    warn!("Distributed tracing requested, but OTLP exporter is temporarily disabled on this build");
    Ok(())
}

/// Shutdown tracing and flush pending spans
pub fn shutdown_tracing() {
    info!("Shutting down distributed tracing");
    global::shutdown_tracer_provider();
}

/// Create a new span for telemetry collection
#[macro_export]
macro_rules! trace_telemetry {
    ($collector_name:expr) => {{
        use opentelemetry::trace::Tracer;
        let tracer = opentelemetry::global::tracer("tamandua-agent");
        tracer.start(format!("collect_{}", $collector_name))
    }};
}

/// Create a new span for transport operations
#[macro_export]
macro_rules! trace_transport {
    ($operation:expr) => {{
        use opentelemetry::trace::Tracer;
        let tracer = opentelemetry::global::tracer("tamandua-agent");
        tracer.start(format!("transport_{}", $operation))
    }};
}

/// Create a new span for analysis operations
#[macro_export]
macro_rules! trace_analysis {
    ($analyzer:expr) => {{
        use opentelemetry::trace::Tracer;
        let tracer = opentelemetry::global::tracer("tamandua-agent");
        tracer.start(format!("analyze_{}", $analyzer))
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_context_serialization() {
        let ctx = TraceContext {
            trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_string(),
            span_id: "00f067aa0ba902b7".to_string(),
            trace_flags: "01".to_string(),
        };

        let traceparent = ctx.to_traceparent();
        assert_eq!(
            traceparent,
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        );

        let parsed = TraceContext::from_traceparent(&traceparent).unwrap();
        assert_eq!(parsed.trace_id, ctx.trace_id);
        assert_eq!(parsed.span_id, ctx.span_id);
        assert_eq!(parsed.trace_flags, ctx.trace_flags);
    }

    #[test]
    fn test_trace_context_inject() {
        let ctx = TraceContext {
            trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_string(),
            span_id: "00f067aa0ba902b7".to_string(),
            trace_flags: "01".to_string(),
        };

        let mut headers = HashMap::new();
        ctx.inject_headers(&mut headers);

        assert!(headers.contains_key("traceparent"));
        assert_eq!(
            headers.get("traceparent").unwrap(),
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        );
    }
}
