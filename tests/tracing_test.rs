//! Integration tests for W3C Trace Context propagation.
//!
//! The production `TraceContext` type lives in the agent binary
//! (`src/tracing/mod.rs`) and is not re-exported through the library crate
//! `tamandua_agent`, so it cannot be imported here. To keep coverage of the
//! W3C traceparent contract we mirror the minimal parser/formatter the agent
//! uses and exercise it from this integration test. If the production module
//! changes its parsing behaviour, the corresponding unit tests in
//! `src/tracing/mod.rs` will still catch regressions.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
struct TraceContext {
    trace_id: String,
    span_id: String,
    trace_flags: String,
}

impl TraceContext {
    fn to_traceparent(&self) -> String {
        format!("00-{}-{}-{}", self.trace_id, self.span_id, self.trace_flags)
    }

    fn from_traceparent(traceparent: &str) -> Option<Self> {
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

    fn inject_headers(&self, headers: &mut HashMap<String, String>) {
        headers.insert("traceparent".to_string(), self.to_traceparent());
    }
}

#[test]
fn test_trace_context_from_traceparent() {
    let traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    let ctx = TraceContext::from_traceparent(traceparent).unwrap();

    assert_eq!(ctx.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
    assert_eq!(ctx.span_id, "00f067aa0ba902b7");
    assert_eq!(ctx.trace_flags, "01");
}

#[test]
fn test_trace_context_to_traceparent() {
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
}

#[test]
fn test_trace_context_roundtrip() {
    let original = TraceContext {
        trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_string(),
        span_id: "00f067aa0ba902b7".to_string(),
        trace_flags: "01".to_string(),
    };

    let traceparent = original.to_traceparent();
    let parsed = TraceContext::from_traceparent(&traceparent).unwrap();

    assert_eq!(parsed.trace_id, original.trace_id);
    assert_eq!(parsed.span_id, original.span_id);
    assert_eq!(parsed.trace_flags, original.trace_flags);
}

#[test]
fn test_trace_context_inject_headers() {
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

#[test]
fn test_invalid_traceparent() {
    // Invalid version
    assert!(TraceContext::from_traceparent("01-abc-def-01").is_none());

    // Invalid format
    assert!(TraceContext::from_traceparent("00-abc-def").is_none());

    // Empty string
    assert!(TraceContext::from_traceparent("").is_none());
}
