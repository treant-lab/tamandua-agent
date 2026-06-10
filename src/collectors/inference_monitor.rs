//! Inference Monitoring Collector
//!
//! Captures real-time ML inference request/response pairs with process correlation.
//! Extends the LLM interceptor infrastructure to capture full inference lifecycle:
//! - Request submission (prompt, model, parameters)
//! - Response reception (content, tokens, latency)
//! - Error handling and timeout detection
//!
//! Platform support:
//! - Linux: eBPF uprobes on SSL_read (responses) + SSL_write (requests)
//! - Windows: WinHTTP ETW events (stub)
//! - macOS: Network Extension (stub)

// LLM inference DLP/exfil monitor. Constants and helper functions retain
// scaffolding for upcoming Windows/macOS code paths and response-shape
// validation that are not yet wired into the active pipeline.
#![allow(dead_code, unused_variables)]

use crate::collectors::llm_interceptor::{LLMProvider, LLMRequestEvent};
use crate::collectors::{EventPayload, EventType, Severity, TelemetryEvent};
use crate::config::AgentConfig;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, error, warn};
use uuid::Uuid;

/// Maximum response preview length (characters)
const RESPONSE_PREVIEW_MAX_LEN: usize = 512;

/// Session timeout for cleanup (seconds)
const SESSION_TIMEOUT_SECONDS: u64 = 120;

/// Maximum latency considered valid (5 minutes)
const MAX_VALID_LATENCY_MS: u64 = 300_000;

// ============================================================================
// Inference Event Types
// ============================================================================

/// Phase of the inference lifecycle
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InferencePhase {
    /// Request sent to LLM API
    Request,
    /// Response received from LLM API
    Response,
    /// Error during inference
    Error,
}

/// Token count information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenCount {
    /// Number of input tokens (prompt)
    pub input_tokens: Option<u32>,
    /// Number of output tokens (response)
    pub output_tokens: Option<u32>,
    /// Total tokens used
    pub total_tokens: Option<u32>,
}

/// Full inference event extending LLMRequestEvent with response data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceEvent {
    // ---- Base fields from LLMRequestEvent ----
    /// Process ID
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// Process path
    pub process_path: String,
    /// API endpoint URL
    pub api_endpoint: String,
    /// LLM provider
    pub api_provider: LLMProvider,
    /// Preview of the prompt (first 512 chars)
    pub prompt_preview: String,
    /// SHA256 hash of the full prompt
    pub full_prompt_hash: String,
    /// Model name if available
    pub model: Option<String>,
    /// Event timestamp (epoch ms)
    pub timestamp: u64,

    // ---- Extended fields for inference tracking ----
    /// Unique session ID to correlate request/response
    pub session_id: String,
    /// Phase of the inference (request, response, error)
    pub event_phase: InferencePhase,
    /// Preview of the response (first 512 chars)
    pub response_preview: Option<String>,
    /// SHA256 hash of the full response
    pub response_hash: Option<String>,
    /// Latency in milliseconds (response - request timestamp)
    pub latency_ms: Option<u64>,
    /// Token usage information
    pub token_count: Option<TokenCount>,
    /// Finish reason (stop, length, content_filter, error)
    pub finish_reason: Option<String>,
    /// Error message if phase is Error
    pub error_message: Option<String>,
}

impl InferenceEvent {
    /// Create a new request event
    pub fn new_request(request: &LLMRequestEvent, session_id: String) -> Self {
        Self {
            pid: request.pid,
            process_name: request.process_name.clone(),
            process_path: request.process_path.clone(),
            api_endpoint: request.api_endpoint.clone(),
            api_provider: request.api_provider.clone(),
            prompt_preview: request.prompt_preview.clone(),
            full_prompt_hash: request.full_prompt_hash.clone(),
            model: request.model.clone(),
            timestamp: request.timestamp,
            session_id,
            event_phase: InferencePhase::Request,
            response_preview: None,
            response_hash: None,
            latency_ms: None,
            token_count: None,
            finish_reason: None,
            error_message: None,
        }
    }

    /// Create a response event from a request session
    pub fn new_response(
        session: &InferenceSession,
        response_preview: String,
        response_hash: String,
        latency_ms: u64,
        token_count: Option<TokenCount>,
        finish_reason: Option<String>,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            pid: session.pid,
            process_name: session.process_name.clone(),
            process_path: session.process_path.clone(),
            api_endpoint: session.api_endpoint.clone(),
            api_provider: session.api_provider.clone(),
            prompt_preview: session.prompt_preview.clone(),
            full_prompt_hash: session.full_prompt_hash.clone(),
            model: session.model.clone(),
            timestamp: now,
            session_id: session.session_id.clone(),
            event_phase: InferencePhase::Response,
            response_preview: Some(response_preview),
            response_hash: Some(response_hash),
            latency_ms: Some(latency_ms),
            token_count,
            finish_reason,
            error_message: None,
        }
    }

    /// Create an error event
    pub fn new_error(
        session: &InferenceSession,
        error_message: String,
        latency_ms: Option<u64>,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            pid: session.pid,
            process_name: session.process_name.clone(),
            process_path: session.process_path.clone(),
            api_endpoint: session.api_endpoint.clone(),
            api_provider: session.api_provider.clone(),
            prompt_preview: session.prompt_preview.clone(),
            full_prompt_hash: session.full_prompt_hash.clone(),
            model: session.model.clone(),
            timestamp: now,
            session_id: session.session_id.clone(),
            event_phase: InferencePhase::Error,
            response_preview: None,
            response_hash: None,
            latency_ms,
            token_count: None,
            finish_reason: Some("error".to_string()),
            error_message: Some(error_message),
        }
    }
}

// ============================================================================
// Session Tracking
// ============================================================================

/// In-flight inference session for request/response correlation
#[derive(Debug, Clone)]
pub struct InferenceSession {
    pub session_id: String,
    pub pid: u32,
    pub process_name: String,
    pub process_path: String,
    pub api_endpoint: String,
    pub api_provider: LLMProvider,
    pub prompt_preview: String,
    pub full_prompt_hash: String,
    pub model: Option<String>,
    pub request_timestamp: u64,
    pub created_at: Instant,
    /// Accumulated streaming response chunks
    pub response_chunks: Vec<String>,
}

impl InferenceSession {
    pub fn from_request(request: &LLMRequestEvent) -> Self {
        Self {
            session_id: Uuid::new_v4().to_string(),
            pid: request.pid,
            process_name: request.process_name.clone(),
            process_path: request.process_path.clone(),
            api_endpoint: request.api_endpoint.clone(),
            api_provider: request.api_provider.clone(),
            prompt_preview: request.prompt_preview.clone(),
            full_prompt_hash: request.full_prompt_hash.clone(),
            model: request.model.clone(),
            request_timestamp: request.timestamp,
            created_at: Instant::now(),
            response_chunks: Vec::new(),
        }
    }

    /// Session key for DashMap lookup
    pub fn key(&self) -> SessionKey {
        SessionKey {
            pid: self.pid,
            api_endpoint: self.api_endpoint.clone(),
            request_hash: self.full_prompt_hash.clone(),
        }
    }

    /// Check if session has timed out
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > Duration::from_secs(SESSION_TIMEOUT_SECONDS)
    }

    /// Calculate latency in milliseconds
    pub fn latency_ms(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        now.saturating_sub(self.request_timestamp)
    }

    /// Add a streaming response chunk
    pub fn add_chunk(&mut self, chunk: &str) {
        self.response_chunks.push(chunk.to_string());
    }

    /// Get combined response from chunks
    pub fn combined_response(&self) -> String {
        self.response_chunks.join("")
    }
}

/// Key for session lookup in DashMap
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct SessionKey {
    pub pid: u32,
    pub api_endpoint: String,
    pub request_hash: String,
}

// ============================================================================
// Response Parsing
// ============================================================================

/// Parsed response data from LLM API
#[derive(Debug, Clone, Default)]
pub struct ParsedResponse {
    pub content: String,
    pub finish_reason: Option<String>,
    pub token_count: Option<TokenCount>,
}

/// Extract response data from OpenAI API response
pub fn extract_openai_response(json: &serde_json::Value) -> Option<ParsedResponse> {
    // Handle standard completion response.
    // Only take this branch for non-streaming choices (those carrying a
    // `message`/`text` field). Streaming chunks carry a `delta` instead and
    // are handled by the streaming branch below.
    if let Some(choices) = json.get("choices").and_then(|c| c.as_array()) {
        if let Some(choice) = choices.first() {
            let is_standard = choice.get("message").is_some() || choice.get("text").is_some();
            if is_standard {
                let content = choice
                    .get("message")
                    .and_then(|m| m.get("content"))
                    .and_then(|c| c.as_str())
                    .or_else(|| choice.get("text").and_then(|t| t.as_str()))
                    .unwrap_or("")
                    .to_string();

                let finish_reason = choice
                    .get("finish_reason")
                    .and_then(|f| f.as_str())
                    .map(|s| s.to_string());

                let token_count = json.get("usage").map(|usage| TokenCount {
                    input_tokens: usage
                        .get("prompt_tokens")
                        .and_then(|t| t.as_u64())
                        .map(|t| t as u32),
                    output_tokens: usage
                        .get("completion_tokens")
                        .and_then(|t| t.as_u64())
                        .map(|t| t as u32),
                    total_tokens: usage
                        .get("total_tokens")
                        .and_then(|t| t.as_u64())
                        .map(|t| t as u32),
                });

                return Some(ParsedResponse {
                    content,
                    finish_reason,
                    token_count,
                });
            }
        }
    }

    // Handle streaming chunk (SSE)
    if let Some(choices) = json.get("choices").and_then(|c| c.as_array()) {
        if let Some(choice) = choices.first() {
            let content = choice
                .get("delta")
                .and_then(|d| d.get("content"))
                .and_then(|c| c.as_str())
                .unwrap_or("")
                .to_string();

            let finish_reason = choice
                .get("finish_reason")
                .and_then(|f| f.as_str())
                .map(|s| s.to_string());

            return Some(ParsedResponse {
                content,
                finish_reason,
                token_count: None,
            });
        }
    }

    None
}

/// Extract response data from Anthropic API response
pub fn extract_anthropic_response(json: &serde_json::Value) -> Option<ParsedResponse> {
    // Handle messages API response
    if let Some(content_blocks) = json.get("content").and_then(|c| c.as_array()) {
        let content: String = content_blocks
            .iter()
            .filter_map(|block| {
                if block.get("type").and_then(|t| t.as_str()) == Some("text") {
                    block.get("text").and_then(|t| t.as_str())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("");

        let finish_reason = json
            .get("stop_reason")
            .and_then(|r| r.as_str())
            .map(|s| s.to_string());

        let token_count = json.get("usage").map(|usage| TokenCount {
            input_tokens: usage
                .get("input_tokens")
                .and_then(|t| t.as_u64())
                .map(|t| t as u32),
            output_tokens: usage
                .get("output_tokens")
                .and_then(|t| t.as_u64())
                .map(|t| t as u32),
            total_tokens: None, // Anthropic reports separately
        });

        return Some(ParsedResponse {
            content,
            finish_reason,
            token_count,
        });
    }

    // Handle streaming event
    if let Some(delta) = json.get("delta") {
        if let Some(text) = delta.get("text").and_then(|t| t.as_str()) {
            return Some(ParsedResponse {
                content: text.to_string(),
                finish_reason: None,
                token_count: None,
            });
        }
    }

    None
}

/// Extract response data from Ollama API response
pub fn extract_ollama_response(json: &serde_json::Value) -> Option<ParsedResponse> {
    // Handle generate API response
    if let Some(response) = json.get("response").and_then(|r| r.as_str()) {
        let done = json.get("done").and_then(|d| d.as_bool()).unwrap_or(false);

        let token_count = if done {
            Some(TokenCount {
                input_tokens: json
                    .get("prompt_eval_count")
                    .and_then(|t| t.as_u64())
                    .map(|t| t as u32),
                output_tokens: json
                    .get("eval_count")
                    .and_then(|t| t.as_u64())
                    .map(|t| t as u32),
                total_tokens: None,
            })
        } else {
            None
        };

        return Some(ParsedResponse {
            content: response.to_string(),
            finish_reason: if done { Some("stop".to_string()) } else { None },
            token_count,
        });
    }

    // Handle chat API response
    if let Some(message) = json.get("message") {
        let content = message
            .get("content")
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string();

        let done = json.get("done").and_then(|d| d.as_bool()).unwrap_or(false);

        return Some(ParsedResponse {
            content,
            finish_reason: if done { Some("stop".to_string()) } else { None },
            token_count: None,
        });
    }

    None
}

/// Truncate response to preview length
fn truncate_response(response: &str, max_len: usize) -> String {
    if response.len() <= max_len {
        response.to_string()
    } else {
        format!("{}...", &response[..max_len])
    }
}

/// Hash the full response content
fn hash_response(response: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(response.as_bytes());
    format!("{:x}", hasher.finalize())
}

// ============================================================================
// Inference Monitor Collector
// ============================================================================

/// Inference monitoring collector with request/response correlation
pub struct InferenceMonitor {
    #[allow(dead_code)]
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    /// Active sessions (shared with monitor task)
    #[allow(dead_code)]
    sessions: Arc<DashMap<SessionKey, InferenceSession>>,
}

impl InferenceMonitor {
    /// Create a new inference monitor
    pub fn new(config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(1000);
        let config_clone = config.clone();
        let sessions: Arc<DashMap<SessionKey, InferenceSession>> = Arc::new(DashMap::new());
        let sessions_clone = sessions.clone();

        // Spawn platform-specific monitor loop
        tokio::spawn(async move {
            #[cfg(target_os = "linux")]
            {
                if let Err(e) = monitor_loop_linux(config_clone, tx, sessions_clone).await {
                    error!("Linux inference monitor loop failed: {}", e);
                }
            }

            #[cfg(target_os = "windows")]
            {
                if let Err(e) = monitor_loop_windows(config_clone, tx, sessions_clone).await {
                    error!("Windows inference monitor loop failed: {}", e);
                }
            }

            #[cfg(target_os = "macos")]
            {
                if let Err(e) = monitor_loop_macos(config_clone, tx, sessions_clone).await {
                    error!("macOS inference monitor loop failed: {}", e);
                }
            }
        });

        // Spawn session cleanup task
        let sessions_cleanup = sessions.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                cleanup_expired_sessions(&sessions_cleanup);
            }
        });

        Self {
            config: config.clone(),
            event_rx: rx,
            sessions,
        }
    }

    /// Get next telemetry event
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }
}

/// Clean up expired sessions
fn cleanup_expired_sessions(sessions: &DashMap<SessionKey, InferenceSession>) {
    let expired_keys: Vec<SessionKey> = sessions
        .iter()
        .filter(|entry| entry.value().is_expired())
        .map(|entry| entry.key().clone())
        .collect();

    for key in expired_keys {
        if let Some((_, session)) = sessions.remove(&key) {
            debug!(
                "Cleaned up expired inference session: {} (pid={})",
                session.session_id, session.pid
            );
        }
    }
}

/// Create a TelemetryEvent from an InferenceEvent
fn create_telemetry_event(inference_event: InferenceEvent) -> TelemetryEvent {
    let event_type = match inference_event.event_phase {
        InferencePhase::Request => EventType::LLMRequest, // We'll keep using LLMRequest for now
        InferencePhase::Response => EventType::LLMRequest,
        InferencePhase::Error => EventType::LLMRequest,
    };

    let severity = match inference_event.event_phase {
        InferencePhase::Request => Severity::Info,
        InferencePhase::Response => Severity::Info,
        InferencePhase::Error => Severity::Medium,
    };

    let mut telemetry = TelemetryEvent::new(
        event_type,
        severity,
        EventPayload::Inference(inference_event.clone()),
    );

    // Add metadata for phase distinction
    telemetry.metadata.insert(
        "inference_phase".to_string(),
        format!("{:?}", inference_event.event_phase).to_lowercase(),
    );
    telemetry
        .metadata
        .insert("session_id".to_string(), inference_event.session_id.clone());

    if let Some(latency) = inference_event.latency_ms {
        telemetry
            .metadata
            .insert("latency_ms".to_string(), latency.to_string());
    }

    telemetry
}

// ============================================================================
// Platform-Specific Monitor Loops
// ============================================================================

#[cfg(target_os = "linux")]
async fn monitor_loop_linux(
    _config: AgentConfig,
    tx: mpsc::Sender<TelemetryEvent>,
    sessions: Arc<DashMap<SessionKey, InferenceSession>>,
) -> Result<(), anyhow::Error> {
    warn!(
        "Linux eBPF inference monitoring requires:\n\
         - eBPF program with SSL_write (requests) + SSL_read (responses)\n\
         - CAP_BPF or CAP_SYS_ADMIN capability\n\
         - Kernel 5.8+ for ring buffer support\n\
         Collector will not produce events until eBPF is available."
    );

    // STUB — DESIGN-DORMANT, not production. Parks forever and emits no events.
    // Placeholder for actual eBPF implementation
    // When eBPF events come in:
    // 1. Parse event_type (0 = request, 1 = response)
    // 2. For requests: Create session, emit InferenceRequest event
    // 3. For responses: Lookup session, compute latency, emit InferenceResponse event
    // Missing: compiled eBPF program + ring-buffer consumer wired to the session map.
    std::future::pending().await
}

#[cfg(target_os = "windows")]
async fn monitor_loop_windows(
    _config: AgentConfig,
    _tx: mpsc::Sender<TelemetryEvent>,
    _sessions: Arc<DashMap<SessionKey, InferenceSession>>,
) -> Result<(), anyhow::Error> {
    // STUB — PLATFORM-INCOMPLETE, not production. Parks forever and emits no events.
    // Missing: WinHTTP/Schannel ETW capture feeding the inference session map.
    warn!("Windows WinHTTP ETW inference monitoring not yet implemented");
    std::future::pending().await
}

#[cfg(target_os = "macos")]
async fn monitor_loop_macos(
    _config: AgentConfig,
    _tx: mpsc::Sender<TelemetryEvent>,
    _sessions: Arc<DashMap<SessionKey, InferenceSession>>,
) -> Result<(), anyhow::Error> {
    // STUB — PLATFORM-INCOMPLETE, not production. Parks forever and emits no events.
    // Missing: Network Extension content filter feeding the inference session map.
    warn!("macOS Network Extension inference monitoring not yet implemented");
    std::future::pending().await
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_openai_response_standard() {
        let json = serde_json::json!({
            "choices": [{
                "message": {"content": "Hello, how can I help?"},
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 6,
                "total_tokens": 16
            }
        });

        let result = extract_openai_response(&json).unwrap();
        assert_eq!(result.content, "Hello, how can I help?");
        assert_eq!(result.finish_reason, Some("stop".to_string()));
        assert!(result.token_count.is_some());
        let tokens = result.token_count.unwrap();
        assert_eq!(tokens.input_tokens, Some(10));
        assert_eq!(tokens.output_tokens, Some(6));
        assert_eq!(tokens.total_tokens, Some(16));
    }

    #[test]
    fn test_extract_openai_response_streaming() {
        let json = serde_json::json!({
            "choices": [{
                "delta": {"content": "Hello"},
                "finish_reason": null
            }]
        });

        let result = extract_openai_response(&json).unwrap();
        assert_eq!(result.content, "Hello");
        assert!(result.finish_reason.is_none());
    }

    #[test]
    fn test_extract_anthropic_response() {
        let json = serde_json::json!({
            "content": [
                {"type": "text", "text": "I can help with that."}
            ],
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 15,
                "output_tokens": 8
            }
        });

        let result = extract_anthropic_response(&json).unwrap();
        assert_eq!(result.content, "I can help with that.");
        assert_eq!(result.finish_reason, Some("end_turn".to_string()));
        assert!(result.token_count.is_some());
    }

    #[test]
    fn test_extract_ollama_response_generate() {
        let json = serde_json::json!({
            "response": "The answer is 42",
            "done": true,
            "prompt_eval_count": 5,
            "eval_count": 4
        });

        let result = extract_ollama_response(&json).unwrap();
        assert_eq!(result.content, "The answer is 42");
        assert_eq!(result.finish_reason, Some("stop".to_string()));
        assert!(result.token_count.is_some());
    }

    #[test]
    fn test_extract_ollama_response_chat() {
        let json = serde_json::json!({
            "message": {"content": "Hello there!"},
            "done": true
        });

        let result = extract_ollama_response(&json).unwrap();
        assert_eq!(result.content, "Hello there!");
        assert_eq!(result.finish_reason, Some("stop".to_string()));
    }

    #[test]
    fn test_session_correlation() {
        let request = LLMRequestEvent {
            pid: 1234,
            process_name: "python".to_string(),
            process_path: "/usr/bin/python".to_string(),
            api_endpoint: "https://api.openai.com/v1/chat/completions".to_string(),
            api_provider: LLMProvider::OpenAI,
            prompt_preview: "Hello".to_string(),
            full_prompt_hash: "abc123".to_string(),
            model: Some("gpt-4".to_string()),
            timestamp: 1000,
        };

        let session = InferenceSession::from_request(&request);
        assert_eq!(session.pid, 1234);
        assert_eq!(session.process_name, "python");
        assert!(!session.session_id.is_empty());

        let key = session.key();
        assert_eq!(key.pid, 1234);
        assert_eq!(key.request_hash, "abc123");
    }

    #[test]
    fn test_inference_event_serialization() {
        let request = LLMRequestEvent {
            pid: 5678,
            process_name: "node".to_string(),
            process_path: "/usr/bin/node".to_string(),
            api_endpoint: "https://api.anthropic.com/v1/messages".to_string(),
            api_provider: LLMProvider::Anthropic,
            prompt_preview: "Test prompt".to_string(),
            full_prompt_hash: "def456".to_string(),
            model: Some("claude-3".to_string()),
            timestamp: 2000,
        };

        let inference_event = InferenceEvent::new_request(&request, "session-123".to_string());

        // Serialize to JSON
        let json = serde_json::to_string(&inference_event).unwrap();

        // Deserialize back
        let deserialized: InferenceEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.pid, 5678);
        assert_eq!(deserialized.session_id, "session-123");
        assert_eq!(deserialized.event_phase, InferencePhase::Request);
    }

    #[test]
    fn test_truncate_response() {
        let short = "Hello";
        assert_eq!(truncate_response(short, 512), "Hello");

        let long = "a".repeat(1000);
        let truncated = truncate_response(&long, 512);
        assert_eq!(truncated.len(), 515); // 512 + "..."
        assert!(truncated.ends_with("..."));
    }

    #[test]
    fn test_hash_response() {
        let response = "Hello, world!";
        let hash = hash_response(response);
        assert_eq!(hash.len(), 64); // SHA256 hex is 64 chars

        // Verify deterministic
        let hash2 = hash_response(response);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_streaming_response_accumulation() {
        let request = LLMRequestEvent {
            pid: 9999,
            process_name: "test".to_string(),
            process_path: "/test".to_string(),
            api_endpoint: "http://localhost:11434".to_string(),
            api_provider: LLMProvider::Ollama,
            prompt_preview: "Test".to_string(),
            full_prompt_hash: "test123".to_string(),
            model: Some("llama2".to_string()),
            timestamp: 3000,
        };

        let mut session = InferenceSession::from_request(&request);
        session.add_chunk("Hello");
        session.add_chunk(" ");
        session.add_chunk("World");

        assert_eq!(session.combined_response(), "Hello World");
    }
}
