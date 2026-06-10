//! LLM API Request Interceptor
//!
//! Monitors LLM API requests from applications using platform-specific techniques:
//! - Linux: eBPF uprobes on SSL_write for HTTPS interception
//! - Windows: WinHTTP ETW events (stub for now)
//! - macOS: Network Extension (stub for now)
//!
//! Extracts prompt content from JSON request bodies and correlates with calling process.

// This collector tracks LLM provider request shapes (OpenAI, Anthropic,
// Ollama, HuggingFace, …) and prompt-extraction helpers for DLP analysis.
// The per-provider extractors and helper utilities are reference scaffolding
// for the Linux eBPF SSL_write hook and forthcoming Windows/macOS sinks; they
// are kept exhaustive even when not yet dispatched on every platform.
#![allow(dead_code)]

use crate::collectors::TelemetryEvent;
use crate::config::AgentConfig;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{error, warn};

/// Maximum prompt preview length (characters)
const PROMPT_PREVIEW_MAX_LEN: usize = 512;

// ============================================================================
// LLM Provider Detection
// ============================================================================

/// LLM API provider
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LLMProvider {
    OpenAI,
    Anthropic,
    Ollama,
    HuggingFace,
    Other(String),
}

/// LLM API request event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMRequestEvent {
    pub pid: u32,
    pub process_name: String,
    pub process_path: String,
    pub api_endpoint: String,
    pub api_provider: LLMProvider,
    pub prompt_preview: String,
    pub full_prompt_hash: String,
    pub model: Option<String>,
    pub timestamp: u64,
}

// ============================================================================
// Prompt Extraction Functions
// ============================================================================

/// Extract prompt from OpenAI API request body
///
/// Handles: {"messages":[{"role":"user","content":"..."},{"role":"assistant","content":"..."}]}
fn extract_openai_prompt(json: &serde_json::Value) -> Option<String> {
    let messages = json.get("messages")?.as_array()?;

    let mut prompts = Vec::new();
    for message in messages {
        if let Some(role) = message.get("role").and_then(|r| r.as_str()) {
            if role == "user" || role == "system" {
                if let Some(content) = message.get("content").and_then(|c| c.as_str()) {
                    prompts.push(content.to_string());
                }
            }
        }
    }

    if prompts.is_empty() {
        None
    } else {
        Some(prompts.join("\n"))
    }
}

/// Extract prompt from Anthropic API request body
///
/// Same format as OpenAI (uses messages array)
fn extract_anthropic_prompt(json: &serde_json::Value) -> Option<String> {
    extract_openai_prompt(json)
}

/// Extract prompt from Ollama API request body
///
/// Handles both:
/// - {"prompt":"..."} (generate API)
/// - {"messages":[...]} (chat API)
fn extract_ollama_prompt(json: &serde_json::Value) -> Option<String> {
    // Try direct prompt field first
    if let Some(prompt) = json.get("prompt").and_then(|p| p.as_str()) {
        return Some(prompt.to_string());
    }

    // Fall back to messages format
    extract_openai_prompt(json)
}

/// Extract model name from request JSON
fn extract_model_name(json: &serde_json::Value) -> Option<String> {
    json.get("model")
        .and_then(|m| m.as_str())
        .map(|s| s.to_string())
}

/// Truncate prompt to preview length
fn truncate_prompt(prompt: &str, max_len: usize) -> String {
    if prompt.len() <= max_len {
        prompt.to_string()
    } else {
        format!("{}...", &prompt[..max_len])
    }
}

/// Detect if hostname/port is an LLM API endpoint
fn is_llm_endpoint(hostname: &str, port: u16) -> Option<LLMProvider> {
    match (hostname, port) {
        ("api.openai.com", 443) => Some(LLMProvider::OpenAI),
        ("api.anthropic.com", 443) => Some(LLMProvider::Anthropic),
        ("localhost", 11434) | ("127.0.0.1", 11434) => Some(LLMProvider::Ollama),
        ("api-inference.huggingface.co", 443) => Some(LLMProvider::HuggingFace),
        _ => None,
    }
}

// ============================================================================
// LLM Interceptor Collector
// ============================================================================

pub struct LLMInterceptor {
    #[allow(dead_code)]
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
}

impl LLMInterceptor {
    /// Create a new LLM interceptor
    pub fn new(config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(1000);
        let config_clone = config.clone();

        // Spawn platform-specific monitor loop
        tokio::spawn(async move {
            #[cfg(target_os = "linux")]
            {
                if let Err(e) = monitor_loop_linux(config_clone, tx).await {
                    error!("Linux LLM monitor loop failed: {}", e);
                }
            }

            #[cfg(target_os = "windows")]
            {
                if let Err(e) = monitor_loop_windows(config_clone, tx).await {
                    error!("Windows LLM monitor loop failed: {}", e);
                }
            }

            #[cfg(target_os = "macos")]
            {
                if let Err(e) = monitor_loop_macos(config_clone, tx).await {
                    error!("macOS LLM monitor loop failed: {}", e);
                }
            }
        });

        Self {
            config: config.clone(),
            event_rx: rx,
        }
    }

    /// Get next telemetry event
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }
}

// ============================================================================
// Platform-Specific Monitor Loops
// ============================================================================

#[cfg(target_os = "linux")]
async fn monitor_loop_linux(
    config: AgentConfig,
    tx: mpsc::Sender<TelemetryEvent>,
) -> Result<(), anyhow::Error> {
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    // Linux eBPF implementation would go here
    // This requires:
    // 1. Load eBPF object file with Aya
    // 2. Find SSL library paths (/usr/lib/x86_64-linux-gnu/libssl.so.*)
    // 3. Attach uprobe to SSL_write
    // 4. Consume ring buffer events
    // 5. Parse JSON and extract prompts
    // 6. Create TelemetryEvent and send to channel
    //
    // For now, log a warning and provide graceful degradation

    warn!(
        "Linux eBPF LLM interception requires:\n\
         - eBPF program compiled with bpf-linker\n\
         - CAP_BPF or CAP_SYS_ADMIN capability\n\
         - Kernel 5.8+ for ring buffer support\n\
         Collector will not produce events until eBPF is available."
    );

    // Example of what the implementation would look like (commented):
    /*
    use aya::{Ebpf, programs::UProbe, maps::RingBuf};
    use tamandua_ebpf_common::LlmRequestEvent;

    // Load eBPF object
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../../target/bpfel-unknown-none/release/llm-uprobe"
    ))?;

    // Find SSL library
    let ssl_paths = [
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
        "/lib/x86_64-linux-gnu/libssl.so.3",
        "/lib/x86_64-linux-gnu/libssl.so.1.1",
    ];

    let mut attached = false;
    for path in &ssl_paths {
        if Path::new(path).exists() {
            let program: &mut UProbe = bpf.program_mut("ssl_write_entry")?.try_into()?;
            program.load()?;
            program.attach(Some("SSL_write"), 0, path, None)?;
            info!("Attached LLM uprobe to {} at SSL_write", path);
            attached = true;
            break;
        }
    }

    if !attached {
        warn!("No SSL library found, LLM interception disabled");
        std::future::pending().await
    }

    // Consume ring buffer
    let mut ring_buf = RingBuf::try_from(bpf.map_mut("LLM_EVENTS")?)?;

    loop {
        if let Some(item) = ring_buf.next() {
            let event: LlmRequestEvent = unsafe {
                std::ptr::read_unaligned(item.as_ptr() as *const LlmRequestEvent)
            };

            // Parse JSON from event data
            let data_len = std::cmp::min(event.data_len as usize, event.data.len());
            if let Ok(body_str) = std::str::from_utf8(&event.data[..data_len]) {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(body_str) {
                    // Extract hostname from HTTP headers (simplified)
                    // In reality, would need to parse HTTP request headers
                    let hostname = "unknown";
                    let port = 443u16;

                    if let Some(provider) = is_llm_endpoint(hostname, port) {
                        // Extract prompt based on provider
                        let prompt = match provider {
                            LLMProvider::OpenAI => extract_openai_prompt(&json),
                            LLMProvider::Anthropic => extract_anthropic_prompt(&json),
                            LLMProvider::Ollama => extract_ollama_prompt(&json),
                            _ => None,
                        };

                        if let Some(full_prompt) = prompt {
                            let prompt_preview = truncate_prompt(&full_prompt, PROMPT_PREVIEW_MAX_LEN);
                            let mut hasher = Sha256::new();
                            hasher.update(full_prompt.as_bytes());
                            let hash = format!("{:x}", hasher.finalize());

                            let llm_event = LLMRequestEvent {
                                pid: event.pid,
                                process_name: get_process_name(event.pid),
                                process_path: get_process_path(event.pid),
                                api_endpoint: format!("{}:{}", hostname, port),
                                api_provider: provider,
                                prompt_preview,
                                full_prompt_hash: hash,
                                model: extract_model_name(&json),
                                timestamp: SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .map(|d| d.as_secs())
                                    .unwrap_or(0),
                            };

                            let telemetry = TelemetryEvent::new(
                                EventType::LLMRequest,
                                Severity::Low,
                                EventPayload::LLMRequest(llm_event),
                            );

                            let _ = tx.send(telemetry).await;
                        }
                    }
                }
            }
        } else {
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }
    }
    */

    // STUB — DESIGN-DORMANT, not production. The real aya/eBPF uprobe path above is
    // commented out; this parks forever and emits no events until the eBPF program is
    // built and wired in. Missing: compiled SSL_write uprobe + ring-buffer consumer.
    std::future::pending().await
}

#[cfg(target_os = "windows")]
async fn monitor_loop_windows(
    _config: AgentConfig,
    _tx: mpsc::Sender<TelemetryEvent>,
) -> Result<(), anyhow::Error> {
    // STUB — PLATFORM-INCOMPLETE, not production. Parks forever and emits no events.
    // Missing: WinHTTP/Schannel ETW capture to intercept outbound LLM API calls.
    warn!("Windows WinHTTP ETW LLM interception not yet implemented");
    std::future::pending().await
}

#[cfg(target_os = "macos")]
async fn monitor_loop_macos(
    _config: AgentConfig,
    _tx: mpsc::Sender<TelemetryEvent>,
) -> Result<(), anyhow::Error> {
    // STUB — PLATFORM-INCOMPLETE, not production. Parks forever and emits no events.
    // Missing: Network Extension content filter to intercept outbound LLM API calls.
    warn!("macOS Network Extension LLM interception not yet implemented");
    std::future::pending().await
}

// ============================================================================
// Process Name Lookup
// ============================================================================

#[cfg(target_os = "linux")]
fn get_process_name(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{}/comm", pid))
        .unwrap_or_else(|_| format!("pid{}", pid))
        .trim()
        .to_string()
}

#[cfg(target_os = "linux")]
fn get_process_path(pid: u32) -> String {
    std::fs::read_link(format!("/proc/{}/exe", pid))
        .ok()
        .and_then(|p| p.to_str().map(|s| s.to_string()))
        .unwrap_or_else(|| format!("/proc/{}/exe", pid))
}

#[cfg(not(target_os = "linux"))]
fn get_process_name(_pid: u32) -> String {
    "unknown".to_string()
}

#[cfg(not(target_os = "linux"))]
fn get_process_path(_pid: u32) -> String {
    "unknown".to_string()
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_openai_prompt_single_message() {
        let json = serde_json::json!({
            "messages": [
                {"role": "user", "content": "Hello"}
            ]
        });

        let prompt = extract_openai_prompt(&json);
        assert_eq!(prompt, Some("Hello".to_string()));
    }

    #[test]
    fn test_extract_openai_prompt_multiple_messages() {
        let json = serde_json::json!({
            "messages": [
                {"role": "system", "content": "You are helpful"},
                {"role": "user", "content": "Hello"},
                {"role": "assistant", "content": "Hi there"},
                {"role": "user", "content": "How are you?"}
            ]
        });

        let prompt = extract_openai_prompt(&json);
        assert_eq!(
            prompt,
            Some("You are helpful\nHello\nHow are you?".to_string())
        );
    }

    #[test]
    fn test_extract_anthropic_prompt() {
        let json = serde_json::json!({
            "messages": [
                {"role": "user", "content": "Hello Anthropic"}
            ]
        });

        let prompt = extract_anthropic_prompt(&json);
        assert_eq!(prompt, Some("Hello Anthropic".to_string()));
    }

    #[test]
    fn test_extract_ollama_prompt_direct() {
        let json = serde_json::json!({
            "prompt": "Hello world"
        });

        let prompt = extract_ollama_prompt(&json);
        assert_eq!(prompt, Some("Hello world".to_string()));
    }

    #[test]
    fn test_extract_ollama_prompt_messages() {
        let json = serde_json::json!({
            "messages": [
                {"role": "user", "content": "Hello Ollama"}
            ]
        });

        let prompt = extract_ollama_prompt(&json);
        assert_eq!(prompt, Some("Hello Ollama".to_string()));
    }

    #[test]
    fn test_is_llm_endpoint_openai() {
        let provider = is_llm_endpoint("api.openai.com", 443);
        assert_eq!(provider, Some(LLMProvider::OpenAI));
    }

    #[test]
    fn test_is_llm_endpoint_anthropic() {
        let provider = is_llm_endpoint("api.anthropic.com", 443);
        assert_eq!(provider, Some(LLMProvider::Anthropic));
    }

    #[test]
    fn test_is_llm_endpoint_ollama_localhost() {
        let provider = is_llm_endpoint("localhost", 11434);
        assert_eq!(provider, Some(LLMProvider::Ollama));
    }

    #[test]
    fn test_is_llm_endpoint_ollama_127() {
        let provider = is_llm_endpoint("127.0.0.1", 11434);
        assert_eq!(provider, Some(LLMProvider::Ollama));
    }

    #[test]
    fn test_truncate_prompt() {
        let short = "Hello";
        assert_eq!(truncate_prompt(short, 512), "Hello");

        let long = "a".repeat(1000);
        let truncated = truncate_prompt(&long, 512);
        assert_eq!(truncated.len(), 515); // 512 + "..."
        assert!(truncated.ends_with("..."));
    }

    #[test]
    fn test_extract_model_name() {
        let json = serde_json::json!({
            "model": "gpt-4",
            "messages": []
        });

        let model = extract_model_name(&json);
        assert_eq!(model, Some("gpt-4".to_string()));
    }
}
