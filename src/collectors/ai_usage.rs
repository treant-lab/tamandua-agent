//! Metadata-only AI usage classification.
//!
//! This module deliberately classifies only observable metadata such as DNS
//! names, SNI values, and known local inference ports. It must not inspect,
//! hash, or emit prompt/response content.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AIUsageClassification {
    pub provider: &'static str,
    pub category: &'static str,
    pub confidence: u8,
    pub signal: &'static str,
}

const DOMAIN_PATTERNS: &[(&str, &str, &str, u8)] = &[
    ("api.openai.com", "openai", "remote_ai_api", 95),
    ("chat.openai.com", "openai", "remote_ai_browser", 95),
    ("chatgpt.com", "openai", "remote_ai_browser", 95),
    ("platform.openai.com", "openai", "remote_ai_console", 90),
    ("api.anthropic.com", "anthropic", "remote_ai_api", 95),
    ("claude.ai", "anthropic", "remote_ai_browser", 95),
    (
        "generativelanguage.googleapis.com",
        "google",
        "remote_ai_api",
        95,
    ),
    ("ai.google.dev", "google", "remote_ai_console", 90),
    ("gemini.google.com", "google", "remote_ai_browser", 95),
    ("bard.google.com", "google", "remote_ai_browser", 85),
    (
        "copilot.microsoft.com",
        "microsoft",
        "remote_ai_browser",
        95,
    ),
    ("openai.azure.com", "microsoft", "remote_ai_api", 90),
    (
        "api.cognitive.microsoft.com",
        "microsoft",
        "remote_ai_api",
        85,
    ),
    ("huggingface.co", "huggingface", "remote_ai_service", 85),
    (
        "api-inference.huggingface.co",
        "huggingface",
        "remote_ai_api",
        95,
    ),
    ("api.cohere.ai", "cohere", "remote_ai_api", 95),
    ("cohere.com", "cohere", "remote_ai_service", 80),
    ("api.replicate.com", "replicate", "remote_ai_api", 95),
    ("replicate.com", "replicate", "remote_ai_service", 80),
    ("api.mistral.ai", "mistral", "remote_ai_api", 95),
    ("api.groq.com", "groq", "remote_ai_api", 95),
    ("console.groq.com", "groq", "remote_ai_console", 85),
    ("openrouter.ai", "openrouter", "remote_ai_gateway", 90),
    ("api.openrouter.ai", "openrouter", "remote_ai_gateway", 95),
    ("api.perplexity.ai", "perplexity", "remote_ai_api", 95),
    ("perplexity.ai", "perplexity", "remote_ai_browser", 90),
    ("bedrock-runtime.", "aws_bedrock", "remote_ai_api", 85),
];

const LOCAL_INFERENCE_PORTS: &[(u16, &str)] = &[
    (11434, "ollama"),
    (8000, "vllm_or_fastapi_ml"),
    (8080, "llama_cpp"),
    (8081, "localai"),
    (5000, "text_generation_inference"),
    (7860, "gradio"),
    (8501, "streamlit_ml"),
    (8888, "jupyter"),
];

pub fn classify_domain(domain: &str) -> Option<AIUsageClassification> {
    let normalized = domain.trim_end_matches('.').to_ascii_lowercase();

    DOMAIN_PATTERNS
        .iter()
        .find(|(pattern, _, _, _)| {
            normalized == *pattern
                || normalized.ends_with(&format!(".{pattern}"))
                || normalized.contains(*pattern)
        })
        .map(
            |(_, provider, category, confidence)| AIUsageClassification {
                provider,
                category,
                confidence: *confidence,
                signal: "domain",
            },
        )
}

pub fn classify_local_port(remote_ip: &str, remote_port: u16) -> Option<AIUsageClassification> {
    if !matches!(remote_ip, "127.0.0.1" | "::1" | "localhost") {
        return None;
    }

    LOCAL_INFERENCE_PORTS
        .iter()
        .find(|(port, _)| *port == remote_port)
        .map(|(_, provider)| AIUsageClassification {
            provider,
            category: "local_inference",
            confidence: 80,
            signal: "local_port",
        })
}

pub fn metadata_pairs(classification: AIUsageClassification) -> [(&'static str, String); 5] {
    [
        ("ai_usage", "true".to_string()),
        ("ai_provider", classification.provider.to_string()),
        ("ai_category", classification.category.to_string()),
        ("ai_confidence", classification.confidence.to_string()),
        ("ai_signal", classification.signal.to_string()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_known_remote_ai_domains() {
        let chatgpt = classify_domain("chatgpt.com").unwrap();
        assert_eq!(chatgpt.provider, "openai");
        assert_eq!(chatgpt.category, "remote_ai_browser");

        let anthropic = classify_domain("api.anthropic.com").unwrap();
        assert_eq!(anthropic.provider, "anthropic");
        assert_eq!(anthropic.category, "remote_ai_api");
    }

    #[test]
    fn classifies_subdomains_and_local_inference_ports() {
        let bedrock = classify_domain("bedrock-runtime.us-east-1.amazonaws.com").unwrap();
        assert_eq!(bedrock.provider, "aws_bedrock");

        let ollama = classify_local_port("127.0.0.1", 11434).unwrap();
        assert_eq!(ollama.provider, "ollama");
        assert_eq!(ollama.category, "local_inference");
    }

    #[test]
    fn ignores_unrelated_metadata() {
        assert!(classify_domain("example.com").is_none());
        assert!(classify_local_port("10.0.0.5", 11434).is_none());
    }
}
