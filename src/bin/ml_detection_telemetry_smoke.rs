use anyhow::{bail, Result};
use clap::Parser;
use std::path::PathBuf;

#[cfg(feature = "onnx")]
use anyhow::Context;
#[cfg(feature = "onnx")]
use serde::Serialize;
#[cfg(feature = "onnx")]
use sha2::{Digest, Sha256};
#[cfg(feature = "onnx")]
use tamandua_agent::collectors::{
    Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent,
};
#[cfg(feature = "onnx")]
use tamandua_agent::config::AgentConfig;
#[cfg(feature = "onnx")]
use tamandua_agent::transport::BackendClient;

#[cfg(feature = "onnx")]
use tamandua_agent::analyzers::onnx_scanner::ScanResult;
#[cfg(feature = "onnx")]
use tamandua_agent::analyzers::{OnnxScanner, OnnxScannerConfig};

#[derive(Debug, Parser)]
#[command(
    name = "ml-detection-telemetry-smoke",
    about = "Scan one file with local ONNX ML and send a real ML detection telemetry event"
)]
struct Args {
    /// Agent TOML config used for server_url, agent_id, token, and TLS settings.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Override backend socket URL, for example ws://host:4000/socket/agent.
    #[arg(long)]
    server_url: Option<String>,

    /// Override agent id.
    #[arg(long)]
    agent_id: Option<String>,

    /// Override auth token. Prefer config/env in shared environments.
    #[arg(long)]
    auth_token: Option<String>,

    /// Path to the Malware-SMELL ONNX model.
    #[arg(long)]
    model: Option<PathBuf>,

    /// File to classify and report if malicious.
    #[arg(long)]
    sample: PathBuf,

    /// Malware confidence threshold.
    #[arg(long, default_value_t = 0.7)]
    threshold: f32,

    /// Send telemetry even when the model classifies the file as benign.
    #[arg(long)]
    send_benign: bool,

    /// Optional JSON report path.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[cfg(feature = "onnx")]
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let mut config = load_config(args.config.as_ref())?;

    if let Some(server_url) = &args.server_url {
        config.server_url = server_url.clone();
    }
    if let Some(agent_id) = &args.agent_id {
        config.agent_id = agent_id.clone();
    }
    let auth_token = args
        .auth_token
        .clone()
        .or_else(|| std::env::var("TAMANDUA_AGENT_AUTH_TOKEN").ok());

    if let Some(auth_token) = auth_token {
        config.auth_token = Some(auth_token.clone());
    }

    let model_path = args
        .model
        .clone()
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData\Tamandua\models\malware_smell.onnx"));

    let mut scanner = OnnxScanner::new(OnnxScannerConfig {
        model_path: model_path.clone(),
        confidence_threshold: args.threshold,
        ..OnnxScannerConfig::default()
    });

    if !scanner.wait_for_model_ready().await {
        bail!("ONNX scanner failed to load model {}", model_path.display());
    }

    let result = scanner
        .scan_file(&args.sample)
        .await
        .with_context(|| format!("failed to scan {}", args.sample.display()))?;

    let should_send = result.is_malicious || args.send_benign;
    let mut sent = false;

    if should_send {
        let sample_sha256 = sha256_file(&args.sample)?;
        let event = build_ml_event(
            &args.sample,
            &model_path,
            &sample_sha256,
            &result,
            args.threshold,
        );
        let client = BackendClient::new(&config, None).await?;
        client.connect().await?;

        let connected = wait_for_backend_ready(&client, std::time::Duration::from_secs(15)).await;
        if !connected {
            bail!("backend connection did not become ready");
        }

        client.send_telemetry_without_triage(&[event]).await?;
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        sent = true;
    }

    let report = SmokeReport {
        api_version: "tamandua.io/ml-detection-telemetry-smoke/v1",
        kind: "MLDetectionTelemetrySmoke",
        server_url: config.server_url,
        agent_id: config.agent_id,
        model_path: model_path.display().to_string(),
        sample_path: args.sample.display().to_string(),
        threshold: args.threshold,
        is_malicious: result.is_malicious,
        confidence: result.confidence,
        family: result.family,
        family_index: result.family_index,
        inference_time_ms: result.inference_time_ms,
        telemetry_sent: sent,
    };

    if let Some(output) = &args.output {
        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(output, serde_json::to_string_pretty(&report)?)?;
    }

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[cfg(feature = "onnx")]
async fn wait_for_backend_ready(client: &BackendClient, timeout: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if client.is_connected().await {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    client.is_connected().await
}

#[cfg(feature = "onnx")]
fn build_ml_event(
    sample: &std::path::Path,
    model: &std::path::Path,
    sample_sha256: &str,
    result: &ScanResult,
    threshold: f32,
) -> TelemetryEvent {
    let family = result
        .family
        .clone()
        .unwrap_or_else(|| "malware".to_string());
    let severity = if result.confidence >= 0.9 {
        Severity::Critical
    } else if result.confidence >= 0.7 {
        Severity::High
    } else {
        Severity::Medium
    };

    let mut event = TelemetryEvent::new(
        EventType::RansomwareDetected,
        severity,
        EventPayload::Custom(serde_json::json!({
            "detection_source": "ml",
            "path": sample.display().to_string(),
            "file_path": sample.display().to_string(),
            "sha256": sample_sha256,
            "ml_verdict": family,
            "model_version": model.file_name().and_then(|name| name.to_str()).unwrap_or("onnx"),
            "confidence": result.confidence,
            "threshold": threshold,
            "family_index": result.family_index,
            "inference_time_ms": result.inference_time_ms,
        })),
    );

    event
        .metadata
        .insert("source".to_string(), "ml".to_string());
    event
        .metadata
        .insert("detection_source".to_string(), "ml".to_string());
    event
        .metadata
        .insert("provider".to_string(), "tamandua_agent".to_string());
    event.add_detection(Detection {
        detection_type: DetectionType::Ml,
        rule_name: format!("ML_MALWARE_{}", family.to_ascii_uppercase()),
        confidence: result.confidence,
        description: format!(
            "Local ONNX ML classified {} as {}",
            sample.display(),
            family
        ),
        mitre_tactics: vec!["execution".to_string()],
        mitre_techniques: vec!["T1204".to_string()],
    });
    event
}

#[cfg(feature = "onnx")]
fn sha256_file(path: &std::path::Path) -> Result<String> {
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("failed to open sample {}", path.display()))?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)
        .with_context(|| format!("failed to hash sample {}", path.display()))?;
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(feature = "onnx")]
fn load_config(path: Option<&PathBuf>) -> Result<AgentConfig> {
    match path {
        Some(path) => AgentConfig::from_file(path)
            .with_context(|| format!("failed to read agent config {}", path.display())),
        None => Ok(AgentConfig::default()),
    }
}

#[cfg(not(feature = "onnx"))]
fn main() -> Result<()> {
    let _args = Args::parse();
    bail!("ml-detection-telemetry-smoke requires --features onnx")
}

#[cfg(feature = "onnx")]
#[derive(Debug, Serialize)]
struct SmokeReport {
    api_version: &'static str,
    kind: &'static str,
    server_url: String,
    agent_id: String,
    model_path: String,
    sample_path: String,
    threshold: f32,
    is_malicious: bool,
    confidence: f32,
    family: Option<String>,
    family_index: usize,
    inference_time_ms: u64,
    telemetry_sent: bool,
}
