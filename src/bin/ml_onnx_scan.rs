use anyhow::{bail, Result};
use clap::Parser;

#[cfg(feature = "onnx")]
use anyhow::Context;
#[cfg(feature = "onnx")]
use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "ml-onnx-scan",
    about = "Run the agent-side Malware-SMELL ONNX scanner against one file"
)]
struct Args {
    /// Path to the Malware-SMELL ONNX model.
    #[arg(long)]
    model: Option<PathBuf>,

    /// File to classify.
    #[arg(long)]
    sample: PathBuf,

    /// Malware confidence threshold.
    #[arg(long, default_value_t = 0.7)]
    threshold: f32,

    /// Output JSON report path.
    #[arg(long)]
    output: PathBuf,
}

#[cfg(feature = "onnx")]
#[tokio::main]
async fn main() -> Result<()> {
    use tamandua_agent::analyzers::{OnnxScanner, OnnxScannerConfig};

    let args = Args::parse();
    let model_path = args
        .model
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

    let report = ScanReport {
        api_version: "tamandua.io/ml-onnx-scan/v1",
        kind: "MLOnnxScan",
        model_path: model_path.display().to_string(),
        sample_path: args.sample.display().to_string(),
        threshold: args.threshold,
        is_malicious: result.is_malicious,
        confidence: result.confidence,
        family: result.family,
        family_index: result.family_index,
        probabilities: result.probabilities,
        inference_time_ms: result.inference_time_ms,
        from_cache: result.from_cache,
    };

    if let Some(parent) = args.output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&args.output, serde_json::to_string_pretty(&report)?)?;
    println!(
        "ml_onnx_scan={} json={}",
        if report.is_malicious {
            "malicious"
        } else {
            "benign"
        },
        args.output.display()
    );
    Ok(())
}

#[cfg(not(feature = "onnx"))]
fn main() -> Result<()> {
    let _args = Args::parse();
    bail!("ml-onnx-scan requires --features onnx")
}

#[cfg(feature = "onnx")]
#[derive(Debug, Serialize)]
struct ScanReport {
    api_version: &'static str,
    kind: &'static str,
    model_path: String,
    sample_path: String,
    threshold: f32,
    is_malicious: bool,
    confidence: f32,
    family: Option<String>,
    family_index: usize,
    probabilities: Vec<f32>,
    inference_time_ms: u64,
    from_cache: bool,
}
