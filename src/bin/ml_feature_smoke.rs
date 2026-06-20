use anyhow::{bail, Context, Result};
use clap::Parser;
use serde::Serialize;
use std::path::PathBuf;
use tamandua_agent::analyzers::ml_local::LocalMLFeatureEngine;

#[derive(Debug, Parser)]
#[command(
    name = "ml-feature-smoke",
    about = "Run the agent-side ml-local feature engine against one file"
)]
struct Args {
    /// Path to the feature ONNX model. Defaults to the platform agent model path.
    #[arg(long)]
    model: Option<PathBuf>,

    /// File to classify.
    #[arg(long)]
    sample: PathBuf,

    /// Malware probability threshold.
    #[arg(long, default_value_t = 0.7)]
    threshold: f32,

    /// Output JSON report path.
    #[arg(long)]
    output: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let model = args
        .model
        .unwrap_or_else(LocalMLFeatureEngine::default_model_path);
    let engine = LocalMLFeatureEngine::new(model.clone(), args.threshold, true);
    if !engine.is_operational() {
        bail!(
            "ml-local engine is not operational for model {}",
            model.display()
        );
    }

    let classification = engine
        .classify_file(&args.sample)
        .with_context(|| format!("failed to classify {}", args.sample.display()))?;

    let report = SmokeReport {
        api_version: "tamandua.io/ml-feature-smoke/v1",
        kind: "MLFeatureSmoke",
        model_path: model.display().to_string(),
        sample_path: args.sample.display().to_string(),
        threshold: args.threshold,
        is_malicious: classification.is_malicious,
        confidence: classification.confidence,
        malware_probability: classification.malware_probability,
        features_extracted: classification.features_extracted,
        model_version: classification.model_version,
        inference_time_ms: classification.inference_time_ms,
    };

    if let Some(parent) = args.output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&args.output, serde_json::to_string_pretty(&report)?)?;
    println!(
        "ml_feature_smoke={} json={}",
        if report.is_malicious {
            "malicious"
        } else {
            "benign"
        },
        args.output.display()
    );
    Ok(())
}

#[derive(Debug, Serialize)]
struct SmokeReport {
    api_version: &'static str,
    kind: &'static str,
    model_path: String,
    sample_path: String,
    threshold: f32,
    is_malicious: bool,
    confidence: f32,
    malware_probability: f32,
    features_extracted: usize,
    model_version: String,
    inference_time_ms: u64,
}
