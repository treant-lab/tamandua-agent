use anyhow::{bail, Result};
use clap::Parser;
#[cfg(feature = "onnx")]
use serde::Serialize;
#[cfg(feature = "onnx")]
use std::path::Path;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "ml-agent-onnx-parity",
    about = "Run Rust ONNX inference against a Tamandua ML-3 parity fixture"
)]
struct Args {
    /// Path to an ML-3 agent parity fixture JSON file.
    #[arg(long)]
    fixture: PathBuf,
    /// Output JSON file with per-sample parity results.
    #[arg(long)]
    output: PathBuf,
}

#[cfg(feature = "onnx")]
#[tokio::main]
async fn main() -> Result<()> {
    use anyhow::Context;
    use tamandua_agent::analyzers::ml_agent_parity_fixture::{
        decode_sample, load_and_validate_fixture,
    };
    use tamandua_agent::analyzers::{OnnxScanner, OnnxScannerConfig};

    let args = Args::parse();
    let (fixture, summary) = load_and_validate_fixture(&args.fixture)?;

    let model_path = resolve_fixture_path_ref(&fixture.onnx_model.path, &args.fixture);

    let mut scanner = OnnxScanner::new(OnnxScannerConfig {
        model_path,
        confidence_threshold: fixture.malicious_threshold(),
        image_size: fixture.input.image_size,
        family_labels: fixture.output.labels.clone(),
        ..OnnxScannerConfig::default()
    });
    if !scanner.wait_for_model_ready().await {
        bail!(
            "ONNX scanner failed to load model {}",
            fixture.onnx_model.path
        );
    }

    let mut samples = Vec::with_capacity(fixture.samples.len());
    let mut max_abs_probability_delta = 0.0_f32;
    let mut verdict_matches = 0_usize;

    for sample in &fixture.samples {
        let decoded = decode_sample(sample)?;
        let result = scanner
            .scan_bytes(&decoded.bytes)
            .await
            .with_context(|| format!("failed to scan sample {}", sample.sample_id))?;

        let deltas = result
            .probabilities
            .iter()
            .zip(sample.expected.probabilities.iter())
            .map(|(actual, expected)| (actual - expected).abs())
            .collect::<Vec<_>>();
        let sample_max_delta = deltas.iter().copied().fold(0.0_f32, f32::max);
        max_abs_probability_delta = max_abs_probability_delta.max(sample_max_delta);

        let verdict_match = result.is_malicious == sample.expected.is_malicious
            && result.family_index == sample.expected.predicted_index;
        if verdict_match {
            verdict_matches += 1;
        }

        samples.push(SampleParityResult {
            sample_id: sample.sample_id.clone(),
            expected_index: sample.expected.predicted_index,
            actual_index: result.family_index,
            expected_is_malicious: sample.expected.is_malicious,
            actual_is_malicious: result.is_malicious,
            expected_confidence: sample.expected.confidence,
            actual_confidence: result.confidence,
            max_abs_probability_delta: sample_max_delta,
            verdict_match,
        });
    }

    let sample_count = samples.len();
    let verdict_agreement = if sample_count == 0 {
        0.0
    } else {
        verdict_matches as f32 / sample_count as f32
    };
    let passed = verdict_agreement >= fixture.agent_tolerance.verdict_agreement_required
        && max_abs_probability_delta <= fixture.agent_tolerance.max_abs_probability_delta;

    let report = AgentOnnxParityResults {
        api_version: "tamandua.io/ml-agent-onnx-parity-results/v1",
        kind: "MLAgentOnnxParityResults",
        fixture_id: summary.fixture_id,
        sample_count,
        verdict_matches,
        verdict_agreement,
        max_abs_probability_delta,
        allowed_max_abs_probability_delta: fixture.agent_tolerance.max_abs_probability_delta,
        passed,
        samples,
    };

    if let Some(parent) = args.output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&args.output, serde_json::to_string_pretty(&report)?)?;
    println!(
        "ml_agent_onnx_parity={passed} json={}",
        args.output.display()
    );
    Ok(())
}

#[cfg(feature = "onnx")]
fn resolve_fixture_path_ref(path_ref: &str, fixture_path: &Path) -> PathBuf {
    let path = PathBuf::from(path_ref);
    if path.is_absolute() || path.exists() {
        return path;
    }

    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let repo_relative = repo_root.join(&path);
    if repo_relative.exists() {
        return repo_relative;
    }

    if let Some(parent) = fixture_path.parent() {
        let fixture_relative = parent.join(&path);
        if fixture_relative.exists() {
            return fixture_relative;
        }
    }

    path
}

#[cfg(not(feature = "onnx"))]
fn main() -> Result<()> {
    let _args = Args::parse();
    bail!("ml_agent_onnx_parity requires --features onnx")
}

#[cfg(feature = "onnx")]
#[derive(Debug, Serialize)]
struct AgentOnnxParityResults {
    api_version: &'static str,
    kind: &'static str,
    fixture_id: String,
    sample_count: usize,
    verdict_matches: usize,
    verdict_agreement: f32,
    max_abs_probability_delta: f32,
    allowed_max_abs_probability_delta: f32,
    passed: bool,
    samples: Vec<SampleParityResult>,
}

#[cfg(feature = "onnx")]
#[derive(Debug, Serialize)]
struct SampleParityResult {
    sample_id: String,
    expected_index: usize,
    actual_index: usize,
    expected_is_malicious: bool,
    actual_is_malicious: bool,
    expected_confidence: f32,
    actual_confidence: f32,
    max_abs_probability_delta: f32,
    verdict_match: bool,
}
