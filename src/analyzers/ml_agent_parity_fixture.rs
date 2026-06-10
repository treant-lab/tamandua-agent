//! ML-3 agent parity fixture contract support.
//!
//! This module parses and validates synthetic parity fixtures produced by
//! `apps/tamandua_ml/scripts/build_agent_parity_fixture.py`. It intentionally
//! does not require ONNX Runtime, so it can run in no-feature builds and prepare
//! the agent-side harness before the ONNX dependency chain is available.

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

pub const FIXTURE_API_VERSION: &str = "tamandua.io/ml-agent-parity-fixture/v1";
pub const FIXTURE_KIND: &str = "MLAgentParityFixture";
pub const CANONICAL_INPUT_NAME: &str = "input";
pub const CANONICAL_OUTPUT_NAME: &str = "output";
pub const CANONICAL_DTYPE: &str = "tensor(float)";
pub const CANONICAL_PREPROCESSING: &str = "binary_to_image_64_rgb_v1";
pub const CANONICAL_THRESHOLD: f32 = 0.7;
pub const CANONICAL_AGENT_MAX_ABS_DELTA: f32 = 0.0001;
pub const CANONICAL_AGENT_VERDICT_AGREEMENT: f32 = 1.0;
pub const CANONICAL_LABELS: [&str; 8] = [
    "benign",
    "trojan",
    "ransomware",
    "spyware",
    "adware",
    "worm",
    "backdoor",
    "unknown_malware",
];

#[derive(Debug, Deserialize)]
pub struct AgentParityFixture {
    pub api_version: String,
    pub kind: String,
    pub metadata: FixtureMetadata,
    pub model_contract_ref: String,
    pub onnx_model: FixtureOnnxModel,
    pub environment: FixtureEnvironment,
    pub input: FixtureInput,
    pub output: FixtureOutput,
    pub agent_tolerance: AgentTolerance,
    pub samples: Vec<FixtureSample>,
}

#[derive(Debug, Deserialize)]
pub struct FixtureMetadata {
    pub fixture_id: String,
    pub created_at: String,
    pub created_by: String,
    pub git_commit: String,
    pub claim_boundary: String,
}

#[derive(Debug, Deserialize)]
pub struct FixtureOnnxModel {
    pub path: String,
    pub sha256: String,
    pub metadata_path: Option<String>,
    pub metadata_sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct FixtureEnvironment {
    pub os: String,
    pub python_version: String,
    pub onnxruntime_version: String,
}

#[derive(Debug, Deserialize)]
pub struct FixtureInput {
    pub name: String,
    pub shape: Vec<serde_json::Value>,
    pub dtype: String,
    pub image_size: usize,
    pub preprocessing: String,
}

#[derive(Debug, Deserialize)]
pub struct FixtureOutput {
    pub name: String,
    pub shape: Vec<serde_json::Value>,
    pub dtype: String,
    pub labels: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct AgentTolerance {
    pub max_abs_probability_delta: f32,
    pub verdict_agreement_required: f32,
}

#[derive(Debug, Deserialize)]
pub struct FixtureSample {
    pub sample_id: String,
    pub description: String,
    pub raw_sha256: String,
    pub raw_size_bytes: usize,
    pub raw_base64: String,
    pub expected: ExpectedOutput,
}

#[derive(Debug, Deserialize)]
pub struct ExpectedOutput {
    pub predicted_index: usize,
    pub predicted_class: String,
    pub confidence: f32,
    pub is_malicious: bool,
    pub probabilities: Vec<f32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedFixtureSample {
    pub sample_id: String,
    pub raw_sha256: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureValidationSummary {
    pub fixture_id: String,
    pub sample_count: usize,
    pub onnx_model_sha256: String,
}

pub fn load_fixture(path: impl AsRef<Path>) -> Result<AgentParityFixture> {
    let path = path.as_ref();
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read fixture {}", path.display()))?;
    serde_json::from_str(&contents)
        .with_context(|| format!("failed to parse fixture {}", path.display()))
}

pub fn load_and_validate_fixture(
    path: impl AsRef<Path>,
) -> Result<(AgentParityFixture, FixtureValidationSummary)> {
    let fixture = load_fixture(path)?;
    let summary = validate_fixture(&fixture)?;
    Ok((fixture, summary))
}

pub fn validate_fixture(fixture: &AgentParityFixture) -> Result<FixtureValidationSummary> {
    validate_header(fixture)?;
    validate_input(&fixture.input)?;
    validate_output(&fixture.output)?;
    validate_tolerance(&fixture.agent_tolerance)?;
    validate_sha256(&fixture.onnx_model.sha256, "onnx_model.sha256")?;
    if let Some(metadata_sha256) = &fixture.onnx_model.metadata_sha256 {
        validate_sha256(metadata_sha256, "onnx_model.metadata_sha256")?;
    }

    if fixture.samples.is_empty() {
        bail!("fixture.samples must not be empty");
    }

    for sample in &fixture.samples {
        validate_sample(sample, &fixture.output.labels)?;
    }

    Ok(FixtureValidationSummary {
        fixture_id: fixture.metadata.fixture_id.clone(),
        sample_count: fixture.samples.len(),
        onnx_model_sha256: fixture.onnx_model.sha256.clone(),
    })
}

pub fn decode_sample(sample: &FixtureSample) -> Result<DecodedFixtureSample> {
    let bytes = BASE64_STANDARD
        .decode(&sample.raw_base64)
        .with_context(|| format!("invalid base64 for sample {}", sample.sample_id))?;

    if bytes.len() != sample.raw_size_bytes {
        bail!(
            "sample {} raw_size_bytes mismatch: expected {}, decoded {}",
            sample.sample_id,
            sample.raw_size_bytes,
            bytes.len()
        );
    }

    let digest = Sha256::digest(&bytes);
    let actual_sha256 = format!("{digest:x}");
    if actual_sha256 != sample.raw_sha256 {
        bail!(
            "sample {} sha256 mismatch: expected {}, decoded {}",
            sample.sample_id,
            sample.raw_sha256,
            actual_sha256
        );
    }

    Ok(DecodedFixtureSample {
        sample_id: sample.sample_id.clone(),
        raw_sha256: sample.raw_sha256.clone(),
        bytes,
    })
}

fn validate_header(fixture: &AgentParityFixture) -> Result<()> {
    if fixture.api_version != FIXTURE_API_VERSION {
        bail!("invalid api_version {}", fixture.api_version);
    }
    if fixture.kind != FIXTURE_KIND {
        bail!("invalid kind {}", fixture.kind);
    }
    if fixture.metadata.fixture_id.trim().is_empty() {
        bail!("metadata.fixture_id must not be empty");
    }
    if fixture.metadata.claim_boundary.len() < 10 {
        bail!("metadata.claim_boundary must describe the claim boundary");
    }
    Ok(())
}

fn validate_input(input: &FixtureInput) -> Result<()> {
    if input.name != CANONICAL_INPUT_NAME {
        bail!("input.name must be {CANONICAL_INPUT_NAME}");
    }
    if input.dtype != CANONICAL_DTYPE {
        bail!("input.dtype must be {CANONICAL_DTYPE}");
    }
    if input.image_size != 64 {
        bail!("input.image_size must be 64");
    }
    if input.preprocessing != CANONICAL_PREPROCESSING {
        bail!("input.preprocessing must be {CANONICAL_PREPROCESSING}");
    }
    if input.shape != canonical_input_shape() {
        bail!("input.shape must be [batch_size, 3, 64, 64]");
    }
    Ok(())
}

fn validate_output(output: &FixtureOutput) -> Result<()> {
    if output.name != CANONICAL_OUTPUT_NAME {
        bail!("output.name must be {CANONICAL_OUTPUT_NAME}");
    }
    if output.dtype != CANONICAL_DTYPE {
        bail!("output.dtype must be {CANONICAL_DTYPE}");
    }
    let expected_labels = CANONICAL_LABELS
        .iter()
        .map(|label| label.to_string())
        .collect::<Vec<_>>();
    if output.labels != expected_labels {
        bail!("output.labels must match the canonical Malware-SMELL label order");
    }
    Ok(())
}

fn validate_tolerance(tolerance: &AgentTolerance) -> Result<()> {
    if (tolerance.max_abs_probability_delta - CANONICAL_AGENT_MAX_ABS_DELTA).abs() > f32::EPSILON {
        bail!("agent_tolerance.max_abs_probability_delta must be {CANONICAL_AGENT_MAX_ABS_DELTA}");
    }
    if (tolerance.verdict_agreement_required - CANONICAL_AGENT_VERDICT_AGREEMENT).abs()
        > f32::EPSILON
    {
        bail!("agent_tolerance.verdict_agreement_required must be {CANONICAL_AGENT_VERDICT_AGREEMENT}");
    }
    Ok(())
}

fn validate_sample(sample: &FixtureSample, labels: &[String]) -> Result<()> {
    if sample.sample_id.trim().is_empty() {
        bail!("sample_id must not be empty");
    }
    if sample.description.trim().is_empty() {
        bail!("sample {} description must not be empty", sample.sample_id);
    }
    decode_sample(sample)?;

    if sample.expected.probabilities.len() != labels.len() {
        bail!(
            "sample {} probability length mismatch: expected {}, got {}",
            sample.sample_id,
            labels.len(),
            sample.expected.probabilities.len()
        );
    }
    if sample.expected.predicted_index >= labels.len() {
        bail!("sample {} predicted_index out of bounds", sample.sample_id);
    }
    if sample.expected.predicted_class != labels[sample.expected.predicted_index] {
        bail!(
            "sample {} predicted_class does not match predicted_index",
            sample.sample_id
        );
    }
    if !(0.0..=1.0).contains(&sample.expected.confidence) {
        bail!(
            "sample {} confidence must be between 0 and 1",
            sample.sample_id
        );
    }
    for (index, probability) in sample.expected.probabilities.iter().enumerate() {
        if !(0.0..=1.0).contains(probability) {
            bail!(
                "sample {} probability {index} must be between 0 and 1",
                sample.sample_id
            );
        }
    }
    let probability_sum = sample.expected.probabilities.iter().sum::<f32>();
    if (probability_sum - 1.0).abs() > 0.001 {
        bail!(
            "sample {} probabilities must sum to 1.0, got {probability_sum}",
            sample.sample_id
        );
    }
    let max_probability = sample
        .expected
        .probabilities
        .iter()
        .copied()
        .fold(f32::NEG_INFINITY, f32::max);
    if (max_probability - sample.expected.confidence).abs() > CANONICAL_AGENT_MAX_ABS_DELTA {
        bail!(
            "sample {} confidence must match max probability",
            sample.sample_id
        );
    }
    let expected_malicious =
        sample.expected.predicted_index != 0 && sample.expected.confidence >= CANONICAL_THRESHOLD;
    if sample.expected.is_malicious != expected_malicious {
        bail!(
            "sample {} is_malicious does not match threshold logic",
            sample.sample_id
        );
    }
    Ok(())
}

fn validate_sha256(value: &str, path: &str) -> Result<()> {
    if value.len() != 64 || !value.chars().all(|character| character.is_ascii_hexdigit()) {
        return Err(anyhow!("{path} must be a 64-character hex SHA256 digest"));
    }
    Ok(())
}

fn canonical_input_shape() -> Vec<serde_json::Value> {
    vec![
        serde_json::Value::String("batch_size".to_string()),
        serde_json::Value::Number(3.into()),
        serde_json::Value::Number(64.into()),
        serde_json::Value::Number(64.into()),
    ]
}
