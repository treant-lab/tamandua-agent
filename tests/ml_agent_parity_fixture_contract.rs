//! Contract tests for Tamandua ML-3 agent parity fixtures.
//!
//! These tests intentionally avoid ONNX Runtime. They verify that the Rust
//! agent harness can consume the frozen fixture format before the ONNX-enabled
//! parity run is executed on a Rust toolchain that supports `ort`.

use std::path::PathBuf;
use tamandua_agent::analyzers::ml_agent_parity_fixture::{
    load_and_validate_fixture, CANONICAL_LABELS, CANONICAL_THRESHOLD,
};

#[test]
fn ml_agent_parity_fixture_contract_is_consumable() {
    let (fixture, summary) = load_and_validate_fixture(fixture_path()).unwrap();

    assert_eq!(
        summary.fixture_id,
        "20260604t174850z_ml_agent_parity_fixture"
    );
    assert_eq!(summary.sample_count, 6);
    assert_eq!(summary.malicious_threshold, CANONICAL_THRESHOLD);
    assert_eq!(fixture.malicious_threshold(), CANONICAL_THRESHOLD);
    assert_eq!(
        fixture.output.labels,
        CANONICAL_LABELS
            .iter()
            .map(|label| label.to_string())
            .collect::<Vec<_>>()
    );
}

fn fixture_path() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .join("..")
        .join("..")
        .join("docs")
        .join("benchmarks")
        .join("runs")
        .join("20260604T174850Z-ml-agent-parity-fixture.json")
}
