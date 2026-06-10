use anyhow::Result;
use clap::Parser;
use tamandua_agent::analyzers::ml_agent_parity_fixture::load_and_validate_fixture;

#[derive(Debug, Parser)]
#[command(
    name = "ml-agent-parity-fixture",
    about = "Validate a Tamandua ML-3 agent parity fixture without ONNX Runtime"
)]
struct Args {
    /// Path to an ML-3 agent parity fixture JSON file.
    #[arg(long)]
    fixture: std::path::PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let (_fixture, summary) = load_and_validate_fixture(&args.fixture)?;

    println!("validated ML-3 agent parity fixture");
    println!("fixture_id={}", summary.fixture_id);
    println!("sample_count={}", summary.sample_count);
    println!("onnx_model_sha256={}", summary.onnx_model_sha256);

    Ok(())
}
