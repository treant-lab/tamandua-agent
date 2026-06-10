//! Build helper for Tamandua eBPF programs
//!
//! Usage: cargo xtask build-ebpf [--release]

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::Command;

#[derive(Parser)]
#[command(name = "xtask")]
#[command(about = "Tamandua build helper")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build eBPF programs
    BuildEbpf {
        /// Build in release mode
        #[arg(long)]
        release: bool,
    },
    /// Build everything (eBPF + agent)
    BuildAll {
        /// Build in release mode
        #[arg(long)]
        release: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::BuildEbpf { release } => build_ebpf(release),
        Commands::BuildAll { release } => {
            build_ebpf(release)?;
            build_agent(release)
        }
    }
}

fn build_ebpf(release: bool) -> Result<()> {
    // Check for required tools
    check_bpf_linker()?;

    let dir = project_root().join("ebpf-programs");

    // Build eBPF programs for the bpf target
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&dir)
        .env("CARGO_CFG_BPF_TARGET_ARCH", std::env::consts::ARCH)
        .args([
            "+nightly",
            "build",
            "--target",
            "bpfel-unknown-none",
            "-Z",
            "build-std=core",
        ]);

    if release {
        cmd.arg("--release");
    }

    println!("Building eBPF programs...");
    println!("Running: {:?}", cmd);

    let status = cmd
        .status()
        .context("Failed to execute cargo build for eBPF")?;

    if !status.success() {
        bail!("eBPF build failed");
    }

    // Copy built program to installation location
    let profile = if release { "release" } else { "debug" };
    let src = dir.join(format!(
        "target/bpfel-unknown-none/{}/tamandua-ebpf",
        profile
    ));
    let dest_dir = PathBuf::from("/opt/tamandua/ebpf");

    if src.exists() {
        std::fs::create_dir_all(&dest_dir).ok();
        let dest = dest_dir.join("tamandua-ebpf");
        if dest_dir.exists() {
            std::fs::copy(&src, &dest)
                .context("Failed to copy eBPF program to /opt/tamandua/ebpf")?;
            println!("eBPF program installed to {}", dest.display());
        } else {
            println!("Note: /opt/tamandua/ebpf doesn't exist. Install manually:");
            println!("  sudo mkdir -p /opt/tamandua/ebpf");
            println!("  sudo cp {} /opt/tamandua/ebpf/", src.display());
        }
    }

    println!("eBPF build completed successfully");
    Ok(())
}

fn build_agent(release: bool) -> Result<()> {
    let dir = project_root();

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&dir).args(["build", "--features", "ebpf"]);

    if release {
        cmd.arg("--release");
    }

    println!("Building agent with eBPF support...");

    let status = cmd.status().context("Failed to build agent")?;

    if !status.success() {
        bail!("Agent build failed");
    }

    println!("Agent build completed successfully");
    Ok(())
}

fn check_bpf_linker() -> Result<()> {
    let status = Command::new("bpf-linker").arg("--version").status();

    match status {
        Ok(s) if s.success() => Ok(()),
        _ => {
            println!("bpf-linker not found. Installing...");

            let status = Command::new("cargo")
                .args(["install", "bpf-linker"])
                .status()
                .context("Failed to install bpf-linker")?;

            if !status.success() {
                bail!(
                    "Failed to install bpf-linker. Please install manually:\n\
                    cargo install bpf-linker"
                );
            }
            Ok(())
        }
    }
}

fn project_root() -> PathBuf {
    let dir = std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::current_dir().unwrap());

    // xtask is in a subdirectory, go up one level
    dir.parent().map(|p| p.to_path_buf()).unwrap_or(dir)
}
