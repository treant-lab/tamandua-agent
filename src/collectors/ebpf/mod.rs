//! eBPF Collectors Module
//!
//! This module provides eBPF-based telemetry collection for Linux systems.
//! It includes LSM hooks with automatic fallback for older kernels.
//!
//! ## Features
//!
//! - **LSM Hooks (kernel >= 5.7)**: Direct security module integration
//! - **Kprobe Fallback (kernel >= 5.4)**: Hook LSM functions via kprobes
//! - **Tracepoint Fallback (kernel >= 4.17)**: Use stable kernel tracepoints
//! - **Raw Tracepoint Fallback (kernel >= 4.15)**: Minimal coverage
//! - **CO-RE (Compile Once, Run Everywhere)**: BTF-based portability
//!
//! ## Usage
//!
//! ```rust,no_run
//! use tamandua_agent::collectors::ebpf::lsm::LsmHookManager;
//!
//! // Load and attach hooks with automatic fallback
//! let mut manager = LsmHookManager::load()?;
//! manager.attach()?;
//!
//! // Read events
//! let mut ring_buf = manager.event_ring_buffer()?;
//! loop {
//!     if let Ok(events) = ring_buf.read() {
//!         for event in events {
//!             // Process event
//!         }
//!     }
//! }
//! # Ok::<(), anyhow::Error>(())
//! ```

pub mod fallback;
pub mod lsm;

#[cfg(test)]
mod lsm_tests;

// Re-export commonly used types
pub use fallback::{AttachMethod, FallbackStrategy, KprobeFallbackTable};
pub use lsm::{AttachStrategy, KernelVersion, LsmHookManager, LsmHookType};

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

/// eBPF collector manager (LEGACY)
///
/// # LEGACY: superseded by `EbpfLinuxCollector`
///
/// This type is the original libbpf-style entry point for eBPF-based telemetry
/// collection on Linux. It manages the `LsmHookManager` lifecycle (load → attach →
/// stop) and exposes config / sensitive-file / stats helpers. It does **not**
/// implement the `next_event()` collector interface used by the rest of the
/// agent, and it is **not** wired into `start_collectors()` in `main.rs`.
///
/// The live, production eBPF collector is
/// [`crate::collectors::ebpf_linux::EbpfLinuxCollector`] (aya-based). New code
/// should use that collector exclusively. `EbpfCollectorManager` is preserved
/// only because it is still gated behind the Linux-only `feature = "ebpf"`
/// build (see `collectors/mod.rs`) and removing it would require coordinated
/// changes that cannot be validated on non-Linux developer hosts. It will be
/// removed once the `EbpfLinuxCollector` migration is fully verified on a Linux
/// target and the `feature = "ebpf"` gate is reconciled with `ebpf_linux`.
///
/// Do not add new call sites. If you need lifecycle management for the
/// aya-based collector, extend `EbpfLinuxCollector` instead.
#[deprecated(
    since = "0.1.0",
    note = "use EbpfLinuxCollector in collectors::ebpf_linux; this libbpf-style \
            manager is not wired into the collector loop and will be removed \
            once the aya-based migration is fully verified on Linux"
)]
pub struct EbpfCollectorManager {
    /// LSM hook manager
    lsm_manager: Arc<Mutex<LsmHookManager>>,
    /// Whether the collector is running
    running: Arc<Mutex<bool>>,
}

#[allow(deprecated)]
impl EbpfCollectorManager {
    /// Create a new eBPF collector manager
    pub async fn new() -> Result<Self> {
        info!("Initializing eBPF collector manager");

        let lsm_manager = LsmHookManager::load()?;
        info!(
            "Loaded eBPF programs for kernel {}.{}.{} using strategy: {:?}",
            lsm_manager.kernel_version().major,
            lsm_manager.kernel_version().minor,
            lsm_manager.kernel_version().patch,
            lsm_manager.strategy()
        );

        Ok(Self {
            lsm_manager: Arc::new(Mutex::new(lsm_manager)),
            running: Arc::new(Mutex::new(false)),
        })
    }

    /// Start the eBPF collector
    pub async fn start(&self) -> Result<()> {
        let mut running = self.running.lock().await;
        if *running {
            warn!("eBPF collector already running");
            return Ok(());
        }

        info!("Starting eBPF collector");

        // Attach LSM hooks
        let mut lsm_manager = self.lsm_manager.lock().await;
        lsm_manager.attach()?;

        *running = true;
        info!("eBPF collector started successfully");

        Ok(())
    }

    /// Stop the eBPF collector
    pub async fn stop(&self) -> Result<()> {
        let mut running = self.running.lock().await;
        if !*running {
            warn!("eBPF collector not running");
            return Ok(());
        }

        info!("Stopping eBPF collector");

        // BPF programs are automatically detached when dropped
        *running = false;

        info!("eBPF collector stopped");
        Ok(())
    }

    /// Check if the collector is running
    pub async fn is_running(&self) -> bool {
        *self.running.lock().await
    }

    /// Get statistics from eBPF programs
    pub async fn get_stats(&self) -> Result<tamandua_ebpf_common::EbpfStats> {
        let mut lsm_manager = self.lsm_manager.lock().await;
        lsm_manager.get_stats()
    }

    /// Update runtime configuration
    pub async fn update_config(&self, config: tamandua_ebpf_common::EbpfConfig) -> Result<()> {
        let mut lsm_manager = self.lsm_manager.lock().await;
        lsm_manager.set_config(config)
    }

    /// Add a sensitive file path to monitor
    pub async fn add_sensitive_file(&self, path: &str, level: u32) -> Result<()> {
        let mut lsm_manager = self.lsm_manager.lock().await;
        lsm_manager.add_sensitive_file(path, level)
    }

    /// Get kernel version
    pub async fn kernel_version(&self) -> KernelVersion {
        let lsm_manager = self.lsm_manager.lock().await;
        *lsm_manager.kernel_version()
    }

    /// Get attachment strategy
    pub async fn attachment_strategy(&self) -> AttachStrategy {
        let lsm_manager = self.lsm_manager.lock().await;
        lsm_manager.strategy()
    }
}

/// Get kernel capabilities summary
pub fn get_kernel_capabilities() -> Result<KernelCapabilities> {
    let version = KernelVersion::current()?;
    let strategy = AttachStrategy::for_kernel(&version);

    Ok(KernelCapabilities {
        version,
        strategy,
        supports_lsm_bpf: version.supports_lsm_bpf(),
        supports_btf: version.supports_btf(),
        supports_kprobes: version.supports_kprobes(),
        supports_tracepoints: version.supports_tracepoints(),
        supports_raw_tracepoints: version.supports_raw_tracepoints(),
        has_btf_vmlinux: std::path::Path::new("/sys/kernel/btf/vmlinux").exists(),
    })
}

/// Kernel capabilities summary
#[derive(Debug, Clone)]
pub struct KernelCapabilities {
    pub version: KernelVersion,
    pub strategy: AttachStrategy,
    pub supports_lsm_bpf: bool,
    pub supports_btf: bool,
    pub supports_kprobes: bool,
    pub supports_tracepoints: bool,
    pub supports_raw_tracepoints: bool,
    pub has_btf_vmlinux: bool,
}

impl KernelCapabilities {
    /// Get a human-readable summary
    pub fn summary(&self) -> String {
        format!(
            "Kernel {}.{}.{} - Strategy: {:?}\n\
             LSM BPF: {} | BTF: {} | Kprobes: {} | Tracepoints: {} | Raw TP: {}\n\
             BTF vmlinux: {}",
            self.version.major,
            self.version.minor,
            self.version.patch,
            self.strategy,
            if self.supports_lsm_bpf { "✓" } else { "✗" },
            if self.supports_btf { "✓" } else { "✗" },
            if self.supports_kprobes { "✓" } else { "✗" },
            if self.supports_tracepoints {
                "✓"
            } else {
                "✗"
            },
            if self.supports_raw_tracepoints {
                "✓"
            } else {
                "✗"
            },
            if self.has_btf_vmlinux { "✓" } else { "✗" },
        )
    }

    /// Get coverage percentage (estimated)
    pub fn coverage_percentage(&self) -> f64 {
        match self.strategy {
            AttachStrategy::LsmBpf => 100.0,
            AttachStrategy::Kprobe => 90.0,
            AttachStrategy::Tracepoint => 60.0,
            AttachStrategy::RawTracepoint => 20.0,
            AttachStrategy::Unsupported => 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_capabilities() {
        let caps = get_kernel_capabilities().expect("Failed to get kernel capabilities");
        println!("{}", caps.summary());
        println!("Coverage: {:.1}%", caps.coverage_percentage());

        assert!(caps.version.major >= 4, "Kernel too old");
    }

    #[tokio::test]
    #[ignore] // Requires root
    #[allow(deprecated)]
    async fn test_ebpf_manager_lifecycle() -> Result<()> {
        let manager = EbpfCollectorManager::new().await?;

        assert!(!manager.is_running().await);

        manager.start().await?;
        assert!(manager.is_running().await);

        let stats = manager.get_stats().await?;
        println!("Stats: {:?}", stats);

        manager.stop().await?;
        assert!(!manager.is_running().await);

        Ok(())
    }
}
