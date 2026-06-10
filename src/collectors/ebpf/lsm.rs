//! LSM BPF Hook Loader with Fallback Strategy
//!
//! This module implements Linux Security Module (LSM) BPF hooks for kernel >= 5.7,
//! with automatic fallback to kprobes/tracepoints for older kernels.
//!
//! ## Hook Strategy
//!
//! 1. **Kernel >= 5.7**: Use BPF_LSM program type (preferred)
//! 2. **Kernel >= 5.4**: Use kprobes on LSM functions (good coverage)
//! 3. **Kernel >= 4.17**: Use tracepoints (limited coverage)
//! 4. **Kernel < 4.17**: Use raw tracepoints (minimal coverage)
//!
//! ## Hook Points
//!
//! - file_open: Monitor file access
//! - file_permission: Detect sensitive file access
//! - task_create/task_kill: Process lifecycle and signal authorization
//! - socket_connect/socket_bind: Network connection monitoring
//! - ptrace_access_check: Debug/injection detection
//! - bprm_check_security: Process execution authorization
//! - mmap_file: Memory mapping with PROT_EXEC detection
//!
//! ## Safety
//!
//! This module uses unsafe code to interface with the kernel via BPF. All BPF programs
//! are verified by the kernel verifier before loading. Userspace code uses safe abstractions
//! provided by the `aya` library.

use anyhow::{anyhow, Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{Array, HashMap, LruHashMap, PerCpuArray, RingBuf},
    programs::{KProbe, Lsm, ProgramError, RawTracePoint, TracePoint},
    Ebpf,
};
use aya_log::EbpfLogger;
use std::fs;
use std::path::Path;
use tracing::{debug, error, info, warn};

use tamandua_ebpf_common::*;

/// Kernel version structure for feature detection
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct KernelVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl KernelVersion {
    /// Parse kernel version from string (e.g., "5.15.0-91-generic")
    pub fn from_string(version: &str) -> Result<Self> {
        let parts: Vec<&str> = version.split(&['.', '-'][..]).collect();
        if parts.len() < 3 {
            return Err(anyhow!("Invalid kernel version format: {}", version));
        }

        Ok(Self {
            major: parts[0].parse().context("Invalid major version")?,
            minor: parts[1].parse().context("Invalid minor version")?,
            patch: parts[2].parse().context("Invalid patch version")?,
        })
    }

    /// Get current running kernel version
    pub fn current() -> Result<Self> {
        let uname = nix::sys::utsname::uname().context("Failed to get kernel version")?;
        let release = uname
            .release()
            .to_str()
            .context("Invalid UTF-8 in kernel version")?;
        Self::from_string(release)
    }

    /// Check if LSM BPF is supported (>= 5.7)
    pub fn supports_lsm_bpf(&self) -> bool {
        *self
            >= Self {
                major: 5,
                minor: 7,
                patch: 0,
            }
    }

    /// Check if BTF is available (>= 5.2)
    pub fn supports_btf(&self) -> bool {
        *self
            >= Self {
                major: 5,
                minor: 2,
                patch: 0,
            }
    }

    /// Check if kprobes are stable (>= 5.4)
    pub fn supports_kprobes(&self) -> bool {
        *self
            >= Self {
                major: 5,
                minor: 4,
                patch: 0,
            }
    }

    /// Check if tracepoints are available (>= 4.17)
    pub fn supports_tracepoints(&self) -> bool {
        *self
            >= Self {
                major: 4,
                minor: 17,
                patch: 0,
            }
    }

    /// Check if raw tracepoints are available (>= 4.15)
    pub fn supports_raw_tracepoints(&self) -> bool {
        *self
            >= Self {
                major: 4,
                minor: 15,
                patch: 0,
            }
    }
}

/// LSM hook types that we support
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LsmHookType {
    FileOpen,
    FilePermission,
    TaskCreate,
    TaskKill,
    SocketConnect,
    SocketBind,
    PtraceAccessCheck,
    BprmCheckSecurity,
    MmapFile,
}

impl LsmHookType {
    /// Get the LSM hook name for BPF_LSM
    pub fn lsm_name(&self) -> &'static str {
        match self {
            Self::FileOpen => "file_open",
            Self::FilePermission => "file_permission",
            Self::TaskCreate => "task_alloc",
            Self::TaskKill => "task_kill",
            Self::SocketConnect => "socket_connect",
            Self::SocketBind => "socket_bind",
            Self::PtraceAccessCheck => "ptrace_access_check",
            Self::BprmCheckSecurity => "bprm_check_security",
            Self::MmapFile => "mmap_file",
        }
    }

    /// Get the kprobe function name for fallback
    pub fn kprobe_name(&self) -> &'static str {
        match self {
            Self::FileOpen => "security_file_open",
            Self::FilePermission => "security_file_permission",
            Self::TaskCreate => "security_task_alloc",
            Self::TaskKill => "security_task_kill",
            Self::SocketConnect => "security_socket_connect",
            Self::SocketBind => "security_socket_bind",
            Self::PtraceAccessCheck => "security_ptrace_access_check",
            Self::BprmCheckSecurity => "security_bprm_check",
            Self::MmapFile => "security_mmap_file",
        }
    }

    /// Get the tracepoint category and name for fallback
    pub fn tracepoint_name(&self) -> Option<(&'static str, &'static str)> {
        match self {
            // LSM-specific tracepoints (available in some kernels)
            Self::FileOpen => Some(("lsm", "file_open")),
            Self::FilePermission => Some(("lsm", "file_permission")),
            Self::TaskKill => Some(("signal", "signal_generate")),
            Self::BprmCheckSecurity => Some(("sched", "sched_process_exec")),
            // Others may not have direct tracepoint equivalents
            _ => None,
        }
    }
}

/// Attachment strategy for LSM hooks
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachStrategy {
    /// Use BPF_LSM (kernel >= 5.7)
    LsmBpf,
    /// Use kprobes (kernel >= 5.4)
    Kprobe,
    /// Use tracepoints (kernel >= 4.17)
    Tracepoint,
    /// Use raw tracepoints (kernel >= 4.15)
    RawTracepoint,
    /// Cannot attach (kernel too old)
    Unsupported,
}

impl AttachStrategy {
    /// Determine the best attachment strategy for the current kernel
    pub fn for_kernel(version: &KernelVersion) -> Self {
        if version.supports_lsm_bpf() {
            Self::LsmBpf
        } else if version.supports_kprobes() {
            Self::Kprobe
        } else if version.supports_tracepoints() {
            Self::Tracepoint
        } else if version.supports_raw_tracepoints() {
            Self::RawTracepoint
        } else {
            Self::Unsupported
        }
    }
}

/// LSM BPF hook manager
pub struct LsmHookManager {
    /// eBPF object loaded in kernel
    ebpf: Ebpf,
    /// Kernel version we're running on
    kernel_version: KernelVersion,
    /// Selected attachment strategy
    strategy: AttachStrategy,
    /// Configuration for filtering
    config: EbpfConfig,
}

impl LsmHookManager {
    /// Load LSM hooks with automatic fallback
    pub fn load() -> Result<Self> {
        let kernel_version = KernelVersion::current()?;
        info!(
            "Detected kernel version: {}.{}.{}",
            kernel_version.major, kernel_version.minor, kernel_version.patch
        );

        let strategy = AttachStrategy::for_kernel(&kernel_version);
        info!("Selected attachment strategy: {:?}", strategy);

        if matches!(strategy, AttachStrategy::Unsupported) {
            return Err(anyhow!(
                "Kernel version {}.{}.{} is too old for eBPF LSM hooks",
                kernel_version.major,
                kernel_version.minor,
                kernel_version.patch
            ));
        }

        // Load the eBPF bytecode
        let ebpf = Self::load_ebpf(&kernel_version, &strategy)?;

        // Default configuration (all enabled)
        let config = EbpfConfig {
            enabled: 1,
            process_enabled: 1,
            file_enabled: 1,
            network_enabled: 1,
            security_enabled: 1,
            container_enabled: 1,
            lsm_enabled: 1,
            xdp_enabled: 0,
            filter_uid: 0,
            containers_only: 0,
            sensitive_files_enabled: 1,
            filter_low_pids: 1,
            _pad: [0; 1],
        };

        Ok(Self {
            ebpf,
            kernel_version,
            strategy,
            config,
        })
    }

    /// Load eBPF bytecode
    fn load_ebpf(_kernel_version: &KernelVersion, _strategy: &AttachStrategy) -> Result<Ebpf> {
        // In production, this would load the compiled BPF object
        // For now, we use the embedded bytecode from the ebpf-programs crate

        // Check if BPF object exists
        let bpf_path = Path::new("/opt/tamandua/bpf/tamandua-ebpf.o");
        let ebpf_bytes = if bpf_path.exists() {
            fs::read(bpf_path).context("Failed to read BPF object file")?
        } else {
            // Fall back to embedded bytecode (included at compile time)
            include_bytes_aligned!(
                "../../../../../../target/bpfel-unknown-none/release/tamandua-ebpf"
            )
            .to_vec()
        };

        // Load BPF with BTF if available
        let mut ebpf = Ebpf::load(&ebpf_bytes).context("Failed to load eBPF program")?;

        // Initialize eBPF logger (for bpf_printk debugging)
        if let Err(e) = EbpfLogger::init(&mut ebpf) {
            warn!("Failed to initialize eBPF logger: {}", e);
        }

        Ok(ebpf)
    }

    /// Attach LSM hooks using the selected strategy
    pub fn attach(&mut self) -> Result<()> {
        info!("Attaching LSM hooks using strategy: {:?}", self.strategy);

        // Set initial configuration
        self.set_config(self.config)?;

        // Initialize host namespace cache for container escape detection
        self.init_host_namespace_cache()?;

        match self.strategy {
            AttachStrategy::LsmBpf => self.attach_lsm_hooks(),
            AttachStrategy::Kprobe => self.attach_kprobe_hooks(),
            AttachStrategy::Tracepoint => self.attach_tracepoint_hooks(),
            AttachStrategy::RawTracepoint => self.attach_raw_tracepoint_hooks(),
            AttachStrategy::Unsupported => Err(anyhow!("Unsupported kernel version")),
        }
    }

    /// Attach using BPF_LSM (preferred method for kernel >= 5.7)
    fn attach_lsm_hooks(&mut self) -> Result<()> {
        let hooks = [
            LsmHookType::FileOpen,
            LsmHookType::FilePermission,
            LsmHookType::TaskKill,
            LsmHookType::SocketConnect,
            LsmHookType::SocketBind,
            LsmHookType::BprmCheckSecurity,
            LsmHookType::MmapFile,
            LsmHookType::PtraceAccessCheck,
        ];

        for hook in &hooks {
            let prog_name = format!("lsm_{}", hook.lsm_name());
            match self.ebpf.program_mut(&prog_name) {
                Some(program) => {
                    let lsm: &mut Lsm = program
                        .try_into()
                        .context(format!("Failed to get LSM program: {}", prog_name))?;

                    lsm.load()
                        .context(format!("Failed to load LSM hook: {:?}", hook))?;
                    lsm.attach()
                        .context(format!("Failed to attach LSM hook: {:?}", hook))?;

                    info!("Attached LSM hook: {:?}", hook);
                }
                None => {
                    warn!("LSM program not found: {}", prog_name);
                }
            }
        }

        // Also attach process monitoring tracepoints
        self.attach_process_tracepoints()?;

        Ok(())
    }

    /// Attach using kprobes (fallback for kernel >= 5.4)
    fn attach_kprobe_hooks(&mut self) -> Result<()> {
        info!("Using kprobe fallback for LSM hooks");

        let hooks = [
            LsmHookType::FileOpen,
            LsmHookType::FilePermission,
            LsmHookType::TaskKill,
            LsmHookType::SocketConnect,
            LsmHookType::SocketBind,
            LsmHookType::BprmCheckSecurity,
            LsmHookType::MmapFile,
        ];

        for hook in &hooks {
            let kprobe_fn = hook.kprobe_name();
            let prog_name = format!("kprobe_{}", kprobe_fn);

            match self.ebpf.program_mut(&prog_name) {
                Some(program) => {
                    let kprobe: &mut KProbe = program
                        .try_into()
                        .context(format!("Failed to get kprobe program: {}", prog_name))?;

                    kprobe
                        .load()
                        .context(format!("Failed to load kprobe: {}", kprobe_fn))?;
                    kprobe
                        .attach(kprobe_fn, 0)
                        .context(format!("Failed to attach kprobe: {}", kprobe_fn))?;

                    info!("Attached kprobe: {} -> {:?}", kprobe_fn, hook);
                }
                None => {
                    // Try without 'security_' prefix (some kernels use different naming)
                    let alt_name = kprobe_fn.strip_prefix("security_").unwrap_or(kprobe_fn);
                    if let Some(program) = self.ebpf.program_mut(alt_name) {
                        let kprobe: &mut KProbe = program.try_into()?;
                        if let Err(e) = kprobe.load().and_then(|_| kprobe.attach(alt_name, 0)) {
                            warn!("Failed to attach kprobe {}: {}", alt_name, e);
                        } else {
                            info!("Attached kprobe: {} -> {:?}", alt_name, hook);
                        }
                    } else {
                        warn!("Kprobe program not found: {}", prog_name);
                    }
                }
            }
        }

        // Attach process monitoring
        self.attach_process_tracepoints()?;

        Ok(())
    }

    /// Attach using tracepoints (fallback for kernel >= 4.17)
    fn attach_tracepoint_hooks(&mut self) -> Result<()> {
        info!("Using tracepoint fallback for LSM hooks");

        let hooks = [
            LsmHookType::FileOpen,
            LsmHookType::TaskKill,
            LsmHookType::BprmCheckSecurity,
        ];

        for hook in &hooks {
            if let Some((category, name)) = hook.tracepoint_name() {
                let prog_name = format!("tp_{}_{}", category, name);

                match self.ebpf.program_mut(&prog_name) {
                    Some(program) => {
                        let tp: &mut TracePoint = program
                            .try_into()
                            .context(format!("Failed to get tracepoint program: {}", prog_name))?;

                        tp.load()
                            .context(format!("Failed to load tracepoint: {}/{}", category, name))?;
                        tp.attach(category, name).context(format!(
                            "Failed to attach tracepoint: {}/{}",
                            category, name
                        ))?;

                        info!("Attached tracepoint: {}/{} -> {:?}", category, name, hook);
                    }
                    None => {
                        warn!("Tracepoint program not found: {}", prog_name);
                    }
                }
            }
        }

        // Attach process monitoring
        self.attach_process_tracepoints()?;

        Ok(())
    }

    /// Attach using raw tracepoints (minimal fallback for kernel >= 4.15)
    fn attach_raw_tracepoint_hooks(&mut self) -> Result<()> {
        warn!("Using raw tracepoint fallback - limited coverage");

        // Only process execution is reliably available via raw tracepoints
        self.attach_process_tracepoints()?;

        info!("Attached minimal raw tracepoint hooks");
        Ok(())
    }

    /// Attach process monitoring tracepoints (available on all supported kernels)
    fn attach_process_tracepoints(&mut self) -> Result<()> {
        let tracepoints = [
            ("sched", "sched_process_exec"),
            ("sched", "sched_process_exit"),
            ("sched", "sched_process_fork"),
        ];

        for (category, name) in &tracepoints {
            let prog_name = if *category == "sched" && *name == "sched_process_exec" {
                // Try BTF tracepoint first
                if self.kernel_version.supports_btf() {
                    "tp_sched_process_exec".to_string()
                } else {
                    format!("{}_{}", category, name)
                }
            } else {
                format!("{}_{}", category, name)
            };

            match self.ebpf.program_mut(&prog_name) {
                Some(program) => {
                    let tp: &mut TracePoint = program
                        .try_into()
                        .context(format!("Failed to get tracepoint: {}", prog_name))?;

                    tp.load()
                        .context(format!("Failed to load tracepoint: {}/{}", category, name))?;
                    tp.attach(category, name).context(format!(
                        "Failed to attach tracepoint: {}/{}",
                        category, name
                    ))?;

                    debug!("Attached process tracepoint: {}/{}", category, name);
                }
                None => {
                    warn!("Process tracepoint not found: {}", prog_name);
                }
            }
        }

        Ok(())
    }

    /// Initialize host namespace cache for container escape detection
    fn init_host_namespace_cache(&mut self) -> Result<()> {
        let mut cache: Array<_, HostNamespaceIds> = Array::try_from(
            self.ebpf
                .map_mut("HOST_NS_CACHE")
                .context("HOST_NS_CACHE map not found")?,
        )?;

        // Read host namespace IDs from /proc/1/ns/
        let mnt_ns = Self::read_namespace_id("/proc/1/ns/mnt")?;
        let pid_ns = Self::read_namespace_id("/proc/1/ns/pid")?;
        let net_ns = Self::read_namespace_id("/proc/1/ns/net")?;
        let user_ns = Self::read_namespace_id("/proc/1/ns/user")?;

        let host_ids = HostNamespaceIds {
            mnt_ns,
            pid_ns,
            net_ns,
            user_ns,
            initialized: 1,
            _pad: [0; 3],
        };

        cache
            .set(0, host_ids, 0)
            .context("Failed to set host namespace cache")?;

        info!(
            "Initialized host namespace cache: mnt={}, pid={}, net={}, user={}",
            mnt_ns, pid_ns, net_ns, user_ns
        );

        Ok(())
    }

    /// Read namespace ID from /proc
    fn read_namespace_id(path: &str) -> Result<u32> {
        let link =
            fs::read_link(path).context(format!("Failed to read namespace link: {}", path))?;
        let link_str = link.to_string_lossy();

        // Parse "type:[id]" format
        let id_str = link_str
            .split(':')
            .nth(1)
            .and_then(|s| s.strip_prefix('['))
            .and_then(|s| s.strip_suffix(']'))
            .context(format!("Invalid namespace link format: {}", link_str))?;

        id_str
            .parse::<u32>()
            .context(format!("Invalid namespace ID: {}", id_str))
    }

    /// Set runtime configuration
    pub fn set_config(&mut self, config: EbpfConfig) -> Result<()> {
        let mut config_map: Array<_, EbpfConfig> = Array::try_from(
            self.ebpf
                .map_mut("CONFIG")
                .context("CONFIG map not found")?,
        )?;

        config_map
            .set(0, config, 0)
            .context("Failed to set config")?;
        self.config = config;

        debug!("Updated eBPF configuration");
        Ok(())
    }

    /// Get ring buffer for reading events
    pub fn event_ring_buffer(&mut self) -> Result<RingBuf<&mut aya::maps::MapData>> {
        RingBuf::try_from(
            self.ebpf
                .map_mut("EVENTS")
                .context("EVENTS map not found")?,
        )
        .context("Failed to get event ring buffer")
    }

    /// Get priority ring buffer for reading high-priority events
    pub fn priority_ring_buffer(&mut self) -> Result<RingBuf<&mut aya::maps::MapData>> {
        RingBuf::try_from(
            self.ebpf
                .map_mut("EVENTS_PRIORITY")
                .context("EVENTS_PRIORITY map not found")?,
        )
        .context("Failed to get priority event ring buffer")
    }

    /// Get statistics from eBPF programs
    pub fn get_stats(&mut self) -> Result<EbpfStats> {
        let stats_map: PerCpuArray<_, EbpfStats> =
            PerCpuArray::try_from(self.ebpf.map_mut("STATS").context("STATS map not found")?)?;

        // Aggregate per-CPU stats
        let mut total_stats = EbpfStats::default();

        // Sum across all CPUs
        for cpu_idx in 0..num_cpus::get() as u32 {
            if let Ok(cpu_stats) = stats_map.get(&cpu_idx, 0) {
                total_stats.events_generated += cpu_stats.events_generated;
                total_stats.events_dropped_full += cpu_stats.events_dropped_full;
                total_stats.events_rate_limited += cpu_stats.events_rate_limited;
                total_stats.map_lookup_failures += cpu_stats.map_lookup_failures;
                total_stats.probe_read_failures += cpu_stats.probe_read_failures;
            }
        }

        Ok(total_stats)
    }

    /// Add sensitive file path to monitoring list
    pub fn add_sensitive_file(&mut self, path: &str, level: u32) -> Result<()> {
        let mut sensitive_files: HashMap<_, [u8; MAX_PATH_LEN], u32> = HashMap::try_from(
            self.ebpf
                .map_mut("SENSITIVE_FILES")
                .context("SENSITIVE_FILES map not found")?,
        )?;

        let mut path_bytes = [0u8; MAX_PATH_LEN];
        let bytes = path.as_bytes();
        let len = bytes.len().min(MAX_PATH_LEN);
        path_bytes[..len].copy_from_slice(&bytes[..len]);

        sensitive_files
            .insert(path_bytes, level, 0)
            .context("Failed to add sensitive file")?;

        debug!("Added sensitive file: {} (level {})", path, level);
        Ok(())
    }

    /// Get kernel version
    pub fn kernel_version(&self) -> &KernelVersion {
        &self.kernel_version
    }

    /// Get attachment strategy
    pub fn strategy(&self) -> AttachStrategy {
        self.strategy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_version_parsing() {
        let v1 = KernelVersion::from_string("5.15.0-91-generic").unwrap();
        assert_eq!(v1.major, 5);
        assert_eq!(v1.minor, 15);
        assert_eq!(v1.patch, 0);

        let v2 = KernelVersion::from_string("6.1.2").unwrap();
        assert_eq!(v2.major, 6);
        assert_eq!(v2.minor, 1);
        assert_eq!(v2.patch, 2);
    }

    #[test]
    fn test_kernel_version_comparison() {
        let v1 = KernelVersion {
            major: 5,
            minor: 7,
            patch: 0,
        };
        let v2 = KernelVersion {
            major: 5,
            minor: 6,
            patch: 19,
        };
        let v3 = KernelVersion {
            major: 5,
            minor: 7,
            patch: 1,
        };

        assert!(v1 > v2);
        assert!(v3 > v1);
        assert!(v1.supports_lsm_bpf());
        assert!(!v2.supports_lsm_bpf());
    }

    #[test]
    fn test_attachment_strategy() {
        let v1 = KernelVersion {
            major: 5,
            minor: 7,
            patch: 0,
        };
        assert_eq!(AttachStrategy::for_kernel(&v1), AttachStrategy::LsmBpf);

        let v2 = KernelVersion {
            major: 5,
            minor: 4,
            patch: 0,
        };
        assert_eq!(AttachStrategy::for_kernel(&v2), AttachStrategy::Kprobe);

        let v3 = KernelVersion {
            major: 4,
            minor: 17,
            patch: 0,
        };
        assert_eq!(AttachStrategy::for_kernel(&v3), AttachStrategy::Tracepoint);

        let v4 = KernelVersion {
            major: 4,
            minor: 14,
            patch: 0,
        };
        assert_eq!(AttachStrategy::for_kernel(&v4), AttachStrategy::Unsupported);
    }

    #[test]
    fn test_lsm_hook_names() {
        assert_eq!(LsmHookType::FileOpen.lsm_name(), "file_open");
        assert_eq!(LsmHookType::FileOpen.kprobe_name(), "security_file_open");
        assert_eq!(
            LsmHookType::FileOpen.tracepoint_name(),
            Some(("lsm", "file_open"))
        );
    }
}
