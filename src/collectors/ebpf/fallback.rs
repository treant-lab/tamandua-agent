//! Fallback Strategy for eBPF LSM Hooks
//!
//! This module implements a comprehensive fallback strategy when BPF_LSM is not available,
//! providing coverage through kprobes, tracepoints, and raw tracepoints.
//!
//! ## Fallback Hierarchy
//!
//! ```text
//! Kernel >= 5.7:  BPF_LSM (preferred)
//!                  ├─ Direct hook into LSM layer
//!                  ├─ Zero overhead
//!                  └─ Full coverage
//!
//! Kernel >= 5.4:  Kprobes
//!                  ├─ Hook LSM functions directly
//!                  ├─ Minimal overhead
//!                  └─ Good coverage
//!
//! Kernel >= 4.17: Tracepoints
//!                  ├─ Use stable kernel tracepoints
//!                  ├─ Low overhead
//!                  └─ Limited coverage
//!
//! Kernel >= 4.15: Raw Tracepoints
//!                  ├─ Minimal stable tracepoints
//!                  ├─ Very low overhead
//!                  └─ Minimal coverage (process exec only)
//! ```
//!
//! ## Coverage Comparison
//!
//! | Feature              | LSM | Kprobe | Tracepoint | Raw TP |
//! |----------------------|-----|--------|------------|--------|
//! | file_open            | ✓   | ✓      | ✓          | ✗      |
//! | file_permission      | ✓   | ✓      | ✓          | ✗      |
//! | socket_connect       | ✓   | ✓      | ✗          | ✗      |
//! | socket_bind          | ✓   | ✓      | ✗          | ✗      |
//! | task_kill            | ✓   | ✓      | ~          | ✗      |
//! | ptrace_access_check  | ✓   | ✓      | ✗          | ✗      |
//! | bprm_check_security  | ✓   | ✓      | ✓          | ✓      |
//! | mmap_file            | ✓   | ✓      | ✗          | ✗      |
//!
//! ✓ = Full support, ~ = Partial support, ✗ = Not available

use anyhow::{anyhow, Context, Result};
use aya::{
    programs::{KProbe, KRetProbe, RawTracePoint, TracePoint},
    Ebpf,
};
use std::collections::HashMap;
use tracing::{debug, info, warn};

use super::lsm::{KernelVersion, LsmHookType};

/// Fallback hook configuration
#[derive(Debug, Clone)]
pub struct FallbackHook {
    /// Hook type
    pub hook_type: LsmHookType,
    /// Priority (0 = highest)
    pub priority: u8,
    /// Whether this hook is critical (must succeed)
    pub critical: bool,
}

/// Fallback strategy manager
pub struct FallbackStrategy {
    /// Kernel version we're running on
    kernel_version: KernelVersion,
    /// Successfully attached hooks
    attached_hooks: HashMap<LsmHookType, AttachedHook>,
}

/// Information about an attached hook
#[derive(Debug)]
pub struct AttachedHook {
    pub hook_type: LsmHookType,
    pub method: AttachMethod,
    pub function_name: String,
}

/// Method used to attach hook
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachMethod {
    Lsm,
    Kprobe,
    KretProbe,
    Tracepoint,
    RawTracepoint,
}

impl FallbackStrategy {
    /// Create new fallback strategy for the given kernel version
    pub fn new(kernel_version: KernelVersion) -> Self {
        Self {
            kernel_version,
            attached_hooks: HashMap::new(),
        }
    }

    /// Attach all hooks with fallback
    pub fn attach_all(&mut self, ebpf: &mut Ebpf) -> Result<()> {
        let hooks = Self::get_hook_priorities();

        for hook_config in hooks {
            if let Err(e) = self.attach_with_fallback(ebpf, &hook_config) {
                if hook_config.critical {
                    return Err(e).context(format!(
                        "Failed to attach critical hook: {:?}",
                        hook_config.hook_type
                    ));
                } else {
                    warn!(
                        "Failed to attach non-critical hook {:?}: {}",
                        hook_config.hook_type, e
                    );
                }
            }
        }

        self.log_coverage();
        Ok(())
    }

    /// Get hook priorities (critical hooks first)
    fn get_hook_priorities() -> Vec<FallbackHook> {
        vec![
            // Critical: Process execution (required for EDR)
            FallbackHook {
                hook_type: LsmHookType::BprmCheckSecurity,
                priority: 0,
                critical: true,
            },
            // Critical: File operations
            FallbackHook {
                hook_type: LsmHookType::FileOpen,
                priority: 1,
                critical: true,
            },
            FallbackHook {
                hook_type: LsmHookType::FilePermission,
                priority: 2,
                critical: false,
            },
            // Critical: Network operations
            FallbackHook {
                hook_type: LsmHookType::SocketConnect,
                priority: 3,
                critical: true,
            },
            FallbackHook {
                hook_type: LsmHookType::SocketBind,
                priority: 4,
                critical: false,
            },
            // Important: Security operations
            FallbackHook {
                hook_type: LsmHookType::TaskKill,
                priority: 5,
                critical: false,
            },
            FallbackHook {
                hook_type: LsmHookType::PtraceAccessCheck,
                priority: 6,
                critical: false,
            },
            FallbackHook {
                hook_type: LsmHookType::MmapFile,
                priority: 7,
                critical: false,
            },
            // Low priority
            FallbackHook {
                hook_type: LsmHookType::TaskCreate,
                priority: 8,
                critical: false,
            },
        ]
    }

    /// Attach a hook with automatic fallback
    fn attach_with_fallback(&mut self, ebpf: &mut Ebpf, config: &FallbackHook) -> Result<()> {
        // Try methods in order of preference
        if self.kernel_version.supports_lsm_bpf() {
            if let Ok(attached) = self.try_attach_lsm(ebpf, config.hook_type) {
                self.attached_hooks.insert(config.hook_type, attached);
                return Ok(());
            }
        }

        if self.kernel_version.supports_kprobes() {
            if let Ok(attached) = self.try_attach_kprobe(ebpf, config.hook_type) {
                self.attached_hooks.insert(config.hook_type, attached);
                return Ok(());
            }
        }

        if self.kernel_version.supports_tracepoints() {
            if let Ok(attached) = self.try_attach_tracepoint(ebpf, config.hook_type) {
                self.attached_hooks.insert(config.hook_type, attached);
                return Ok(());
            }
        }

        if self.kernel_version.supports_raw_tracepoints() {
            if let Ok(attached) = self.try_attach_raw_tracepoint(ebpf, config.hook_type) {
                self.attached_hooks.insert(config.hook_type, attached);
                return Ok(());
            }
        }

        Err(anyhow!(
            "No fallback method available for hook: {:?}",
            config.hook_type
        ))
    }

    /// Try to attach using LSM BPF
    fn try_attach_lsm(&self, ebpf: &mut Ebpf, hook_type: LsmHookType) -> Result<AttachedHook> {
        let prog_name = format!("lsm_{}", hook_type.lsm_name());

        let program = ebpf
            .program_mut(&prog_name)
            .ok_or_else(|| anyhow!("LSM program not found: {}", prog_name))?;

        let lsm: &mut aya::programs::Lsm = program
            .try_into()
            .context("Failed to convert to LSM program")?;

        lsm.load().context("Failed to load LSM program")?;
        lsm.attach().context("Failed to attach LSM hook")?;

        info!("Attached LSM hook: {:?} via BPF_LSM", hook_type);

        Ok(AttachedHook {
            hook_type,
            method: AttachMethod::Lsm,
            function_name: hook_type.lsm_name().to_string(),
        })
    }

    /// Try to attach using kprobe
    fn try_attach_kprobe(&self, ebpf: &mut Ebpf, hook_type: LsmHookType) -> Result<AttachedHook> {
        let kprobe_fn = hook_type.kprobe_name();
        let prog_name = format!("kprobe_{}", kprobe_fn);

        let program = ebpf
            .program_mut(&prog_name)
            .ok_or_else(|| anyhow!("Kprobe program not found: {}", prog_name))?;

        let kprobe: &mut KProbe = program.try_into().context("Failed to convert to kprobe")?;

        kprobe.load().context("Failed to load kprobe")?;
        kprobe
            .attach(kprobe_fn, 0)
            .context("Failed to attach kprobe")?;

        info!(
            "Attached LSM hook: {:?} via kprobe {}",
            hook_type, kprobe_fn
        );

        Ok(AttachedHook {
            hook_type,
            method: AttachMethod::Kprobe,
            function_name: kprobe_fn.to_string(),
        })
    }

    /// Try to attach using tracepoint
    fn try_attach_tracepoint(
        &self,
        ebpf: &mut Ebpf,
        hook_type: LsmHookType,
    ) -> Result<AttachedHook> {
        let (category, name) = hook_type
            .tracepoint_name()
            .ok_or_else(|| anyhow!("No tracepoint available for hook: {:?}", hook_type))?;

        let prog_name = format!("tp_{}_{}", category, name);

        let program = ebpf
            .program_mut(&prog_name)
            .ok_or_else(|| anyhow!("Tracepoint program not found: {}", prog_name))?;

        let tp: &mut TracePoint = program
            .try_into()
            .context("Failed to convert to tracepoint")?;

        tp.load().context("Failed to load tracepoint")?;
        tp.attach(category, name)
            .context("Failed to attach tracepoint")?;

        info!(
            "Attached LSM hook: {:?} via tracepoint {}/{}",
            hook_type, category, name
        );

        Ok(AttachedHook {
            hook_type,
            method: AttachMethod::Tracepoint,
            function_name: format!("{}/{}", category, name),
        })
    }

    /// Try to attach using raw tracepoint
    fn try_attach_raw_tracepoint(
        &self,
        ebpf: &mut Ebpf,
        hook_type: LsmHookType,
    ) -> Result<AttachedHook> {
        // Only sched_process_exec is reliably available as raw tracepoint
        if hook_type != LsmHookType::BprmCheckSecurity {
            return Err(anyhow!(
                "No raw tracepoint available for hook: {:?}",
                hook_type
            ));
        }

        let name = "sched_process_exec";
        let prog_name = format!("raw_tp_{}", name);

        let program = ebpf
            .program_mut(&prog_name)
            .ok_or_else(|| anyhow!("Raw tracepoint program not found: {}", prog_name))?;

        let raw_tp: &mut RawTracePoint = program
            .try_into()
            .context("Failed to convert to raw tracepoint")?;

        raw_tp.load().context("Failed to load raw tracepoint")?;
        raw_tp
            .attach(name)
            .context("Failed to attach raw tracepoint")?;

        info!(
            "Attached LSM hook: {:?} via raw tracepoint {}",
            hook_type, name
        );

        Ok(AttachedHook {
            hook_type,
            method: AttachMethod::RawTracepoint,
            function_name: name.to_string(),
        })
    }

    /// Log coverage summary
    fn log_coverage(&self) {
        let total_hooks = LsmHookType::all().len();
        let attached_count = self.attached_hooks.len();
        let coverage = (attached_count as f64 / total_hooks as f64) * 100.0;

        info!(
            "LSM Hook Coverage: {}/{} ({:.1}%)",
            attached_count, total_hooks, coverage
        );

        // Log per-method breakdown
        let mut method_counts: HashMap<AttachMethod, usize> = HashMap::new();
        for hook in self.attached_hooks.values() {
            *method_counts.entry(hook.method).or_insert(0) += 1;
        }

        for (method, count) in method_counts {
            debug!("  {:?}: {} hooks", method, count);
        }

        // Warn about missing critical hooks
        for hook_type in LsmHookType::all() {
            if !self.attached_hooks.contains_key(&hook_type) {
                if Self::is_critical(hook_type) {
                    warn!("Critical hook not attached: {:?}", hook_type);
                } else {
                    debug!("Optional hook not attached: {:?}", hook_type);
                }
            }
        }
    }

    /// Check if a hook type is critical
    fn is_critical(hook_type: LsmHookType) -> bool {
        matches!(
            hook_type,
            LsmHookType::BprmCheckSecurity | LsmHookType::FileOpen | LsmHookType::SocketConnect
        )
    }

    /// Get list of attached hooks
    pub fn attached_hooks(&self) -> &HashMap<LsmHookType, AttachedHook> {
        &self.attached_hooks
    }

    /// Check if a specific hook is attached
    pub fn is_attached(&self, hook_type: LsmHookType) -> bool {
        self.attached_hooks.contains_key(&hook_type)
    }

    /// Get attachment method for a hook
    pub fn get_method(&self, hook_type: LsmHookType) -> Option<AttachMethod> {
        self.attached_hooks.get(&hook_type).map(|h| h.method)
    }
}

impl LsmHookType {
    /// Get all hook types
    pub fn all() -> Vec<LsmHookType> {
        vec![
            Self::FileOpen,
            Self::FilePermission,
            Self::TaskCreate,
            Self::TaskKill,
            Self::SocketConnect,
            Self::SocketBind,
            Self::PtraceAccessCheck,
            Self::BprmCheckSecurity,
            Self::MmapFile,
        ]
    }
}

/// Kprobe fallback table for different kernel versions
pub struct KprobeFallbackTable {
    /// Maps hook type to possible kprobe function names (in order of preference)
    fallbacks: HashMap<LsmHookType, Vec<String>>,
}

impl KprobeFallbackTable {
    /// Create fallback table for the given kernel version
    pub fn for_kernel(version: &KernelVersion) -> Self {
        let mut fallbacks = HashMap::new();

        // file_open variants
        fallbacks.insert(
            LsmHookType::FileOpen,
            vec![
                "security_file_open".to_string(),
                "do_dentry_open".to_string(), // Older kernels
                "vfs_open".to_string(),       // Even older
            ],
        );

        // file_permission variants
        fallbacks.insert(
            LsmHookType::FilePermission,
            vec![
                "security_file_permission".to_string(),
                "inode_permission".to_string(),
            ],
        );

        // socket_connect variants
        fallbacks.insert(
            LsmHookType::SocketConnect,
            vec![
                "security_socket_connect".to_string(),
                "__sys_connect".to_string(),
                "sys_connect".to_string(),
            ],
        );

        // socket_bind variants
        fallbacks.insert(
            LsmHookType::SocketBind,
            vec![
                "security_socket_bind".to_string(),
                "__sys_bind".to_string(),
                "sys_bind".to_string(),
            ],
        );

        // bprm_check_security variants
        fallbacks.insert(
            LsmHookType::BprmCheckSecurity,
            vec![
                "security_bprm_check".to_string(),
                "prepare_binprm".to_string(),
            ],
        );

        // mmap_file variants
        fallbacks.insert(
            LsmHookType::MmapFile,
            vec!["security_mmap_file".to_string(), "do_mmap".to_string()],
        );

        // ptrace variants
        fallbacks.insert(
            LsmHookType::PtraceAccessCheck,
            vec![
                "security_ptrace_access_check".to_string(),
                "ptrace_attach".to_string(),
            ],
        );

        // task_kill variants
        fallbacks.insert(
            LsmHookType::TaskKill,
            vec![
                "security_task_kill".to_string(),
                "kill_pid_info".to_string(),
            ],
        );

        Self { fallbacks }
    }

    /// Get fallback functions for a hook type
    pub fn get_fallbacks(&self, hook_type: LsmHookType) -> Option<&Vec<String>> {
        self.fallbacks.get(&hook_type)
    }

    /// Try to find available kprobe for a hook
    pub fn find_available(&self, hook_type: LsmHookType) -> Option<String> {
        let fallbacks = self.get_fallbacks(hook_type)?;

        for func_name in fallbacks {
            // Check if function exists in /proc/kallsyms
            if Self::function_exists(func_name) {
                return Some(func_name.clone());
            }
        }

        None
    }

    /// Check if a kernel function exists
    fn function_exists(func_name: &str) -> bool {
        // Read /proc/kallsyms to check if function is exported
        if let Ok(kallsyms) = std::fs::read_to_string("/proc/kallsyms") {
            for line in kallsyms.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 && parts[2] == func_name {
                    // Check if it's a function (type 'T' or 't')
                    if parts[1] == "T" || parts[1] == "t" {
                        return true;
                    }
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fallback_table() {
        let version = KernelVersion {
            major: 5,
            minor: 4,
            patch: 0,
        };
        let table = KprobeFallbackTable::for_kernel(&version);

        let fallbacks = table.get_fallbacks(LsmHookType::FileOpen).unwrap();
        assert!(fallbacks.contains(&"security_file_open".to_string()));
    }

    #[test]
    fn test_all_hooks() {
        let hooks = LsmHookType::all();
        assert!(hooks.len() >= 8);
        assert!(hooks.contains(&LsmHookType::FileOpen));
        assert!(hooks.contains(&LsmHookType::BprmCheckSecurity));
    }
}
