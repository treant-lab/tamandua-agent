//! Container runtime detection and configuration.
//!
//! Detects whether the agent is running inside a container and which
//! runtime (Docker, Podman, containerd, etc.) is being used. Also checks
//! for eBPF capabilities and privilege levels.
//!
//! # Example
//!
//! ```no_run
//! use tamandua_agent::config::container::{detect_runtime, get_container_info, ContainerRuntime};
//!
//! let runtime = detect_runtime();
//! match runtime {
//!     ContainerRuntime::Docker => println!("Running in Docker"),
//!     ContainerRuntime::Podman => println!("Running in Podman"),
//!     ContainerRuntime::Containerd => println!("Running in containerd/Kubernetes"),
//!     ContainerRuntime::None => println!("Not running in a container"),
//!     ContainerRuntime::Unknown => println!("Unknown container runtime"),
//! }
//!
//! let info = get_container_info();
//! if info.has_ebpf_access {
//!     println!("eBPF is available");
//! }
//! ```

use std::fs;
use std::path::Path;
use tracing::{debug, info};

/// Container runtime type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ContainerRuntime {
    /// Docker runtime
    Docker,
    /// Podman runtime
    Podman,
    /// containerd (Kubernetes CRI)
    Containerd,
    /// LXC/LXD container
    Lxc,
    /// Not running in a container
    #[default]
    None,
    /// Unknown container runtime
    Unknown,
}

impl std::fmt::Display for ContainerRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Docker => write!(f, "docker"),
            Self::Podman => write!(f, "podman"),
            Self::Containerd => write!(f, "containerd"),
            Self::Lxc => write!(f, "lxc"),
            Self::None => write!(f, "none"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Container environment information.
#[derive(Debug, Clone)]
pub struct ContainerInfo {
    /// Detected container runtime
    pub runtime: ContainerRuntime,
    /// Container ID (if detectable)
    pub container_id: Option<String>,
    /// Whether running with elevated/privileged mode
    pub is_privileged: bool,
    /// Whether eBPF filesystem and capabilities are accessible
    pub has_ebpf_access: bool,
    /// Whether BTF (BPF Type Format) is available for CO-RE
    pub has_btf: bool,
    /// Kernel version string
    pub kernel_version: String,
    /// Host procfs mount path (if different from /proc)
    pub host_proc_path: Option<String>,
}

impl Default for ContainerInfo {
    fn default() -> Self {
        Self {
            runtime: ContainerRuntime::None,
            container_id: None,
            is_privileged: false,
            has_ebpf_access: false,
            has_btf: false,
            kernel_version: String::new(),
            host_proc_path: None,
        }
    }
}

/// Detect the container runtime environment.
///
/// Checks various filesystem markers and cgroup information to determine
/// if the agent is running inside a container and which runtime is being used.
///
/// # Returns
///
/// The detected [`ContainerRuntime`], or `None` if not in a container.
pub fn detect_runtime() -> ContainerRuntime {
    // Check for Docker marker file
    if Path::new("/.dockerenv").exists() {
        debug!("Detected Docker via /.dockerenv marker");
        return ContainerRuntime::Docker;
    }

    // Check for Podman marker file
    if Path::new("/run/.containerenv").exists() {
        debug!("Detected Podman via /run/.containerenv marker");
        return ContainerRuntime::Podman;
    }

    // Check cgroup for container signatures (works for both cgroup v1 and v2)
    if let Some(runtime) = detect_from_cgroup() {
        return runtime;
    }

    // Check mountinfo for container hints
    if let Some(runtime) = detect_from_mountinfo() {
        return runtime;
    }

    // Check environment variables set by container runtimes
    if let Some(runtime) = detect_from_environment() {
        return runtime;
    }

    ContainerRuntime::None
}

/// Detect container runtime from cgroup information.
fn detect_from_cgroup() -> Option<ContainerRuntime> {
    // Try cgroup v1 path first
    let cgroup_content = fs::read_to_string("/proc/1/cgroup").ok()?;

    if cgroup_content.contains("docker") {
        debug!("Detected Docker via cgroup");
        return Some(ContainerRuntime::Docker);
    }
    if cgroup_content.contains("podman") {
        debug!("Detected Podman via cgroup");
        return Some(ContainerRuntime::Podman);
    }
    if cgroup_content.contains("containerd") || cgroup_content.contains("cri-containerd") {
        debug!("Detected containerd via cgroup");
        return Some(ContainerRuntime::Containerd);
    }
    // kubepods indicates Kubernetes, which typically uses containerd
    if cgroup_content.contains("kubepods") {
        debug!("Detected Kubernetes (containerd) via cgroup");
        return Some(ContainerRuntime::Containerd);
    }
    if cgroup_content.contains("lxc") {
        debug!("Detected LXC via cgroup");
        return Some(ContainerRuntime::Lxc);
    }

    // Check if we're in any cgroup namespace (cgroup v2)
    if cgroup_content.contains("0::/") && !cgroup_content.contains("0::/init.scope") {
        // We're in a cgroup namespace but can't determine the runtime
        debug!("Detected unknown container runtime via cgroup v2 namespace");
        return Some(ContainerRuntime::Unknown);
    }

    None
}

/// Detect container runtime from mount information.
fn detect_from_mountinfo() -> Option<ContainerRuntime> {
    let mountinfo = fs::read_to_string("/proc/1/mountinfo").ok()?;

    if mountinfo.contains("/docker/")
        || mountinfo.contains("overlay") && mountinfo.contains("docker")
    {
        debug!("Detected Docker via mountinfo");
        return Some(ContainerRuntime::Docker);
    }
    if mountinfo.contains("/containers/") {
        debug!("Detected containerd via mountinfo");
        return Some(ContainerRuntime::Containerd);
    }

    None
}

/// Detect container runtime from environment variables.
fn detect_from_environment() -> Option<ContainerRuntime> {
    // Check for CONTAINER_RUNTIME environment variable (set by our entrypoint)
    if let Ok(runtime) = std::env::var("CONTAINER_RUNTIME") {
        match runtime.to_lowercase().as_str() {
            "docker" => return Some(ContainerRuntime::Docker),
            "podman" => return Some(ContainerRuntime::Podman),
            "containerd" | "kubernetes" => return Some(ContainerRuntime::Containerd),
            "lxc" => return Some(ContainerRuntime::Lxc),
            "unknown" => return Some(ContainerRuntime::Unknown),
            _ => {}
        }
    }

    // Check for Kubernetes-specific environment variables
    if std::env::var("KUBERNETES_SERVICE_HOST").is_ok() {
        debug!("Detected Kubernetes via KUBERNETES_SERVICE_HOST");
        return Some(ContainerRuntime::Containerd);
    }

    None
}

/// Get container ID from cgroup or environment.
///
/// Attempts to extract the container ID from:
/// 1. Environment variable (CONTAINER_ID, set by entrypoint)
/// 2. Cgroup path (contains 64-character hex ID)
/// 3. Hostname (containers often use short container ID as hostname)
///
/// # Returns
///
/// The container ID (full 64-char or shortened 12-char), or `None` if not detectable.
pub fn get_container_id() -> Option<String> {
    // Check environment variable first (set by our entrypoint)
    if let Ok(id) = std::env::var("CONTAINER_ID") {
        if !id.is_empty() {
            return Some(id);
        }
    }

    // Parse cgroup for container ID (64-char hex string)
    if let Ok(cgroup) = fs::read_to_string("/proc/1/cgroup") {
        // Look for 64-character hex ID in cgroup path
        for line in cgroup.lines() {
            if let Some(id) = extract_container_id_from_path(line) {
                return Some(id);
            }
        }
    }

    // Fallback: hostname might be the container ID
    if let Ok(hostname) = hostname::get() {
        let hostname = hostname.to_string_lossy();
        // Docker uses 12-char hex ID as default hostname
        if hostname.len() == 12 && hostname.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(hostname.to_string());
        }
    }

    None
}

/// Extract container ID from a cgroup path.
fn extract_container_id_from_path(path: &str) -> Option<String> {
    // Look for 64-character hex string (full container ID)
    let hex_chars: String = path.chars().filter(|c| c.is_ascii_hexdigit()).collect();

    // Find sequences of 64 hex characters
    if hex_chars.len() >= 64 {
        for i in 0..=hex_chars.len() - 64 {
            let candidate = &hex_chars[i..i + 64];
            if candidate.chars().all(|c| c.is_ascii_hexdigit()) {
                // Return shortened 12-char ID (like Docker does)
                return Some(candidate[..12].to_string());
            }
        }
    }

    None
}

/// Check if container has eBPF access.
///
/// Verifies that:
/// 1. `/sys/fs/bpf` is mounted (bpffs)
/// 2. `/sys/kernel/debug/tracing` is accessible (debugfs)
///
/// Note: This does not verify actual eBPF syscall capabilities,
/// which requires attempting to load a program.
///
/// # Returns
///
/// `true` if eBPF filesystem requirements are met.
pub fn has_ebpf_access() -> bool {
    let bpffs_available = Path::new("/sys/fs/bpf").exists();
    let debugfs_available = Path::new("/sys/kernel/debug/tracing").exists();

    if !bpffs_available {
        debug!("eBPF: /sys/fs/bpf not available");
    }
    if !debugfs_available {
        debug!("eBPF: /sys/kernel/debug/tracing not available");
    }

    bpffs_available && debugfs_available
}

/// Check if BTF (BPF Type Format) is available for CO-RE.
///
/// BTF enables Compile Once - Run Everywhere (CO-RE) eBPF programs
/// that can run on different kernel versions without recompilation.
///
/// # Returns
///
/// `true` if BTF is available.
pub fn has_btf() -> bool {
    // Check for vmlinux BTF (kernel 5.2+)
    if Path::new("/sys/kernel/btf/vmlinux").exists() {
        debug!("BTF available via /sys/kernel/btf/vmlinux");
        return true;
    }

    // Check for BTF in kernel module
    let kernel_version = get_kernel_version();
    let btf_path = format!("/boot/vmlinux-{}", kernel_version);
    if Path::new(&btf_path).exists() {
        debug!("BTF available via {}", btf_path);
        return true;
    }

    // Check lib/modules for BTF
    let modules_btf = format!("/lib/modules/{}/vmlinux", kernel_version);
    if Path::new(&modules_btf).exists() {
        debug!("BTF available via {}", modules_btf);
        return true;
    }

    debug!("BTF not available");
    false
}

/// Get kernel version string.
fn get_kernel_version() -> String {
    fs::read_to_string("/proc/version")
        .ok()
        .and_then(|v| v.split_whitespace().nth(2).map(|s| s.to_string()))
        .unwrap_or_else(|| "unknown".to_string())
}

/// Check if running with elevated privileges.
///
/// Determines if the container is running with:
/// - Root user (UID 0)
/// - Privileged mode (access to all devices)
/// - Required capabilities for eBPF
///
/// # Returns
///
/// `true` if running with elevated privileges.
pub fn is_privileged() -> bool {
    // Check if running as root
    #[cfg(unix)]
    {
        if unsafe { libc::geteuid() } == 0 {
            // Root user, now check for additional privilege indicators

            // Check for privileged mode (all devices accessible)
            let has_all_devices = Path::new("/dev/mem").exists()
                && std::fs::metadata("/dev/mem")
                    .map(|m| m.permissions().readonly() == false)
                    .unwrap_or(false);

            // Check for CAP_SYS_ADMIN (required for many privileged operations)
            let has_sys_admin = check_capability_sys_admin();

            debug!(
                "Privilege check: root=true, all_devices={}, sys_admin={}",
                has_all_devices, has_sys_admin
            );

            return has_all_devices || has_sys_admin;
        }
    }

    // Non-Unix platforms or non-root
    false
}

/// Check if CAP_SYS_ADMIN capability is available.
#[cfg(target_os = "linux")]
fn check_capability_sys_admin() -> bool {
    // Try to read /proc/self/status for capabilities
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("CapEff:") {
                // CapEff is the effective capability set in hex
                // CAP_SYS_ADMIN is bit 21 (0x200000)
                if let Some(hex) = line.split_whitespace().nth(1) {
                    if let Ok(caps) = u64::from_str_radix(hex, 16) {
                        return (caps & (1 << 21)) != 0;
                    }
                }
            }
        }
    }
    false
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
fn check_capability_sys_admin() -> bool {
    false
}

/// Get full container environment info.
///
/// Collects all container-related information including runtime detection,
/// privilege levels, eBPF availability, and kernel information.
///
/// # Example
///
/// ```no_run
/// use tamandua_agent::config::container::get_container_info;
///
/// let info = get_container_info();
/// println!("Runtime: {}", info.runtime);
/// println!("Privileged: {}", info.is_privileged);
/// println!("eBPF: {}", info.has_ebpf_access);
/// ```
pub fn get_container_info() -> ContainerInfo {
    let runtime = detect_runtime();
    let container_id = get_container_id();
    let is_privileged = is_privileged();
    let has_ebpf = has_ebpf_access();
    let has_btf_support = has_btf();
    let kernel_version = get_kernel_version();

    // Check for host proc mount (for container-aware scanning)
    let host_proc_path = std::env::var("HOST_PROC")
        .ok()
        .filter(|p| Path::new(p).exists());

    let info = ContainerInfo {
        runtime,
        container_id,
        is_privileged,
        has_ebpf_access: has_ebpf,
        has_btf: has_btf_support,
        kernel_version,
        host_proc_path,
    };

    // Log container info at startup
    info!(
        runtime = %info.runtime,
        container_id = ?info.container_id,
        privileged = info.is_privileged,
        ebpf = info.has_ebpf_access,
        btf = info.has_btf,
        kernel = %info.kernel_version,
        "Container environment detected"
    );

    info
}

/// Check if running inside any container.
///
/// Quick check to determine if the agent is running in a containerized
/// environment without gathering full information.
///
/// # Returns
///
/// `true` if running inside a container.
#[inline]
pub fn is_containerized() -> bool {
    !matches!(detect_runtime(), ContainerRuntime::None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_container_runtime_display() {
        assert_eq!(ContainerRuntime::Docker.to_string(), "docker");
        assert_eq!(ContainerRuntime::Podman.to_string(), "podman");
        assert_eq!(ContainerRuntime::Containerd.to_string(), "containerd");
        assert_eq!(ContainerRuntime::Lxc.to_string(), "lxc");
        assert_eq!(ContainerRuntime::None.to_string(), "none");
        assert_eq!(ContainerRuntime::Unknown.to_string(), "unknown");
    }

    #[test]
    fn test_container_runtime_default() {
        assert_eq!(ContainerRuntime::default(), ContainerRuntime::None);
    }

    #[test]
    fn test_container_info_default() {
        let info = ContainerInfo::default();
        assert_eq!(info.runtime, ContainerRuntime::None);
        assert!(info.container_id.is_none());
        assert!(!info.is_privileged);
        assert!(!info.has_ebpf_access);
        assert!(!info.has_btf);
        assert!(info.kernel_version.is_empty());
        assert!(info.host_proc_path.is_none());
    }

    #[test]
    fn test_extract_container_id_docker() {
        let path = "/system.slice/docker-abc123def456789012345678901234567890123456789012345678901234.scope";
        let id = extract_container_id_from_path(path);
        assert!(id.is_some());
        assert_eq!(id.unwrap().len(), 12);
    }

    #[test]
    fn test_extract_container_id_no_id() {
        let path = "/user.slice/user-1000.slice/session-1.scope";
        let id = extract_container_id_from_path(path);
        assert!(id.is_none());
    }

    #[test]
    fn test_detect_runtime_returns_valid() {
        // This test just verifies the function runs without panic
        // Actual result depends on execution environment
        let runtime = detect_runtime();
        // Should be one of the valid variants
        assert!(matches!(
            runtime,
            ContainerRuntime::Docker
                | ContainerRuntime::Podman
                | ContainerRuntime::Containerd
                | ContainerRuntime::Lxc
                | ContainerRuntime::None
                | ContainerRuntime::Unknown
        ));
    }

    #[test]
    fn test_get_container_info_returns_valid() {
        // This test verifies the function returns valid info
        let info = get_container_info();

        // Runtime should be detected (or None if not in container)
        assert!(matches!(
            info.runtime,
            ContainerRuntime::Docker
                | ContainerRuntime::Podman
                | ContainerRuntime::Containerd
                | ContainerRuntime::Lxc
                | ContainerRuntime::None
                | ContainerRuntime::Unknown
        ));

        // Kernel version should be detected (or "unknown")
        assert!(!info.kernel_version.is_empty() || info.kernel_version == "unknown");
    }

    #[test]
    fn test_is_containerized() {
        // Just verify it doesn't panic
        let _ = is_containerized();
    }
}
