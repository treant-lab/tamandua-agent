//! Container Runtime Security Collector
//!
//! Provides comprehensive container runtime security monitoring for Docker, containerd,
//! CRI-O, and Kubernetes environments. Detects container escape attempts, privileged
//! operations, and other container-specific threats.
//!
//! Features:
//! - Container lifecycle event monitoring (create, start, stop, exec)
//! - Privileged container detection
//! - Sensitive mount detection (/var/run/docker.sock, /etc/shadow, etc.)
//! - Container escape pattern detection (nsenter, chroot, cgroup escape)
//! - Kubernetes pod security monitoring
//! - Service account token access monitoring
//! - Host namespace sharing detection (pid, network, ipc)
//!
//! MITRE ATT&CK Mapping:
//! - T1610: Deploy Container
//! - T1611: Escape to Host
//! - T1613: Container and Resource Discovery

use super::{Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent};
use crate::config::AgentConfig;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

// ============================================================================
// Container Event Types (matching requirements specification)
// ============================================================================

/// Container event payload for telemetry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerEvent {
    /// Container ID (truncated or full)
    pub container_id: String,
    /// Container name
    pub container_name: String,
    /// Container image name
    pub image: String,
    /// Image digest (sha256)
    pub image_digest: String,
    /// Type of container event
    pub event_type: ContainerEventType,
    /// Kubernetes pod name (if in K8s environment)
    pub pod_name: Option<String>,
    /// Kubernetes namespace (if in K8s environment)
    pub namespace: Option<String>,
    /// Container labels
    pub labels: HashMap<String, String>,
}

/// Type of container event
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerEventType {
    /// Container created
    Created,
    /// Container started
    Started,
    /// Container stopped
    Stopped,
    /// Container died (crashed or killed)
    Died,
    /// Exec command started inside container (important for threat detection)
    ExecStarted,
    /// Container killed by OOM
    OomKilled,
    /// Container paused
    Paused,
    /// Container resumed
    Resumed,
}

// ============================================================================
// Extended Container Event (for internal use with full details)
// ============================================================================

/// Extended container event with full security context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerSecurityEvent {
    /// Container ID (short or full)
    pub container_id: String,
    /// Container name
    pub container_name: String,
    /// Container image
    pub image: String,
    /// Image tag
    pub image_tag: String,
    /// Container runtime (docker, containerd, cri-o, podman)
    pub runtime: ContainerRuntime,
    /// Event action (created, started, stopped, deleted, exec, etc.)
    pub action: ContainerAction,
    /// Is privileged container
    pub privileged: bool,
    /// Process ID of container init process
    pub pid: u32,
    /// User running the container
    pub user: String,
    /// Command being executed
    pub command: String,
    /// Environment variables of interest
    pub env_vars: HashMap<String, String>,
    /// Host mounts (source:destination)
    pub host_mounts: Vec<HostMount>,
    /// Network mode (host, bridge, none, container)
    pub network_mode: String,
    /// PID namespace mode (host, private)
    pub pid_mode: String,
    /// IPC namespace mode
    pub ipc_mode: String,
    /// Linux capabilities
    pub capabilities: Vec<String>,
    /// Security options (AppArmor, SELinux, seccomp)
    pub security_opts: Vec<String>,
    /// Read-only root filesystem
    pub read_only_rootfs: bool,
    /// Labels/annotations
    pub labels: HashMap<String, String>,
    /// Kubernetes namespace (if running on K8s)
    pub k8s_namespace: Option<String>,
    /// Kubernetes pod name
    pub k8s_pod: Option<String>,
    /// Kubernetes service account
    pub k8s_service_account: Option<String>,
    /// Security context violations
    pub security_violations: Vec<SecurityViolation>,
}

/// Container runtime types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContainerRuntime {
    Docker,
    Containerd,
    CriO,
    Podman,
    Unknown,
}

impl std::fmt::Display for ContainerRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContainerRuntime::Docker => write!(f, "docker"),
            ContainerRuntime::Containerd => write!(f, "containerd"),
            ContainerRuntime::CriO => write!(f, "cri-o"),
            ContainerRuntime::Podman => write!(f, "podman"),
            ContainerRuntime::Unknown => write!(f, "unknown"),
        }
    }
}

/// Container actions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContainerAction {
    Create,
    Start,
    Stop,
    Kill,
    Delete,
    Exec,
    Attach,
    Commit,
    Export,
    Pause,
    Unpause,
    Update,
    Rename,
    NetworkConnect,
    NetworkDisconnect,
    VolumeMount,
    SecretAccess,
    Unknown,
}

impl std::fmt::Display for ContainerAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContainerAction::Create => write!(f, "create"),
            ContainerAction::Start => write!(f, "start"),
            ContainerAction::Stop => write!(f, "stop"),
            ContainerAction::Kill => write!(f, "kill"),
            ContainerAction::Delete => write!(f, "delete"),
            ContainerAction::Exec => write!(f, "exec"),
            ContainerAction::Attach => write!(f, "attach"),
            ContainerAction::Commit => write!(f, "commit"),
            ContainerAction::Export => write!(f, "export"),
            ContainerAction::Pause => write!(f, "pause"),
            ContainerAction::Unpause => write!(f, "unpause"),
            ContainerAction::Update => write!(f, "update"),
            ContainerAction::Rename => write!(f, "rename"),
            ContainerAction::NetworkConnect => write!(f, "network_connect"),
            ContainerAction::NetworkDisconnect => write!(f, "network_disconnect"),
            ContainerAction::VolumeMount => write!(f, "volume_mount"),
            ContainerAction::SecretAccess => write!(f, "secret_access"),
            ContainerAction::Unknown => write!(f, "unknown"),
        }
    }
}

/// Host mount information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostMount {
    /// Source path on host
    pub source: String,
    /// Destination path in container
    pub destination: String,
    /// Mount mode (rw, ro)
    pub mode: String,
    /// Mount propagation
    pub propagation: String,
    /// Is sensitive path
    pub is_sensitive: bool,
}

/// Security violation types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityViolation {
    /// Violation type
    pub violation_type: ViolationType,
    /// Description
    pub description: String,
    /// Severity level
    pub severity: String,
    /// MITRE technique ID
    pub mitre_technique: String,
}

/// Types of security violations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ViolationType {
    PrivilegedContainer,
    HostNetworkAccess,
    HostPidAccess,
    HostIpcAccess,
    SensitiveHostMount,
    DangerousCapability,
    RunAsRoot,
    WritableRootfs,
    NoSeccompProfile,
    NoAppArmor,
    ContainerEscapeAttempt,
    ServiceAccountTokenAccess,
    SecretsAccess,
    EtcdAccess,
    KubeletApiAccess,
    UnverifiedImage,
    VulnerableBaseImage,
    ShellSpawn,
    SuspiciousNetworkActivity,
    KernelModuleLoad,
    ProcSysAbuse,
    CgroupEscape,
    RuncVulnerability,
}

/// Known vulnerable base images
const VULNERABLE_IMAGES: &[&str] = &[
    "alpine:3.13",    // CVE-2021-36159
    "alpine:3.12",    // Multiple CVEs
    "ubuntu:18.04",   // Multiple CVEs (EOL)
    "debian:stretch", // EOL
    "centos:7",       // EOL approaching
    "python:2.7",     // Python 2 EOL
    "node:10",        // Node 10 EOL
    "node:12",        // Node 12 EOL
];

/// Dangerous Linux capabilities
const DANGEROUS_CAPABILITIES: &[&str] = &[
    "CAP_SYS_ADMIN",
    "CAP_NET_ADMIN",
    "CAP_SYS_PTRACE",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_BOOT",
    "CAP_SYS_TIME",
    "CAP_NET_RAW",
    "CAP_MKNOD",
    "CAP_SETUID",
    "CAP_SETGID",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL",
];

/// Sensitive host paths
const SENSITIVE_HOST_PATHS: &[&str] = &[
    "/",
    "/etc",
    "/etc/shadow",
    "/etc/passwd",
    "/etc/kubernetes",
    "/var/run/docker.sock",
    "/var/run/containerd",
    "/var/run/crio",
    "/run/containerd",
    "/var/lib/kubelet",
    "/var/lib/docker",
    "/var/lib/containers",
    "/proc",
    "/sys",
    "/sys/fs/cgroup",
    "/dev",
    "/boot",
    "/lib/modules",
    "/root",
    "/home",
    "/.ssh",
];

/// Shell binaries that indicate potential escape
const SHELL_BINARIES: &[&str] = &[
    "/bin/sh",
    "/bin/bash",
    "/bin/ash",
    "/bin/zsh",
    "/bin/ksh",
    "/bin/csh",
    "/bin/tcsh",
    "/bin/fish",
    "/usr/bin/sh",
    "/usr/bin/bash",
    "/usr/bin/zsh",
];

/// Suspicious binaries commonly used in container attacks
const SUSPICIOUS_CONTAINER_BINARIES: &[&str] = &[
    // Container escape tools
    "nsenter",
    "unshare",
    "chroot",
    "pivot_root",
    // Debugging/inspection tools
    "strace",
    "ltrace",
    "gdb",
    // Network reconnaissance
    "nmap",
    "masscan",
    "netcat",
    "nc",
    "ncat",
    "socat",
    // Cryptominers
    "xmrig",
    "minerd",
    "cpuminer",
    "ccminer",
    "ethminer",
    "cgminer",
    // Kubernetes-specific
    "kubectl",
    "ctr",
    "crictl",
    // System modification
    "iptables",
    "ip6tables",
    "nft",
    "modprobe",
    "insmod",
    "rmmod",
];

// ============================================================================
// Container Environment Detection
// ============================================================================

/// Information about the container environment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerEnvironment {
    /// Whether the agent is running inside a container
    pub is_containerized: bool,
    /// Container ID (if running inside a container)
    pub container_id: Option<String>,
    /// Container runtime type
    pub runtime: ContainerRuntime,
    /// cgroup version (v1 or v2)
    pub cgroup_version: CgroupVersion,
    /// Kubernetes environment info (if applicable)
    pub kubernetes: Option<KubernetesEnvironment>,
}

/// cgroup version
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CgroupVersion {
    V1,
    V2,
    Unknown,
}

/// Kubernetes environment information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesEnvironment {
    /// Pod name
    pub pod_name: String,
    /// Namespace
    pub namespace: String,
    /// Node name
    pub node_name: Option<String>,
    /// Service account name
    pub service_account: Option<String>,
    /// Pod labels
    pub labels: HashMap<String, String>,
    /// Pod annotations
    pub annotations: HashMap<String, String>,
}

/// Container collector
pub struct ContainerCollector {
    #[allow(dead_code)]
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    runtime: ContainerRuntime,
    /// Container environment information
    environment: ContainerEnvironment,
}

impl ContainerCollector {
    /// Create a new container collector
    pub fn new(config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(1000);

        // Detect container environment
        let environment = Self::detect_environment();
        let runtime = environment.runtime.clone();

        info!(
            runtime = %runtime,
            is_containerized = environment.is_containerized,
            container_id = ?environment.container_id,
            cgroup_version = ?environment.cgroup_version,
            kubernetes = environment.kubernetes.is_some(),
            "Container collector initialized"
        );

        // Start monitoring in background
        let config_clone = config.clone();
        let runtime_clone = runtime.clone();
        let env_clone = environment.clone();
        tokio::spawn(async move {
            Self::monitor_loop(tx, config_clone, runtime_clone, env_clone).await;
        });

        Self {
            config: config.clone(),
            event_rx: rx,
            runtime,
            environment,
        }
    }

    /// Detect the full container environment
    fn detect_environment() -> ContainerEnvironment {
        let is_containerized = Self::detect_containerized();
        let container_id = if is_containerized {
            Self::extract_container_id()
        } else {
            None
        };
        let runtime = Self::detect_runtime();
        let cgroup_version = Self::detect_cgroup_version();
        let kubernetes = Self::detect_kubernetes_environment();

        ContainerEnvironment {
            is_containerized,
            container_id,
            runtime,
            cgroup_version,
            kubernetes,
        }
    }

    /// Detect if we're running inside a container
    fn detect_containerized() -> bool {
        // Method 1: Check for /.dockerenv
        if Path::new("/.dockerenv").exists() {
            debug!("Detected container via /.dockerenv");
            return true;
        }

        // Method 2: Check for Podman container marker
        if Path::new("/run/.containerenv").exists() {
            debug!("Detected container via /run/.containerenv (Podman)");
            return true;
        }

        // Method 3: Check cgroup v1 (/proc/1/cgroup)
        if let Ok(cgroup) = std::fs::read_to_string("/proc/1/cgroup") {
            // In a container, PID 1's cgroup will contain docker/containerd/kubepods/etc.
            if cgroup.contains("/docker/")
                || cgroup.contains("/containerd/")
                || cgroup.contains("/kubepods/")
                || cgroup.contains("/crio-")
                || cgroup.contains("/podman-")
                || cgroup.contains("/libpod-")
            {
                debug!("Detected container via cgroup v1");
                return true;
            }
        }

        // Method 4: Check cgroup v2 (/proc/self/cgroup for unified hierarchy)
        if let Ok(cgroup) = std::fs::read_to_string("/proc/self/cgroup") {
            // In cgroup v2, the path format is different
            if cgroup.contains("docker")
                || cgroup.contains("containerd")
                || cgroup.contains("kubepods")
                || cgroup.contains("crio")
                || cgroup.contains("podman")
            {
                debug!("Detected container via cgroup v2");
                return true;
            }
        }

        // Method 5: Check if init process (PID 1) is not systemd/init
        if let Ok(cmdline) = std::fs::read_to_string("/proc/1/cmdline") {
            let cmd = cmdline.split('\0').next().unwrap_or("");
            // Container init processes are usually not /sbin/init or systemd
            if cmd.contains("pause") || cmd.contains("dumb-init") || cmd.contains("tini") {
                debug!("Detected container via init process: {}", cmd);
                return true;
            }
        }

        // Method 6: Check for Kubernetes service account token
        if Path::new("/var/run/secrets/kubernetes.io/serviceaccount").exists() {
            debug!("Detected container via Kubernetes service account");
            return true;
        }

        false
    }

    /// Extract container ID from cgroup information
    fn extract_container_id() -> Option<String> {
        // Try cgroup v1 first (/proc/self/cgroup)
        if let Ok(cgroup) = std::fs::read_to_string("/proc/self/cgroup") {
            for line in cgroup.lines() {
                // Docker format: ...:/docker/<container_id>
                if let Some(pos) = line.find("/docker/") {
                    let id = &line[pos + 8..];
                    if id.len() >= 12 && id.chars().all(|c| c.is_ascii_hexdigit()) {
                        return Some(id[..12].to_string());
                    }
                }

                // Containerd/K8s format: ...:/kubepods/.../cri-containerd-<container_id>
                if let Some(pos) = line.find("cri-containerd-") {
                    let id = &line[pos + 15..];
                    if id.len() >= 12 {
                        // Extract just the container ID part
                        let clean_id: String =
                            id.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
                        if clean_id.len() >= 12 {
                            return Some(clean_id[..12].to_string());
                        }
                    }
                }

                // CRI-O format: ...:/crio-<container_id>
                if let Some(pos) = line.find("/crio-") {
                    let id = &line[pos + 6..];
                    if id.len() >= 12 {
                        let clean_id: String =
                            id.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
                        if clean_id.len() >= 12 {
                            return Some(clean_id[..12].to_string());
                        }
                    }
                }

                // Podman format: ...:/libpod-<container_id>
                if let Some(pos) = line.find("/libpod-") {
                    let id = &line[pos + 8..];
                    if id.len() >= 12 {
                        let clean_id: String =
                            id.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
                        if clean_id.len() >= 12 {
                            return Some(clean_id[..12].to_string());
                        }
                    }
                }
            }
        }

        // Try hostname as fallback (often set to container ID in K8s)
        if let Ok(hostname) = std::fs::read_to_string("/etc/hostname") {
            let hostname = hostname.trim();
            // Check if it looks like a container ID (64 hex chars, take first 12)
            if hostname.len() >= 12 && hostname.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(hostname[..12].to_string());
            }
        }

        None
    }

    /// Detect cgroup version
    fn detect_cgroup_version() -> CgroupVersion {
        // Check for cgroup v2 unified hierarchy
        if Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
            return CgroupVersion::V2;
        }

        // Check for cgroup v1
        if Path::new("/sys/fs/cgroup/cpu").exists() || Path::new("/sys/fs/cgroup/memory").exists() {
            return CgroupVersion::V1;
        }

        // Check via /proc/filesystems
        if let Ok(filesystems) = std::fs::read_to_string("/proc/filesystems") {
            if filesystems.contains("cgroup2") {
                return CgroupVersion::V2;
            }
            if filesystems.contains("cgroup") {
                return CgroupVersion::V1;
            }
        }

        CgroupVersion::Unknown
    }

    /// Detect Kubernetes environment details
    fn detect_kubernetes_environment() -> Option<KubernetesEnvironment> {
        // Check for Kubernetes service account
        let sa_path = "/var/run/secrets/kubernetes.io/serviceaccount";
        if !Path::new(sa_path).exists() {
            return None;
        }

        // Read namespace
        let namespace = std::fs::read_to_string(format!("{}/namespace", sa_path))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "default".to_string());

        // Pod name from hostname or downward API
        let pod_name = std::env::var("HOSTNAME")
            .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
            .unwrap_or_else(|_| "unknown".to_string());

        // Node name from downward API
        let node_name = std::env::var("NODE_NAME").ok();

        // Service account name
        let service_account = std::env::var("SERVICE_ACCOUNT_NAME").ok().or_else(|| {
            // Try to infer from pod name or annotations
            None
        });

        // Read pod labels from downward API
        let labels = Self::read_downward_api_file("/etc/podinfo/labels");

        // Read pod annotations from downward API
        let annotations = Self::read_downward_api_file("/etc/podinfo/annotations");

        Some(KubernetesEnvironment {
            pod_name,
            namespace,
            node_name,
            service_account,
            labels,
            annotations,
        })
    }

    /// Read downward API file (labels or annotations format: "key"="value")
    fn read_downward_api_file(path: &str) -> HashMap<String, String> {
        let mut result = HashMap::new();

        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                // Format: "key"="value"
                if let Some(eq_pos) = line.find('=') {
                    let key = line[..eq_pos].trim_matches('"').to_string();
                    let value = line[eq_pos + 1..].trim_matches('"').to_string();
                    result.insert(key, value);
                }
            }
        }

        result
    }

    /// Get the container environment information
    pub fn get_environment(&self) -> &ContainerEnvironment {
        &self.environment
    }

    /// Check if running inside a container
    pub fn is_containerized(&self) -> bool {
        self.environment.is_containerized
    }

    /// Get the container ID (if running in a container)
    pub fn get_container_id(&self) -> Option<&str> {
        self.environment.container_id.as_deref()
    }

    /// Get Kubernetes environment info
    pub fn get_kubernetes_info(&self) -> Option<&KubernetesEnvironment> {
        self.environment.kubernetes.as_ref()
    }

    /// Detect which container runtime is available
    fn detect_runtime() -> ContainerRuntime {
        // Check for Docker socket
        if Path::new("/var/run/docker.sock").exists() {
            return ContainerRuntime::Docker;
        }

        // Check for containerd socket
        if Path::new("/run/containerd/containerd.sock").exists()
            || Path::new("/var/run/containerd/containerd.sock").exists()
        {
            return ContainerRuntime::Containerd;
        }

        // Check for CRI-O socket
        if Path::new("/var/run/crio/crio.sock").exists() {
            return ContainerRuntime::CriO;
        }

        // Check for Podman socket
        if Path::new("/run/podman/podman.sock").exists()
            || Path::new("/var/run/podman/podman.sock").exists()
        {
            // Also check for rootless podman
            if let Ok(xdg_runtime) = std::env::var("XDG_RUNTIME_DIR") {
                let podman_sock = format!("{}/podman/podman.sock", xdg_runtime);
                if Path::new(&podman_sock).exists() {
                    return ContainerRuntime::Podman;
                }
            }
            return ContainerRuntime::Podman;
        }

        // Check if we're running inside a container
        if Path::new("/.dockerenv").exists() || Self::is_inside_container() {
            return ContainerRuntime::Docker;
        }

        ContainerRuntime::Unknown
    }

    /// Check if we're running inside a container
    fn is_inside_container() -> bool {
        // Check cgroup for container indicators
        if let Ok(cgroup) = std::fs::read_to_string("/proc/1/cgroup") {
            if cgroup.contains("docker")
                || cgroup.contains("kubepods")
                || cgroup.contains("containerd")
                || cgroup.contains("crio")
            {
                return true;
            }
        }

        // Check for container-specific environment variables
        std::env::var("KUBERNETES_SERVICE_HOST").is_ok()
    }

    async fn monitor_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        config: AgentConfig,
        runtime: ContainerRuntime,
        environment: ContainerEnvironment,
    ) {
        let mut known_containers: HashSet<String> = HashSet::new();
        let mut known_processes: HashMap<u32, String> = HashMap::new();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(2));

        // Also monitor for Kubernetes-specific events
        let is_k8s = environment.kubernetes.is_some();
        let is_containerized = environment.is_containerized;
        if is_k8s {
            info!("Kubernetes environment detected, enabling K8s security monitoring");
        }
        if is_containerized {
            info!("Running inside container, enabling in-container security monitoring");
        }

        loop {
            interval.tick().await;

            // Get current containers based on runtime
            let containers = match runtime {
                ContainerRuntime::Docker => Self::get_docker_containers().await,
                ContainerRuntime::Containerd => Self::get_containerd_containers().await,
                ContainerRuntime::CriO => Self::get_crio_containers().await,
                ContainerRuntime::Podman => Self::get_podman_containers().await,
                ContainerRuntime::Unknown => {
                    // Try all runtimes
                    let mut containers = Self::get_docker_containers().await;
                    if containers.is_empty() {
                        containers = Self::get_containerd_containers().await;
                    }
                    if containers.is_empty() {
                        containers = Self::get_podman_containers().await;
                    }
                    containers
                }
            };

            let current_ids: HashSet<String> =
                containers.iter().map(|c| c.container_id.clone()).collect();

            // Check for new containers
            for container in &containers {
                if !known_containers.contains(&container.container_id) {
                    // New container detected
                    let mut event = Self::create_container_event(container, &runtime, is_k8s);

                    // Analyze for security issues
                    Self::analyze_security(&mut event, container);

                    if tx.send(event).await.is_err() {
                        warn!("Event channel closed");
                        return;
                    }
                }
            }

            // Check for deleted containers
            for id in known_containers.difference(&current_ids) {
                let delete_event = TelemetryEvent::new(
                    EventType::ContainerActivity,
                    Severity::Info,
                    EventPayload::Custom(serde_json::json!({
                        "container_id": id,
                        "action": "deleted",
                        "runtime": runtime.to_string(),
                    })),
                );

                if tx.send(delete_event).await.is_err() {
                    warn!("Event channel closed");
                    return;
                }
            }

            known_containers = current_ids;

            // Monitor for container escape attempts
            if let Some(escape_event) = Self::detect_escape_attempts(&config).await {
                if tx.send(escape_event).await.is_err() {
                    warn!("Event channel closed");
                    return;
                }
            }

            // Monitor Kubernetes-specific security issues
            if is_k8s {
                if let Some(k8s_event) = Self::monitor_kubernetes_security().await {
                    if tx.send(k8s_event).await.is_err() {
                        warn!("Event channel closed");
                        return;
                    }
                }
            }

            // Monitor for suspicious container activities
            for container in &containers {
                if let Some(activity_event) = Self::monitor_container_activity(container).await {
                    if tx.send(activity_event).await.is_err() {
                        warn!("Event channel closed");
                        return;
                    }
                }
            }

            // Monitor for suspicious processes (cryptominers, escape tools, etc.)
            if is_containerized {
                if let Some(events) =
                    Self::monitor_suspicious_processes(&environment, &mut known_processes).await
                {
                    for event in events {
                        if tx.send(event).await.is_err() {
                            warn!("Event channel closed");
                            return;
                        }
                    }
                }

                // Monitor sensitive mounts in current container
                if let Some(mount_events) = Self::monitor_sensitive_mounts(&environment).await {
                    for event in mount_events {
                        if tx.send(event).await.is_err() {
                            warn!("Event channel closed");
                            return;
                        }
                    }
                }

                // Monitor host namespace sharing violations
                if let Some(ns_events) = Self::monitor_namespace_violations(&environment).await {
                    for event in ns_events {
                        if tx.send(event).await.is_err() {
                            warn!("Event channel closed");
                            return;
                        }
                    }
                }
            }
        }
    }

    /// Monitor for suspicious processes in container (cryptominers, escape tools, etc.)
    async fn monitor_suspicious_processes(
        environment: &ContainerEnvironment,
        known_processes: &mut HashMap<u32, String>,
    ) -> Option<Vec<TelemetryEvent>> {
        let mut events = Vec::new();

        // Scan /proc for processes
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.filter_map(|e| e.ok()) {
                let name = entry.file_name();
                let pid: u32 = match name.to_str().and_then(|s| s.parse().ok()) {
                    Some(p) => p,
                    None => continue,
                };

                // Read process comm
                let comm_path = format!("/proc/{}/comm", pid);
                let comm = match std::fs::read_to_string(&comm_path) {
                    Ok(c) => c.trim().to_string(),
                    Err(_) => continue,
                };

                // Check if this is a new process
                if known_processes.contains_key(&pid) {
                    continue;
                }

                // Check if it's a suspicious binary
                if SUSPICIOUS_CONTAINER_BINARIES.iter().any(|b| comm == *b) {
                    // Get full command line
                    let cmdline = std::fs::read_to_string(format!("/proc/{}/cmdline", pid))
                        .unwrap_or_default()
                        .replace('\0', " ")
                        .trim()
                        .to_string();

                    let severity = Self::get_suspicious_process_severity(&comm);
                    let reason = Self::get_suspicious_process_reason(&comm);

                    let container_event = ContainerEvent {
                        container_id: environment.container_id.clone().unwrap_or_default(),
                        container_name: std::env::var("HOSTNAME").unwrap_or_default(),
                        image: String::new(),
                        image_digest: String::new(),
                        event_type: ContainerEventType::ExecStarted,
                        pod_name: environment.kubernetes.as_ref().map(|k| k.pod_name.clone()),
                        namespace: environment.kubernetes.as_ref().map(|k| k.namespace.clone()),
                        labels: HashMap::new(),
                    };

                    let mut event = TelemetryEvent::new(
                        EventType::ContainerActivity,
                        severity.clone(),
                        EventPayload::Custom(serde_json::json!({
                            "container": container_event,
                            "process": {
                                "pid": pid,
                                "command": comm,
                                "cmdline": cmdline,
                                "reason": reason,
                            }
                        })),
                    );

                    event.add_detection(Detection {
                        detection_type: DetectionType::Behavioral,
                        rule_name: "suspicious_process_in_container".to_string(),
                        confidence: 0.85,
                        description: format!(
                            "Suspicious process '{}' detected in container: {} - {}",
                            comm, cmdline, reason
                        ),
                        mitre_tactics: vec![
                            "execution".to_string(),
                            "privilege-escalation".to_string(),
                        ],
                        mitre_techniques: vec!["T1610".to_string(), "T1611".to_string()],
                    });

                    events.push(event);
                }

                known_processes.insert(pid, comm);
            }
        }

        // Clean up exited processes
        known_processes.retain(|pid, _| Path::new(&format!("/proc/{}", pid)).exists());

        if events.is_empty() {
            None
        } else {
            Some(events)
        }
    }

    /// Get severity for suspicious process
    fn get_suspicious_process_severity(command: &str) -> Severity {
        match command {
            // Critical - direct escape tools
            "nsenter" | "unshare" | "chroot" | "pivot_root" => Severity::Critical,
            "modprobe" | "insmod" | "rmmod" => Severity::Critical,
            // High - cryptominers and network tools
            "xmrig" | "minerd" | "cpuminer" | "ccminer" | "ethminer" | "cgminer" => Severity::High,
            "netcat" | "nc" | "ncat" | "socat" => Severity::High,
            "strace" | "ltrace" | "gdb" => Severity::High,
            // Medium - reconnaissance and kubernetes tools
            "nmap" | "masscan" => Severity::Medium,
            "kubectl" | "ctr" | "crictl" => Severity::Medium,
            "iptables" | "ip6tables" | "nft" => Severity::Medium,
            _ => Severity::Medium,
        }
    }

    /// Get reason for suspicious process
    fn get_suspicious_process_reason(command: &str) -> String {
        match command {
            "nsenter" | "unshare" => {
                "Namespace manipulation tool (potential container escape)".to_string()
            }
            "chroot" | "pivot_root" => {
                "Root filesystem manipulation (potential container escape)".to_string()
            }
            "strace" | "ltrace" | "gdb" => {
                "Debugging/tracing tool (potential credential theft)".to_string()
            }
            "nmap" | "masscan" => "Network scanner (potential reconnaissance)".to_string(),
            "netcat" | "nc" | "ncat" | "socat" => {
                "Network utility (potential reverse shell)".to_string()
            }
            "xmrig" | "minerd" | "cpuminer" | "ccminer" | "ethminer" | "cgminer" => {
                "Cryptocurrency miner (cryptojacking)".to_string()
            }
            "kubectl" | "ctr" | "crictl" => "Container/Kubernetes management tool".to_string(),
            "iptables" | "ip6tables" | "nft" => "Firewall manipulation tool".to_string(),
            "modprobe" | "insmod" | "rmmod" => {
                "Kernel module manipulation (potential rootkit)".to_string()
            }
            _ => "Suspicious binary execution".to_string(),
        }
    }

    /// Monitor sensitive mounts in the current container
    async fn monitor_sensitive_mounts(
        environment: &ContainerEnvironment,
    ) -> Option<Vec<TelemetryEvent>> {
        let mut events = Vec::new();

        // Read /proc/self/mounts to detect sensitive mounts
        if let Ok(mounts) = std::fs::read_to_string("/proc/self/mounts") {
            for line in mounts.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 2 {
                    continue;
                }

                let source = parts[0];
                let mount_point = parts[1];

                // Check against sensitive paths
                for sensitive_path in SENSITIVE_HOST_PATHS {
                    if mount_point.starts_with(sensitive_path) || mount_point == *sensitive_path {
                        // Skip common safe mounts
                        if mount_point == "/etc/resolv.conf"
                            || mount_point == "/etc/hostname"
                            || mount_point == "/etc/hosts"
                        {
                            continue;
                        }

                        let severity = Self::get_mount_severity(sensitive_path);

                        let container_event = ContainerEvent {
                            container_id: environment.container_id.clone().unwrap_or_default(),
                            container_name: std::env::var("HOSTNAME").unwrap_or_default(),
                            image: String::new(),
                            image_digest: String::new(),
                            event_type: ContainerEventType::Started, // Using Started as a proxy for mount detection
                            pod_name: environment.kubernetes.as_ref().map(|k| k.pod_name.clone()),
                            namespace: environment.kubernetes.as_ref().map(|k| k.namespace.clone()),
                            labels: HashMap::new(),
                        };

                        let mut event = TelemetryEvent::new(
                            EventType::ContainerActivity,
                            severity.clone(),
                            EventPayload::Custom(serde_json::json!({
                                "container": container_event,
                                "mount": {
                                    "source": source,
                                    "destination": mount_point,
                                    "sensitive_path": sensitive_path,
                                }
                            })),
                        );

                        event.add_detection(Detection {
                            detection_type: DetectionType::Behavioral,
                            rule_name: "sensitive_host_mount".to_string(),
                            confidence: 0.9,
                            description: format!(
                                "Sensitive host path mounted: {} -> {}",
                                source, mount_point
                            ),
                            mitre_tactics: vec!["privilege-escalation".to_string()],
                            mitre_techniques: vec!["T1611".to_string()],
                        });

                        events.push(event);
                        break; // Only report once per mount point
                    }
                }
            }
        }

        if events.is_empty() {
            None
        } else {
            Some(events)
        }
    }

    /// Get severity for sensitive mount
    fn get_mount_severity(path: &str) -> Severity {
        match path {
            "/var/run/docker.sock"
            | "/var/run/containerd"
            | "/var/run/crio"
            | "/run/containerd" => Severity::Critical,
            "/etc/shadow" | "/boot" | "/lib/modules" | "/" => Severity::Critical,
            "/sys/fs/cgroup" | "/proc" | "/sys" => Severity::High,
            "/etc" | "/etc/passwd" | "/etc/kubernetes" | "/var/lib/kubelet" => Severity::High,
            "/dev" | "/root" | "/home" | "/.ssh" => Severity::Medium,
            _ => Severity::Low,
        }
    }

    /// Monitor host namespace sharing violations
    async fn monitor_namespace_violations(
        environment: &ContainerEnvironment,
    ) -> Option<Vec<TelemetryEvent>> {
        let mut events = Vec::new();
        let ns_types = [
            ("pid", "host_pid_namespace"),
            ("net", "host_network_namespace"),
            ("ipc", "host_ipc_namespace"),
        ];

        for (ns_type, violation_name) in ns_types {
            if Self::check_host_namespace(ns_type) {
                let container_event = ContainerEvent {
                    container_id: environment.container_id.clone().unwrap_or_default(),
                    container_name: std::env::var("HOSTNAME").unwrap_or_default(),
                    image: String::new(),
                    image_digest: String::new(),
                    event_type: ContainerEventType::Started,
                    pod_name: environment.kubernetes.as_ref().map(|k| k.pod_name.clone()),
                    namespace: environment.kubernetes.as_ref().map(|k| k.namespace.clone()),
                    labels: HashMap::new(),
                };

                let mut event = TelemetryEvent::new(
                    EventType::ContainerActivity,
                    Severity::High,
                    EventPayload::Custom(serde_json::json!({
                        "container": container_event,
                        "violation": violation_name,
                        "namespace_type": ns_type,
                    })),
                );

                event.add_detection(Detection {
                    detection_type: DetectionType::Behavioral,
                    rule_name: violation_name.to_string(),
                    confidence: 0.85,
                    description: format!(
                        "Container is using host {} namespace, reducing isolation",
                        ns_type.to_uppercase()
                    ),
                    mitre_tactics: vec!["privilege-escalation".to_string()],
                    mitre_techniques: vec!["T1611".to_string()],
                });

                events.push(event);
            }
        }

        if events.is_empty() {
            None
        } else {
            Some(events)
        }
    }

    /// Check if using host namespace
    fn check_host_namespace(ns_type: &str) -> bool {
        let self_ns = format!("/proc/self/ns/{}", ns_type);
        let init_ns = format!("/proc/1/ns/{}", ns_type);

        if let (Ok(self_link), Ok(init_link)) =
            (std::fs::read_link(&self_ns), std::fs::read_link(&init_ns))
        {
            return self_link == init_link;
        }

        false
    }

    /// Get Docker containers via docker CLI or socket
    async fn get_docker_containers() -> Vec<ContainerInfo> {
        let mut containers = Vec::new();

        // Try docker CLI first
        let output = tokio::process::Command::new("docker")
            .args([
                "ps",
                "-a",
                "--format",
                "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}",
            ])
            .output()
            .await;

        if let Ok(output) = output {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let parts: Vec<&str> = line.split('|').collect();
                    if parts.len() >= 4 {
                        let container_id = parts[0].to_string();
                        let container_name = parts[1].to_string();
                        let image = parts[2].to_string();

                        // Get detailed container info
                        if let Some(info) = Self::get_docker_container_details(&container_id).await
                        {
                            containers.push(info);
                        } else {
                            // Basic info if detailed inspection fails
                            let (image_name, image_tag) = Self::parse_image_tag(&image);
                            containers.push(ContainerInfo {
                                container_id,
                                container_name,
                                image: image_name,
                                image_tag,
                                pid: 0,
                                user: String::new(),
                                command: String::new(),
                                env_vars: HashMap::new(),
                                privileged: false,
                                host_mounts: Vec::new(),
                                network_mode: String::new(),
                                pid_mode: String::new(),
                                ipc_mode: String::new(),
                                capabilities: Vec::new(),
                                security_opts: Vec::new(),
                                read_only_rootfs: false,
                                labels: HashMap::new(),
                            });
                        }
                    }
                }
            }
        }

        containers
    }

    /// Get detailed Docker container information
    async fn get_docker_container_details(container_id: &str) -> Option<ContainerInfo> {
        let output = tokio::process::Command::new("docker")
            .args(["inspect", container_id])
            .output()
            .await
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let inspect: Vec<serde_json::Value> = serde_json::from_str(&stdout).ok()?;
        let container = inspect.first()?;

        let config = container.get("Config")?;
        let host_config = container.get("HostConfig")?;
        let state = container.get("State")?;

        let image = config
            .get("Image")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let (image_name, image_tag) = Self::parse_image_tag(&image);

        // Parse mounts
        let mut host_mounts = Vec::new();
        if let Some(mounts) = container.get("Mounts").and_then(|v| v.as_array()) {
            for mount in mounts {
                let source = mount
                    .get("Source")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let destination = mount
                    .get("Destination")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let mode = mount
                    .get("Mode")
                    .and_then(|v| v.as_str())
                    .unwrap_or("rw")
                    .to_string();
                let propagation = mount
                    .get("Propagation")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let is_sensitive = SENSITIVE_HOST_PATHS.iter().any(|p| source.starts_with(p));

                host_mounts.push(HostMount {
                    source,
                    destination,
                    mode,
                    propagation,
                    is_sensitive,
                });
            }
        }

        // Parse capabilities
        let mut capabilities = Vec::new();
        if let Some(cap_add) = host_config.get("CapAdd").and_then(|v| v.as_array()) {
            for cap in cap_add {
                if let Some(c) = cap.as_str() {
                    capabilities.push(c.to_string());
                }
            }
        }

        // Parse environment variables of interest
        let mut env_vars = HashMap::new();
        if let Some(env) = config.get("Env").and_then(|v| v.as_array()) {
            for e in env {
                if let Some(ev) = e.as_str() {
                    let parts: Vec<&str> = ev.splitn(2, '=').collect();
                    if parts.len() == 2 {
                        // Only capture security-relevant env vars
                        let key = parts[0];
                        if key.contains("SECRET")
                            || key.contains("PASSWORD")
                            || key.contains("TOKEN")
                            || key.contains("KEY")
                            || key.contains("CREDENTIAL")
                            || key.starts_with("AWS_")
                            || key.starts_with("KUBERNETES_")
                        {
                            // Mask the value for security
                            env_vars.insert(key.to_string(), "[REDACTED]".to_string());
                        }
                    }
                }
            }
        }

        // Parse security options
        let mut security_opts = Vec::new();
        if let Some(opts) = host_config.get("SecurityOpt").and_then(|v| v.as_array()) {
            for opt in opts {
                if let Some(o) = opt.as_str() {
                    security_opts.push(o.to_string());
                }
            }
        }

        // Parse labels
        let mut labels = HashMap::new();
        if let Some(lbls) = config.get("Labels").and_then(|v| v.as_object()) {
            for (k, v) in lbls {
                if let Some(val) = v.as_str() {
                    labels.insert(k.clone(), val.to_string());
                }
            }
        }

        Some(ContainerInfo {
            container_id: container
                .get("Id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .chars()
                .take(12)
                .collect(),
            container_name: container
                .get("Name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim_start_matches('/')
                .to_string(),
            image: image_name,
            image_tag,
            pid: state.get("Pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
            user: config
                .get("User")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            command: config
                .get("Cmd")
                .and_then(|v| {
                    v.as_array().map(|arr| {
                        arr.iter()
                            .filter_map(|x| x.as_str())
                            .collect::<Vec<_>>()
                            .join(" ")
                    })
                })
                .unwrap_or_default(),
            env_vars,
            privileged: host_config
                .get("Privileged")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            host_mounts,
            network_mode: host_config
                .get("NetworkMode")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            pid_mode: host_config
                .get("PidMode")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            ipc_mode: host_config
                .get("IpcMode")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            capabilities,
            security_opts,
            read_only_rootfs: host_config
                .get("ReadonlyRootfs")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            labels,
        })
    }

    /// Get containerd containers via ctr or crictl
    async fn get_containerd_containers() -> Vec<ContainerInfo> {
        let mut containers = Vec::new();

        // Try crictl first (for Kubernetes environments)
        let output = tokio::process::Command::new("crictl")
            .args(["ps", "-a", "-o", "json"])
            .output()
            .await;

        if let Ok(output) = output {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
                    if let Some(ctrs) = json.get("containers").and_then(|v| v.as_array()) {
                        for ctr in ctrs {
                            let container_id: String = ctr
                                .get("id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .chars()
                                .take(12)
                                .collect();

                            let image = ctr
                                .get("imageRef")
                                .or_else(|| ctr.get("image"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();

                            let (image_name, image_tag) = Self::parse_image_tag(&image);

                            // Get detailed info via crictl inspect
                            let info = Self::get_crictl_container_details(&container_id).await;

                            containers.push(ContainerInfo {
                                container_id,
                                container_name: ctr
                                    .get("metadata")
                                    .and_then(|m| m.get("name"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                image: image_name,
                                image_tag,
                                pid: info.as_ref().map(|i| i.pid).unwrap_or(0),
                                user: info.as_ref().map(|i| i.user.clone()).unwrap_or_default(),
                                command: info
                                    .as_ref()
                                    .map(|i| i.command.clone())
                                    .unwrap_or_default(),
                                env_vars: info
                                    .as_ref()
                                    .map(|i| i.env_vars.clone())
                                    .unwrap_or_default(),
                                privileged: info.as_ref().map(|i| i.privileged).unwrap_or(false),
                                host_mounts: info
                                    .as_ref()
                                    .map(|i| i.host_mounts.clone())
                                    .unwrap_or_default(),
                                network_mode: info
                                    .as_ref()
                                    .map(|i| i.network_mode.clone())
                                    .unwrap_or_default(),
                                pid_mode: info
                                    .as_ref()
                                    .map(|i| i.pid_mode.clone())
                                    .unwrap_or_default(),
                                ipc_mode: info
                                    .as_ref()
                                    .map(|i| i.ipc_mode.clone())
                                    .unwrap_or_default(),
                                capabilities: info
                                    .as_ref()
                                    .map(|i| i.capabilities.clone())
                                    .unwrap_or_default(),
                                security_opts: info
                                    .as_ref()
                                    .map(|i| i.security_opts.clone())
                                    .unwrap_or_default(),
                                read_only_rootfs: info
                                    .as_ref()
                                    .map(|i| i.read_only_rootfs)
                                    .unwrap_or(false),
                                labels: ctr
                                    .get("labels")
                                    .and_then(|v| v.as_object())
                                    .map(|m| {
                                        m.iter()
                                            .filter_map(|(k, v)| {
                                                v.as_str().map(|s| (k.clone(), s.to_string()))
                                            })
                                            .collect()
                                    })
                                    .unwrap_or_default(),
                            });
                        }
                    }
                }
            }
        }

        // Fallback to ctr for non-Kubernetes containerd
        if containers.is_empty() {
            let output = tokio::process::Command::new("ctr")
                .args(["-n", "k8s.io", "containers", "list", "-q"])
                .output()
                .await;

            if let Ok(output) = output {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for id in stdout.lines() {
                        if !id.is_empty() {
                            containers.push(ContainerInfo {
                                container_id: id.chars().take(12).collect(),
                                container_name: id.to_string(),
                                image: String::new(),
                                image_tag: String::new(),
                                pid: 0,
                                user: String::new(),
                                command: String::new(),
                                env_vars: HashMap::new(),
                                privileged: false,
                                host_mounts: Vec::new(),
                                network_mode: String::new(),
                                pid_mode: String::new(),
                                ipc_mode: String::new(),
                                capabilities: Vec::new(),
                                security_opts: Vec::new(),
                                read_only_rootfs: false,
                                labels: HashMap::new(),
                            });
                        }
                    }
                }
            }
        }

        containers
    }

    /// Get detailed container info via crictl inspect
    async fn get_crictl_container_details(container_id: &str) -> Option<ContainerInfo> {
        let output = tokio::process::Command::new("crictl")
            .args(["inspect", container_id])
            .output()
            .await
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let inspect: serde_json::Value = serde_json::from_str(&stdout).ok()?;

        let info = inspect.get("info")?;
        let config = info.get("config")?;
        let runtime_spec = info.get("runtimeSpec")?;

        // Parse Linux security context
        let linux = runtime_spec.get("linux");
        let security_context = config.get("linux").and_then(|l| l.get("security_context"));

        let privileged = security_context
            .and_then(|sc| sc.get("privileged"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Parse mounts
        let mut host_mounts = Vec::new();
        if let Some(mounts) = runtime_spec.get("mounts").and_then(|v| v.as_array()) {
            for mount in mounts {
                let source = mount
                    .get("source")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let destination = mount
                    .get("destination")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let options: Vec<String> = mount
                    .get("options")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|x| x.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();

                let mode = if options.contains(&"ro".to_string()) {
                    "ro"
                } else {
                    "rw"
                }
                .to_string();

                let is_sensitive = SENSITIVE_HOST_PATHS.iter().any(|p| source.starts_with(p));

                host_mounts.push(HostMount {
                    source,
                    destination,
                    mode,
                    propagation: String::new(),
                    is_sensitive,
                });
            }
        }

        // Parse capabilities
        let mut capabilities = Vec::new();
        if let Some(caps) = linux
            .and_then(|l| l.get("capabilities"))
            .and_then(|c| c.get("bounding"))
            .and_then(|v| v.as_array())
        {
            for cap in caps {
                if let Some(c) = cap.as_str() {
                    capabilities.push(c.to_string());
                }
            }
        }

        // Parse namespace modes
        let namespaces = linux
            .and_then(|l| l.get("namespaces"))
            .and_then(|v| v.as_array());

        let mut pid_mode = "private".to_string();
        let mut network_mode = "private".to_string();
        let mut ipc_mode = "private".to_string();

        if let Some(ns_list) = namespaces {
            for ns in ns_list {
                let ns_type = ns.get("type").and_then(|v| v.as_str()).unwrap_or("");
                let ns_path = ns.get("path").and_then(|v| v.as_str()).unwrap_or("");

                match ns_type {
                    "pid" if ns_path.is_empty() => pid_mode = "host".to_string(),
                    "network" if ns_path.is_empty() => network_mode = "host".to_string(),
                    "ipc" if ns_path.is_empty() => ipc_mode = "host".to_string(),
                    _ => {}
                }
            }
        }

        Some(ContainerInfo {
            container_id: container_id.to_string(),
            container_name: config
                .get("metadata")
                .and_then(|m| m.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            image: config
                .get("image")
                .and_then(|i| i.get("image"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            image_tag: String::new(),
            pid: info.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
            user: security_context
                .and_then(|sc| sc.get("run_as_user"))
                .and_then(|v| v.as_u64())
                .map(|u| u.to_string())
                .unwrap_or_default(),
            command: config
                .get("command")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str())
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default(),
            env_vars: HashMap::new(),
            privileged,
            host_mounts,
            network_mode,
            pid_mode,
            ipc_mode,
            capabilities,
            security_opts: Vec::new(),
            read_only_rootfs: security_context
                .and_then(|sc| sc.get("readonly_rootfs"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            labels: HashMap::new(),
        })
    }

    /// Get CRI-O containers
    async fn get_crio_containers() -> Vec<ContainerInfo> {
        // CRI-O uses the same CRI interface as containerd
        Self::get_containerd_containers().await
    }

    /// Get Podman containers
    async fn get_podman_containers() -> Vec<ContainerInfo> {
        let mut containers = Vec::new();

        let output = tokio::process::Command::new("podman")
            .args(["ps", "-a", "--format", "json"])
            .output()
            .await;

        if let Ok(output) = output {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Ok(ctrs) = serde_json::from_str::<Vec<serde_json::Value>>(&stdout) {
                    for ctr in ctrs {
                        let container_id: String = ctr
                            .get("Id")
                            .or_else(|| ctr.get("id"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .chars()
                            .take(12)
                            .collect();

                        let image = ctr
                            .get("Image")
                            .or_else(|| ctr.get("image"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();

                        let (image_name, image_tag) = Self::parse_image_tag(&image);

                        // Get detailed info
                        let info = Self::get_podman_container_details(&container_id).await;

                        containers.push(ContainerInfo {
                            container_id,
                            container_name: ctr
                                .get("Names")
                                .and_then(|v| v.as_array())
                                .and_then(|arr| arr.first())
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                            image: image_name,
                            image_tag,
                            pid: info.as_ref().map(|i| i.pid).unwrap_or(0),
                            user: info.as_ref().map(|i| i.user.clone()).unwrap_or_default(),
                            command: ctr
                                .get("Command")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                            env_vars: info
                                .as_ref()
                                .map(|i| i.env_vars.clone())
                                .unwrap_or_default(),
                            privileged: info.as_ref().map(|i| i.privileged).unwrap_or(false),
                            host_mounts: info
                                .as_ref()
                                .map(|i| i.host_mounts.clone())
                                .unwrap_or_default(),
                            network_mode: info
                                .as_ref()
                                .map(|i| i.network_mode.clone())
                                .unwrap_or_default(),
                            pid_mode: info
                                .as_ref()
                                .map(|i| i.pid_mode.clone())
                                .unwrap_or_default(),
                            ipc_mode: info
                                .as_ref()
                                .map(|i| i.ipc_mode.clone())
                                .unwrap_or_default(),
                            capabilities: info
                                .as_ref()
                                .map(|i| i.capabilities.clone())
                                .unwrap_or_default(),
                            security_opts: info
                                .as_ref()
                                .map(|i| i.security_opts.clone())
                                .unwrap_or_default(),
                            read_only_rootfs: info
                                .as_ref()
                                .map(|i| i.read_only_rootfs)
                                .unwrap_or(false),
                            labels: ctr
                                .get("Labels")
                                .and_then(|v| v.as_object())
                                .map(|m| {
                                    m.iter()
                                        .filter_map(|(k, v)| {
                                            v.as_str().map(|s| (k.clone(), s.to_string()))
                                        })
                                        .collect()
                                })
                                .unwrap_or_default(),
                        });
                    }
                }
            }
        }

        containers
    }

    /// Get detailed Podman container information
    async fn get_podman_container_details(container_id: &str) -> Option<ContainerInfo> {
        let output = tokio::process::Command::new("podman")
            .args(["inspect", container_id])
            .output()
            .await
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let inspect: Vec<serde_json::Value> = serde_json::from_str(&stdout).ok()?;
        let container = inspect.first()?;

        // Podman inspect format is similar to Docker
        Self::parse_docker_inspect_format(container)
    }

    /// Parse Docker/Podman inspect JSON format
    fn parse_docker_inspect_format(container: &serde_json::Value) -> Option<ContainerInfo> {
        let config = container.get("Config")?;
        let host_config = container.get("HostConfig")?;
        let state = container.get("State")?;

        let image = config
            .get("Image")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let (image_name, image_tag) = Self::parse_image_tag(&image);

        // Parse mounts
        let mut host_mounts = Vec::new();
        if let Some(mounts) = container.get("Mounts").and_then(|v| v.as_array()) {
            for mount in mounts {
                let source = mount
                    .get("Source")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let destination = mount
                    .get("Destination")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let mode = mount
                    .get("Mode")
                    .and_then(|v| v.as_str())
                    .unwrap_or("rw")
                    .to_string();
                let propagation = mount
                    .get("Propagation")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let is_sensitive = SENSITIVE_HOST_PATHS.iter().any(|p| source.starts_with(p));

                host_mounts.push(HostMount {
                    source,
                    destination,
                    mode,
                    propagation,
                    is_sensitive,
                });
            }
        }

        // Parse capabilities
        let mut capabilities = Vec::new();
        if let Some(cap_add) = host_config.get("CapAdd").and_then(|v| v.as_array()) {
            for cap in cap_add {
                if let Some(c) = cap.as_str() {
                    capabilities.push(c.to_string());
                }
            }
        }

        // Parse security options
        let mut security_opts = Vec::new();
        if let Some(opts) = host_config.get("SecurityOpt").and_then(|v| v.as_array()) {
            for opt in opts {
                if let Some(o) = opt.as_str() {
                    security_opts.push(o.to_string());
                }
            }
        }

        Some(ContainerInfo {
            container_id: container
                .get("Id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .chars()
                .take(12)
                .collect(),
            container_name: container
                .get("Name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim_start_matches('/')
                .to_string(),
            image: image_name,
            image_tag,
            pid: state.get("Pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
            user: config
                .get("User")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            command: config
                .get("Cmd")
                .and_then(|v| {
                    v.as_array().map(|arr| {
                        arr.iter()
                            .filter_map(|x| x.as_str())
                            .collect::<Vec<_>>()
                            .join(" ")
                    })
                })
                .unwrap_or_default(),
            env_vars: HashMap::new(),
            privileged: host_config
                .get("Privileged")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            host_mounts,
            network_mode: host_config
                .get("NetworkMode")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            pid_mode: host_config
                .get("PidMode")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            ipc_mode: host_config
                .get("IpcMode")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            capabilities,
            security_opts,
            read_only_rootfs: host_config
                .get("ReadonlyRootfs")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            labels: config
                .get("Labels")
                .and_then(|v| v.as_object())
                .map(|m| {
                    m.iter()
                        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                        .collect()
                })
                .unwrap_or_default(),
        })
    }

    /// Parse image name and tag
    fn parse_image_tag(image: &str) -> (String, String) {
        // Handle format: registry/repo:tag or repo:tag or repo@sha256:digest
        let image = image.trim();

        // Handle digest format
        if let Some(at_pos) = image.find('@') {
            let name = &image[..at_pos];
            let digest = &image[at_pos + 1..];
            return (name.to_string(), digest.to_string());
        }

        // Handle tag format
        if let Some(colon_pos) = image.rfind(':') {
            // Make sure it's not the colon in a port number
            let after_colon = &image[colon_pos + 1..];
            if !after_colon.contains('/') {
                let name = &image[..colon_pos];
                let tag = after_colon;
                return (name.to_string(), tag.to_string());
            }
        }

        (image.to_string(), "latest".to_string())
    }

    /// Check if running in Kubernetes environment
    fn is_kubernetes_environment() -> bool {
        std::env::var("KUBERNETES_SERVICE_HOST").is_ok()
            || Path::new("/var/run/secrets/kubernetes.io").exists()
    }

    /// Create telemetry event from container info
    fn create_container_event(
        info: &ContainerInfo,
        runtime: &ContainerRuntime,
        is_k8s: bool,
    ) -> TelemetryEvent {
        let mut security_violations = Vec::new();

        // Check for security violations
        if info.privileged {
            security_violations.push(SecurityViolation {
                violation_type: ViolationType::PrivilegedContainer,
                description: "Container is running in privileged mode".to_string(),
                severity: "critical".to_string(),
                mitre_technique: "T1611".to_string(),
            });
        }

        if info.network_mode == "host" {
            security_violations.push(SecurityViolation {
                violation_type: ViolationType::HostNetworkAccess,
                description: "Container has host network access".to_string(),
                severity: "high".to_string(),
                mitre_technique: "T1611".to_string(),
            });
        }

        if info.pid_mode == "host" {
            security_violations.push(SecurityViolation {
                violation_type: ViolationType::HostPidAccess,
                description: "Container has host PID namespace access".to_string(),
                severity: "high".to_string(),
                mitre_technique: "T1611".to_string(),
            });
        }

        if info.ipc_mode == "host" {
            security_violations.push(SecurityViolation {
                violation_type: ViolationType::HostIpcAccess,
                description: "Container has host IPC namespace access".to_string(),
                severity: "medium".to_string(),
                mitre_technique: "T1611".to_string(),
            });
        }

        // Check for sensitive host mounts
        for mount in &info.host_mounts {
            if mount.is_sensitive {
                security_violations.push(SecurityViolation {
                    violation_type: ViolationType::SensitiveHostMount,
                    description: format!(
                        "Sensitive host path mounted: {} -> {}",
                        mount.source, mount.destination
                    ),
                    severity: "high".to_string(),
                    mitre_technique: "T1611".to_string(),
                });
            }
        }

        // Check for dangerous capabilities
        for cap in &info.capabilities {
            if DANGEROUS_CAPABILITIES.iter().any(|dc| cap.contains(dc)) {
                security_violations.push(SecurityViolation {
                    violation_type: ViolationType::DangerousCapability,
                    description: format!("Dangerous capability granted: {}", cap),
                    severity: "high".to_string(),
                    mitre_technique: "T1611".to_string(),
                });
            }
        }

        // Check if running as root
        if info.user.is_empty() || info.user == "0" || info.user == "root" {
            security_violations.push(SecurityViolation {
                violation_type: ViolationType::RunAsRoot,
                description: "Container is running as root".to_string(),
                severity: "medium".to_string(),
                mitre_technique: "T1610".to_string(),
            });
        }

        // Check for writable root filesystem
        if !info.read_only_rootfs {
            security_violations.push(SecurityViolation {
                violation_type: ViolationType::WritableRootfs,
                description: "Container has writable root filesystem".to_string(),
                severity: "low".to_string(),
                mitre_technique: "T1610".to_string(),
            });
        }

        // Check for missing security profiles
        let has_seccomp = info.security_opts.iter().any(|o| o.contains("seccomp"));
        let has_apparmor = info.security_opts.iter().any(|o| o.contains("apparmor"));

        if !has_seccomp {
            security_violations.push(SecurityViolation {
                violation_type: ViolationType::NoSeccompProfile,
                description: "No seccomp profile applied".to_string(),
                severity: "low".to_string(),
                mitre_technique: "T1610".to_string(),
            });
        }

        if !has_apparmor {
            security_violations.push(SecurityViolation {
                violation_type: ViolationType::NoAppArmor,
                description: "No AppArmor profile applied".to_string(),
                severity: "low".to_string(),
                mitre_technique: "T1610".to_string(),
            });
        }

        // Check for vulnerable base images
        let full_image = format!("{}:{}", info.image, info.image_tag);
        if VULNERABLE_IMAGES.iter().any(|vi| full_image.contains(vi)) {
            security_violations.push(SecurityViolation {
                violation_type: ViolationType::VulnerableBaseImage,
                description: format!("Running from known vulnerable base image: {}", full_image),
                severity: "medium".to_string(),
                mitre_technique: "T1610".to_string(),
            });
        }

        // Extract K8s info from labels
        let k8s_namespace = info.labels.get("io.kubernetes.pod.namespace").cloned();
        let k8s_pod = info.labels.get("io.kubernetes.pod.name").cloned();
        let k8s_service_account = info
            .labels
            .get("io.kubernetes.pod.serviceAccountName")
            .cloned();

        // Determine severity based on violations
        let severity = if security_violations.iter().any(|v| v.severity == "critical") {
            Severity::Critical
        } else if security_violations.iter().any(|v| v.severity == "high") {
            Severity::High
        } else if security_violations.iter().any(|v| v.severity == "medium") {
            Severity::Medium
        } else if !security_violations.is_empty() {
            Severity::Low
        } else {
            Severity::Info
        };

        let container_event = ContainerSecurityEvent {
            container_id: info.container_id.clone(),
            container_name: info.container_name.clone(),
            image: info.image.clone(),
            image_tag: info.image_tag.clone(),
            runtime: runtime.clone(),
            action: ContainerAction::Create,
            privileged: info.privileged,
            pid: info.pid,
            user: info.user.clone(),
            command: info.command.clone(),
            env_vars: info.env_vars.clone(),
            host_mounts: info.host_mounts.clone(),
            network_mode: info.network_mode.clone(),
            pid_mode: info.pid_mode.clone(),
            ipc_mode: info.ipc_mode.clone(),
            capabilities: info.capabilities.clone(),
            security_opts: info.security_opts.clone(),
            read_only_rootfs: info.read_only_rootfs,
            labels: info.labels.clone(),
            k8s_namespace,
            k8s_pod,
            k8s_service_account,
            security_violations: security_violations.clone(),
        };

        let mut event = TelemetryEvent::new(
            EventType::ContainerActivity,
            severity,
            EventPayload::Custom(serde_json::to_value(&container_event).unwrap_or_default()),
        );

        // Add detections for significant violations
        for violation in security_violations {
            if violation.severity == "critical" || violation.severity == "high" {
                event.add_detection(Detection {
                    detection_type: DetectionType::Behavioral,
                    rule_name: format!("container_{:?}", violation.violation_type).to_lowercase(),
                    confidence: 0.9,
                    description: violation.description,
                    mitre_tactics: vec![
                        "execution".to_string(),
                        "privilege-escalation".to_string(),
                    ],
                    mitre_techniques: vec![violation.mitre_technique],
                });
            }
        }

        event
    }

    /// Analyze container for additional security issues
    fn analyze_security(event: &mut TelemetryEvent, info: &ContainerInfo) {
        // Check for shell spawn indicators in command
        for shell in SHELL_BINARIES {
            if info.command.contains(shell) {
                event.add_detection(Detection {
                    detection_type: DetectionType::Behavioral,
                    rule_name: "container_shell_spawn".to_string(),
                    confidence: 0.7,
                    description: format!(
                        "Container {} may be spawning a shell: {}",
                        info.container_name, info.command
                    ),
                    mitre_tactics: vec!["execution".to_string()],
                    mitre_techniques: vec!["T1059".to_string()],
                });
                break;
            }
        }

        // Check for suspicious commands
        let suspicious_commands = [
            ("nsenter", "Namespace manipulation tool detected"),
            ("chroot", "Chroot detected, potential escape attempt"),
            ("mount", "Mount command detected"),
            ("insmod", "Kernel module loading detected"),
            ("modprobe", "Kernel module loading detected"),
            ("iptables", "Firewall manipulation detected"),
            ("ip route", "Network routing manipulation detected"),
            ("tc ", "Traffic control manipulation detected"),
            ("curl", "Network download tool"),
            ("wget", "Network download tool"),
            ("nc ", "Netcat detected"),
            ("ncat", "Ncat detected"),
            ("python -c", "Python inline execution"),
            ("perl -e", "Perl inline execution"),
            ("ruby -e", "Ruby inline execution"),
        ];

        for (cmd, desc) in suspicious_commands {
            if info.command.contains(cmd) {
                event.add_detection(Detection {
                    detection_type: DetectionType::Behavioral,
                    rule_name: "container_suspicious_command".to_string(),
                    confidence: 0.6,
                    description: format!(
                        "{} in container {}: {}",
                        desc, info.container_name, info.command
                    ),
                    mitre_tactics: vec!["execution".to_string()],
                    mitre_techniques: vec!["T1059".to_string()],
                });
            }
        }

        // Check for Docker socket mount (container escape vector)
        for mount in &info.host_mounts {
            if mount.source.contains("docker.sock")
                || mount.source.contains("containerd.sock")
                || mount.source.contains("crio.sock")
            {
                event.add_detection(Detection {
                    detection_type: DetectionType::Behavioral,
                    rule_name: "container_runtime_socket_mount".to_string(),
                    confidence: 0.95,
                    description: format!(
                        "Container {} has access to container runtime socket: {}",
                        info.container_name, mount.source
                    ),
                    mitre_tactics: vec!["privilege-escalation".to_string()],
                    mitre_techniques: vec!["T1611".to_string()],
                });
                event.severity = Severity::Critical;
            }
        }
    }

    /// Detect container escape attempts
    async fn detect_escape_attempts(_config: &AgentConfig) -> Option<TelemetryEvent> {
        // Check for CVE-2019-5736 (runc vulnerability) indicators
        // This involves monitoring for /proc/self/exe access patterns
        if let Ok(content) = tokio::fs::read_to_string("/proc/1/cgroup").await {
            if content.contains("docker") || content.contains("kubepods") {
                // We're inside a container, check for escape attempts

                // Check for /proc/sys abuse
                let proc_sys_paths = [
                    "/proc/sys/kernel/core_pattern",
                    "/proc/sys/kernel/modprobe",
                    "/proc/sysrq-trigger",
                    "/proc/sys/vm/panic_on_oom",
                ];

                for path in proc_sys_paths {
                    if Path::new(path).exists() {
                        // Check if writable (potential escape vector)
                        if let Ok(metadata) = std::fs::metadata(path) {
                            if !metadata.permissions().readonly() {
                                return Some(Self::create_escape_detection_event(
                                    ViolationType::ProcSysAbuse,
                                    format!("Writable {} detected in container", path),
                                ));
                            }
                        }
                    }
                }

                // Check for cgroup escape indicators
                let cgroup_paths = [
                    "/sys/fs/cgroup/*/release_agent",
                    "/sys/fs/cgroup/*/notify_on_release",
                ];

                for pattern in cgroup_paths {
                    // Simple pattern matching for cgroup paths
                    if let Ok(entries) = std::fs::read_dir("/sys/fs/cgroup") {
                        for entry in entries.flatten() {
                            let release_agent = entry.path().join("release_agent");
                            if release_agent.exists() {
                                if let Ok(content) = std::fs::read_to_string(&release_agent) {
                                    if !content.trim().is_empty() {
                                        return Some(Self::create_escape_detection_event(
                                            ViolationType::CgroupEscape,
                                            format!(
                                                "Cgroup release_agent set: {:?}",
                                                release_agent
                                            ),
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }

                // Check for kernel module loading attempts
                if Path::new("/lib/modules").exists() {
                    if let Ok(entries) = std::fs::read_dir("/lib/modules") {
                        for entry in entries.flatten() {
                            // If container has access to kernel modules, it's suspicious
                            let kernel_dir = entry.path();
                            if kernel_dir.join("modules.dep").exists() {
                                return Some(Self::create_escape_detection_event(
                                    ViolationType::KernelModuleLoad,
                                    format!(
                                        "Container has access to kernel modules: {:?}",
                                        kernel_dir
                                    ),
                                ));
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// Create escape detection event
    fn create_escape_detection_event(
        violation_type: ViolationType,
        description: String,
    ) -> TelemetryEvent {
        let mut event = TelemetryEvent::new(
            EventType::ContainerActivity,
            Severity::Critical,
            EventPayload::Custom(serde_json::json!({
                "action": "escape_attempt",
                "violation_type": violation_type,
                "description": description,
            })),
        );

        event.add_detection(Detection {
            detection_type: DetectionType::Behavioral,
            rule_name: format!("container_escape_{:?}", violation_type).to_lowercase(),
            confidence: 0.9,
            description,
            mitre_tactics: vec!["privilege-escalation".to_string()],
            mitre_techniques: vec!["T1611".to_string()],
        });

        event
    }

    /// Monitor Kubernetes-specific security issues
    async fn monitor_kubernetes_security() -> Option<TelemetryEvent> {
        // Check for ServiceAccount token access
        let sa_token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token";
        if Path::new(sa_token_path).exists() {
            // Check if the token was recently accessed
            if let Ok(metadata) = std::fs::metadata(sa_token_path) {
                if let Ok(accessed) = metadata.accessed() {
                    let now = std::time::SystemTime::now();
                    if let Ok(duration) = now.duration_since(accessed) {
                        // If accessed in the last 5 seconds, report it
                        if duration.as_secs() < 5 {
                            let mut event = TelemetryEvent::new(
                                EventType::ContainerActivity,
                                Severity::Medium,
                                EventPayload::Custom(serde_json::json!({
                                    "action": "secret_access",
                                    "path": sa_token_path,
                                    "type": "service_account_token",
                                })),
                            );

                            event.add_detection(Detection {
                                detection_type: DetectionType::Behavioral,
                                rule_name: "k8s_service_account_token_access".to_string(),
                                confidence: 0.6,
                                description: "ServiceAccount token accessed".to_string(),
                                mitre_tactics: vec!["credential-access".to_string()],
                                mitre_techniques: vec!["T1552.007".to_string()],
                            });

                            return Some(event);
                        }
                    }
                }
            }
        }

        // Check for etcd access attempts (port 2379, 2380)
        if let Ok(content) = tokio::fs::read_to_string("/proc/net/tcp").await {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    // Parse remote address
                    if let Some((_, port)) = Self::parse_proc_net_address(parts[2]) {
                        if port == 2379 || port == 2380 {
                            let mut event = TelemetryEvent::new(
                                EventType::ContainerActivity,
                                Severity::High,
                                EventPayload::Custom(serde_json::json!({
                                    "action": "etcd_access_attempt",
                                    "port": port,
                                })),
                            );

                            event.add_detection(Detection {
                                detection_type: DetectionType::Behavioral,
                                rule_name: "k8s_etcd_access".to_string(),
                                confidence: 0.85,
                                description: format!("Attempt to connect to etcd on port {}", port),
                                mitre_tactics: vec!["credential-access".to_string()],
                                mitre_techniques: vec!["T1552".to_string()],
                            });

                            return Some(event);
                        }
                    }
                }
            }
        }

        // Check for kubelet API access (port 10250, 10255)
        if let Ok(content) = tokio::fs::read_to_string("/proc/net/tcp").await {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Some((_, port)) = Self::parse_proc_net_address(parts[2]) {
                        if port == 10250 || port == 10255 {
                            let mut event = TelemetryEvent::new(
                                EventType::ContainerActivity,
                                Severity::High,
                                EventPayload::Custom(serde_json::json!({
                                    "action": "kubelet_api_access",
                                    "port": port,
                                })),
                            );

                            event.add_detection(Detection {
                                detection_type: DetectionType::Behavioral,
                                rule_name: "k8s_kubelet_access".to_string(),
                                confidence: 0.8,
                                description: format!(
                                    "Attempt to access kubelet API on port {}",
                                    port
                                ),
                                mitre_tactics: vec!["discovery".to_string()],
                                mitre_techniques: vec!["T1613".to_string()],
                            });

                            return Some(event);
                        }
                    }
                }
            }
        }

        None
    }

    /// Parse /proc/net address format
    fn parse_proc_net_address(hex: &str) -> Option<(String, u16)> {
        let parts: Vec<&str> = hex.split(':').collect();
        if parts.len() != 2 {
            return None;
        }

        let port = u16::from_str_radix(parts[1], 16).ok()?;
        let ip = u32::from_str_radix(parts[0], 16).ok()?;
        let ip_str = format!(
            "{}.{}.{}.{}",
            ip & 0xff,
            (ip >> 8) & 0xff,
            (ip >> 16) & 0xff,
            (ip >> 24) & 0xff
        );

        Some((ip_str, port))
    }

    /// Monitor container activity for suspicious behavior
    async fn monitor_container_activity(info: &ContainerInfo) -> Option<TelemetryEvent> {
        if info.pid == 0 {
            return None;
        }

        // Check what processes are running inside the container
        let proc_path = format!("/proc/{}/task", info.pid);
        if let Ok(entries) = std::fs::read_dir(&proc_path) {
            for entry in entries.flatten() {
                let comm_path = entry.path().join("comm");
                if let Ok(comm) = std::fs::read_to_string(&comm_path) {
                    let comm = comm.trim();

                    // Check for shell processes
                    if SHELL_BINARIES
                        .iter()
                        .any(|s| s.ends_with(&format!("/{}", comm)))
                    {
                        let mut event = TelemetryEvent::new(
                            EventType::ContainerActivity,
                            Severity::Medium,
                            EventPayload::Custom(serde_json::json!({
                                "container_id": info.container_id,
                                "container_name": info.container_name,
                                "action": "shell_spawn",
                                "shell": comm,
                                "pid": info.pid,
                            })),
                        );

                        event.add_detection(Detection {
                            detection_type: DetectionType::Behavioral,
                            rule_name: "container_shell_activity".to_string(),
                            confidence: 0.7,
                            description: format!(
                                "Shell process {} detected in container {}",
                                comm, info.container_name
                            ),
                            mitre_tactics: vec!["execution".to_string()],
                            mitre_techniques: vec!["T1059".to_string()],
                        });

                        return Some(event);
                    }

                    // Check for suspicious tools
                    let suspicious_tools = [
                        "nmap",
                        "masscan",
                        "metasploit",
                        "msfconsole",
                        "msfvenom",
                        "sqlmap",
                        "nikto",
                        "hydra",
                        "john",
                        "hashcat",
                        "mimikatz",
                        "crackmapexec",
                        "responder",
                        "bloodhound",
                        "evil-winrm",
                    ];

                    if suspicious_tools.contains(&comm) {
                        let mut event = TelemetryEvent::new(
                            EventType::ContainerActivity,
                            Severity::High,
                            EventPayload::Custom(serde_json::json!({
                                "container_id": info.container_id,
                                "container_name": info.container_name,
                                "action": "suspicious_tool",
                                "tool": comm,
                                "pid": info.pid,
                            })),
                        );

                        event.add_detection(Detection {
                            detection_type: DetectionType::Behavioral,
                            rule_name: "container_hacking_tool".to_string(),
                            confidence: 0.9,
                            description: format!(
                                "Suspicious tool {} detected in container {}",
                                comm, info.container_name
                            ),
                            mitre_tactics: vec!["execution".to_string()],
                            mitre_techniques: vec!["T1059".to_string()],
                        });

                        return Some(event);
                    }
                }
            }
        }

        None
    }

    /// Get next event from collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }

    /// Get detected container runtime
    pub fn get_runtime(&self) -> &ContainerRuntime {
        &self.runtime
    }
}

/// Internal container info structure
#[derive(Debug, Clone)]
struct ContainerInfo {
    container_id: String,
    container_name: String,
    image: String,
    image_tag: String,
    pid: u32,
    user: String,
    command: String,
    env_vars: HashMap<String, String>,
    privileged: bool,
    host_mounts: Vec<HostMount>,
    network_mode: String,
    pid_mode: String,
    ipc_mode: String,
    capabilities: Vec<String>,
    security_opts: Vec<String>,
    read_only_rootfs: bool,
    labels: HashMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_image_tag() {
        let (name, tag) = ContainerCollector::parse_image_tag("nginx:latest");
        assert_eq!(name, "nginx");
        assert_eq!(tag, "latest");

        let (name, tag) = ContainerCollector::parse_image_tag("nginx");
        assert_eq!(name, "nginx");
        assert_eq!(tag, "latest");

        let (name, tag) = ContainerCollector::parse_image_tag("gcr.io/project/image:v1.0.0");
        assert_eq!(name, "gcr.io/project/image");
        assert_eq!(tag, "v1.0.0");

        let (name, tag) = ContainerCollector::parse_image_tag("nginx@sha256:abc123");
        assert_eq!(name, "nginx");
        assert_eq!(tag, "sha256:abc123");
    }

    #[test]
    fn test_dangerous_capabilities() {
        assert!(DANGEROUS_CAPABILITIES.contains(&"CAP_SYS_ADMIN"));
        assert!(DANGEROUS_CAPABILITIES.contains(&"CAP_NET_ADMIN"));
        assert!(DANGEROUS_CAPABILITIES.contains(&"CAP_SYS_PTRACE"));
    }

    #[test]
    fn test_sensitive_paths() {
        assert!(SENSITIVE_HOST_PATHS.contains(&"/var/run/docker.sock"));
        assert!(SENSITIVE_HOST_PATHS.contains(&"/etc/shadow"));
        assert!(SENSITIVE_HOST_PATHS.contains(&"/proc"));
    }

    #[test]
    fn test_violation_type_serialization() {
        let violation = SecurityViolation {
            violation_type: ViolationType::PrivilegedContainer,
            description: "Test".to_string(),
            severity: "critical".to_string(),
            mitre_technique: "T1611".to_string(),
        };

        let json = serde_json::to_string(&violation).unwrap();
        assert!(json.contains("privileged_container"));
    }

    #[test]
    fn test_container_event_type_serialization() {
        let event_type = ContainerEventType::ExecStarted;
        let serialized = serde_json::to_string(&event_type).unwrap();
        assert_eq!(serialized, "\"exec_started\"");

        let created = ContainerEventType::Created;
        let serialized = serde_json::to_string(&created).unwrap();
        assert_eq!(serialized, "\"created\"");

        let oom = ContainerEventType::OomKilled;
        let serialized = serde_json::to_string(&oom).unwrap();
        assert_eq!(serialized, "\"oom_killed\"");
    }

    #[test]
    fn test_container_event_serialization() {
        let event = ContainerEvent {
            container_id: "abc123def456".to_string(),
            container_name: "test-container".to_string(),
            image: "nginx".to_string(),
            image_digest: "sha256:abc123".to_string(),
            event_type: ContainerEventType::Started,
            pod_name: Some("test-pod".to_string()),
            namespace: Some("default".to_string()),
            labels: {
                let mut labels = HashMap::new();
                labels.insert("app".to_string(), "test".to_string());
                labels
            },
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("abc123def456"));
        assert!(json.contains("test-container"));
        assert!(json.contains("nginx"));
        assert!(json.contains("started"));
        assert!(json.contains("test-pod"));
        assert!(json.contains("default"));
    }

    #[test]
    fn test_suspicious_process_severity() {
        assert_eq!(
            ContainerCollector::get_suspicious_process_severity("nsenter"),
            Severity::Critical
        );
        assert_eq!(
            ContainerCollector::get_suspicious_process_severity("chroot"),
            Severity::Critical
        );
        assert_eq!(
            ContainerCollector::get_suspicious_process_severity("xmrig"),
            Severity::High
        );
        assert_eq!(
            ContainerCollector::get_suspicious_process_severity("nmap"),
            Severity::Medium
        );
        assert_eq!(
            ContainerCollector::get_suspicious_process_severity("kubectl"),
            Severity::Medium
        );
    }

    #[test]
    fn test_suspicious_process_reason() {
        let reason = ContainerCollector::get_suspicious_process_reason("nsenter");
        assert!(reason.contains("container escape"));

        let reason = ContainerCollector::get_suspicious_process_reason("xmrig");
        assert!(reason.contains("cryptojacking"));

        let reason = ContainerCollector::get_suspicious_process_reason("nmap");
        assert!(reason.contains("reconnaissance"));
    }

    #[test]
    fn test_mount_severity() {
        assert_eq!(
            ContainerCollector::get_mount_severity("/var/run/docker.sock"),
            Severity::Critical
        );
        assert_eq!(
            ContainerCollector::get_mount_severity("/etc/shadow"),
            Severity::Critical
        );
        assert_eq!(
            ContainerCollector::get_mount_severity("/sys/fs/cgroup"),
            Severity::High
        );
        assert_eq!(
            ContainerCollector::get_mount_severity("/home"),
            Severity::Medium
        );
    }

    #[test]
    fn test_cgroup_version_serialization() {
        let v1 = CgroupVersion::V1;
        let serialized = serde_json::to_string(&v1).unwrap();
        assert_eq!(serialized, "\"v1\"");

        let v2 = CgroupVersion::V2;
        let serialized = serde_json::to_string(&v2).unwrap();
        assert_eq!(serialized, "\"v2\"");
    }

    #[test]
    fn test_suspicious_container_binaries() {
        assert!(SUSPICIOUS_CONTAINER_BINARIES.contains(&"nsenter"));
        assert!(SUSPICIOUS_CONTAINER_BINARIES.contains(&"xmrig"));
        assert!(SUSPICIOUS_CONTAINER_BINARIES.contains(&"kubectl"));
        assert!(SUSPICIOUS_CONTAINER_BINARIES.contains(&"modprobe"));
    }

    #[test]
    fn test_container_runtime_display() {
        assert_eq!(ContainerRuntime::Docker.to_string(), "docker");
        assert_eq!(ContainerRuntime::Containerd.to_string(), "containerd");
        assert_eq!(ContainerRuntime::CriO.to_string(), "cri-o");
        assert_eq!(ContainerRuntime::Podman.to_string(), "podman");
        assert_eq!(ContainerRuntime::Unknown.to_string(), "unknown");
    }

    #[test]
    fn test_container_action_display() {
        assert_eq!(ContainerAction::Create.to_string(), "create");
        assert_eq!(ContainerAction::Start.to_string(), "start");
        assert_eq!(ContainerAction::Exec.to_string(), "exec");
        assert_eq!(ContainerAction::SecretAccess.to_string(), "secret_access");
    }

    #[test]
    fn test_kubernetes_environment_serialization() {
        let env = KubernetesEnvironment {
            pod_name: "test-pod".to_string(),
            namespace: "production".to_string(),
            node_name: Some("worker-1".to_string()),
            service_account: Some("default".to_string()),
            labels: HashMap::new(),
            annotations: HashMap::new(),
        };

        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains("test-pod"));
        assert!(json.contains("production"));
        assert!(json.contains("worker-1"));
    }

    #[test]
    fn test_container_environment_serialization() {
        let env = ContainerEnvironment {
            is_containerized: true,
            container_id: Some("abc123def456".to_string()),
            runtime: ContainerRuntime::Docker,
            cgroup_version: CgroupVersion::V2,
            kubernetes: None,
        };

        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains("abc123def456"));
        assert!(json.contains("docker"));
        assert!(json.contains("v2"));
    }
}
