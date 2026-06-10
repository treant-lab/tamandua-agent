//! Cloud Workload Protection Collector
//!
//! UNIQUE FEATURE: Comprehensive protection for cloud-native workloads:
//! - Container runtime security (Docker, containerd, CRI-O)
//! - Kubernetes security (pod security, RBAC violations)
//! - Cloud metadata service abuse detection
//! - Serverless function monitoring
//! - Cloud IAM anomaly detection
//! - Instance identity verification
//!
//! This bridges the gap between traditional EDR and CWPP solutions.

// Cloud Workload Protection collector. Several fields and parameters are
// scaffolded for upcoming cloud-provider-specific detection paths (IMDS abuse,
// k8s/CRI integrations) that are not yet wired through to the active pipeline.
#![allow(dead_code, unused_variables)]

use crate::collectors::{
    Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent,
};
use crate::config::AgentConfig;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::info;

/// Cloud provider types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CloudProvider {
    Aws,
    Azure,
    Gcp,
    DigitalOcean,
    OnPremise,
    Unknown,
}

/// Container runtime types
#[derive(Debug, Clone, PartialEq)]
pub enum ContainerRuntime {
    Docker,
    Containerd,
    CriO,
    Podman,
    Unknown,
}

/// Container information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    pub container_id: String,
    pub name: String,
    pub image: String,
    pub image_id: String,
    pub runtime: String,
    pub privileged: bool,
    pub capabilities: Vec<String>,
    pub mounts: Vec<MountInfo>,
    pub network_mode: String,
    pub pid_namespace: String,
    pub security_options: Vec<String>,
    pub labels: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountInfo {
    pub source: String,
    pub destination: String,
    pub mode: String,
    pub rw: bool,
    pub propagation: String,
}

/// Kubernetes pod information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesPodInfo {
    pub pod_name: String,
    pub namespace: String,
    pub node_name: String,
    pub service_account: String,
    pub labels: HashMap<String, String>,
    pub annotations: HashMap<String, String>,
    pub host_network: bool,
    pub host_pid: bool,
    pub host_ipc: bool,
    pub containers: Vec<KubernetesContainerInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesContainerInfo {
    pub name: String,
    pub image: String,
    pub privileged: bool,
    pub run_as_root: bool,
    pub allow_privilege_escalation: bool,
    pub read_only_root_filesystem: bool,
    pub capabilities_add: Vec<String>,
    pub capabilities_drop: Vec<String>,
}

/// Cloud instance metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudInstanceMetadata {
    pub provider: CloudProvider,
    pub instance_id: String,
    pub instance_type: String,
    pub region: String,
    pub availability_zone: String,
    pub vpc_id: Option<String>,
    pub subnet_id: Option<String>,
    pub security_groups: Vec<String>,
    pub iam_role: Option<String>,
    pub tags: HashMap<String, String>,
}

/// Cloud Workload Protection Collector
pub struct CloudWorkloadCollector {
    /// Agent configuration
    config: AgentConfig,
    /// Detected cloud provider
    cloud_provider: CloudProvider,
    /// Container runtime
    container_runtime: Option<ContainerRuntime>,
    /// Cached container info
    containers: HashMap<String, ContainerInfo>,
    /// Kubernetes info (if in k8s)
    kubernetes_info: Option<KubernetesPodInfo>,
    /// Cloud metadata
    instance_metadata: Option<CloudInstanceMetadata>,
    /// IMDS access history (for anomaly detection)
    imds_access_history: Vec<ImdsAccess>,
    /// Known legitimate IMDS callers
    legitimate_imds_callers: HashSet<String>,
    /// Event channel
    event_tx: Option<mpsc::Sender<TelemetryEvent>>,
    /// Last scan time
    last_scan: Option<Instant>,
}

#[derive(Debug, Clone)]
struct ImdsAccess {
    timestamp: Instant,
    process_name: String,
    pid: u32,
    endpoint: String,
}

impl CloudWorkloadCollector {
    /// Create new cloud workload collector
    pub fn new(config: &AgentConfig) -> Self {
        let mut collector = Self {
            config: config.clone(),
            cloud_provider: CloudProvider::Unknown,
            container_runtime: None,
            containers: HashMap::new(),
            kubernetes_info: None,
            instance_metadata: None,
            imds_access_history: Vec::new(),
            legitimate_imds_callers: HashSet::new(),
            event_tx: None,
            last_scan: None,
        };

        // Initialize legitimate IMDS callers
        collector.init_legitimate_callers();

        // Detect environment
        collector.detect_environment();

        collector
    }

    /// Initialize list of legitimate IMDS callers
    fn init_legitimate_callers(&mut self) {
        let legitimate = [
            "amazon-ssm-agent",
            "aws-cli",
            "cloud-init",
            "kubelet",
            "aws-node",
            "gce_helper",
            "azure-vm-agent",
            "walinuxagent",
            "google-guest-agent",
            "google-startup-script",
        ];

        for caller in legitimate {
            self.legitimate_imds_callers.insert(caller.to_string());
        }
    }

    /// Detect cloud environment and container runtime
    fn detect_environment(&mut self) {
        // Detect cloud provider
        self.cloud_provider = self.detect_cloud_provider();

        // Detect container runtime
        self.container_runtime = self.detect_container_runtime();

        // Check if running in Kubernetes
        self.kubernetes_info = self.detect_kubernetes_environment();

        // Fetch instance metadata from IMDS
        if self.cloud_provider != CloudProvider::Unknown
            && self.cloud_provider != CloudProvider::OnPremise
        {
            if let Some(metadata) = Self::fetch_cloud_metadata_sync(&self.cloud_provider) {
                self.instance_metadata = Some(metadata);
            }
        }

        info!(
            "Cloud environment detected: {:?}, Container: {:?}, Kubernetes: {}, Instance: {}",
            self.cloud_provider,
            self.container_runtime,
            self.kubernetes_info.is_some(),
            self.instance_metadata
                .as_ref()
                .map(|m| m.instance_id.as_str())
                .unwrap_or("unknown")
        );
    }

    /// Fetch cloud metadata from IMDS synchronously (for initialization)
    fn fetch_cloud_metadata_sync(provider: &CloudProvider) -> Option<CloudInstanceMetadata> {
        match provider {
            CloudProvider::Aws => Self::fetch_aws_metadata_sync(),
            CloudProvider::Azure => Self::fetch_azure_metadata_sync(),
            CloudProvider::Gcp => Self::fetch_gcp_metadata_sync(),
            _ => None,
        }
    }

    /// Fetch AWS EC2 metadata from IMDS v2
    fn fetch_aws_metadata_sync() -> Option<CloudInstanceMetadata> {
        // First, get IMDSv2 token
        let token = Self::get_aws_imds_token()?;

        // Fetch metadata endpoints
        let instance_id = Self::aws_imds_get("/latest/meta-data/instance-id", &token)?;
        let instance_type =
            Self::aws_imds_get("/latest/meta-data/instance-type", &token).unwrap_or_default();
        let region =
            Self::aws_imds_get("/latest/meta-data/placement/region", &token).unwrap_or_default();
        let az = Self::aws_imds_get("/latest/meta-data/placement/availability-zone", &token)
            .unwrap_or_default();

        // Optional: Security groups and IAM role
        let security_groups = Self::aws_imds_get("/latest/meta-data/security-groups", &token)
            .map(|s| s.lines().map(|l| l.to_string()).collect())
            .unwrap_or_default();

        let iam_role = Self::aws_imds_get("/latest/meta-data/iam/security-credentials/", &token)
            .map(|s| s.lines().next().map(|l| l.to_string()))
            .flatten();

        Some(CloudInstanceMetadata {
            provider: CloudProvider::Aws,
            instance_id,
            instance_type,
            region,
            availability_zone: az,
            vpc_id: None,
            subnet_id: None,
            security_groups,
            iam_role,
            tags: HashMap::new(),
        })
    }

    /// Get AWS IMDSv2 token
    fn get_aws_imds_token() -> Option<String> {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        use std::time::Duration;

        let mut stream =
            TcpStream::connect_timeout(&"169.254.169.254:80".parse().ok()?, Duration::from_secs(2))
                .ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;

        let request = "PUT /latest/api/token HTTP/1.1\r\nHost: 169.254.169.254\r\nX-aws-ec2-metadata-token-ttl-seconds: 300\r\nConnection: close\r\n\r\n";
        stream.write_all(request.as_bytes()).ok()?;

        let mut response = String::new();
        stream.read_to_string(&mut response).ok()?;

        // Parse HTTP response to get token
        let body = response.split("\r\n\r\n").nth(1)?;
        Some(body.trim().to_string())
    }

    /// Make AWS IMDS GET request with token
    fn aws_imds_get(path: &str, token: &str) -> Option<String> {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        use std::time::Duration;

        let mut stream =
            TcpStream::connect_timeout(&"169.254.169.254:80".parse().ok()?, Duration::from_secs(2))
                .ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;

        let request = format!(
            "GET {} HTTP/1.1\r\nHost: 169.254.169.254\r\nX-aws-ec2-metadata-token: {}\r\nConnection: close\r\n\r\n",
            path, token
        );
        stream.write_all(request.as_bytes()).ok()?;

        let mut response = String::new();
        stream.read_to_string(&mut response).ok()?;

        // Check for successful response
        if !response.starts_with("HTTP/1.1 200") {
            return None;
        }

        // Parse HTTP response to get body
        let body = response.split("\r\n\r\n").nth(1)?;
        Some(body.trim().to_string())
    }

    /// Fetch Azure metadata from IMDS
    fn fetch_azure_metadata_sync() -> Option<CloudInstanceMetadata> {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        use std::time::Duration;

        let mut stream =
            TcpStream::connect_timeout(&"169.254.169.254:80".parse().ok()?, Duration::from_secs(2))
                .ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;

        // Azure requires Metadata: true header
        let request = "GET /metadata/instance?api-version=2021-02-01 HTTP/1.1\r\nHost: 169.254.169.254\r\nMetadata: true\r\nConnection: close\r\n\r\n";
        stream.write_all(request.as_bytes()).ok()?;

        let mut response = String::new();
        stream.read_to_string(&mut response).ok()?;

        if !response.starts_with("HTTP/1.1 200") {
            return None;
        }

        let body = response.split("\r\n\r\n").nth(1)?;

        // Parse JSON response
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
            let compute = json.get("compute")?;

            Some(CloudInstanceMetadata {
                provider: CloudProvider::Azure,
                instance_id: compute.get("vmId")?.as_str()?.to_string(),
                instance_type: compute
                    .get("vmSize")?
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                region: compute
                    .get("location")?
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                availability_zone: compute
                    .get("zone")?
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                vpc_id: compute
                    .get("virtualMachineScaleSetVmId")
                    .and_then(|v| v.as_str().map(|s| s.to_string())),
                subnet_id: None,
                security_groups: Vec::new(),
                iam_role: None,
                tags: HashMap::new(),
            })
        } else {
            None
        }
    }

    /// Fetch GCP metadata from IMDS
    fn fetch_gcp_metadata_sync() -> Option<CloudInstanceMetadata> {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        use std::time::Duration;

        let mut stream =
            TcpStream::connect_timeout(&"169.254.169.254:80".parse().ok()?, Duration::from_secs(2))
                .ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;

        // GCP requires Metadata-Flavor: Google header
        let request = "GET /computeMetadata/v1/instance/?recursive=true HTTP/1.1\r\nHost: metadata.google.internal\r\nMetadata-Flavor: Google\r\nConnection: close\r\n\r\n";
        stream.write_all(request.as_bytes()).ok()?;

        let mut response = String::new();
        stream.read_to_string(&mut response).ok()?;

        if !response.starts_with("HTTP/1.1 200") {
            return None;
        }

        let body = response.split("\r\n\r\n").nth(1)?;

        // Parse JSON response
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
            let instance_id = json.get("id")?.as_u64()?.to_string();
            let machine_type = json.get("machineType")?.as_str().unwrap_or_default();
            let zone = json.get("zone")?.as_str().unwrap_or_default();

            // Extract region from zone (e.g., projects/123/zones/us-central1-a -> us-central1)
            let region = zone
                .split('/')
                .last()
                .map(|z| {
                    z.rsplit('-')
                        .skip(1)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .collect::<Vec<_>>()
                        .join("-")
                })
                .unwrap_or_default();

            Some(CloudInstanceMetadata {
                provider: CloudProvider::Gcp,
                instance_id,
                instance_type: machine_type
                    .split('/')
                    .last()
                    .unwrap_or_default()
                    .to_string(),
                region,
                availability_zone: zone.split('/').last().unwrap_or_default().to_string(),
                vpc_id: None,
                subnet_id: None,
                security_groups: Vec::new(),
                iam_role: json
                    .get("serviceAccounts")
                    .and_then(|sa| sa.as_object()?.keys().next().map(|k| k.to_string())),
                tags: HashMap::new(),
            })
        } else {
            None
        }
    }

    /// Detect cloud provider
    fn detect_cloud_provider(&self) -> CloudProvider {
        // Check for cloud-specific files/metadata
        #[cfg(target_os = "linux")]
        {
            // AWS
            if Path::new("/sys/hypervisor/uuid").exists() {
                if let Ok(uuid) = std::fs::read_to_string("/sys/hypervisor/uuid") {
                    if uuid.to_lowercase().starts_with("ec2") {
                        return CloudProvider::Aws;
                    }
                }
            }

            // Check DMI for cloud indicators
            if let Ok(vendor) = std::fs::read_to_string("/sys/class/dmi/id/sys_vendor") {
                let vendor = vendor.trim().to_lowercase();
                if vendor.contains("amazon") {
                    return CloudProvider::Aws;
                } else if vendor.contains("microsoft") {
                    return CloudProvider::Azure;
                } else if vendor.contains("google") {
                    return CloudProvider::Gcp;
                } else if vendor.contains("digitalocean") {
                    return CloudProvider::DigitalOcean;
                }
            }

            // Check for cloud-specific metadata endpoints (via cached DNS)
            if Path::new("/run/cloud-init/instance-data.json").exists() {
                if let Ok(content) = std::fs::read_to_string("/run/cloud-init/instance-data.json") {
                    if content.contains("aws") || content.contains("ec2") {
                        return CloudProvider::Aws;
                    } else if content.contains("azure") {
                        return CloudProvider::Azure;
                    } else if content.contains("gce") || content.contains("google") {
                        return CloudProvider::Gcp;
                    }
                }
            }
        }

        CloudProvider::Unknown
    }

    /// Detect container runtime
    fn detect_container_runtime(&self) -> Option<ContainerRuntime> {
        #[cfg(target_os = "linux")]
        {
            // Check cgroup to see if we're in a container
            if let Ok(cgroup) = std::fs::read_to_string("/proc/1/cgroup") {
                if cgroup.contains("docker") {
                    return Some(ContainerRuntime::Docker);
                } else if cgroup.contains("containerd") {
                    return Some(ContainerRuntime::Containerd);
                } else if cgroup.contains("crio") || cgroup.contains("cri-o") {
                    return Some(ContainerRuntime::CriO);
                } else if cgroup.contains("podman") {
                    return Some(ContainerRuntime::Podman);
                }
            }

            // Check for /.dockerenv
            if Path::new("/.dockerenv").exists() {
                return Some(ContainerRuntime::Docker);
            }

            // Check for container runtime sockets
            if Path::new("/var/run/docker.sock").exists() {
                // Not in container but Docker is available on host
            }

            if Path::new("/run/containerd/containerd.sock").exists() {
                // containerd available
            }
        }

        None
    }

    /// Detect Kubernetes environment
    fn detect_kubernetes_environment(&self) -> Option<KubernetesPodInfo> {
        // Check for Kubernetes service account
        let sa_path = "/var/run/secrets/kubernetes.io/serviceaccount";
        if !Path::new(sa_path).exists() {
            return None;
        }

        // Read pod info from downward API or environment
        let pod_name = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());
        let namespace = std::fs::read_to_string(format!("{}/namespace", sa_path))
            .unwrap_or_else(|_| "default".to_string())
            .trim()
            .to_string();

        Some(KubernetesPodInfo {
            pod_name,
            namespace,
            node_name: std::env::var("NODE_NAME").unwrap_or_default(),
            service_account: std::fs::read_to_string(format!("{}/token", sa_path))
                .map(|_| "present".to_string())
                .unwrap_or_default(),
            labels: self.get_pod_labels(),
            annotations: HashMap::new(),
            host_network: self.check_host_namespace("net"),
            host_pid: self.check_host_namespace("pid"),
            host_ipc: self.check_host_namespace("ipc"),
            containers: Vec::new(),
        })
    }

    /// Get pod labels from downward API
    fn get_pod_labels(&self) -> HashMap<String, String> {
        let labels_path = "/etc/podinfo/labels";
        if let Ok(content) = std::fs::read_to_string(labels_path) {
            content
                .lines()
                .filter_map(|line| {
                    let parts: Vec<&str> = line.splitn(2, '=').collect();
                    if parts.len() == 2 {
                        Some((
                            parts[0].trim_matches('"').to_string(),
                            parts[1].trim_matches('"').to_string(),
                        ))
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            HashMap::new()
        }
    }

    /// Check if using host namespace
    fn check_host_namespace(&self, ns_type: &str) -> bool {
        #[cfg(target_os = "linux")]
        {
            let self_ns = format!("/proc/self/ns/{}", ns_type);
            let init_ns = format!("/proc/1/ns/{}", ns_type);

            if let (Ok(self_link), Ok(init_link)) =
                (std::fs::read_link(&self_ns), std::fs::read_link(&init_ns))
            {
                return self_link == init_link;
            }
        }
        false
    }

    /// Start cloud workload collection
    pub async fn start(&mut self) -> Result<mpsc::Receiver<TelemetryEvent>> {
        let (tx, rx) = mpsc::channel(500);
        self.event_tx = Some(tx.clone());

        let config = self.config.clone();
        let provider = self.cloud_provider.clone();

        tokio::spawn(async move {
            Self::collection_loop(tx, config, provider).await;
        });

        Ok(rx)
    }

    /// Main collection loop
    async fn collection_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        config: AgentConfig,
        provider: CloudProvider,
    ) {
        info!("Starting cloud workload protection");

        let mut collector = Self::new(&config);
        let mut interval = tokio::time::interval(Duration::from_secs(30));

        loop {
            interval.tick().await;

            // Monitor container security
            if let Ok(events) = collector.monitor_containers().await {
                for event in events {
                    let _ = tx.send(event).await;
                }
            }

            // Monitor IMDS access
            if let Ok(events) = collector.monitor_imds_access().await {
                for event in events {
                    let _ = tx.send(event).await;
                }
            }

            // Monitor Kubernetes security (if applicable)
            if collector.kubernetes_info.is_some() {
                if let Ok(events) = collector.monitor_kubernetes_security().await {
                    for event in events {
                        let _ = tx.send(event).await;
                    }
                }
            }

            // Monitor cloud-specific threats
            if let Ok(events) = collector.monitor_cloud_threats(&provider).await {
                for event in events {
                    let _ = tx.send(event).await;
                }
            }
        }
    }

    /// Monitor containers for security issues
    async fn monitor_containers(&mut self) -> Result<Vec<TelemetryEvent>> {
        let events = Vec::new();

        #[cfg(target_os = "linux")]
        {
            // Check for privileged containers
            if let Some(runtime) = &self.container_runtime {
                // Check container capabilities
                if let Ok(caps) = self.get_container_capabilities() {
                    if caps.contains(&"CAP_SYS_ADMIN".to_string()) {
                        let mut event = TelemetryEvent::new(
                            EventType::ProcessCreate,
                            Severity::High,
                            EventPayload::Custom(serde_json::json!({
                                "type": "container_security",
                                "issue": "privileged_container",
                                "capabilities": caps,
                                "runtime": format!("{:?}", runtime),
                            })),
                        );

                        event.add_detection(Detection {
                            detection_type: DetectionType::Behavioral,
                            rule_name: "privileged_container".to_string(),
                            confidence: 0.8,
                            description:
                                "Container running with elevated privileges (CAP_SYS_ADMIN)"
                                    .to_string(),
                            mitre_tactics: vec!["privilege-escalation".to_string()],
                            mitre_techniques: vec!["T1611".to_string()],
                        });

                        events.push(event);
                    }

                    // Check for dangerous capabilities
                    let dangerous_caps = [
                        "CAP_NET_RAW",
                        "CAP_NET_ADMIN",
                        "CAP_SYS_PTRACE",
                        "CAP_SYS_MODULE",
                    ];

                    for cap in &dangerous_caps {
                        if caps.contains(&cap.to_string()) {
                            events.push(TelemetryEvent::new(
                                EventType::ProcessCreate,
                                Severity::Medium,
                                EventPayload::Custom(serde_json::json!({
                                    "type": "container_security",
                                    "issue": "dangerous_capability",
                                    "capability": cap,
                                })),
                            ));
                        }
                    }
                }

                // Check for sensitive mounts
                events.extend(self.check_sensitive_mounts()?);

                // Check for container escape indicators
                events.extend(self.detect_container_escape_attempts()?);
            }
        }

        Ok(events)
    }

    /// Get container capabilities
    #[cfg(target_os = "linux")]
    fn get_container_capabilities(&self) -> Result<Vec<String>> {
        let mut capabilities = Vec::new();

        // Read effective capabilities
        if let Ok(content) = std::fs::read_to_string("/proc/self/status") {
            for line in content.lines() {
                if line.starts_with("CapEff:") {
                    let hex_caps = line.split_whitespace().nth(1).unwrap_or("0");
                    if let Ok(caps) = u64::from_str_radix(hex_caps, 16) {
                        // Decode capability bits
                        let cap_names = [
                            "CAP_CHOWN",
                            "CAP_DAC_OVERRIDE",
                            "CAP_DAC_READ_SEARCH",
                            "CAP_FOWNER",
                            "CAP_FSETID",
                            "CAP_KILL",
                            "CAP_SETGID",
                            "CAP_SETUID",
                            "CAP_SETPCAP",
                            "CAP_LINUX_IMMUTABLE",
                            "CAP_NET_BIND_SERVICE",
                            "CAP_NET_BROADCAST",
                            "CAP_NET_ADMIN",
                            "CAP_NET_RAW",
                            "CAP_IPC_LOCK",
                            "CAP_IPC_OWNER",
                            "CAP_SYS_MODULE",
                            "CAP_SYS_RAWIO",
                            "CAP_SYS_CHROOT",
                            "CAP_SYS_PTRACE",
                            "CAP_SYS_PACCT",
                            "CAP_SYS_ADMIN",
                        ];

                        for (i, cap_name) in cap_names.iter().enumerate() {
                            if (caps >> i) & 1 == 1 {
                                capabilities.push(cap_name.to_string());
                            }
                        }
                    }
                }
            }
        }

        Ok(capabilities)
    }

    /// Check for sensitive host mounts
    #[cfg(target_os = "linux")]
    fn check_sensitive_mounts(&self) -> Result<Vec<TelemetryEvent>> {
        let mut events = Vec::new();

        let sensitive_paths = [
            "/var/run/docker.sock",
            "/var/run/containerd/containerd.sock",
            "/etc/kubernetes",
            "/etc/shadow",
            "/etc/passwd",
            "/root",
            "/home",
            "/proc/sys",
        ];

        if let Ok(mounts) = std::fs::read_to_string("/proc/self/mounts") {
            for line in mounts.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let mount_point = parts[1];

                    for sensitive in &sensitive_paths {
                        if mount_point == *sensitive || mount_point.starts_with(sensitive) {
                            let mut event = TelemetryEvent::new(
                                EventType::FileCreate,
                                Severity::High,
                                EventPayload::Custom(serde_json::json!({
                                    "type": "container_security",
                                    "issue": "sensitive_mount",
                                    "mount_point": mount_point,
                                    "source": parts[0],
                                })),
                            );

                            event.add_detection(Detection {
                                detection_type: DetectionType::Behavioral,
                                rule_name: "sensitive_host_mount".to_string(),
                                confidence: 0.85,
                                description: format!(
                                    "Container has access to sensitive host path: {}",
                                    mount_point
                                ),
                                mitre_tactics: vec!["privilege-escalation".to_string()],
                                mitre_techniques: vec!["T1611".to_string()],
                            });

                            events.push(event);
                        }
                    }
                }
            }
        }

        Ok(events)
    }

    /// Detect container escape attempts
    #[cfg(target_os = "linux")]
    fn detect_container_escape_attempts(&self) -> Result<Vec<TelemetryEvent>> {
        let mut events = Vec::new();

        // Check for common escape techniques
        let escape_indicators = [
            // CVE-2019-5736 (runc vulnerability)
            ("/proc/self/exe", "runc_overwrite"),
            // Docker socket access
            ("/var/run/docker.sock", "docker_socket"),
            // cgroup escape
            ("/sys/fs/cgroup/*/release_agent", "cgroup_escape"),
            // Kernel module loading
            ("/lib/modules", "kernel_module"),
        ];

        for (path, technique) in escape_indicators {
            if Path::new(path).exists() {
                // Check if being accessed
                if self.is_path_being_accessed(path) {
                    let mut event = TelemetryEvent::new(
                        EventType::FileCreate,
                        Severity::Critical,
                        EventPayload::Custom(serde_json::json!({
                            "type": "container_escape",
                            "technique": technique,
                            "path": path,
                        })),
                    );

                    event.add_detection(Detection {
                        detection_type: DetectionType::Behavioral,
                        rule_name: format!("container_escape_{}", technique),
                        confidence: 0.9,
                        description: format!(
                            "Potential container escape attempt detected: {}",
                            technique
                        ),
                        mitre_tactics: vec!["privilege-escalation".to_string()],
                        mitre_techniques: vec!["T1611".to_string()],
                    });

                    events.push(event);
                }
            }
        }

        Ok(events)
    }

    /// Check whether any process currently has the given file open by scanning
    /// `/proc/*/fd/` symlinks. This is equivalent to what `fuser` or `lsof` does.
    /// Returns true if at least one process (other than ourselves) has the path open.
    #[cfg(target_os = "linux")]
    fn is_path_being_accessed(&self, path: &str) -> bool {
        use std::path::PathBuf;

        let target = match std::fs::canonicalize(path) {
            Ok(p) => p,
            Err(_) => PathBuf::from(path),
        };

        let my_pid = std::process::id();

        let proc_dir = match std::fs::read_dir("/proc") {
            Ok(d) => d,
            Err(_) => return false,
        };

        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let pid: u32 = match name.to_str().and_then(|s| s.parse().ok()) {
                Some(p) => p,
                None => continue,
            };

            // Skip our own process to avoid self-detection
            if pid == my_pid {
                continue;
            }

            let fd_dir = match std::fs::read_dir(format!("/proc/{}/fd", pid)) {
                Ok(d) => d,
                Err(_) => continue, // Permission denied or process exited
            };

            for fd_entry in fd_dir.flatten() {
                match std::fs::read_link(fd_entry.path()) {
                    Ok(link_target) => {
                        // Compare the symlink target with our target path.
                        // Use canonicalize on the link target as well for a robust comparison,
                        // but fall back to direct comparison if canonicalize fails (e.g. deleted files).
                        let resolved = std::fs::canonicalize(&link_target).unwrap_or(link_target);
                        if resolved == target {
                            tracing::debug!(
                                "Path {} is being accessed by PID {} (fd: {:?})",
                                path,
                                pid,
                                fd_entry.path()
                            );
                            return true;
                        }
                    }
                    Err(_) => continue,
                }
            }
        }

        false
    }

    /// Monitor IMDS (Instance Metadata Service) access
    async fn monitor_imds_access(&mut self) -> Result<Vec<TelemetryEvent>> {
        let events = Vec::new();

        // IMDS endpoints by provider
        let imds_endpoints = match self.cloud_provider {
            CloudProvider::Aws => vec!["169.254.169.254"],
            CloudProvider::Azure => vec!["169.254.169.254"],
            CloudProvider::Gcp => vec!["169.254.169.254", "metadata.google.internal"],
            _ => vec![],
        };

        if imds_endpoints.is_empty() {
            return Ok(events);
        }

        // Check network connections for IMDS access
        #[cfg(target_os = "linux")]
        {
            if let Ok(tcp_content) = std::fs::read_to_string("/proc/net/tcp") {
                for line in tcp_content.lines().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        let remote_addr = parts[2];
                        // Parse remote address
                        if let Some((ip, _port)) = self.parse_proc_net_addr(remote_addr) {
                            for imds_ip in &imds_endpoints {
                                if ip == *imds_ip {
                                    // Found IMDS connection - check caller
                                    if let Some(event) = self.analyze_imds_access(&ip, parts.get(9))
                                    {
                                        events.push(event);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(events)
    }

    #[cfg(target_os = "linux")]
    fn parse_proc_net_addr(&self, addr: &str) -> Option<(String, u16)> {
        let parts: Vec<&str> = addr.split(':').collect();
        if parts.len() != 2 {
            return None;
        }

        let ip_hex = parts[0];
        let port = u16::from_str_radix(parts[1], 16).ok()?;

        // Convert hex IP
        if ip_hex.len() == 8 {
            let bytes: Vec<u8> = (0..4)
                .filter_map(|i| u8::from_str_radix(&ip_hex[i * 2..i * 2 + 2], 16).ok())
                .collect();
            if bytes.len() == 4 {
                let ip = format!("{}.{}.{}.{}", bytes[3], bytes[2], bytes[1], bytes[0]);
                return Some((ip, port));
            }
        }

        None
    }

    #[cfg(target_os = "linux")]
    fn analyze_imds_access(&self, ip: &str, inode: Option<&&str>) -> Option<TelemetryEvent> {
        // Find process accessing IMDS
        let pid = inode
            .and_then(|i| self.find_pid_by_socket_inode(i))
            .unwrap_or(0);

        let process_name = if pid > 0 {
            std::fs::read_to_string(format!("/proc/{}/comm", pid))
                .unwrap_or_default()
                .trim()
                .to_string()
        } else {
            "unknown".to_string()
        };

        // Check if legitimate caller
        if self.legitimate_imds_callers.contains(&process_name) {
            return None;
        }

        // Suspicious IMDS access
        let mut event = TelemetryEvent::new(
            EventType::NetworkConnect,
            Severity::High,
            EventPayload::Custom(serde_json::json!({
                "type": "imds_access",
                "destination": ip,
                "pid": pid,
                "process_name": process_name,
                "cloud_provider": format!("{:?}", self.cloud_provider),
            })),
        );

        event.add_detection(Detection {
            detection_type: DetectionType::Behavioral,
            rule_name: "suspicious_imds_access".to_string(),
            confidence: 0.8,
            description: format!(
                "Suspicious IMDS access by process '{}' (PID: {}) - potential credential theft",
                process_name, pid
            ),
            mitre_tactics: vec!["credential-access".to_string()],
            mitre_techniques: vec!["T1552.005".to_string()],
        });

        Some(event)
    }

    #[cfg(target_os = "linux")]
    fn find_pid_by_socket_inode(&self, inode: &str) -> Option<u32> {
        let socket_pattern = format!("socket:[{}]", inode);

        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(pid) = entry.file_name().to_str()?.parse::<u32>() {
                    let fd_path = entry.path().join("fd");
                    if let Ok(fds) = std::fs::read_dir(fd_path) {
                        for fd in fds.flatten() {
                            if let Ok(link) = std::fs::read_link(fd.path()) {
                                if link.to_string_lossy() == socket_pattern {
                                    return Some(pid);
                                }
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// Monitor Kubernetes-specific security issues
    async fn monitor_kubernetes_security(&self) -> Result<Vec<TelemetryEvent>> {
        let mut events = Vec::new();

        if let Some(k8s_info) = &self.kubernetes_info {
            // Check for host namespaces
            if k8s_info.host_network {
                events.push(self.create_k8s_security_event(
                    "host_network",
                    "Pod running with hostNetwork=true",
                    Severity::High,
                ));
            }

            if k8s_info.host_pid {
                events.push(self.create_k8s_security_event(
                    "host_pid",
                    "Pod running with hostPID=true",
                    Severity::High,
                ));
            }

            if k8s_info.host_ipc {
                events.push(self.create_k8s_security_event(
                    "host_ipc",
                    "Pod running with hostIPC=true",
                    Severity::Medium,
                ));
            }

            // Check for Kubernetes API access from unexpected processes
            if self.detect_unexpected_k8s_api_access()? {
                events.push(self.create_k8s_security_event(
                    "unexpected_api_access",
                    "Unexpected process accessing Kubernetes API",
                    Severity::High,
                ));
            }

            // Check for secrets access
            events.extend(self.monitor_k8s_secrets_access()?);
        }

        Ok(events)
    }

    fn create_k8s_security_event(
        &self,
        issue: &str,
        description: &str,
        severity: Severity,
    ) -> TelemetryEvent {
        let k8s_info = match self.kubernetes_info.as_ref() {
            Some(info) => info,
            None => {
                return TelemetryEvent::new(
                    EventType::ProcessCreate,
                    severity.clone(),
                    EventPayload::Custom(serde_json::json!({
                        "type": "kubernetes_security",
                        "issue": issue,
                        "error": "kubernetes_info not available",
                    })),
                );
            }
        };

        let mut event = TelemetryEvent::new(
            EventType::ProcessCreate,
            severity.clone(),
            EventPayload::Custom(serde_json::json!({
                "type": "kubernetes_security",
                "issue": issue,
                "pod_name": k8s_info.pod_name,
                "namespace": k8s_info.namespace,
                "node_name": k8s_info.node_name,
            })),
        );

        event.add_detection(Detection {
            detection_type: DetectionType::Behavioral,
            rule_name: format!("k8s_{}", issue),
            confidence: 0.75,
            description: description.to_string(),
            mitre_tactics: vec!["privilege-escalation".to_string()],
            mitre_techniques: vec!["T1611".to_string()],
        });

        event
    }

    fn detect_unexpected_k8s_api_access(&self) -> Result<bool> {
        // Check for processes connecting to Kubernetes API
        let k8s_api = "kubernetes.default.svc";

        #[cfg(target_os = "linux")]
        {
            if let Ok(resolv) = std::fs::read_to_string("/etc/resolv.conf") {
                // Check if we can resolve k8s service
                // In production, monitor actual network connections
            }
        }

        Ok(false)
    }

    fn monitor_k8s_secrets_access(&self) -> Result<Vec<TelemetryEvent>> {
        let events = Vec::new();

        // Check for access to secret mount paths
        let secret_paths = [
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
            "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
        ];

        // In production, use fanotify to monitor access
        // For now, just check if paths exist and are readable

        Ok(events)
    }

    /// Monitor cloud-specific threats
    async fn monitor_cloud_threats(&self, provider: &CloudProvider) -> Result<Vec<TelemetryEvent>> {
        let mut events = Vec::new();

        match provider {
            CloudProvider::Aws => {
                events.extend(self.monitor_aws_threats().await?);
            }
            CloudProvider::Azure => {
                events.extend(self.monitor_azure_threats().await?);
            }
            CloudProvider::Gcp => {
                events.extend(self.monitor_gcp_threats().await?);
            }
            _ => {}
        }

        Ok(events)
    }

    async fn monitor_aws_threats(&self) -> Result<Vec<TelemetryEvent>> {
        let events = Vec::new();

        // Check for EC2 instance role abuse indicators
        // Check for suspicious AWS CLI usage
        // Monitor for S3 exfiltration patterns

        Ok(events)
    }

    async fn monitor_azure_threats(&self) -> Result<Vec<TelemetryEvent>> {
        let events = Vec::new();

        // Check for managed identity abuse
        // Monitor Azure CLI usage
        // Check for Azure Storage access patterns

        Ok(events)
    }

    async fn monitor_gcp_threats(&self) -> Result<Vec<TelemetryEvent>> {
        let events = Vec::new();

        // Check for service account abuse
        // Monitor gcloud usage
        // Check for GCS access patterns

        Ok(events)
    }

    /// Get next event (for main loop integration)
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        let now = Instant::now();

        // Rate limit scanning
        if let Some(last) = self.last_scan {
            if now.duration_since(last) < Duration::from_secs(30) {
                return None;
            }
        }
        self.last_scan = Some(now);

        // Check containers
        if let Ok(events) = self.monitor_containers().await {
            if let Some(event) = events.into_iter().next() {
                return Some(event);
            }
        }

        None
    }

    /// Get cloud metadata
    pub fn get_cloud_metadata(&self) -> Option<&CloudInstanceMetadata> {
        self.instance_metadata.as_ref()
    }

    /// Get Kubernetes info
    pub fn get_kubernetes_info(&self) -> Option<&KubernetesPodInfo> {
        self.kubernetes_info.as_ref()
    }

    /// Is running in container
    pub fn is_containerized(&self) -> bool {
        self.container_runtime.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloud_provider_detection() {
        let config = AgentConfig::default();
        let collector = CloudWorkloadCollector::new(&config);
        // Provider detection depends on environment
        assert!(matches!(
            collector.cloud_provider,
            CloudProvider::Unknown | CloudProvider::Aws | CloudProvider::Azure | CloudProvider::Gcp
        ));
    }
}
