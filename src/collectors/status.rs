//! Collector capability and policy status reporting.

use crate::config::{AgentConfig, CollectorConfig, PerformanceProfile};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Agent-side collector capability and policy status slice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorCapabilityStatus {
    /// Contract version for server-side compatibility handling.
    pub contract_version: u32,
    /// Supported collector names on this platform/build.
    pub supported_collectors: Vec<String>,
    /// Config-enabled collector names on this endpoint.
    pub enabled_collectors: Vec<String>,
    /// Per-collector capability/config/runtime status.
    pub collectors: Vec<CollectorStatus>,
    /// Currently applied performance profile.
    pub active_profile: PerformanceProfile,
    /// Policy apply and drift state derived from the active config.
    pub policy: PolicyStatus,
}

/// Per-collector status entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorStatus {
    pub name: String,
    pub supported: bool,
    pub enabled: bool,
    pub state: CollectorState,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<CollectorError>,
}

/// Coarse collector state understood by the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectorState {
    Enabled,
    Disabled,
    Unsupported,
    Degraded,
}

/// Collector error/status detail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorError {
    pub code: String,
    pub message: String,
}

/// Policy apply/drift state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyStatus {
    pub apply_state: PolicyApplyState,
    pub drift_detected: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub drift_reasons: Vec<String>,
    pub active_profile: PerformanceProfile,
    pub requested_profile: PerformanceProfile,
    pub profile_policy_applied: bool,
    pub config_fingerprint_sha256: String,
}

/// Status of the last locally-applied policy/config view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyApplyState {
    Applied,
}

#[derive(Debug, Clone, Copy)]
struct CollectorDefinition {
    name: &'static str,
    enabled: fn(&CollectorConfig) -> bool,
    supported: bool,
}

impl CollectorCapabilityStatus {
    pub fn from_config(config: &AgentConfig) -> Self {
        let collectors: Vec<CollectorStatus> = collector_definitions()
            .into_iter()
            .map(|definition| {
                let enabled = (definition.enabled)(&config.collectors);
                let state = match (definition.supported, enabled) {
                    (true, true) => CollectorState::Enabled,
                    (true, false) => CollectorState::Disabled,
                    (false, true) => CollectorState::Degraded,
                    (false, false) => CollectorState::Unsupported,
                };
                let errors = if !definition.supported && enabled {
                    vec![CollectorError {
                        code: "unsupported_platform".to_string(),
                        message: format!(
                            "Collector '{}' is enabled in config but unsupported on this platform/build",
                            definition.name
                        ),
                    }]
                } else {
                    Vec::new()
                };

                CollectorStatus {
                    name: definition.name.to_string(),
                    supported: definition.supported,
                    enabled,
                    state,
                    errors,
                }
            })
            .collect();

        let mut collectors = collectors;
        apply_runtime_collector_state(&mut collectors);

        let supported_collectors = collectors
            .iter()
            .filter(|collector| collector.supported)
            .map(|collector| collector.name.clone())
            .collect();
        let enabled_collectors = collectors
            .iter()
            .filter(|collector| collector.supported && collector.enabled)
            .map(|collector| collector.name.clone())
            .collect();

        Self {
            contract_version: 1,
            supported_collectors,
            enabled_collectors,
            collectors,
            active_profile: config.performance_profile,
            policy: PolicyStatus {
                apply_state: PolicyApplyState::Applied,
                drift_detected: false,
                drift_reasons: Vec::new(),
                active_profile: config.performance_profile,
                requested_profile: config.performance_profile,
                profile_policy_applied: true,
                config_fingerprint_sha256: config_fingerprint(config),
            },
        }
    }
}

/// Apply per-collector runtime/platform state on top of the static
/// config-derived `CollectorStatus` list. This is where we surface
/// kernel/runtime prerequisites that cannot be known from config alone.
fn apply_runtime_collector_state(collectors: &mut [CollectorStatus]) {
    for status in collectors.iter_mut() {
        if status.name == "ebpf" {
            populate_ebpf_runtime_errors(status);
        }
    }
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn populate_ebpf_runtime_errors(status: &mut CollectorStatus) {
    use crate::collectors::ebpf_linux::LinuxEbpfCapabilities;

    // Probe the live kernel/runtime view. `missing_prerequisites` is
    // populated by `detect_for_object` via `compute_missing_prerequisites`.
    let caps = LinuxEbpfCapabilities::detect();
    if !caps.missing_prerequisites.is_empty() {
        // Mark the collector as degraded when the agent thinks it should be
        // running but the host is missing one or more kernel prerequisites.
        if status.enabled && status.supported && status.state == CollectorState::Enabled {
            status.state = CollectorState::Degraded;
        }
        for missing in &caps.missing_prerequisites {
            status.errors.push(CollectorError {
                code: "ebpf_missing_prerequisite".to_string(),
                message: missing.clone(),
            });
        }
    }
}

#[cfg(not(all(target_os = "linux", feature = "ebpf")))]
fn populate_ebpf_runtime_errors(_status: &mut CollectorStatus) {
    // No live eBPF runtime to probe on this platform/build; leave `errors`
    // untouched so the static config-derived state stands on its own.
}

fn config_fingerprint(config: &AgentConfig) -> String {
    let encoded = serde_json::to_vec(config).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(encoded);
    hex::encode(hasher.finalize())
}

fn collector_definitions() -> Vec<CollectorDefinition> {
    vec![
        CollectorDefinition {
            name: "process",
            enabled: |c| c.process_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "file",
            enabled: |c| c.file_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "network",
            enabled: |c| c.network_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "dns",
            enabled: |c| c.dns_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "injection",
            enabled: |c| c.injection_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "ntdll_write_monitor",
            enabled: |c| c.ntdll_write_monitor_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "named_pipes",
            enabled: |c| c.named_pipes_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "usb",
            enabled: |c| c.usb_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "ransomware_canary",
            enabled: |c| c.ransomware_canary_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "driver_blocklist",
            enabled: |c| c.driver_blocklist_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "memory",
            enabled: |c| c.memory_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "network_dpi",
            enabled: |c| c.network_dpi_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "network_anomaly",
            enabled: |c| c.network_anomaly_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "cloud",
            enabled: |c| c.cloud_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "exploit_mitigation",
            enabled: |c| c.exploit_mitigation_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "defense_evasion",
            enabled: |c| c.defense_evasion_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "syscall_evasion",
            enabled: |c| c.syscall_evasion_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "persistence",
            enabled: |c| c.persistence_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "script_inspector",
            enabled: |c| c.script_inspector_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "credential_theft",
            enabled: |c| c.credential_theft_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "lateral_movement",
            enabled: |c| c.lateral_movement_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "container",
            enabled: |c| c.container_enabled,
            supported: cfg!(target_os = "linux"),
        },
        CollectorDefinition {
            name: "process_hollowing",
            enabled: |c| c.process_hollowing_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "scheduled_tasks",
            enabled: |c| c.scheduled_tasks_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "firmware",
            enabled: |c| c.firmware_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "clipboard",
            enabled: |c| c.clipboard_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "browser_protection",
            enabled: |c| c.browser_protection_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "input_capture",
            enabled: |c| c.input_capture_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "office_email",
            enabled: |c| c.office_email_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "ad_monitor",
            enabled: |c| c.ad_monitor_enabled,
            supported: cfg!(target_os = "windows"),
        },
        CollectorDefinition {
            name: "health",
            enabled: |c| c.health_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "software_inventory",
            enabled: |c| c.software_inventory_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "ai_discovery",
            enabled: |c| c.ai_discovery_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "fim",
            enabled: |c| c.fim_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "dlp",
            enabled: |c| c.dlp_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "clipboard_dlp",
            enabled: |c| c.clipboard_dlp_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "network_discovery",
            enabled: |c| c.network_discovery_enabled,
            supported: true,
        },
        CollectorDefinition {
            name: "llm_interceptor",
            enabled: |_| cfg!(target_os = "linux"),
            supported: cfg!(target_os = "linux"),
        },
        CollectorDefinition {
            name: "auditd",
            enabled: auditd_enabled,
            supported: cfg!(all(target_os = "linux", feature = "auditd")),
        },
        platform_collector("identity", identity_enabled, cfg!(target_os = "windows")),
        platform_collector("registry", registry_enabled, cfg!(target_os = "windows")),
        platform_collector("etw", etw_enabled, cfg!(target_os = "windows")),
        platform_collector("amsi", amsi_enabled, cfg!(target_os = "windows")),
        platform_collector("lsass", lsass_enabled, cfg!(target_os = "windows")),
        platform_collector("wmi", wmi_enabled, cfg!(target_os = "windows")),
        platform_collector("clr", clr_enabled, cfg!(target_os = "windows")),
        platform_collector(
            "ebpf",
            ebpf_enabled,
            cfg!(all(target_os = "linux", feature = "ebpf")),
        ),
        platform_collector(
            "tcc_monitor",
            tcc_monitor_enabled,
            cfg!(target_os = "macos"),
        ),
        platform_collector(
            "xpc_monitor",
            xpc_monitor_enabled,
            cfg!(target_os = "macos"),
        ),
        CollectorDefinition {
            name: "endpoint_security",
            enabled: endpoint_security_enabled,
            supported: cfg!(target_os = "macos"),
        },
        CollectorDefinition {
            name: "sysext_bridge",
            enabled: sysext_bridge_enabled,
            supported: cfg!(target_os = "macos"),
        },
    ]
}

fn platform_collector(
    name: &'static str,
    enabled: fn(&CollectorConfig) -> bool,
    supported: bool,
) -> CollectorDefinition {
    CollectorDefinition {
        name,
        enabled,
        supported,
    }
}

#[cfg(target_os = "windows")]
fn identity_enabled(config: &CollectorConfig) -> bool {
    config.identity_enabled
}
#[cfg(not(target_os = "windows"))]
fn identity_enabled(_config: &CollectorConfig) -> bool {
    false
}

#[cfg(target_os = "windows")]
fn registry_enabled(config: &CollectorConfig) -> bool {
    config.registry_enabled
}
#[cfg(not(target_os = "windows"))]
fn registry_enabled(_config: &CollectorConfig) -> bool {
    false
}

#[cfg(target_os = "windows")]
fn etw_enabled(config: &CollectorConfig) -> bool {
    config.etw_enabled
}
#[cfg(not(target_os = "windows"))]
fn etw_enabled(_config: &CollectorConfig) -> bool {
    false
}

#[cfg(target_os = "windows")]
fn amsi_enabled(config: &CollectorConfig) -> bool {
    config.amsi_enabled
}
#[cfg(not(target_os = "windows"))]
fn amsi_enabled(_config: &CollectorConfig) -> bool {
    false
}

#[cfg(target_os = "windows")]
fn lsass_enabled(config: &CollectorConfig) -> bool {
    config.lsass_enabled
}
#[cfg(not(target_os = "windows"))]
fn lsass_enabled(_config: &CollectorConfig) -> bool {
    false
}

#[cfg(target_os = "windows")]
fn wmi_enabled(config: &CollectorConfig) -> bool {
    config.wmi_enabled
}
#[cfg(not(target_os = "windows"))]
fn wmi_enabled(_config: &CollectorConfig) -> bool {
    false
}

#[cfg(target_os = "windows")]
fn clr_enabled(config: &CollectorConfig) -> bool {
    config.clr_enabled
}
#[cfg(not(target_os = "windows"))]
fn clr_enabled(_config: &CollectorConfig) -> bool {
    false
}

#[cfg(target_os = "linux")]
fn ebpf_enabled(config: &CollectorConfig) -> bool {
    config.ebpf_enabled
}
#[cfg(not(target_os = "linux"))]
fn ebpf_enabled(_config: &CollectorConfig) -> bool {
    false
}

#[cfg(target_os = "linux")]
fn auditd_enabled(config: &CollectorConfig) -> bool {
    config.auditd_enabled
}
#[cfg(not(target_os = "linux"))]
fn auditd_enabled(_config: &CollectorConfig) -> bool {
    false
}

#[cfg(target_os = "macos")]
fn tcc_monitor_enabled(config: &CollectorConfig) -> bool {
    config.tcc_monitor_enabled
}
#[cfg(not(target_os = "macos"))]
fn tcc_monitor_enabled(_config: &CollectorConfig) -> bool {
    false
}

#[cfg(target_os = "macos")]
fn xpc_monitor_enabled(config: &CollectorConfig) -> bool {
    config.xpc_monitor_enabled
}
#[cfg(not(target_os = "macos"))]
fn xpc_monitor_enabled(_config: &CollectorConfig) -> bool {
    false
}

#[cfg(target_os = "macos")]
fn endpoint_security_enabled(config: &CollectorConfig) -> bool {
    config.endpoint_security_enabled
}
#[cfg(not(target_os = "macos"))]
fn endpoint_security_enabled(_config: &CollectorConfig) -> bool {
    false
}

#[cfg(target_os = "macos")]
fn sysext_bridge_enabled(config: &CollectorConfig) -> bool {
    config.sysext_bridge_enabled
}
#[cfg(not(target_os = "macos"))]
fn sysext_bridge_enabled(_config: &CollectorConfig) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_reports_profile_and_enabled_collectors() {
        let mut config = AgentConfig::default();
        config.performance_profile = PerformanceProfile::Lightweight;
        config.collectors.memory_enabled = false;

        let status = CollectorCapabilityStatus::from_config(&config);

        assert_eq!(status.contract_version, 1);
        assert_eq!(status.active_profile, PerformanceProfile::Lightweight);
        assert!(status.enabled_collectors.contains(&"process".to_string()));
        assert!(!status.enabled_collectors.contains(&"memory".to_string()));
        assert_eq!(status.policy.apply_state, PolicyApplyState::Applied);
        assert!(!status.policy.drift_detected);
        assert_eq!(status.policy.config_fingerprint_sha256.len(), 64);
    }
}
