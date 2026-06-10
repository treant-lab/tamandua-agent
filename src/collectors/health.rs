//! System Health Collector
//!
//! Collects CPU, memory, and disk usage metrics along with system uptime.
//! Sends periodic SystemHealth events so the backend can display live
//! resource utilisation on the dashboard and agent detail pages.

use super::{CollectorCapabilityStatus, EventPayload, EventType, Severity, TelemetryEvent};
use crate::config::AgentConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use sysinfo::{Disks, System};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// System health snapshot sent as an event payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealthEvent {
    /// Overall CPU usage percentage (0.0 - 100.0)
    pub cpu_usage: f32,
    /// Total physical memory in bytes
    pub memory_total: u64,
    /// Used physical memory in bytes
    pub memory_used: u64,
    /// Available physical memory in bytes
    pub memory_available: u64,
    /// Memory usage percentage (0.0 - 100.0)
    pub memory_usage_percent: f32,
    /// Total disk space in bytes (sum of all mounted disks)
    pub disk_total: u64,
    /// Used disk space in bytes
    pub disk_used: u64,
    /// Disk usage percentage (0.0 - 100.0)
    pub disk_usage_percent: f32,
    /// System uptime in seconds
    pub uptime_seconds: u64,
    /// Collector capability/config/policy status snapshot.
    pub collector_status: CollectorCapabilityStatus,
    /// Platform sensor readiness and runtime state for kernel/OS-specific sources.
    #[serde(default)]
    pub platform_status: Vec<PlatformSensorHealth>,
    /// Windows kernel driver/ring-buffer status, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver_status: Option<DriverHealthEvent>,
}

/// Readiness/runtime status for platform-specific sensors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformSensorHealth {
    pub name: String,
    pub platform: String,
    pub kind: String,
    pub state: String,
    pub configured: bool,
    pub compiled: bool,
    pub running: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Driver telemetry health snapshot included in normal health events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverHealthEvent {
    pub supported: bool,
    pub loaded: bool,
    pub connected: bool,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entitlement_status: Option<String>,
    pub lab_level: u32,
    pub feature_level: String,
    pub writable_read_index: bool,
    pub protocol_version: u32,
    pub buffer_size: u32,
    pub write_index: i32,
    pub read_index: i32,
    pub sequence_number: u32,
    pub flags: u32,
    pub events_consumed: u64,
    pub events_converted: u64,
    pub events_skipped: u64,
    pub events_malformed: u64,
    pub channel_drops: u64,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub raw_event_type_counts: HashMap<String, u64>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub converted_event_type_counts: HashMap<String, u64>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub skipped_event_type_counts: HashMap<String, u64>,
    pub kernel_events_written: u64,
    pub kernel_events_dropped: u64,
    pub reconnect_attempts: u64,
    pub consecutive_failures: u32,
    pub last_event_at: Option<String>,
    pub last_error: Option<String>,
}

/// Health metrics collector
pub struct HealthCollector {
    event_rx: mpsc::Receiver<TelemetryEvent>,
}

impl HealthCollector {
    /// Create a new health collector.
    ///
    /// The `interval_seconds` parameter controls how frequently metrics are
    /// sampled.  The default (used when the config value is 0 or absent) is
    /// 60 seconds.
    pub fn new(config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(64);

        let interval_secs = if config.health_interval_seconds > 0 {
            config.health_interval_seconds
        } else {
            60
        };

        let collector_status = CollectorCapabilityStatus::from_config(config);
        let config_snapshot = config.clone();

        tokio::spawn(Self::monitor_loop(
            tx,
            interval_secs,
            collector_status,
            config_snapshot,
        ));

        info!(
            interval_seconds = interval_secs,
            "Health collector initialized"
        );

        Self { event_rx: rx }
    }

    async fn monitor_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        interval_secs: u32,
        collector_status: CollectorCapabilityStatus,
        config: AgentConfig,
    ) {
        let mut sys = System::new();

        // Allow the first CPU measurement to settle (sysinfo needs two
        // refreshes to produce a meaningful global CPU value).
        sys.refresh_cpu_usage();
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        let mut interval =
            tokio::time::interval(tokio::time::Duration::from_secs(interval_secs as u64));

        loop {
            interval.tick().await;

            // Refresh only the subsystems we care about
            sys.refresh_cpu_usage();
            sys.refresh_memory();
            let disks = Disks::new_with_refreshed_list();

            // sysinfo 0.30: use global_cpu_info().cpu_usage() instead of deprecated global_cpu_usage()
            let cpu_usage = sys.global_cpu_info().cpu_usage();

            let memory_total = sys.total_memory();
            let memory_used = sys.used_memory();
            let memory_available = sys.available_memory();
            let memory_usage_percent = if memory_total > 0 {
                (memory_used as f64 / memory_total as f64 * 100.0) as f32
            } else {
                0.0
            };

            let mut disk_total: u64 = 0;
            let mut disk_used: u64 = 0;
            for disk in disks.list() {
                disk_total += disk.total_space();
                disk_used += disk.total_space() - disk.available_space();
            }
            let disk_usage_percent = if disk_total > 0 {
                (disk_used as f64 / disk_total as f64 * 100.0) as f32
            } else {
                0.0
            };

            let uptime_seconds = System::uptime();
            // Pull the most recent runtime eBPF health snapshot published by
            // the eBPF collector. Will be `None` on non-Linux or when the
            // collector has not yet published.
            let ebpf_health = crate::collectors::ebpf_linux::latest_health();
            let platform_status = Self::platform_status_snapshot(&config, ebpf_health.as_ref());

            let health = SystemHealthEvent {
                cpu_usage,
                memory_total,
                memory_used,
                memory_available,
                memory_usage_percent,
                disk_total,
                disk_used,
                disk_usage_percent,
                uptime_seconds,
                collector_status: collector_status.clone(),
                platform_status,
                driver_status: Self::driver_health_snapshot(),
            };

            debug!(
                cpu = %format!("{:.1}%", cpu_usage),
                mem = %format!("{:.1}%", memory_usage_percent),
                disk = %format!("{:.1}%", disk_usage_percent),
                uptime = uptime_seconds,
                "Health metrics collected"
            );

            let event = TelemetryEvent::new(
                EventType::SystemHealth,
                Severity::Info,
                EventPayload::SystemHealth(health),
            );

            if tx.send(event).await.is_err() {
                warn!("Health event channel closed");
                return;
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn driver_health_snapshot() -> Option<DriverHealthEvent> {
        let stats = crate::driver::ring_buffer::global_stats();
        let loaded = crate::driver::is_driver_loaded();
        let state = if stats.connected {
            "loaded"
        } else if loaded {
            "loaded_no_telemetry"
        } else {
            "not_loaded"
        };

        Some(DriverHealthEvent {
            supported: true,
            loaded,
            connected: stats.connected,
            state: state.to_string(),
            platform: Some("windows".to_string()),
            provider: Some("kernel_driver".to_string()),
            service_name: Some("Tamandua".to_string()),
            entitlement_status: None,
            lab_level: crate::driver::LAB_LEVEL,
            feature_level: crate::driver::lab_feature_level().to_string(),
            writable_read_index: stats.writable_read_index,
            protocol_version: stats.protocol_version,
            buffer_size: stats.buffer_size,
            write_index: stats.write_index,
            read_index: stats.read_index,
            sequence_number: stats.sequence_number,
            flags: stats.flags,
            events_consumed: stats.events_consumed,
            events_converted: stats.events_converted,
            events_skipped: stats.events_skipped,
            events_malformed: stats.events_malformed,
            channel_drops: stats.channel_drops,
            raw_event_type_counts: stats.raw_event_type_counts,
            converted_event_type_counts: stats.converted_event_type_counts,
            skipped_event_type_counts: stats.skipped_event_type_counts,
            kernel_events_written: stats.kernel_events_written,
            kernel_events_dropped: stats.kernel_events_dropped,
            reconnect_attempts: stats.reconnect_attempts,
            consecutive_failures: stats.consecutive_failures,
            last_event_at: stats.last_event_at.map(|dt| dt.to_rfc3339()),
            last_error: stats.last_error,
        })
    }

    #[cfg(target_os = "macos")]
    fn driver_health_snapshot() -> Option<DriverHealthEvent> {
        const SYSEXT_SERVICE_NAME: &str = "com.tamandua.agent.filemonitor";
        const ES_FRAMEWORK_PATH: &str = "/System/Library/Frameworks/EndpointSecurity.framework";

        let endpoint_security_available = std::path::Path::new(ES_FRAMEWORK_PATH).exists();
        let sysext_state = macos_service_state(SYSEXT_SERVICE_NAME);
        let connected = matches!(sysext_state.as_deref(), Some("running"));
        let loaded = endpoint_security_available || sysext_state.is_some();

        let state = if connected {
            "loaded"
        } else if loaded {
            "loaded_no_telemetry"
        } else {
            "not_loaded"
        };

        let last_error = if !endpoint_security_available {
            Some("EndpointSecurity.framework is not available on this macOS host".to_string())
        } else if !connected {
            Some(format!(
                "System Extension Mach service '{}' is not currently reachable",
                SYSEXT_SERVICE_NAME
            ))
        } else {
            None
        };

        Some(DriverHealthEvent {
            supported: true,
            loaded,
            connected,
            state: state.to_string(),
            platform: Some("macos".to_string()),
            provider: Some("endpoint_security_sysext".to_string()),
            service_name: Some(SYSEXT_SERVICE_NAME.to_string()),
            entitlement_status: Some(if endpoint_security_available {
                "framework_available".to_string()
            } else {
                "framework_missing".to_string()
            }),
            lab_level: 0,
            feature_level: "endpoint_security".to_string(),
            writable_read_index: false,
            protocol_version: 1,
            buffer_size: 0,
            write_index: 0,
            read_index: 0,
            sequence_number: 0,
            flags: 0,
            events_consumed: 0,
            events_converted: 0,
            events_skipped: 0,
            events_malformed: 0,
            channel_drops: 0,
            raw_event_type_counts: HashMap::new(),
            converted_event_type_counts: HashMap::new(),
            skipped_event_type_counts: HashMap::new(),
            kernel_events_written: 0,
            kernel_events_dropped: 0,
            reconnect_attempts: 0,
            consecutive_failures: if connected { 0 } else { 1 },
            last_event_at: None,
            last_error,
        })
    }

    #[cfg(not(target_os = "windows"))]
    #[cfg(not(target_os = "macos"))]
    fn driver_health_snapshot() -> Option<DriverHealthEvent> {
        None
    }

    #[cfg(target_os = "windows")]
    fn platform_status_snapshot(
        _config: &AgentConfig,
        _ebpf_health: Option<&crate::collectors::ebpf_linux::EbpfLinuxHealth>,
    ) -> Vec<PlatformSensorHealth> {
        let driver = Self::driver_health_snapshot();
        let (state, running, reason) = match driver.as_ref() {
            Some(status) if status.connected => ("running", true, None),
            Some(status) if status.loaded => (
                "degraded",
                false,
                Some("driver_loaded_but_telemetry_not_connected".to_string()),
            ),
            Some(_) => (
                "not_loaded",
                false,
                Some("driver_service_or_filter_not_loaded".to_string()),
            ),
            None => (
                "unsupported",
                false,
                Some("windows_driver_status_unavailable".to_string()),
            ),
        };

        vec![PlatformSensorHealth {
            name: "windows_kernel_driver".to_string(),
            platform: "windows".to_string(),
            kind: "kernel_driver".to_string(),
            state: state.to_string(),
            configured: true,
            compiled: true,
            running,
            reason,
            detail: driver.map(|status| {
                format!(
                    "level={} feature={} drops={} kernel_drops={}",
                    status.lab_level,
                    status.feature_level,
                    status.channel_drops,
                    status.kernel_events_dropped
                )
            }),
        }]
    }

    #[cfg(target_os = "linux")]
    fn platform_status_snapshot(
        config: &AgentConfig,
        ebpf_health: Option<&crate::collectors::ebpf_linux::EbpfLinuxHealth>,
    ) -> Vec<PlatformSensorHealth> {
        let ebpf_configured = config.collectors.ebpf_enabled;
        let ebpf_compiled = cfg!(feature = "ebpf");
        let btf_present = std::path::Path::new("/sys/kernel/btf/vmlinux").exists();

        // Prefer the live runtime state published by the eBPF collector.
        // Fall back to the static config/BTF-derived state when nothing has
        // been published yet (e.g. collector disabled or not yet constructed).
        #[cfg(feature = "ebpf")]
        let (ebpf_state, ebpf_running, ebpf_reason, ebpf_detail) = match ebpf_health {
            Some(h) => {
                let state = match h.state {
                    crate::collectors::ebpf_linux::EbpfLinuxHealthState::Active => "active",
                    crate::collectors::ebpf_linux::EbpfLinuxHealthState::Degraded => "degraded",
                    crate::collectors::ebpf_linux::EbpfLinuxHealthState::Unavailable => {
                        "unavailable"
                    }
                };
                let reason = if h.missing_prerequisites.is_empty() {
                    Some(format!(
                        "runtime eBPF maturity: {} (active={})",
                        h.maturity, h.ebpf_active
                    ))
                } else {
                    Some(format!(
                        "missing prerequisites: {}",
                        h.missing_prerequisites.join("; ")
                    ))
                };
                let detail = Some(format!(
                    "btf_vmlinux_present={} events_received={} events_processed={} parse_errors={}",
                    btf_present,
                    h.stats.events_received,
                    h.stats.events_processed,
                    h.stats.parse_errors
                ));
                (state.to_string(), h.ebpf_active, reason, detail)
            }
            None => {
                let fallback = if !ebpf_compiled {
                    "not_compiled"
                } else if !ebpf_configured {
                    "disabled"
                } else if !btf_present {
                    "degraded"
                } else {
                    "configured"
                };
                (
                    fallback.to_string(),
                    false,
                    Self::linux_ebpf_reason(ebpf_compiled, ebpf_configured, btf_present),
                    Some(format!("btf_vmlinux_present={}", btf_present)),
                )
            }
        };

        // When the `ebpf` feature is not compiled in, there is no live
        // runtime state to consume; preserve previous static reporting.
        #[cfg(not(feature = "ebpf"))]
        let (ebpf_state, ebpf_running, ebpf_reason, ebpf_detail) = {
            let _ = ebpf_health; // unused in this build configuration
            let fallback = if !ebpf_configured {
                "disabled"
            } else if !btf_present {
                "degraded"
            } else {
                "not_compiled"
            };
            (
                fallback.to_string(),
                false,
                Self::linux_ebpf_reason(ebpf_compiled, ebpf_configured, btf_present),
                Some(format!("btf_vmlinux_present={}", btf_present)),
            )
        };

        vec![
            PlatformSensorHealth {
                name: "linux_ebpf".to_string(),
                platform: "linux".to_string(),
                kind: "kernel_telemetry".to_string(),
                state: ebpf_state,
                configured: ebpf_configured,
                compiled: ebpf_compiled,
                running: ebpf_running,
                reason: ebpf_reason,
                detail: ebpf_detail,
            },
            PlatformSensorHealth {
                name: "linux_auditd".to_string(),
                platform: "linux".to_string(),
                kind: "audit_telemetry".to_string(),
                state: if cfg!(feature = "auditd") {
                    "compiled_not_wired"
                } else {
                    "not_compiled"
                }
                .to_string(),
                configured: false,
                compiled: cfg!(feature = "auditd"),
                running: false,
                reason: Some(
                    if cfg!(feature = "auditd") {
                        "auditd collector is compiled but not yet wired into the main runtime"
                    } else {
                        "binary was not built with the auditd feature"
                    }
                    .to_string(),
                ),
                detail: None,
            },
        ]
    }

    #[cfg(target_os = "linux")]
    fn linux_ebpf_reason(compiled: bool, configured: bool, btf_present: bool) -> Option<String> {
        if !compiled {
            Some("binary was not built with the ebpf feature".to_string())
        } else if !configured {
            Some("ebpf collector disabled by config or active performance profile".to_string())
        } else if !btf_present {
            Some("kernel BTF vmlinux is missing; CO-RE eBPF portability is degraded".to_string())
        } else {
            Some(
                "compiled and configured; runtime attach status must be reported by the collector"
                    .to_string(),
            )
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    fn platform_status_snapshot(
        _config: &AgentConfig,
        _ebpf_health: Option<&crate::collectors::ebpf_linux::EbpfLinuxHealth>,
    ) -> Vec<PlatformSensorHealth> {
        Vec::new()
    }

    /// Get next event from collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }
}

#[cfg(target_os = "macos")]
fn macos_service_state(service_name: &str) -> Option<String> {
    let domains = macos_launchctl_domains();

    for domain in domains {
        let target = format!("{}/{}", domain, service_name);
        let output = std::process::Command::new("launchctl")
            .args(["print", &target])
            .output();

        let Ok(output) = output else {
            continue;
        };

        if !output.status.success() {
            continue;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("state = running") {
            return Some("running".to_string());
        }
        if stdout.contains("state = waiting") {
            return Some("waiting".to_string());
        }
        if stdout.contains("state = exited") {
            return Some("exited".to_string());
        }

        return Some("registered".to_string());
    }

    None
}

#[cfg(target_os = "macos")]
fn macos_launchctl_domains() -> Vec<String> {
    let mut domains = vec!["system".to_string()];

    if let Ok(uid) = std::env::var("UID") {
        domains.push(format!("gui/{}", uid));
    } else if let Ok(output) = std::process::Command::new("id").arg("-u").output() {
        if output.status.success() {
            let uid = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !uid.is_empty() {
                domains.push(format!("gui/{}", uid));
            }
        }
    }

    domains
}
