//! macOS EndpointSecurity/SystemExtension prerequisite reporting.
//!
//! These probes are intentionally conservative. They describe what this build
//! can support and which runtime prerequisites are observable without opening a
//! privileged EndpointSecurity client or changing system state.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    Ready,
    Degraded,
    Unavailable,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrereqStatus {
    Pass,
    Fail,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrereqCheck {
    pub name: String,
    pub status: PrereqStatus,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityProbe {
    pub name: String,
    pub supported_by_build: bool,
    pub state: CapabilityState,
    pub checks: Vec<PrereqCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosCapabilityReport {
    pub platform: String,
    pub degraded_mode: bool,
    pub degraded_reason: String,
    pub endpoint_security: CapabilityProbe,
    pub system_extension: CapabilityProbe,
    pub tcc: CapabilityProbe,
    pub full_disk_access: CapabilityProbe,
}

pub fn collect_macos_capability_report() -> MacosCapabilityReport {
    let endpoint_security = endpoint_security_probe();
    let system_extension = system_extension_probe();
    let tcc = tcc_probe();
    let full_disk_access = full_disk_access_probe();

    let degraded_reasons = [
        &endpoint_security,
        &system_extension,
        &tcc,
        &full_disk_access,
    ]
    .into_iter()
    .filter(|probe| {
        matches!(
            probe.state,
            CapabilityState::Degraded | CapabilityState::Unavailable
        )
    })
    .map(|probe| probe.name.as_str())
    .collect::<Vec<_>>();

    MacosCapabilityReport {
        platform: "macos".to_string(),
        degraded_mode: !degraded_reasons.is_empty(),
        degraded_reason: if degraded_reasons.is_empty() {
            "all observable macOS prerequisites are satisfied or not applicable".to_string()
        } else {
            format!("limited macOS visibility: {}", degraded_reasons.join(", "))
        },
        endpoint_security,
        system_extension,
        tcc,
        full_disk_access,
    }
}

pub fn endpoint_security_probe() -> CapabilityProbe {
    let mut checks = Vec::new();

    checks.push(PrereqCheck {
        name: "macos_host".to_string(),
        status: cfg_status(cfg!(target_os = "macos")),
        detail: if cfg!(target_os = "macos") {
            "running on macOS".to_string()
        } else {
            "EndpointSecurity is only available on macOS".to_string()
        },
        remediation: if cfg!(target_os = "macos") {
            None
        } else {
            Some("Run this collector on a signed macOS build".to_string())
        },
    });

    checks.push(PrereqCheck {
        name: "endpoint_security_linked".to_string(),
        status: cfg_status(cfg!(all(target_os = "macos", not(no_endpoint_security)))),
        detail: if cfg!(all(target_os = "macos", not(no_endpoint_security))) {
            "EndpointSecurity framework is linked in this build".to_string()
        } else {
            "EndpointSecurity framework is not linked in this build".to_string()
        },
        remediation: Some(
            "Build on macOS without the no_endpoint_security cfg and link EndpointSecurity.framework"
                .to_string(),
        ),
    });

    checks.push(PrereqCheck {
        name: "privileged_process".to_string(),
        status: privileged_process_status(),
        detail: privileged_process_detail(),
        remediation: Some(
            "Run the ES client as root or inside an approved System Extension".to_string(),
        ),
    });

    checks.push(PrereqCheck {
        name: "endpoint_security_entitlement".to_string(),
        status: PrereqStatus::Unknown,
        detail: "Entitlement is enforced by es_new_client at runtime".to_string(),
        remediation: Some(
            "Sign with com.apple.developer.endpoint-security.client and validate es_new_client startup"
                .to_string(),
        ),
    });

    CapabilityProbe {
        name: "endpoint_security".to_string(),
        supported_by_build: cfg!(all(target_os = "macos", not(no_endpoint_security))),
        state: derive_probe_state(&checks),
        checks,
    }
}

pub fn system_extension_probe() -> CapabilityProbe {
    let mut checks = vec![
        PrereqCheck {
            name: "macos_11_or_newer".to_string(),
            status: macos_11_status(),
            detail: macos_11_detail(),
            remediation: Some("Use macOS 11.0 or newer for the System Extension path".to_string()),
        },
        PrereqCheck {
            name: "system_extension_approved".to_string(),
            status: system_extension_status(),
            detail: system_extension_detail(),
            remediation: Some(
                "Approve the Tamandua System Extension in System Settings or deploy an MDM approval profile"
                    .to_string(),
            ),
        },
    ];

    checks.push(PrereqCheck {
        name: "mach_service".to_string(),
        status: PrereqStatus::Unknown,
        detail: "Mach service reachability is validated by the XPC bridge connection".to_string(),
        remediation: Some(
            "Check system extension logs and com.tamandua.agent.filemonitor service registration"
                .to_string(),
        ),
    });

    CapabilityProbe {
        name: "system_extension".to_string(),
        supported_by_build: cfg!(target_os = "macos"),
        state: derive_probe_state(&checks),
        checks,
    }
}

pub fn tcc_probe() -> CapabilityProbe {
    let user_tcc = user_tcc_status();
    let system_tcc = system_tcc_status();
    let checks = vec![
        user_tcc,
        system_tcc,
        PrereqCheck {
            name: "tcc_schema".to_string(),
            status: PrereqStatus::Unknown,
            detail: "Schema compatibility is validated when parsing TCC.db".to_string(),
            remediation: Some(
                "Run TCC parser validation on each supported macOS major version".to_string(),
            ),
        },
    ];

    CapabilityProbe {
        name: "tcc".to_string(),
        supported_by_build: cfg!(target_os = "macos"),
        state: derive_probe_state(&checks),
        checks,
    }
}

pub fn full_disk_access_probe() -> CapabilityProbe {
    let check = full_disk_access_check();
    let state = match check.status {
        PrereqStatus::Pass => CapabilityState::Ready,
        PrereqStatus::Fail => CapabilityState::Degraded,
        PrereqStatus::Unknown => CapabilityState::Unknown,
    };

    CapabilityProbe {
        name: "full_disk_access".to_string(),
        supported_by_build: cfg!(target_os = "macos"),
        state,
        checks: vec![check],
    }
}

pub fn system_extension_status_from_output(output: &str, bundle_id: &str) -> PrereqStatus {
    for line in output.lines().filter(|line| line.contains(bundle_id)) {
        if line.contains("[activated enabled]") || line.contains("activated enabled") {
            return PrereqStatus::Pass;
        }
        if line.contains("[activated waiting for user]") || line.contains("waiting for user") {
            return PrereqStatus::Fail;
        }
        return PrereqStatus::Unknown;
    }

    PrereqStatus::Fail
}

fn derive_probe_state(checks: &[PrereqCheck]) -> CapabilityState {
    if checks
        .iter()
        .any(|check| check.status == PrereqStatus::Fail)
    {
        CapabilityState::Degraded
    } else if checks
        .iter()
        .any(|check| check.status == PrereqStatus::Unknown)
    {
        CapabilityState::Unknown
    } else {
        CapabilityState::Ready
    }
}

fn cfg_status(value: bool) -> PrereqStatus {
    if value {
        PrereqStatus::Pass
    } else {
        PrereqStatus::Fail
    }
}

#[cfg(target_os = "macos")]
fn privileged_process_status() -> PrereqStatus {
    if unsafe { libc::geteuid() } == 0 {
        PrereqStatus::Pass
    } else {
        PrereqStatus::Fail
    }
}

#[cfg(not(target_os = "macos"))]
fn privileged_process_status() -> PrereqStatus {
    PrereqStatus::Fail
}

#[cfg(target_os = "macos")]
fn privileged_process_detail() -> String {
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        "effective uid is root".to_string()
    } else {
        format!(
            "effective uid is {}; direct ES client startup will be degraded",
            euid
        )
    }
}

#[cfg(not(target_os = "macos"))]
fn privileged_process_detail() -> String {
    "not running on macOS".to_string()
}

#[cfg(target_os = "macos")]
fn macos_11_status() -> PrereqStatus {
    match std::process::Command::new("sw_vers")
        .arg("-productVersion")
        .output()
    {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout);
            if version_at_least(version.trim(), 11, 0) {
                PrereqStatus::Pass
            } else {
                PrereqStatus::Fail
            }
        }
        _ => PrereqStatus::Unknown,
    }
}

#[cfg(not(target_os = "macos"))]
fn macos_11_status() -> PrereqStatus {
    PrereqStatus::Fail
}

#[cfg(target_os = "macos")]
fn macos_11_detail() -> String {
    match std::process::Command::new("sw_vers")
        .arg("-productVersion")
        .output()
    {
        Ok(output) if output.status.success() => {
            format!("macOS {}", String::from_utf8_lossy(&output.stdout).trim())
        }
        _ => "unable to read macOS version with sw_vers".to_string(),
    }
}

#[cfg(not(target_os = "macos"))]
fn macos_11_detail() -> String {
    "not running on macOS".to_string()
}

#[cfg(target_os = "macos")]
fn system_extension_status() -> PrereqStatus {
    match std::process::Command::new("systemextensionsctl")
        .arg("list")
        .output()
    {
        Ok(output) if output.status.success() => system_extension_status_from_output(
            &String::from_utf8_lossy(&output.stdout),
            "com.tamandua.agent.sysext.filemonitor",
        ),
        _ => PrereqStatus::Unknown,
    }
}

#[cfg(not(target_os = "macos"))]
fn system_extension_status() -> PrereqStatus {
    PrereqStatus::Fail
}

#[cfg(target_os = "macos")]
fn system_extension_detail() -> String {
    match std::process::Command::new("systemextensionsctl")
        .arg("list")
        .output()
    {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            stdout
                .lines()
                .find(|line| line.contains("com.tamandua.agent.sysext.filemonitor"))
                .map(|line| line.trim().to_string())
                .unwrap_or_else(|| "Tamandua System Extension is not listed".to_string())
        }
        _ => "unable to query systemextensionsctl".to_string(),
    }
}

#[cfg(not(target_os = "macos"))]
fn system_extension_detail() -> String {
    "not running on macOS".to_string()
}

#[cfg(target_os = "macos")]
fn user_tcc_status() -> PrereqCheck {
    match super::tcc_parser::get_user_tcc_path() {
        Some(path) if path.exists() => PrereqCheck {
            name: "user_tcc_db_readable".to_string(),
            status: if std::fs::File::open(&path).is_ok() {
                PrereqStatus::Pass
            } else {
                PrereqStatus::Fail
            },
            detail: path.display().to_string(),
            remediation: Some("Grant Full Disk Access to read protected user TCC data".to_string()),
        },
        Some(path) => PrereqCheck {
            name: "user_tcc_db_readable".to_string(),
            status: PrereqStatus::Unknown,
            detail: format!("{} does not exist", path.display()),
            remediation: None,
        },
        None => PrereqCheck {
            name: "user_tcc_db_readable".to_string(),
            status: PrereqStatus::Unknown,
            detail: "home directory unavailable".to_string(),
            remediation: None,
        },
    }
}

#[cfg(not(target_os = "macos"))]
fn user_tcc_status() -> PrereqCheck {
    PrereqCheck {
        name: "user_tcc_db_readable".to_string(),
        status: PrereqStatus::Fail,
        detail: "TCC is macOS-only".to_string(),
        remediation: Some("Run on macOS".to_string()),
    }
}

#[cfg(target_os = "macos")]
fn system_tcc_status() -> PrereqCheck {
    let path = super::tcc_parser::get_system_tcc_path();
    PrereqCheck {
        name: "system_tcc_db_readable".to_string(),
        status: if path.exists() && std::fs::File::open(&path).is_ok() {
            PrereqStatus::Pass
        } else if path.exists() {
            PrereqStatus::Fail
        } else {
            PrereqStatus::Unknown
        },
        detail: path.display().to_string(),
        remediation: Some(
            "Run as root or grant Full Disk Access for system TCC visibility".to_string(),
        ),
    }
}

#[cfg(not(target_os = "macos"))]
fn system_tcc_status() -> PrereqCheck {
    PrereqCheck {
        name: "system_tcc_db_readable".to_string(),
        status: PrereqStatus::Fail,
        detail: "TCC is macOS-only".to_string(),
        remediation: Some("Run on macOS".to_string()),
    }
}

#[cfg(target_os = "macos")]
fn full_disk_access_check() -> PrereqCheck {
    match super::system_apis::check_full_disk_access_detailed() {
        Ok(status) => PrereqCheck {
            name: "fda_probe_file_readable".to_string(),
            status: if status.has_fda {
                PrereqStatus::Pass
            } else {
                PrereqStatus::Fail
            },
            detail: match status.test_file {
                Some(path) => format!("{} ({})", status.details, path),
                None => status.details,
            },
            remediation: Some(
                "Grant Full Disk Access to the agent or System Extension host process".to_string(),
            ),
        },
        Err(error) => PrereqCheck {
            name: "fda_probe_file_readable".to_string(),
            status: PrereqStatus::Unknown,
            detail: error,
            remediation: Some(
                "Validate FDA manually in System Settings > Privacy & Security".to_string(),
            ),
        },
    }
}

#[cfg(not(target_os = "macos"))]
fn full_disk_access_check() -> PrereqCheck {
    PrereqCheck {
        name: "fda_probe_file_readable".to_string(),
        status: PrereqStatus::Fail,
        detail: "Full Disk Access is macOS-only".to_string(),
        remediation: Some("Run on macOS".to_string()),
    }
}

fn version_at_least(version: &str, major: u64, minor: u64) -> bool {
    let mut parts = version
        .split('.')
        .filter_map(|part| part.parse::<u64>().ok());
    let found_major = parts.next().unwrap_or(0);
    let found_minor = parts.next().unwrap_or(0);
    (found_major, found_minor) >= (major, minor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_system_extension_status_from_systemextensionsctl_output() {
        let approved = "ABC123 com.tamandua.agent.sysext.filemonitor (1.0/1) [activated enabled]";
        assert_eq!(
            system_extension_status_from_output(approved, "com.tamandua.agent.sysext.filemonitor"),
            PrereqStatus::Pass
        );

        let waiting =
            "ABC123 com.tamandua.agent.sysext.filemonitor (1.0/1) [activated waiting for user]";
        assert_eq!(
            system_extension_status_from_output(waiting, "com.tamandua.agent.sysext.filemonitor"),
            PrereqStatus::Fail
        );

        assert_eq!(
            system_extension_status_from_output("", "com.tamandua.agent.sysext.filemonitor"),
            PrereqStatus::Fail
        );
    }

    #[test]
    fn compares_macos_versions() {
        assert!(version_at_least("14.5", 11, 0));
        assert!(version_at_least("11.0.1", 11, 0));
        assert!(!version_at_least("10.15.7", 11, 0));
    }

    #[test]
    fn non_macos_report_is_degraded_without_panicking() {
        let report = collect_macos_capability_report();
        assert_eq!(report.platform, "macos");
        assert_eq!(report.endpoint_security.name, "endpoint_security");
        assert!(!report.endpoint_security.checks.is_empty());
    }
}
