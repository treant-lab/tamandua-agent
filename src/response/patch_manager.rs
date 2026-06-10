//! Patch Management Agent Module
//!
//! Cross-platform patch management for Windows, Linux, and macOS endpoints.
//!
//! ## Windows
//! Uses Windows Update Agent (WUA) COM interfaces via `IUpdateSearcher`,
//! `IUpdateDownloader`, and `IUpdateInstaller` patterns to query, download,
//! and install updates.
//!
//! ## Linux
//! Detects the package manager (apt, yum, dnf, zypper) and executes
//! update queries and installations through the system package manager.
//!
//! ## macOS
//! Uses `softwareupdate` CLI tool for system update management.
//!
//! ## Telemetry
//! Reports `PatchStatus` events back to the server containing:
//! - Installed patches
//! - Missing patches
//! - Pending reboot status
//! - Last scan timestamp

// This module enumerates package-manager families (apt/yum/dnf/zypper/WUA/
// softwareupdate) and per-platform parsing helpers. Reserved helpers for the
// macOS softwareupdate / Linux APT/RPM paths are kept exhaustive even when
// some platforms only consume a subset of them at build time.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use tracing::info;

use crate::transport::CommandResult;

/// Information about a single patch/update
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchInfo {
    /// KB article ID (Windows) or package name (Linux/macOS)
    pub kb_id: String,
    /// Human-readable title
    pub title: String,
    /// Severity: critical, high, medium, low
    pub severity: String,
    /// Associated CVE identifiers
    pub cve_ids: Vec<String>,
    /// Download size in bytes
    pub size_bytes: u64,
    /// Whether a reboot is required after installation
    pub requires_reboot: bool,
    /// Release date (ISO 8601)
    pub release_date: Option<String>,
    /// Package version (Linux)
    pub version: Option<String>,
    /// Package source repository (Linux)
    pub source: Option<String>,
}

/// Current patch status reported to the server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchStatus {
    /// List of currently installed patches
    pub installed_patches: Vec<PatchInfo>,
    /// List of available but not-installed patches
    pub missing_patches: Vec<PatchInfo>,
    /// Whether the system is pending a reboot for patch completion
    pub pending_reboot: bool,
    /// Timestamp of the last patch scan
    pub last_scan: SystemTime,
}

/// Result of a patch installation attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchInstallResult {
    /// KB or package identifier
    pub kb_id: String,
    /// Whether installation succeeded
    pub success: bool,
    /// Error message if installation failed
    pub error: Option<String>,
    /// Whether a reboot is now required
    pub requires_reboot: bool,
}

/// Detected package manager on Linux
#[derive(Debug, Clone, PartialEq)]
enum PackageManager {
    Apt,
    Yum,
    Dnf,
    Zypper,
    Unknown,
}

// ============================================================================
// Public API
// ============================================================================

/// Scan for missing patches and return current patch status.
pub async fn scan_patches() -> anyhow::Result<PatchStatus> {
    info!("Starting patch scan");

    #[cfg(target_os = "windows")]
    {
        scan_windows_updates().await
    }

    #[cfg(target_os = "linux")]
    {
        scan_linux_updates().await
    }

    #[cfg(target_os = "macos")]
    {
        scan_macos_updates().await
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        Err(anyhow::anyhow!("Unsupported platform for patch management"))
    }
}

/// Install specific patches by KB/package identifier.
pub async fn install_patches(patches: &[String], reboot_policy: &str) -> Vec<PatchInstallResult> {
    info!(
        count = patches.len(),
        reboot_policy = reboot_policy,
        "Installing patches"
    );

    #[cfg(target_os = "windows")]
    {
        install_windows_updates(patches, reboot_policy).await
    }

    #[cfg(target_os = "linux")]
    {
        install_linux_packages(patches, reboot_policy).await
    }

    #[cfg(target_os = "macos")]
    {
        install_macos_updates(patches, reboot_policy).await
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        patches
            .iter()
            .map(|kb| PatchInstallResult {
                kb_id: kb.clone(),
                success: false,
                error: Some("Unsupported platform".to_string()),
                requires_reboot: false,
            })
            .collect()
    }
}

/// Handle the install_patches command from the server.
pub async fn handle_install_patches(payload: &serde_json::Value) -> CommandResult {
    let deployment_id = payload
        .get("deployment_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let patches: Vec<String> = payload
        .get("patches")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|p| {
                    p.get("kb_id")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
                .collect()
        })
        .unwrap_or_default();

    let reboot_policy = payload
        .get("reboot_policy")
        .and_then(|v| v.as_str())
        .unwrap_or("deferred");

    if patches.is_empty() {
        return CommandResult {
            success: false,
            error_message: Some("No patches specified".to_string()),
            result_data: None,
        };
    }

    info!(
        deployment_id = deployment_id,
        patches_count = patches.len(),
        "Handling patch install command"
    );

    let results = install_patches(&patches, reboot_policy).await;

    let any_failed = results.iter().any(|r| !r.success);
    let needs_reboot = results.iter().any(|r| r.requires_reboot);

    CommandResult {
        success: !any_failed,
        error_message: if any_failed {
            let failures: Vec<_> = results
                .iter()
                .filter(|r| !r.success)
                .map(|r| format!("{}: {}", r.kb_id, r.error.as_deref().unwrap_or("unknown")))
                .collect();
            Some(format!("Failed patches: {}", failures.join(", ")))
        } else {
            None
        },
        result_data: Some(serde_json::json!({
            "deployment_id": deployment_id,
            "results": results,
            "needs_reboot": needs_reboot,
        })),
    }
}

/// Handle the scan_patches command from the server.
pub async fn handle_scan_patches(_payload: &serde_json::Value) -> CommandResult {
    match scan_patches().await {
        Ok(status) => CommandResult {
            success: true,
            error_message: None,
            result_data: Some(serde_json::to_value(&status).unwrap_or_default()),
        },
        Err(e) => CommandResult {
            success: false,
            error_message: Some(format!("Patch scan failed: {}", e)),
            result_data: None,
        },
    }
}

/// Check whether the system is pending a reboot.
pub fn check_pending_reboot() -> bool {
    #[cfg(target_os = "windows")]
    {
        check_windows_pending_reboot()
    }

    #[cfg(target_os = "linux")]
    {
        check_linux_pending_reboot()
    }

    #[cfg(target_os = "macos")]
    {
        check_macos_pending_reboot()
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

// ============================================================================
// Windows Implementation
// ============================================================================

#[cfg(target_os = "windows")]
async fn scan_windows_updates() -> anyhow::Result<PatchStatus> {
    use std::process::Command;

    info!("Scanning for Windows updates via WUA");

    // Use PowerShell to query Windows Update Agent
    // This avoids direct COM interop complexity while still using WUA
    let scan_script = r#"
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $searcher = $updateSession.CreateUpdateSearcher()

        # Search for applicable but not installed updates
        $searchResult = $searcher.Search("IsInstalled=0 and IsHidden=0")

        $missing = @()
        foreach ($update in $searchResult.Updates) {
            $cves = @()
            foreach ($cve in $update.CveIDs) { $cves += $cve }

            $severity = switch ($update.MsrcSeverity) {
                'Critical'  { 'critical' }
                'Important' { 'high' }
                'Moderate'  { 'medium' }
                'Low'       { 'low' }
                default     { 'medium' }
            }

            $kbIds = @()
            foreach ($kb in $update.KBArticleIDs) { $kbIds += "KB$kb" }
            $kbId = if ($kbIds.Count -gt 0) { $kbIds[0] } else { $update.Identity.UpdateID }

            $missing += @{
                kb_id = $kbId
                title = $update.Title
                severity = $severity
                cve_ids = $cves
                size_bytes = $update.MaxDownloadSize
                requires_reboot = $update.RebootRequired
                release_date = if ($update.LastDeploymentChangeTime) { $update.LastDeploymentChangeTime.ToString("yyyy-MM-dd") } else { $null }
            }
        }

        # Search for installed updates (last 90 days)
        $installedResult = $searcher.Search("IsInstalled=1")
        $installed = @()
        $cutoff = (Get-Date).AddDays(-90)

        foreach ($update in $installedResult.Updates) {
            if ($update.LastDeploymentChangeTime -gt $cutoff) {
                $kbIds = @()
                foreach ($kb in $update.KBArticleIDs) { $kbIds += "KB$kb" }
                $kbId = if ($kbIds.Count -gt 0) { $kbIds[0] } else { $update.Identity.UpdateID }

                $installed += @{
                    kb_id = $kbId
                    title = $update.Title
                    severity = 'info'
                    cve_ids = @()
                    size_bytes = 0
                    requires_reboot = $false
                }
            }
        }

        # Check pending reboot
        $pendingReboot = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
                         (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')

        @{
            missing = $missing
            installed = $installed
            pending_reboot = $pendingReboot
        } | ConvertTo-Json -Depth 5
    "#;

    let output = Command::new("powershell")
        .args(&[
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            scan_script,
        ])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("Windows Update scan failed: {}", stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: serde_json::Value = serde_json::from_str(&stdout)?;

    let missing = parse_patches_from_json(result.get("missing"));
    let installed = parse_patches_from_json(result.get("installed"));
    let pending_reboot = result
        .get("pending_reboot")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    Ok(PatchStatus {
        installed_patches: installed,
        missing_patches: missing,
        pending_reboot,
        last_scan: SystemTime::now(),
    })
}

#[cfg(target_os = "windows")]
async fn install_windows_updates(
    patches: &[String],
    reboot_policy: &str,
) -> Vec<PatchInstallResult> {
    use std::process::Command;

    let mut results = Vec::new();

    for kb_id in patches {
        info!(kb_id = %kb_id, "Installing Windows update");

        // Use PowerShell to download and install specific KB
        let install_script = format!(
            r#"
            $updateSession = New-Object -ComObject Microsoft.Update.Session
            $searcher = $updateSession.CreateUpdateSearcher()
            $searchResult = $searcher.Search("IsInstalled=0 and IsHidden=0")

            $targetUpdate = $null
            foreach ($update in $searchResult.Updates) {{
                foreach ($kb in $update.KBArticleIDs) {{
                    if ("KB$kb" -eq "{kb_id}" -or $kb -eq "{kb_id}") {{
                        $targetUpdate = $update
                        break
                    }}
                }}
                if ($targetUpdate) {{ break }}
            }}

            if (-not $targetUpdate) {{
                @{{ success = $false; error = "Update {kb_id} not found"; requires_reboot = $false }} | ConvertTo-Json
                return
            }}

            # Accept EULA
            if (-not $targetUpdate.EulaAccepted) {{
                $targetUpdate.AcceptEula()
            }}

            # Download
            $updatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl
            $updatesToDownload.Add($targetUpdate) | Out-Null
            $downloader = $updateSession.CreateUpdateDownloader()
            $downloader.Updates = $updatesToDownload
            $downloadResult = $downloader.Download()

            if ($downloadResult.ResultCode -ne 2) {{
                @{{ success = $false; error = "Download failed with code $($downloadResult.ResultCode)"; requires_reboot = $false }} | ConvertTo-Json
                return
            }}

            # Install
            $updatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
            $updatesToInstall.Add($targetUpdate) | Out-Null
            $installer = $updateSession.CreateUpdateInstaller()
            $installer.Updates = $updatesToInstall
            $installResult = $installer.Install()

            @{{
                success = ($installResult.ResultCode -eq 2)
                error = if ($installResult.ResultCode -ne 2) {{ "Install failed with code $($installResult.ResultCode)" }} else {{ $null }}
                requires_reboot = $installResult.RebootRequired
            }} | ConvertTo-Json
            "#,
            kb_id = kb_id
        );

        match Command::new("powershell")
            .args(&[
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                &install_script,
            ])
            .output()
        {
            Ok(output) => {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    if let Ok(result) = serde_json::from_str::<serde_json::Value>(&stdout) {
                        results.push(PatchInstallResult {
                            kb_id: kb_id.clone(),
                            success: result
                                .get("success")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false),
                            error: result
                                .get("error")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string()),
                            requires_reboot: result
                                .get("requires_reboot")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false),
                        });
                    } else {
                        results.push(PatchInstallResult {
                            kb_id: kb_id.clone(),
                            success: false,
                            error: Some("Failed to parse install result".to_string()),
                            requires_reboot: false,
                        });
                    }
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    results.push(PatchInstallResult {
                        kb_id: kb_id.clone(),
                        success: false,
                        error: Some(format!("PowerShell error: {}", stderr)),
                        requires_reboot: false,
                    });
                }
            }
            Err(e) => {
                results.push(PatchInstallResult {
                    kb_id: kb_id.clone(),
                    success: false,
                    error: Some(format!("Failed to execute: {}", e)),
                    requires_reboot: false,
                });
            }
        }
    }

    // Handle reboot policy
    let needs_reboot = results.iter().any(|r| r.requires_reboot);
    if needs_reboot {
        handle_reboot_policy_windows(reboot_policy);
    }

    results
}

#[cfg(target_os = "windows")]
fn check_windows_pending_reboot() -> bool {
    use std::process::Command;

    let script = r#"
        (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
        (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
    "#;

    match Command::new("powershell")
        .args(&["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout)
                .trim()
                .to_lowercase();
            stdout == "true"
        }
        Err(_) => false,
    }
}

#[cfg(target_os = "windows")]
fn handle_reboot_policy_windows(policy: &str) {
    match policy {
        "immediate" => {
            info!("Reboot policy: immediate - scheduling reboot in 60 seconds");
            let _ = std::process::Command::new("shutdown")
                .args(&[
                    "/r",
                    "/t",
                    "60",
                    "/c",
                    "Tamandua EDR: Patch installation requires reboot",
                ])
                .spawn();
        }
        "deferred" => {
            info!("Reboot policy: deferred - reboot pending, will complete at next maintenance window");
        }
        "never" => {
            info!("Reboot policy: never - reboot required but will not be initiated");
        }
        _ => {
            info!("Reboot policy: user_choice - notifying user");
        }
    }
}

// ============================================================================
// Linux Implementation
// ============================================================================

#[cfg(target_os = "linux")]
fn detect_package_manager() -> PackageManager {
    use std::path::Path;

    if Path::new("/usr/bin/apt").exists() || Path::new("/usr/bin/apt-get").exists() {
        PackageManager::Apt
    } else if Path::new("/usr/bin/dnf").exists() {
        PackageManager::Dnf
    } else if Path::new("/usr/bin/yum").exists() {
        PackageManager::Yum
    } else if Path::new("/usr/bin/zypper").exists() {
        PackageManager::Zypper
    } else {
        PackageManager::Unknown
    }
}

#[cfg(target_os = "linux")]
async fn scan_linux_updates() -> anyhow::Result<PatchStatus> {
    let pkg_mgr = detect_package_manager();
    info!(package_manager = ?pkg_mgr, "Scanning for Linux updates");

    match pkg_mgr {
        PackageManager::Apt => scan_apt_updates().await,
        PackageManager::Dnf => scan_dnf_updates().await,
        PackageManager::Yum => scan_yum_updates().await,
        PackageManager::Zypper => scan_zypper_updates().await,
        PackageManager::Unknown => Err(anyhow::anyhow!("No supported package manager found")),
    }
}

#[cfg(target_os = "linux")]
async fn scan_apt_updates() -> anyhow::Result<PatchStatus> {
    use std::process::Command;

    // Update package lists
    let _ = Command::new("apt-get").args(&["update", "-qq"]).output();

    // List upgradable packages
    let output = Command::new("apt")
        .args(&["list", "--upgradable"])
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let missing: Vec<PatchInfo> = stdout
        .lines()
        .skip(1) // Skip "Listing..." header
        .filter(|line| !line.is_empty())
        .filter_map(|line| parse_apt_upgradable_line(line))
        .collect();

    // List installed packages (security updates only for brevity)
    let installed_output = Command::new("apt")
        .args(&["list", "--installed"])
        .output()?;

    let installed_stdout = String::from_utf8_lossy(&installed_output.stdout);
    let installed: Vec<PatchInfo> = installed_stdout
        .lines()
        .skip(1)
        .take(500) // Limit to avoid memory issues
        .filter(|line| !line.is_empty())
        .filter_map(|line| parse_apt_installed_line(line))
        .collect();

    let pending_reboot = check_linux_pending_reboot();

    Ok(PatchStatus {
        installed_patches: installed,
        missing_patches: missing,
        pending_reboot,
        last_scan: SystemTime::now(),
    })
}

#[cfg(target_os = "linux")]
fn parse_apt_upgradable_line(line: &str) -> Option<PatchInfo> {
    // Format: "package/suite version_new arch [upgradable from: version_old]"
    let parts: Vec<&str> = line.split('/').collect();
    if parts.len() < 2 {
        return None;
    }

    let name = parts[0].to_string();
    let rest = parts[1..].join("/");
    let version = rest.split_whitespace().next().unwrap_or("").to_string();

    let is_security = line.contains("-security");
    let severity = if is_security { "high" } else { "medium" };

    Some(PatchInfo {
        kb_id: name.clone(),
        title: format!("{} {}", name, version),
        severity: severity.to_string(),
        cve_ids: vec![],
        size_bytes: 0,
        requires_reboot: name.contains("linux-image")
            || name.contains("systemd")
            || name.contains("glibc"),
        release_date: None,
        version: Some(version),
        source: Some("apt".to_string()),
    })
}

#[cfg(target_os = "linux")]
fn parse_apt_installed_line(line: &str) -> Option<PatchInfo> {
    let parts: Vec<&str> = line.split('/').collect();
    if parts.len() < 2 {
        return None;
    }

    let name = parts[0].to_string();
    let rest = parts[1..].join("/");
    let version = rest.split_whitespace().next().unwrap_or("").to_string();

    Some(PatchInfo {
        kb_id: name.clone(),
        title: format!("{} {}", name, version),
        severity: "info".to_string(),
        cve_ids: vec![],
        size_bytes: 0,
        requires_reboot: false,
        release_date: None,
        version: Some(version),
        source: Some("apt".to_string()),
    })
}

#[cfg(target_os = "linux")]
async fn scan_dnf_updates() -> anyhow::Result<PatchStatus> {
    use std::process::Command;

    let output = Command::new("dnf")
        .args(&["check-update", "--quiet"])
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let missing: Vec<PatchInfo> = stdout
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with("Last metadata"))
        .filter_map(|line| parse_dnf_update_line(line))
        .collect();

    Ok(PatchStatus {
        installed_patches: vec![],
        missing_patches: missing,
        pending_reboot: check_linux_pending_reboot(),
        last_scan: SystemTime::now(),
    })
}

#[cfg(target_os = "linux")]
fn parse_dnf_update_line(line: &str) -> Option<PatchInfo> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }

    let name = parts[0].to_string();
    let version = parts[1].to_string();
    let repo = parts[2].to_string();

    let is_security = repo.contains("security");
    let severity = if is_security { "high" } else { "medium" };

    Some(PatchInfo {
        kb_id: name.clone(),
        title: format!("{} {}", name, version),
        severity: severity.to_string(),
        cve_ids: vec![],
        size_bytes: 0,
        requires_reboot: name.contains("kernel")
            || name.contains("systemd")
            || name.contains("glibc"),
        release_date: None,
        version: Some(version),
        source: Some(repo),
    })
}

#[cfg(target_os = "linux")]
async fn scan_yum_updates() -> anyhow::Result<PatchStatus> {
    use std::process::Command;

    let output = Command::new("yum")
        .args(&["check-update", "--quiet"])
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let missing: Vec<PatchInfo> = stdout
        .lines()
        .filter(|line| !line.is_empty())
        .filter_map(|line| parse_dnf_update_line(line)) // Same format as dnf
        .collect();

    Ok(PatchStatus {
        installed_patches: vec![],
        missing_patches: missing,
        pending_reboot: check_linux_pending_reboot(),
        last_scan: SystemTime::now(),
    })
}

#[cfg(target_os = "linux")]
async fn scan_zypper_updates() -> anyhow::Result<PatchStatus> {
    use std::process::Command;

    let output = Command::new("zypper")
        .args(&["--non-interactive", "list-updates"])
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let missing: Vec<PatchInfo> = stdout
        .lines()
        .filter(|line| line.contains('|'))
        .skip(2) // Skip table header
        .filter_map(|line| {
            let cols: Vec<&str> = line.split('|').map(|s| s.trim()).collect();
            if cols.len() >= 5 {
                Some(PatchInfo {
                    kb_id: cols.get(2).unwrap_or(&"").to_string(),
                    title: format!(
                        "{} {}",
                        cols.get(2).unwrap_or(&""),
                        cols.get(4).unwrap_or(&"")
                    ),
                    severity: "medium".to_string(),
                    cve_ids: vec![],
                    size_bytes: 0,
                    requires_reboot: false,
                    release_date: None,
                    version: Some(cols.get(4).unwrap_or(&"").to_string()),
                    source: Some("zypper".to_string()),
                })
            } else {
                None
            }
        })
        .collect();

    Ok(PatchStatus {
        installed_patches: vec![],
        missing_patches: missing,
        pending_reboot: check_linux_pending_reboot(),
        last_scan: SystemTime::now(),
    })
}

#[cfg(target_os = "linux")]
async fn install_linux_packages(
    packages: &[String],
    reboot_policy: &str,
) -> Vec<PatchInstallResult> {
    use std::process::Command;

    let pkg_mgr = detect_package_manager();
    let mut results = Vec::new();

    for package in packages {
        info!(package = %package, pkg_mgr = ?pkg_mgr, "Installing Linux package");

        let output = match pkg_mgr {
            PackageManager::Apt => Command::new("apt-get")
                .args(&["install", "-y", "--only-upgrade", package])
                .env("DEBIAN_FRONTEND", "noninteractive")
                .output(),
            PackageManager::Dnf => Command::new("dnf")
                .args(&["update", "-y", package])
                .output(),
            PackageManager::Yum => Command::new("yum")
                .args(&["update", "-y", package])
                .output(),
            PackageManager::Zypper => Command::new("zypper")
                .args(&["--non-interactive", "update", package])
                .output(),
            PackageManager::Unknown => {
                results.push(PatchInstallResult {
                    kb_id: package.clone(),
                    success: false,
                    error: Some("No supported package manager found".to_string()),
                    requires_reboot: false,
                });
                continue;
            }
        };

        match output {
            Ok(out) => {
                let success = out.status.success();
                let needs_reboot = package.contains("linux-image")
                    || package.contains("kernel")
                    || package.contains("systemd")
                    || package.contains("glibc");

                results.push(PatchInstallResult {
                    kb_id: package.clone(),
                    success,
                    error: if !success {
                        Some(String::from_utf8_lossy(&out.stderr).to_string())
                    } else {
                        None
                    },
                    requires_reboot: needs_reboot && success,
                });
            }
            Err(e) => {
                results.push(PatchInstallResult {
                    kb_id: package.clone(),
                    success: false,
                    error: Some(format!("Failed to execute: {}", e)),
                    requires_reboot: false,
                });
            }
        }
    }

    // Handle reboot if needed
    let needs_reboot = results.iter().any(|r| r.requires_reboot);
    if needs_reboot {
        handle_reboot_policy_linux(reboot_policy);
    }

    results
}

#[cfg(target_os = "linux")]
fn check_linux_pending_reboot() -> bool {
    use std::path::Path;

    // Debian/Ubuntu
    if Path::new("/var/run/reboot-required").exists() {
        return true;
    }

    // RHEL/CentOS: check if running kernel differs from installed
    if let Ok(output) = std::process::Command::new("needs-restarting")
        .args(&["-r"])
        .output()
    {
        if output.status.code() == Some(1) {
            return true;
        }
    }

    false
}

#[cfg(target_os = "linux")]
fn handle_reboot_policy_linux(policy: &str) {
    match policy {
        "immediate" => {
            info!("Reboot policy: immediate - scheduling reboot in 60 seconds");
            let _ = std::process::Command::new("shutdown")
                .args(&[
                    "-r",
                    "+1",
                    "Tamandua EDR: Patch installation requires reboot",
                ])
                .spawn();
        }
        "deferred" => {
            info!("Reboot policy: deferred - reboot pending");
        }
        "never" => {
            info!("Reboot policy: never - reboot will not be initiated");
        }
        _ => {
            info!("Reboot policy: user_choice");
        }
    }
}

// ============================================================================
// macOS Implementation
// ============================================================================

#[cfg(target_os = "macos")]
async fn scan_macos_updates() -> anyhow::Result<PatchStatus> {
    use std::process::Command;

    info!("Scanning for macOS updates via softwareupdate");

    let output = Command::new("softwareupdate")
        .args(&["--list", "--no-scan"])
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let combined = format!("{}\n{}", stdout, stderr);
    let missing = parse_macos_softwareupdate_output(&combined);

    Ok(PatchStatus {
        installed_patches: vec![],
        missing_patches: missing,
        pending_reboot: check_macos_pending_reboot(),
        last_scan: SystemTime::now(),
    })
}

fn extract_size_from_line(line: &str) -> u64 {
    // Look for "Size: NNK" or "Size: NNM" or "Size: NNG"
    if let Some(pos) = line.find("Size:") {
        let rest = &line[pos + 5..];
        let number_str: String = rest
            .trim_start()
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == ',')
            .collect();
        let normalized_number = if number_str.contains(',')
            && !number_str.contains('.')
            && number_str.rsplit(',').next().map(str::len) == Some(3)
        {
            number_str.replace(',', "")
        } else {
            number_str.replace(',', ".")
        };
        if let Ok(num) = normalized_number.parse::<f64>() {
            let multiplier = if rest.contains('G') {
                1024_f64 * 1024_f64 * 1024_f64
            } else if rest.contains('M') {
                1024_f64 * 1024_f64
            } else {
                1024_f64
            };

            return (num * multiplier).round() as u64;
        } else if let Ok(num) = normalized_number.parse::<u64>() {
            if rest.contains('G') {
                return num * 1024 * 1024 * 1024;
            } else if rest.contains('M') {
                return num * 1024 * 1024;
            } else {
                return num * 1024; // Assume KB
            }
        }
    }
    0
}

fn parse_macos_softwareupdate_output(output: &str) -> Vec<PatchInfo> {
    // Format varies, but current macOS commonly emits:
    // * Label: macOS Sonoma 14.1
    //   Title: macOS Sonoma 14.1, Version: 14.1, Size: 2.3G, Recommended: YES, Action: restart
    let mut missing = Vec::new();
    let mut current_label: Option<String> = None;

    for line in output.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("* Label:") || trimmed.starts_with('*') {
            current_label = Some(
                trimmed
                    .trim_start_matches("* Label:")
                    .trim_start_matches("* ")
                    .trim()
                    .to_string(),
            );
            continue;
        }

        if let Some(ref label) = current_label {
            if trimmed.starts_with("Title:") || trimmed.contains("Size:") {
                let requires_reboot = trimmed.contains("restart") || trimmed.contains("shut down");
                let is_recommended = trimmed.contains("Recommended: YES");
                let severity = if is_recommended { "high" } else { "medium" };

                missing.push(PatchInfo {
                    kb_id: label.clone(),
                    title: extract_macos_update_title(trimmed).unwrap_or_else(|| label.clone()),
                    severity: severity.to_string(),
                    cve_ids: vec![],
                    size_bytes: extract_size_from_line(trimmed),
                    requires_reboot,
                    release_date: None,
                    version: extract_macos_update_version(trimmed),
                    source: Some("softwareupdate".to_string()),
                });

                current_label = None;
            }
        }
    }

    missing
}

fn extract_macos_update_title(line: &str) -> Option<String> {
    extract_macos_metadata_field(line, "Title:")
}

fn extract_macos_update_version(line: &str) -> Option<String> {
    extract_macos_metadata_field(line, "Version:")
}

fn extract_macos_metadata_field(line: &str, field: &str) -> Option<String> {
    let start = line.find(field)? + field.len();
    let rest = line[start..].trim_start();
    let value = rest.split(',').next()?.trim();

    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

#[cfg(target_os = "macos")]
async fn install_macos_updates(updates: &[String], reboot_policy: &str) -> Vec<PatchInstallResult> {
    use std::process::Command;

    let mut results = Vec::new();

    for update in updates {
        info!(update = %update, "Installing macOS update");

        let output = Command::new("softwareupdate")
            .args(&["--install", update, "--no-scan"])
            .output();

        match output {
            Ok(out) => {
                let success = out.status.success();
                let stdout = String::from_utf8_lossy(&out.stdout);
                let requires_reboot = stdout.contains("restart") || stdout.contains("shut down");

                results.push(PatchInstallResult {
                    kb_id: update.clone(),
                    success,
                    error: if !success {
                        Some(String::from_utf8_lossy(&out.stderr).to_string())
                    } else {
                        None
                    },
                    requires_reboot,
                });
            }
            Err(e) => {
                results.push(PatchInstallResult {
                    kb_id: update.clone(),
                    success: false,
                    error: Some(format!("Failed to execute: {}", e)),
                    requires_reboot: false,
                });
            }
        }
    }

    // Handle reboot
    let needs_reboot = results.iter().any(|r| r.requires_reboot);
    if needs_reboot && reboot_policy == "immediate" {
        info!("Reboot policy: immediate - scheduling reboot");
        let _ = Command::new("shutdown").args(&["-r", "+1"]).spawn();
    }

    results
}

#[cfg(target_os = "macos")]
fn check_macos_pending_reboot() -> bool {
    use std::process::Command;

    // Check if softwareupdate requires a restart
    match Command::new("softwareupdate")
        .args(&["--list", "--no-scan"])
        .output()
    {
        Ok(output) => {
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            combined.contains("restart")
        }
        Err(_) => false,
    }
}

// ============================================================================
// Common Helpers
// ============================================================================

#[cfg(target_os = "windows")]
fn parse_patches_from_json(value: Option<&serde_json::Value>) -> Vec<PatchInfo> {
    match value {
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|item| {
                Some(PatchInfo {
                    kb_id: item.get("kb_id")?.as_str()?.to_string(),
                    title: item
                        .get("title")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    severity: item
                        .get("severity")
                        .and_then(|v| v.as_str())
                        .unwrap_or("medium")
                        .to_string(),
                    cve_ids: item
                        .get("cve_ids")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default(),
                    size_bytes: item.get("size_bytes").and_then(|v| v.as_u64()).unwrap_or(0),
                    requires_reboot: item
                        .get("requires_reboot")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                    release_date: item
                        .get("release_date")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    version: None,
                    source: Some("windows_update".to_string()),
                })
            })
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_patch_info_serialization() {
        let patch = PatchInfo {
            kb_id: "KB5001234".to_string(),
            title: "Security Update for Windows".to_string(),
            severity: "critical".to_string(),
            cve_ids: vec!["CVE-2024-1234".to_string()],
            size_bytes: 1024 * 1024,
            requires_reboot: true,
            release_date: Some("2024-01-15".to_string()),
            version: None,
            source: Some("windows_update".to_string()),
        };

        let json = serde_json::to_string(&patch).unwrap();
        let deserialized: PatchInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.kb_id, "KB5001234");
        assert_eq!(deserialized.severity, "critical");
        assert!(deserialized.requires_reboot);
    }

    #[test]
    fn test_patch_status_serialization() {
        let status = PatchStatus {
            installed_patches: vec![],
            missing_patches: vec![PatchInfo {
                kb_id: "KB5001234".to_string(),
                title: "Test".to_string(),
                severity: "high".to_string(),
                cve_ids: vec![],
                size_bytes: 0,
                requires_reboot: false,
                release_date: None,
                version: None,
                source: None,
            }],
            pending_reboot: false,
            last_scan: SystemTime::now(),
        };

        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(status.missing_patches.len(), 1);
        assert!(!status.pending_reboot);
    }

    #[test]
    fn test_patch_install_result() {
        let result = PatchInstallResult {
            kb_id: "KB5001234".to_string(),
            success: true,
            error: None,
            requires_reboot: true,
        };

        assert!(result.success);
        assert!(result.requires_reboot);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_parse_macos_softwareupdate_output() {
        let output = r#"
Software Update Tool

Finding available software
Software Update found the following new or updated software:
* Label: macOS Sonoma 14.5-23F79
    Title: macOS Sonoma 14.5, Version: 14.5, Size: 2.3G, Recommended: YES, Action: restart
* Label: Safari17.5SonomaAuto-17.5
    Title: Safari, Version: 17.5, Size: 144.7M, Recommended: YES,
* Command Line Tools for Xcode-15.3
    Title: Command Line Tools for Xcode, Version: 15.3, Size: 1,234K, Recommended: NO,
"#;

        let patches = parse_macos_softwareupdate_output(output);

        assert_eq!(patches.len(), 3);
        assert_eq!(patches[0].kb_id, "macOS Sonoma 14.5-23F79");
        assert_eq!(patches[0].title, "macOS Sonoma 14.5");
        assert_eq!(patches[0].version.as_deref(), Some("14.5"));
        assert_eq!(patches[0].severity, "high");
        assert!(patches[0].requires_reboot);
        assert_eq!(patches[0].source.as_deref(), Some("softwareupdate"));
        assert_eq!(patches[0].size_bytes, 2_469_606_195);

        assert_eq!(patches[1].title, "Safari");
        assert!(!patches[1].requires_reboot);
        assert_eq!(patches[1].size_bytes, 151_728_947);

        assert_eq!(patches[2].kb_id, "Command Line Tools for Xcode-15.3");
        assert_eq!(patches[2].severity, "medium");
        assert_eq!(patches[2].size_bytes, 1_263_616);
    }
}
