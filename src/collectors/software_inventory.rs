//! Software Inventory Collector
//!
//! Collects installed software information for vulnerability tracking and compliance.
//!
//! Features:
//! - Enumerate installed programs from registry (Windows) or package managers (Linux/macOS)
//! - Detect software versions for CVE matching
//! - Track software changes (install/uninstall/update)
//! - Identify potentially unwanted programs (PUPs)
//!
//! Windows: Registry (Uninstall keys), WMI
//! Linux: dpkg, rpm, snap, flatpak
//! macOS: Applications folder, Homebrew

// Software inventory collector. Fields are scaffolded for upcoming
// vulnerability cross-referencing not yet wired through.
#![allow(dead_code, unused_variables)]

use super::{Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent};
use crate::config::AgentConfig;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Installed software information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledSoftware {
    /// Software name
    pub name: String,
    /// Version string
    pub version: String,
    /// Vendor/Publisher
    pub vendor: Option<String>,
    /// Installation date
    pub install_date: Option<String>,
    /// Installation path
    pub install_path: Option<String>,
    /// Uninstall string/command
    pub uninstall_string: Option<String>,
    /// Software category (detected)
    pub category: SoftwareCategory,
    /// Is this software potentially unwanted
    pub is_pup: bool,
    /// Architecture (x86, x64, etc.)
    pub architecture: Option<String>,
    /// Size in bytes
    pub size_bytes: Option<u64>,
    /// Source (registry, wmi, dpkg, etc.)
    pub source: String,
    /// CPE (Common Platform Enumeration) for CVE matching
    /// Format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
    pub cpe: Option<String>,
    /// Parsed version components for range matching
    pub version_info: Option<VersionInfo>,
}

/// Parsed version information for vulnerability range matching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    /// Major version number
    pub major: Option<u32>,
    /// Minor version number
    pub minor: Option<u32>,
    /// Patch/build number
    pub patch: Option<u32>,
    /// Pre-release identifier (alpha, beta, rc, etc.)
    pub prerelease: Option<String>,
    /// Build metadata
    pub build: Option<String>,
    /// Original version string
    pub raw: String,
}

/// Software category for classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareCategory {
    /// Operating system component
    System,
    /// Security software (AV, firewall, etc.)
    Security,
    /// Web browser
    Browser,
    /// Office/productivity suite
    Productivity,
    /// Development tools
    Development,
    /// Remote access tools
    RemoteAccess,
    /// Media players
    Media,
    /// Communication software
    Communication,
    /// Utilities
    Utility,
    /// Games
    Game,
    /// Potentially unwanted
    PotentiallyUnwanted,
    /// Unknown category
    Unknown,
}

impl SoftwareCategory {
    /// Detect category from software name
    pub fn from_name(name: &str) -> Self {
        let name_lower = name.to_lowercase();

        // Security
        if name_lower.contains("antivirus")
            || name_lower.contains("defender")
            || name_lower.contains("security")
            || name_lower.contains("firewall")
            || name_lower.contains("malwarebytes")
            || name_lower.contains("norton")
            || name_lower.contains("kaspersky")
            || name_lower.contains("avast")
            || name_lower.contains("bitdefender")
        {
            return Self::Security;
        }

        // Browsers
        if name_lower.contains("chrome")
            || name_lower.contains("firefox")
            || name_lower.contains("edge")
            || name_lower.contains("safari")
            || name_lower.contains("opera")
            || name_lower.contains("brave")
        {
            return Self::Browser;
        }

        // Remote access (high risk)
        if name_lower.contains("teamviewer")
            || name_lower.contains("anydesk")
            || name_lower.contains("vnc")
            || name_lower.contains("remote desktop")
            || name_lower.contains("logmein")
            || name_lower.contains("ammyy")
            || name_lower.contains("radmin")
            || name_lower.contains("rustdesk")
        {
            return Self::RemoteAccess;
        }

        // Productivity
        if name_lower.contains("office")
            || name_lower.contains("word")
            || name_lower.contains("excel")
            || name_lower.contains("powerpoint")
            || name_lower.contains("outlook")
            || name_lower.contains("libreoffice")
            || name_lower.contains("google docs")
        {
            return Self::Productivity;
        }

        // Development
        if name_lower.contains("visual studio")
            || name_lower.contains("vscode")
            || name_lower.contains("intellij")
            || name_lower.contains("pycharm")
            || name_lower.contains("eclipse")
            || name_lower.contains("git")
            || name_lower.contains("nodejs")
            || name_lower.contains("python")
            || name_lower.contains("java")
            || name_lower.contains("rust")
            || name_lower.contains("golang")
            || name_lower.contains("docker")
        {
            return Self::Development;
        }

        // Potentially unwanted
        if name_lower.contains("toolbar")
            || name_lower.contains("adware")
            || name_lower.contains("torrent")
            || name_lower.contains("crack")
            || name_lower.contains("keygen")
            || name_lower.contains("activator")
        {
            return Self::PotentiallyUnwanted;
        }

        // Media
        if name_lower.contains("vlc")
            || name_lower.contains("media player")
            || name_lower.contains("spotify")
            || name_lower.contains("itunes")
            || name_lower.contains("winamp")
        {
            return Self::Media;
        }

        // Communication
        if name_lower.contains("teams")
            || name_lower.contains("slack")
            || name_lower.contains("zoom")
            || name_lower.contains("discord")
            || name_lower.contains("skype")
            || name_lower.contains("webex")
        {
            return Self::Communication;
        }

        // Utilities
        if name_lower.contains("7-zip")
            || name_lower.contains("winrar")
            || name_lower.contains("notepad++")
            || name_lower.contains("acrobat")
            || name_lower.contains("pdf")
        {
            return Self::Utility;
        }

        // System
        if name_lower.contains("microsoft")
            || name_lower.contains("windows")
            || name_lower.starts_with("update for")
        {
            return Self::System;
        }

        Self::Unknown
    }

    /// Check if this category is potentially high-risk
    pub fn is_high_risk(&self) -> bool {
        matches!(self, Self::RemoteAccess | Self::PotentiallyUnwanted)
    }
}

/// Software change event type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareChangeType {
    /// New software installed
    Installed,
    /// Software removed
    Uninstalled,
    /// Software version changed (updated)
    Updated,
    /// Initial inventory (first scan)
    Initial,
}

/// Software inventory event payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareInventoryEvent {
    /// Change type
    pub change_type: SoftwareChangeType,
    /// Software information
    pub software: InstalledSoftware,
    /// Previous version (for updates)
    pub previous_version: Option<String>,
}

/// Full inventory report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryReport {
    /// All installed software
    pub software: Vec<InstalledSoftware>,
    /// Total count
    pub total_count: usize,
    /// Count by category
    pub by_category: HashMap<String, usize>,
    /// Potentially unwanted count
    pub pup_count: usize,
    /// Remote access tools count
    pub remote_access_count: usize,
    /// Scan timestamp
    pub scanned_at: chrono::DateTime<chrono::Utc>,
}

/// Software inventory collector
pub struct SoftwareInventoryCollector {
    config: AgentConfig,
    known_software: HashMap<String, InstalledSoftware>,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    #[allow(dead_code)]
    event_tx: mpsc::Sender<TelemetryEvent>,
    /// Scan interval in seconds
    scan_interval_secs: u64,
}

impl SoftwareInventoryCollector {
    /// Create a new software inventory collector
    pub fn new(config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(1000);

        let collector = Self {
            config: config.clone(),
            known_software: HashMap::new(),
            event_rx: rx,
            event_tx: tx.clone(),
            scan_interval_secs: 3600, // Default: scan every hour
        };

        // Start background scanning
        tokio::spawn(async move {
            Self::scan_loop(tx).await;
        });

        collector
    }

    /// Get the next event
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }

    /// Perform full inventory scan
    pub async fn full_inventory() -> InventoryReport {
        let software = Self::enumerate_software().await;

        let mut by_category: HashMap<String, usize> = HashMap::new();
        let mut pup_count = 0;
        let mut remote_access_count = 0;

        for sw in &software {
            let cat_name = format!("{:?}", sw.category).to_lowercase();
            *by_category.entry(cat_name).or_insert(0) += 1;

            if sw.is_pup {
                pup_count += 1;
            }
            if sw.category == SoftwareCategory::RemoteAccess {
                remote_access_count += 1;
            }
        }

        InventoryReport {
            total_count: software.len(),
            software,
            by_category,
            pup_count,
            remote_access_count,
            scanned_at: chrono::Utc::now(),
        }
    }

    async fn scan_loop(tx: mpsc::Sender<TelemetryEvent>) {
        let mut known_software: HashMap<String, InstalledSoftware> = HashMap::new();
        let mut first_scan = true;

        loop {
            debug!("Starting software inventory scan");

            let current = Self::enumerate_software().await;

            // Create a map of current software by name+version key
            let current_map: HashMap<String, InstalledSoftware> = current
                .into_iter()
                .map(|sw| (format!("{}:{}", sw.name, sw.version), sw))
                .collect();

            let current_keys: HashSet<String> = current_map.keys().cloned().collect();
            let known_keys: HashSet<String> = known_software.keys().cloned().collect();

            if first_scan {
                // Send full inventory on first scan
                for (key, sw) in &current_map {
                    let event = Self::create_event(&sw, SoftwareChangeType::Initial, None);

                    if tx.send(event).await.is_err() {
                        warn!("Software inventory channel closed");
                        return;
                    }
                }

                known_software = current_map.clone();
                first_scan = false;
                info!(
                    count = known_software.len(),
                    "Initial software inventory complete"
                );
            } else {
                // Check for new software (installed)
                for key in current_keys.difference(&known_keys) {
                    if let Some(sw) = current_map.get(key) {
                        info!(name = %sw.name, version = %sw.version, "New software detected");

                        let event = Self::create_event(sw, SoftwareChangeType::Installed, None);

                        if tx.send(event).await.is_err() {
                            warn!("Software inventory channel closed");
                            return;
                        }

                        known_software.insert(key.clone(), sw.clone());
                    }
                }

                // Check for removed software (uninstalled)
                for key in known_keys.difference(&current_keys) {
                    if let Some(sw) = known_software.remove(key) {
                        info!(name = %sw.name, version = %sw.version, "Software removed");

                        let event = Self::create_event(&sw, SoftwareChangeType::Uninstalled, None);

                        if tx.send(event).await.is_err() {
                            warn!("Software inventory channel closed");
                            return;
                        }
                    }
                }

                // Check for updates (same name, different version)
                // This is handled implicitly by the install/uninstall detection
            }

            // Wait before next scan
            tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
        }
    }

    fn create_event(
        software: &InstalledSoftware,
        change_type: SoftwareChangeType,
        previous_version: Option<String>,
    ) -> TelemetryEvent {
        let severity = match (&change_type, software.category.is_high_risk()) {
            (SoftwareChangeType::Installed, true) => Severity::High,
            (SoftwareChangeType::Installed, false) => Severity::Low,
            (SoftwareChangeType::Uninstalled, _) => Severity::Info,
            (SoftwareChangeType::Updated, _) => Severity::Low,
            (SoftwareChangeType::Initial, _) => Severity::Info,
        };

        let event_type = match change_type {
            SoftwareChangeType::Installed => EventType::SoftwareInstall,
            SoftwareChangeType::Uninstalled => EventType::SoftwareUninstall,
            SoftwareChangeType::Updated => EventType::SoftwareChange,
            SoftwareChangeType::Initial => EventType::SoftwareInventory,
        };

        // Create generic payload
        let payload = serde_json::json!({
            "change_type": format!("{:?}", change_type).to_lowercase(),
            "name": software.name,
            "version": software.version,
            "vendor": software.vendor,
            "install_date": software.install_date,
            "install_path": software.install_path,
            "category": format!("{:?}", software.category).to_lowercase(),
            "is_pup": software.is_pup,
            "previous_version": previous_version,
        });

        let mut event = TelemetryEvent::new(event_type, severity, EventPayload::Custom(payload));

        event.metadata.insert(
            "event_category".to_string(),
            "software_inventory".to_string(),
        );
        event
            .metadata
            .insert("software_name".to_string(), software.name.clone());
        event
            .metadata
            .insert("software_version".to_string(), software.version.clone());

        // Add detection for potentially unwanted software
        if software.is_pup || software.category == SoftwareCategory::PotentiallyUnwanted {
            event.add_detection(Detection {
                detection_type: DetectionType::Behavioral,
                rule_name: "potentially_unwanted_software".to_string(),
                confidence: 0.8,
                description: format!(
                    "Potentially unwanted software detected: {} {}",
                    software.name, software.version
                ),
                mitre_tactics: vec!["persistence".to_string()],
                mitre_techniques: vec!["T1176".to_string()],
            });
        }

        // Add detection for unauthorized remote access tools
        if software.category == SoftwareCategory::RemoteAccess {
            event.add_detection(Detection {
                detection_type: DetectionType::Behavioral,
                rule_name: "remote_access_tool_installed".to_string(),
                confidence: 0.7,
                description: format!(
                    "Remote access software detected: {} {}",
                    software.name, software.version
                ),
                mitre_tactics: vec!["command-and-control".to_string(), "persistence".to_string()],
                mitre_techniques: vec!["T1219".to_string()],
            });
        }

        event
    }

    /// Enumerate all installed software
    async fn enumerate_software() -> Vec<InstalledSoftware> {
        #[cfg(target_os = "windows")]
        return Self::enumerate_software_windows().await;

        #[cfg(target_os = "linux")]
        return Self::enumerate_software_linux().await;

        #[cfg(target_os = "macos")]
        return Self::enumerate_software_macos().await;

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        return Vec::new();
    }

    // ========================================================================
    // Windows Implementation
    // ========================================================================

    #[cfg(target_os = "windows")]
    async fn enumerate_software_windows() -> Vec<InstalledSoftware> {
        use winreg::enums::*;
        use winreg::RegKey;

        let mut software = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        // Registry paths for installed software
        let registry_paths = [
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            ),
            (
                HKEY_CURRENT_USER,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            ),
        ];

        for (hkey, path) in &registry_paths {
            let root = RegKey::predef(*hkey);
            if let Ok(uninstall_key) = root.open_subkey_with_flags(path, KEY_READ) {
                for subkey_name in uninstall_key.enum_keys().filter_map(|k| k.ok()) {
                    if let Ok(subkey) = uninstall_key.open_subkey_with_flags(&subkey_name, KEY_READ)
                    {
                        if let Some(sw) = Self::parse_windows_registry_entry(&subkey, &subkey_name)
                        {
                            // Deduplicate by name+version
                            let key = format!("{}:{}", sw.name, sw.version);
                            if !seen.contains(&key) {
                                seen.insert(key);
                                software.push(sw);
                            }
                        }
                    }
                }
            }
        }

        software
    }

    #[cfg(target_os = "windows")]
    fn parse_windows_registry_entry(
        key: &winreg::RegKey,
        subkey_name: &str,
    ) -> Option<InstalledSoftware> {
        // Get display name (required)
        let name: String = key.get_value("DisplayName").ok()?;

        // Skip empty or system entries
        if name.is_empty() || name.starts_with("KB") || name.starts_with("Update for") {
            return None;
        }

        let version: String = key.get_value("DisplayVersion").unwrap_or_default();
        let vendor: Option<String> = key.get_value("Publisher").ok();
        let install_date: Option<String> = key.get_value("InstallDate").ok();
        let install_path: Option<String> = key.get_value("InstallLocation").ok();
        let uninstall_string: Option<String> = key.get_value("UninstallString").ok();
        let estimated_size: Option<u32> = key.get_value("EstimatedSize").ok();

        let category = SoftwareCategory::from_name(&name);
        let is_pup = Self::is_potentially_unwanted(&name, &vendor);

        // Generate CPE for vulnerability matching
        let cpe = Self::generate_cpe(&name, &version, &vendor);
        let version_info = Some(Self::parse_version(&version));

        Some(InstalledSoftware {
            name,
            version,
            vendor,
            install_date,
            install_path,
            uninstall_string,
            category,
            is_pup,
            architecture: None,
            size_bytes: estimated_size.map(|s| s as u64 * 1024),
            source: "registry".to_string(),
            cpe,
            version_info,
        })
    }

    // ========================================================================
    // Linux Implementation
    // ========================================================================

    #[cfg(target_os = "linux")]
    async fn enumerate_software_linux() -> Vec<InstalledSoftware> {
        let mut software = Vec::new();

        // Try dpkg (Debian/Ubuntu)
        software.extend(Self::enumerate_dpkg().await);

        // Try rpm (RHEL/Fedora)
        software.extend(Self::enumerate_rpm().await);

        // Try snap
        software.extend(Self::enumerate_snap().await);

        // Try flatpak
        software.extend(Self::enumerate_flatpak().await);

        software
    }

    #[cfg(target_os = "linux")]
    async fn enumerate_dpkg() -> Vec<InstalledSoftware> {
        let mut software = Vec::new();

        let output = match tokio::process::Command::new("dpkg-query")
            .args([
                "-W",
                "-f",
                "${Package}|${Version}|${Status}|${Maintainer}|${Installed-Size}\n",
            ])
            .output()
            .await
        {
            Ok(o) if o.status.success() => o,
            _ => return software,
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() >= 3 && parts[2].contains("installed") {
                let name = parts[0].to_string();
                let version = parts.get(1).unwrap_or(&"").to_string();
                let vendor = parts.get(3).map(|s| s.to_string());
                let size: Option<u64> = parts
                    .get(4)
                    .and_then(|s| s.parse().ok())
                    .map(|kb: u64| kb * 1024);

                let category = SoftwareCategory::from_name(&name);
                let is_pup = Self::is_potentially_unwanted(&name, &vendor);
                let cpe = Self::generate_cpe(&name, &version, &vendor);
                let version_info = Some(Self::parse_version(&version));

                software.push(InstalledSoftware {
                    name,
                    version,
                    vendor,
                    install_date: None,
                    install_path: None,
                    uninstall_string: None,
                    category,
                    is_pup,
                    architecture: None,
                    size_bytes: size,
                    source: "dpkg".to_string(),
                    cpe,
                    version_info,
                });
            }
        }

        software
    }

    #[cfg(target_os = "linux")]
    async fn enumerate_rpm() -> Vec<InstalledSoftware> {
        let mut software = Vec::new();

        let output = match tokio::process::Command::new("rpm")
            .args([
                "-qa",
                "--queryformat",
                "%{NAME}|%{VERSION}|%{VENDOR}|%{SIZE}|%{INSTALLTIME}\n",
            ])
            .output()
            .await
        {
            Ok(o) if o.status.success() => o,
            _ => return software,
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() >= 2 {
                let name = parts[0].to_string();
                let version = parts[1].to_string();
                let vendor = parts
                    .get(2)
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string());
                let size: Option<u64> = parts.get(3).and_then(|s| s.parse().ok());

                let category = SoftwareCategory::from_name(&name);
                let is_pup = Self::is_potentially_unwanted(&name, &vendor);
                let cpe = Self::generate_cpe(&name, &version, &vendor);
                let version_info = Some(Self::parse_version(&version));

                software.push(InstalledSoftware {
                    name,
                    version,
                    vendor,
                    install_date: None,
                    install_path: None,
                    uninstall_string: None,
                    category,
                    is_pup,
                    architecture: None,
                    size_bytes: size,
                    source: "rpm".to_string(),
                    cpe,
                    version_info,
                });
            }
        }

        software
    }

    #[cfg(target_os = "linux")]
    async fn enumerate_snap() -> Vec<InstalledSoftware> {
        let mut software = Vec::new();

        let output = match tokio::process::Command::new("snap")
            .args(["list"])
            .output()
            .await
        {
            Ok(o) if o.status.success() => o,
            _ => return software,
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().skip(1) {
            // Skip header
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let name = parts[0].to_string();
                let version = parts[1].to_string();

                let category = SoftwareCategory::from_name(&name);
                let is_pup = Self::is_potentially_unwanted(&name, &None);
                let cpe = Self::generate_cpe(&name, &version, &None);
                let version_info = Some(Self::parse_version(&version));

                software.push(InstalledSoftware {
                    name,
                    version,
                    vendor: None,
                    install_date: None,
                    install_path: None,
                    uninstall_string: None,
                    category,
                    is_pup,
                    architecture: None,
                    size_bytes: None,
                    source: "snap".to_string(),
                    cpe,
                    version_info,
                });
            }
        }

        software
    }

    #[cfg(target_os = "linux")]
    async fn enumerate_flatpak() -> Vec<InstalledSoftware> {
        let mut software = Vec::new();

        let output = match tokio::process::Command::new("flatpak")
            .args(["list", "--columns=application,version,origin"])
            .output()
            .await
        {
            Ok(o) if o.status.success() => o,
            _ => return software,
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 2 {
                let name = parts[0].to_string();
                let version = parts.get(1).unwrap_or(&"").to_string();

                let category = SoftwareCategory::from_name(&name);
                let is_pup = Self::is_potentially_unwanted(&name, &None);
                let cpe = Self::generate_cpe(&name, &version, &None);
                let version_info = Some(Self::parse_version(&version));

                software.push(InstalledSoftware {
                    name,
                    version,
                    vendor: None,
                    install_date: None,
                    install_path: None,
                    uninstall_string: None,
                    category,
                    is_pup,
                    architecture: None,
                    size_bytes: None,
                    source: "flatpak".to_string(),
                    cpe,
                    version_info,
                });
            }
        }

        software
    }

    // ========================================================================
    // macOS Implementation
    // ========================================================================

    #[cfg(target_os = "macos")]
    async fn enumerate_software_macos() -> Vec<InstalledSoftware> {
        let mut software = Vec::new();

        // Enumerate /Applications
        software.extend(Self::enumerate_macos_applications().await);

        // Enumerate Homebrew
        software.extend(Self::enumerate_homebrew().await);

        software
    }

    #[cfg(target_os = "macos")]
    async fn enumerate_macos_applications() -> Vec<InstalledSoftware> {
        let mut software = Vec::new();

        let output = match tokio::process::Command::new("system_profiler")
            .args(["SPApplicationsDataType", "-json"])
            .output()
            .await
        {
            Ok(o) if o.status.success() => o,
            _ => return software,
        };

        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
            if let Some(apps) = json
                .get("SPApplicationsDataType")
                .and_then(|v| v.as_array())
            {
                for app in apps {
                    let name = app
                        .get("_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let version = app
                        .get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let vendor = app
                        .get("obtained_from")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let path = app.get("path").and_then(|v| v.as_str()).map(String::from);

                    if !name.is_empty() {
                        let category = SoftwareCategory::from_name(&name);
                        let is_pup = Self::is_potentially_unwanted(&name, &vendor);
                        let cpe = Self::generate_cpe(&name, &version, &vendor);
                        let version_info = Some(Self::parse_version(&version));

                        software.push(InstalledSoftware {
                            name,
                            version,
                            vendor,
                            install_date: None,
                            install_path: path,
                            uninstall_string: None,
                            category,
                            is_pup,
                            architecture: None,
                            size_bytes: None,
                            source: "applications".to_string(),
                            cpe,
                            version_info,
                        });
                    }
                }
            }
        }

        software
    }

    #[cfg(target_os = "macos")]
    async fn enumerate_homebrew() -> Vec<InstalledSoftware> {
        let mut software = Vec::new();

        // List Homebrew formulae
        let output = match tokio::process::Command::new("brew")
            .args(["list", "--formula", "--versions"])
            .output()
            .await
        {
            Ok(o) if o.status.success() => o,
            _ => return software,
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let name = parts[0].to_string();
                let version = parts[1].to_string();

                let category = SoftwareCategory::from_name(&name);
                let is_pup = Self::is_potentially_unwanted(&name, &None);
                let vendor = Some("Homebrew".to_string());
                let cpe = Self::generate_cpe(&name, &version, &vendor);
                let version_info = Some(Self::parse_version(&version));

                software.push(InstalledSoftware {
                    name,
                    version,
                    vendor,
                    install_date: None,
                    install_path: None,
                    uninstall_string: None,
                    category,
                    is_pup,
                    architecture: None,
                    size_bytes: None,
                    source: "homebrew".to_string(),
                    cpe,
                    version_info,
                });
            }
        }

        // List Homebrew casks
        let output = match tokio::process::Command::new("brew")
            .args(["list", "--cask", "--versions"])
            .output()
            .await
        {
            Ok(o) if o.status.success() => o,
            _ => return software,
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let name = parts[0].to_string();
                let version = parts[1].to_string();

                let category = SoftwareCategory::from_name(&name);
                let is_pup = Self::is_potentially_unwanted(&name, &None);
                let vendor = Some("Homebrew Cask".to_string());
                let cpe = Self::generate_cpe(&name, &version, &vendor);
                let version_info = Some(Self::parse_version(&version));

                software.push(InstalledSoftware {
                    name,
                    version,
                    vendor,
                    install_date: None,
                    install_path: None,
                    uninstall_string: None,
                    category,
                    is_pup,
                    architecture: None,
                    size_bytes: None,
                    source: "homebrew-cask".to_string(),
                    cpe,
                    version_info,
                });
            }
        }

        software
    }

    // ========================================================================
    // Common Helpers
    // ========================================================================

    /// Generate CPE (Common Platform Enumeration) string for software
    /// Format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
    pub fn generate_cpe(name: &str, version: &str, vendor: &Option<String>) -> Option<String> {
        // Normalize vendor
        let vendor_normalized = vendor
            .as_ref()
            .map(|v| Self::normalize_cpe_component(v))
            .unwrap_or_else(|| Self::infer_vendor_from_name(name));

        // Normalize product name
        let product_normalized = Self::normalize_cpe_component(name);

        // Normalize version
        let version_normalized = Self::normalize_cpe_version(version);

        if product_normalized.is_empty() || version_normalized.is_empty() {
            return None;
        }

        Some(format!(
            "cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*",
            vendor_normalized, product_normalized, version_normalized
        ))
    }

    /// Normalize a component for CPE format (lowercase, replace spaces with underscores, remove special chars)
    fn normalize_cpe_component(s: &str) -> String {
        s.to_lowercase()
            .chars()
            .map(|c| {
                if c.is_alphanumeric() {
                    c
                } else if c == ' ' || c == '-' {
                    '_'
                } else {
                    '_'
                }
            })
            .collect::<String>()
            .trim_matches('_')
            .to_string()
    }

    /// Normalize version for CPE format
    fn normalize_cpe_version(version: &str) -> String {
        // Extract just the version number portion
        let version_clean: String = version
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '-' || *c == '_')
            .collect();

        if version_clean.is_empty() {
            version
                .to_lowercase()
                .replace(' ', "_")
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == '.' || *c == '_')
                .collect()
        } else {
            version_clean
        }
    }

    /// Infer vendor from software name using common patterns
    fn infer_vendor_from_name(name: &str) -> String {
        let name_lower = name.to_lowercase();

        // Common vendor mappings
        let vendor_patterns = [
            ("microsoft", "microsoft"),
            ("windows", "microsoft"),
            ("office", "microsoft"),
            ("visual studio", "microsoft"),
            ("google", "google"),
            ("chrome", "google"),
            ("mozilla", "mozilla"),
            ("firefox", "mozilla"),
            ("adobe", "adobe"),
            ("acrobat", "adobe"),
            ("reader", "adobe"),
            ("photoshop", "adobe"),
            ("oracle", "oracle"),
            ("java", "oracle"),
            ("vmware", "vmware"),
            ("citrix", "citrix"),
            ("cisco", "cisco"),
            ("intel", "intel"),
            ("nvidia", "nvidia"),
            ("amd", "amd"),
            ("apple", "apple"),
            ("nodejs", "nodejs"),
            ("node.js", "nodejs"),
            ("python", "python"),
            ("postgresql", "postgresql"),
            ("mysql", "oracle"),
            ("redis", "redis"),
            ("nginx", "nginx"),
            ("apache", "apache"),
            ("openssl", "openssl"),
            ("curl", "haxx"),
            ("git", "git-scm"),
            ("docker", "docker"),
            ("kubernetes", "kubernetes"),
            ("elastic", "elastic"),
            ("zoom", "zoom"),
            ("slack", "slack"),
            ("teams", "microsoft"),
            ("vscode", "microsoft"),
        ];

        for (pattern, vendor) in vendor_patterns {
            if name_lower.contains(pattern) {
                return vendor.to_string();
            }
        }

        // Default: use first word of name as vendor
        name_lower
            .split_whitespace()
            .next()
            .map(|s| Self::normalize_cpe_component(s))
            .unwrap_or_else(|| "unknown".to_string())
    }

    /// Parse version string into components
    pub fn parse_version(version: &str) -> VersionInfo {
        let raw = version.to_string();

        // Remove common prefixes like 'v', 'V', 'version'
        let version_clean = version
            .trim()
            .trim_start_matches(|c| c == 'v' || c == 'V')
            .trim_start_matches("ersion")
            .trim_start_matches(' ');

        // Split by common separators
        let parts: Vec<&str> = version_clean
            .split(|c| c == '.' || c == '-' || c == '_')
            .collect();

        let mut major = None;
        let mut minor = None;
        let mut patch = None;
        let mut prerelease = None;
        let mut build = None;

        for (i, part) in parts.iter().enumerate() {
            if let Ok(num) = part.parse::<u32>() {
                match i {
                    0 => major = Some(num),
                    1 => minor = Some(num),
                    2 => patch = Some(num),
                    _ => {
                        // Additional version components go to build
                        if build.is_none() {
                            build = Some(part.to_string());
                        }
                    }
                }
            } else {
                // Non-numeric part - check if it's prerelease
                let part_lower = part.to_lowercase();
                if part_lower.starts_with("alpha")
                    || part_lower.starts_with("beta")
                    || part_lower.starts_with("rc")
                    || part_lower.starts_with("pre")
                    || part_lower.starts_with("dev")
                {
                    prerelease = Some(part.to_string());
                } else if i > 0 {
                    build = Some(part.to_string());
                }
            }
        }

        VersionInfo {
            major,
            minor,
            patch,
            prerelease,
            build,
            raw,
        }
    }

    /// Check if software is potentially unwanted
    fn is_potentially_unwanted(name: &str, vendor: &Option<String>) -> bool {
        let name_lower = name.to_lowercase();
        let vendor_lower = vendor
            .as_ref()
            .map(|v| v.to_lowercase())
            .unwrap_or_default();

        // Known PUP indicators
        let pup_keywords = [
            "toolbar",
            "adware",
            "conduit",
            "ask.com",
            "babylon",
            "mywebsearch",
            "searchqu",
            "delta-search",
            "iminent",
            "sweetim",
            "funmoods",
            "softonic",
            "download manager",
            "browser helper",
            "registry cleaner",
            "driver updater",
            "optimizer",
            "pc cleaner",
        ];

        for keyword in &pup_keywords {
            if name_lower.contains(keyword) || vendor_lower.contains(keyword) {
                return true;
            }
        }

        // Known PUP vendors
        let pup_vendors = [
            "conduit",
            "babylon",
            "ask",
            "softonic",
            "download.com",
            "cnet",
        ];

        for vendor_keyword in &pup_vendors {
            if vendor_lower.contains(vendor_keyword) {
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_category_detection() {
        assert_eq!(
            SoftwareCategory::from_name("Google Chrome"),
            SoftwareCategory::Browser
        );
        assert_eq!(
            SoftwareCategory::from_name("TeamViewer"),
            SoftwareCategory::RemoteAccess
        );
        assert_eq!(
            SoftwareCategory::from_name("Microsoft Office"),
            SoftwareCategory::Productivity
        );
        assert_eq!(
            SoftwareCategory::from_name("Visual Studio Code"),
            SoftwareCategory::Development
        );
        assert_eq!(
            SoftwareCategory::from_name("Windows Defender"),
            SoftwareCategory::Security
        );
    }

    #[test]
    fn test_pup_detection() {
        assert!(SoftwareInventoryCollector::is_potentially_unwanted(
            "Conduit Toolbar",
            &None
        ));
        assert!(SoftwareInventoryCollector::is_potentially_unwanted(
            "Random Software",
            &Some("Babylon Ltd".to_string())
        ));
        assert!(!SoftwareInventoryCollector::is_potentially_unwanted(
            "Google Chrome",
            &Some("Google LLC".to_string())
        ));
    }

    #[test]
    fn test_high_risk_categories() {
        assert!(SoftwareCategory::RemoteAccess.is_high_risk());
        assert!(SoftwareCategory::PotentiallyUnwanted.is_high_risk());
        assert!(!SoftwareCategory::Browser.is_high_risk());
        assert!(!SoftwareCategory::Productivity.is_high_risk());
    }
}
