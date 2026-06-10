//! Browser Credential and Data Protection Collector
//!
//! Monitors and protects browser credential databases and sensitive data from theft.
//! Detects known stealer malware patterns (RedLine, Raccoon, Vidar, etc.)
//!
//! Features:
//! - Browser data file monitoring (Login Data, cookies, history)
//! - Non-browser process access detection
//! - Known stealer pattern matching
//! - Browser extension monitoring
//! - Session/cookie theft detection
//!
//! MITRE ATT&CK:
//! - T1555.003 (Credentials from Password Stores: Web Browsers)
//! - T1539 (Steal Web Session Cookie)
//! - T1176 (Browser Extensions)

// Browser credential protection. Scaffolded macOS/Safari paths retained.
#![allow(dead_code, unused_variables)]

use super::{
    BrowserCredentialEvent, Detection, DetectionType, EventPayload, EventType, Severity,
    TelemetryEvent,
};
use crate::config::AgentConfig;
use anyhow::Result;
use notify::{Event as NotifyEvent, EventKind, RecursiveMode, Watcher};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Browser types supported
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BrowserType {
    Chrome,
    Firefox,
    Edge,
    Safari,
    Brave,
    Vivaldi,
    Opera,
    Chromium,
}

impl BrowserType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Chrome => "Chrome",
            Self::Firefox => "Firefox",
            Self::Edge => "Edge",
            Self::Safari => "Safari",
            Self::Brave => "Brave",
            Self::Vivaldi => "Vivaldi",
            Self::Opera => "Opera",
            Self::Chromium => "Chromium",
        }
    }

    /// Get the executable names associated with this browser
    pub fn executable_names(&self) -> Vec<&'static str> {
        match self {
            Self::Chrome => vec![
                "chrome",
                "chrome.exe",
                "google-chrome",
                "google-chrome-stable",
            ],
            Self::Firefox => vec!["firefox", "firefox.exe", "firefox-esr"],
            Self::Edge => vec!["msedge", "msedge.exe", "microsoft-edge"],
            Self::Safari => vec!["Safari", "safari"],
            Self::Brave => vec!["brave", "brave.exe", "brave-browser"],
            Self::Vivaldi => vec!["vivaldi", "vivaldi.exe", "vivaldi-stable"],
            Self::Opera => vec!["opera", "opera.exe"],
            Self::Chromium => vec!["chromium", "chromium.exe", "chromium-browser"],
        }
    }

    /// Check if a process name belongs to this browser
    pub fn matches_process(&self, process_name: &str) -> bool {
        let name_lower = process_name.to_lowercase();
        self.executable_names()
            .iter()
            .any(|exec| name_lower == exec.to_lowercase())
    }
}

/// Data file types in browsers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserDataType {
    Credentials,
    Cookies,
    History,
    WebData,
    LocalStorage,
    SessionStorage,
    Extensions,
    Keychain,
    KeyDatabase,
}

impl BrowserDataType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Credentials => "credentials",
            Self::Cookies => "cookies",
            Self::History => "history",
            Self::WebData => "webdata",
            Self::LocalStorage => "local_storage",
            Self::SessionStorage => "session_storage",
            Self::Extensions => "extensions",
            Self::Keychain => "keychain",
            Self::KeyDatabase => "key_database",
        }
    }
}

/// Known stealer malware families
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StealerFamily {
    RedLine,
    Raccoon,
    Vidar,
    AZORult,
    Lumma,
    StealC,
    MetaStealer,
    Arkei,
    Generic,
}

impl StealerFamily {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RedLine => "RedLine",
            Self::Raccoon => "Raccoon",
            Self::Vidar => "Vidar",
            Self::AZORult => "AZORult",
            Self::Lumma => "Lumma",
            Self::StealC => "StealC",
            Self::MetaStealer => "MetaStealer",
            Self::Arkei => "Arkei",
            Self::Generic => "Generic",
        }
    }
}

/// Browser data file configuration
#[derive(Debug, Clone)]
pub struct BrowserDataFile {
    pub browser: BrowserType,
    pub data_type: BrowserDataType,
    pub filename: String,
    pub relative_path: String,
}

/// Browser profile paths
#[derive(Debug, Clone)]
pub struct BrowserProfile {
    pub browser: BrowserType,
    pub profile_path: PathBuf,
    pub data_files: Vec<BrowserDataFile>,
}

/// Known stealer patterns
#[derive(Debug, Clone)]
pub struct StealerPattern {
    pub family: StealerFamily,
    pub path_patterns: Vec<String>,
    pub cmdline_patterns: Vec<String>,
    pub file_patterns: Vec<String>,
}

/// Browser Protection Collector
pub struct BrowserProtectionCollector {
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    browser_profiles: Vec<BrowserProfile>,
    whitelisted_processes: HashSet<String>,
}

impl BrowserProtectionCollector {
    /// Create a new browser protection collector
    pub fn new(config: &AgentConfig) -> Result<Self> {
        let (tx, rx) = mpsc::channel(500);

        info!("Initializing Browser Protection Collector");

        // Discover browser profiles
        let browser_profiles = Self::discover_browser_profiles();
        info!(
            profiles = browser_profiles.len(),
            "Discovered browser profiles"
        );

        for profile in &browser_profiles {
            debug!(
                browser = profile.browser.as_str(),
                path = %profile.profile_path.display(),
                files = profile.data_files.len(),
                "Found browser profile"
            );
        }

        // Initialize whitelisted processes
        let whitelisted_processes = Self::build_whitelist();

        // Start monitoring
        let config_clone = config.clone();
        let profiles_clone = browser_profiles.clone();
        let whitelist_clone = whitelisted_processes.clone();

        let monitor_tx = tx.clone();
        std::thread::spawn(move || {
            if let Err(e) =
                Self::monitor_loop(monitor_tx, config_clone, profiles_clone, whitelist_clone)
            {
                error!(error = %e, "Browser protection monitor error");
            }
        });

        #[cfg(target_os = "windows")]
        {
            let tx_clone = tx.clone();
            std::thread::spawn(move || {
                Self::monitor_remote_debugging_abuse(tx_clone);
            });

            let tx_clone = tx.clone();
            let profiles_clone = browser_profiles.clone();
            let whitelist_clone = whitelisted_processes.clone();
            std::thread::spawn(move || {
                Self::monitor_browser_targeting_processes(
                    tx_clone,
                    profiles_clone,
                    whitelist_clone,
                );
            });

            let tx_clone = tx.clone();
            std::thread::spawn(move || {
                Self::monitor_chrome_abe_event_log(tx_clone);
            });
        }

        Ok(Self {
            config: config.clone(),
            event_rx: rx,
            browser_profiles,
            whitelisted_processes,
        })
    }

    /// Build whitelist of legitimate processes that may access browser data
    fn build_whitelist() -> HashSet<String> {
        let mut whitelist = HashSet::new();

        // Browser executables
        for browser in [
            BrowserType::Chrome,
            BrowserType::Firefox,
            BrowserType::Edge,
            BrowserType::Safari,
            BrowserType::Brave,
            BrowserType::Vivaldi,
            BrowserType::Opera,
            BrowserType::Chromium,
        ] {
            for exec in browser.executable_names() {
                whitelist.insert(exec.to_lowercase());
            }
        }

        // Browser updaters
        whitelist.insert("googleupdate.exe".to_string());
        whitelist.insert("google_update.exe".to_string());
        whitelist.insert("microsoftedgeupdate.exe".to_string());
        whitelist.insert("software_reporter_tool.exe".to_string());
        whitelist.insert("crashhandler.exe".to_string());
        whitelist.insert("crashpad_handler".to_string());

        // System processes
        whitelist.insert("system".to_string());
        whitelist.insert("svchost.exe".to_string());
        whitelist.insert("searchindexer.exe".to_string());
        whitelist.insert("searchprotocolhost.exe".to_string());
        whitelist.insert("tiworker.exe".to_string());
        whitelist.insert("trustedinstaller.exe".to_string());

        // Security software
        whitelist.insert("msmpeng.exe".to_string());
        whitelist.insert("mssense.exe".to_string());
        whitelist.insert("sensenir.exe".to_string());
        whitelist.insert("securityhealthservice.exe".to_string());
        whitelist.insert("mbamservice.exe".to_string());
        whitelist.insert("mbamtray.exe".to_string());

        // Backup software
        whitelist.insert("backupexec.exe".to_string());
        whitelist.insert("veeam.backup.service.exe".to_string());

        // Our own agent
        whitelist.insert("tamandua-agent".to_string());
        whitelist.insert("tamandua-agent.exe".to_string());

        whitelist
    }

    /// Discover all browser profiles on the system
    fn discover_browser_profiles() -> Vec<BrowserProfile> {
        let mut profiles = Vec::new();

        #[cfg(target_os = "windows")]
        {
            profiles.extend(Self::discover_windows_profiles());
        }

        #[cfg(target_os = "linux")]
        {
            profiles.extend(Self::discover_linux_profiles());
        }

        #[cfg(target_os = "macos")]
        {
            profiles.extend(Self::discover_macos_profiles());
        }

        profiles
    }

    /// Discover browser profiles on Windows
    #[cfg(target_os = "windows")]
    fn discover_windows_profiles() -> Vec<BrowserProfile> {
        let mut profiles = Vec::new();

        // Get user profile directories
        let local_appdata = std::env::var("LOCALAPPDATA").unwrap_or_default();
        let appdata = std::env::var("APPDATA").unwrap_or_default();

        if local_appdata.is_empty() {
            return profiles;
        }

        // Chromium-based browsers (Chrome, Edge, Brave, Vivaldi, Opera)
        let chromium_browsers = [
            (
                BrowserType::Chrome,
                format!("{}\\Google\\Chrome\\User Data", local_appdata),
            ),
            (
                BrowserType::Edge,
                format!("{}\\Microsoft\\Edge\\User Data", local_appdata),
            ),
            (
                BrowserType::Brave,
                format!("{}\\BraveSoftware\\Brave-Browser\\User Data", local_appdata),
            ),
            (
                BrowserType::Vivaldi,
                format!("{}\\Vivaldi\\User Data", local_appdata),
            ),
            (
                BrowserType::Opera,
                format!("{}\\Opera Software\\Opera Stable", appdata),
            ),
            (
                BrowserType::Chromium,
                format!("{}\\Chromium\\User Data", local_appdata),
            ),
        ];

        for (browser, base_path) in chromium_browsers {
            let base = PathBuf::from(&base_path);
            if base.exists() {
                // Check Default profile
                let default_profile = base.join("Default");
                if default_profile.exists() {
                    profiles.push(Self::create_chromium_profile(browser, default_profile));
                }

                // Check numbered profiles (Profile 1, Profile 2, etc.)
                if let Ok(entries) = std::fs::read_dir(&base) {
                    for entry in entries.filter_map(|e| e.ok()) {
                        let name = entry.file_name().to_string_lossy().to_string();
                        if name.starts_with("Profile ") {
                            profiles.push(Self::create_chromium_profile(browser, entry.path()));
                        }
                    }
                }
            }
        }

        // Firefox
        let firefox_path = format!("{}\\Mozilla\\Firefox\\Profiles", appdata);
        let firefox_base = PathBuf::from(&firefox_path);
        if firefox_base.exists() {
            if let Ok(entries) = std::fs::read_dir(&firefox_base) {
                for entry in entries.filter_map(|e| e.ok()) {
                    if entry.path().is_dir() {
                        profiles.push(Self::create_firefox_profile(entry.path()));
                    }
                }
            }
        }

        profiles
    }

    /// Discover browser profiles on Linux
    #[cfg(target_os = "linux")]
    fn discover_linux_profiles() -> Vec<BrowserProfile> {
        let mut profiles = Vec::new();

        let home = std::env::var("HOME").unwrap_or_else(|_| "/home".to_string());

        // Chromium-based browsers
        let chromium_browsers = [
            (
                BrowserType::Chrome,
                format!("{}/.config/google-chrome", home),
            ),
            (BrowserType::Chromium, format!("{}/.config/chromium", home)),
            (
                BrowserType::Brave,
                format!("{}/.config/BraveSoftware/Brave-Browser", home),
            ),
            (BrowserType::Vivaldi, format!("{}/.config/vivaldi", home)),
            (BrowserType::Opera, format!("{}/.config/opera", home)),
        ];

        for (browser, base_path) in chromium_browsers {
            let base = PathBuf::from(&base_path);
            if base.exists() {
                let default_profile = base.join("Default");
                if default_profile.exists() {
                    profiles.push(Self::create_chromium_profile(browser, default_profile));
                }

                if let Ok(entries) = std::fs::read_dir(&base) {
                    for entry in entries.filter_map(|e| e.ok()) {
                        let name = entry.file_name().to_string_lossy().to_string();
                        if name.starts_with("Profile ") {
                            profiles.push(Self::create_chromium_profile(browser, entry.path()));
                        }
                    }
                }
            }
        }

        // Firefox
        let firefox_path = format!("{}/.mozilla/firefox", home);
        let firefox_base = PathBuf::from(&firefox_path);
        if firefox_base.exists() {
            if let Ok(entries) = std::fs::read_dir(&firefox_base) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if entry.path().is_dir()
                        && (name.ends_with(".default") || name.ends_with(".default-release"))
                    {
                        profiles.push(Self::create_firefox_profile(entry.path()));
                    }
                }
            }
        }

        profiles
    }

    /// Discover browser profiles on macOS
    #[cfg(target_os = "macos")]
    fn discover_linux_profiles() -> Vec<BrowserProfile> {
        // Stub for non-macOS builds
        Vec::new()
    }

    #[cfg(target_os = "macos")]
    fn discover_macos_profiles() -> Vec<BrowserProfile> {
        let mut profiles = Vec::new();

        let home = std::env::var("HOME").unwrap_or_else(|_| "/Users".to_string());

        // Chromium-based browsers
        let chromium_browsers = [
            (
                BrowserType::Chrome,
                format!("{}/Library/Application Support/Google/Chrome", home),
            ),
            (
                BrowserType::Edge,
                format!("{}/Library/Application Support/Microsoft Edge", home),
            ),
            (
                BrowserType::Brave,
                format!(
                    "{}/Library/Application Support/BraveSoftware/Brave-Browser",
                    home
                ),
            ),
            (
                BrowserType::Vivaldi,
                format!("{}/Library/Application Support/Vivaldi", home),
            ),
            (
                BrowserType::Opera,
                format!(
                    "{}/Library/Application Support/com.operasoftware.Opera",
                    home
                ),
            ),
        ];

        for (browser, base_path) in chromium_browsers {
            let base = PathBuf::from(&base_path);
            if base.exists() {
                let default_profile = base.join("Default");
                if default_profile.exists() {
                    profiles.push(Self::create_chromium_profile(browser, default_profile));
                }
            }
        }

        // Firefox
        let firefox_path = format!("{}/Library/Application Support/Firefox/Profiles", home);
        let firefox_base = PathBuf::from(&firefox_path);
        if firefox_base.exists() {
            if let Ok(entries) = std::fs::read_dir(&firefox_base) {
                for entry in entries.filter_map(|e| e.ok()) {
                    if entry.path().is_dir() {
                        profiles.push(Self::create_firefox_profile(entry.path()));
                    }
                }
            }
        }

        // Safari
        let safari_path = format!("{}/Library/Safari", home);
        let safari_base = PathBuf::from(&safari_path);
        if safari_base.exists() {
            profiles.push(Self::create_safari_profile(safari_base));
        }

        profiles
    }

    #[cfg(not(target_os = "macos"))]
    fn discover_macos_profiles() -> Vec<BrowserProfile> {
        Vec::new()
    }

    /// Create a Chromium-based browser profile
    fn create_chromium_profile(browser: BrowserType, profile_path: PathBuf) -> BrowserProfile {
        let data_files = vec![
            BrowserDataFile {
                browser,
                data_type: BrowserDataType::Credentials,
                filename: "Login Data".to_string(),
                relative_path: "Login Data".to_string(),
            },
            BrowserDataFile {
                browser,
                data_type: BrowserDataType::Credentials,
                filename: "Login Data-journal".to_string(),
                relative_path: "Login Data-journal".to_string(),
            },
            BrowserDataFile {
                browser,
                data_type: BrowserDataType::Cookies,
                filename: "Cookies".to_string(),
                relative_path: "Cookies".to_string(),
            },
            BrowserDataFile {
                browser,
                data_type: BrowserDataType::Cookies,
                filename: "Network\\Cookies".to_string(),
                relative_path: "Network/Cookies".to_string(),
            },
            BrowserDataFile {
                browser,
                data_type: BrowserDataType::History,
                filename: "History".to_string(),
                relative_path: "History".to_string(),
            },
            BrowserDataFile {
                browser,
                data_type: BrowserDataType::WebData,
                filename: "Web Data".to_string(),
                relative_path: "Web Data".to_string(),
            },
            BrowserDataFile {
                browser,
                data_type: BrowserDataType::LocalStorage,
                filename: "Local Storage".to_string(),
                relative_path: "Local Storage".to_string(),
            },
            BrowserDataFile {
                browser,
                data_type: BrowserDataType::Extensions,
                filename: "Extensions".to_string(),
                relative_path: "Extensions".to_string(),
            },
        ];

        BrowserProfile {
            browser,
            profile_path,
            data_files,
        }
    }

    /// Create a Firefox browser profile
    fn create_firefox_profile(profile_path: PathBuf) -> BrowserProfile {
        let data_files = vec![
            BrowserDataFile {
                browser: BrowserType::Firefox,
                data_type: BrowserDataType::Credentials,
                filename: "logins.json".to_string(),
                relative_path: "logins.json".to_string(),
            },
            BrowserDataFile {
                browser: BrowserType::Firefox,
                data_type: BrowserDataType::KeyDatabase,
                filename: "key4.db".to_string(),
                relative_path: "key4.db".to_string(),
            },
            BrowserDataFile {
                browser: BrowserType::Firefox,
                data_type: BrowserDataType::KeyDatabase,
                filename: "key3.db".to_string(),
                relative_path: "key3.db".to_string(),
            },
            BrowserDataFile {
                browser: BrowserType::Firefox,
                data_type: BrowserDataType::Cookies,
                filename: "cookies.sqlite".to_string(),
                relative_path: "cookies.sqlite".to_string(),
            },
            BrowserDataFile {
                browser: BrowserType::Firefox,
                data_type: BrowserDataType::History,
                filename: "places.sqlite".to_string(),
                relative_path: "places.sqlite".to_string(),
            },
            BrowserDataFile {
                browser: BrowserType::Firefox,
                data_type: BrowserDataType::WebData,
                filename: "formhistory.sqlite".to_string(),
                relative_path: "formhistory.sqlite".to_string(),
            },
            BrowserDataFile {
                browser: BrowserType::Firefox,
                data_type: BrowserDataType::Credentials,
                filename: "signons.sqlite".to_string(),
                relative_path: "signons.sqlite".to_string(),
            },
        ];

        BrowserProfile {
            browser: BrowserType::Firefox,
            profile_path,
            data_files,
        }
    }

    /// Create a Safari browser profile (macOS)
    #[cfg(target_os = "macos")]
    fn create_safari_profile(profile_path: PathBuf) -> BrowserProfile {
        let data_files = vec![
            BrowserDataFile {
                browser: BrowserType::Safari,
                data_type: BrowserDataType::Cookies,
                filename: "Cookies.binarycookies".to_string(),
                relative_path: "Cookies.binarycookies".to_string(),
            },
            BrowserDataFile {
                browser: BrowserType::Safari,
                data_type: BrowserDataType::History,
                filename: "History.db".to_string(),
                relative_path: "History.db".to_string(),
            },
            BrowserDataFile {
                browser: BrowserType::Safari,
                data_type: BrowserDataType::LocalStorage,
                filename: "LocalStorage".to_string(),
                relative_path: "LocalStorage".to_string(),
            },
        ];

        BrowserProfile {
            browser: BrowserType::Safari,
            profile_path,
            data_files,
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn create_safari_profile(_profile_path: PathBuf) -> BrowserProfile {
        BrowserProfile {
            browser: BrowserType::Safari,
            profile_path: PathBuf::new(),
            data_files: Vec::new(),
        }
    }

    /// Get known stealer patterns
    fn get_stealer_patterns() -> Vec<StealerPattern> {
        vec![
            // RedLine Stealer
            StealerPattern {
                family: StealerFamily::RedLine,
                path_patterns: vec![
                    "\\appdata\\local\\temp\\".to_string(),
                    "\\programdata\\".to_string(),
                ],
                cmdline_patterns: vec![
                    "login data".to_string(),
                    "cookies".to_string(),
                    "web data".to_string(),
                    "logins.json".to_string(),
                    "\\google\\chrome\\".to_string(),
                    "\\mozilla\\firefox\\".to_string(),
                ],
                file_patterns: vec![
                    "autofill".to_string(),
                    "credit".to_string(),
                    "password".to_string(),
                ],
            },
            // Raccoon Stealer
            StealerPattern {
                family: StealerFamily::Raccoon,
                path_patterns: vec![
                    "\\appdata\\local\\temp\\".to_string(),
                    "\\user\\public\\".to_string(),
                ],
                cmdline_patterns: vec![
                    "machinegun".to_string(),
                    "stealer".to_string(),
                    "grabber".to_string(),
                ],
                file_patterns: vec!["wallet".to_string(), "browser".to_string()],
            },
            // Vidar Stealer
            StealerPattern {
                family: StealerFamily::Vidar,
                path_patterns: vec![
                    "\\appdata\\local\\temp\\".to_string(),
                    "\\programdata\\".to_string(),
                ],
                cmdline_patterns: vec![
                    "telegram".to_string(),
                    "discord".to_string(),
                    "steam".to_string(),
                ],
                file_patterns: vec!["history".to_string(), "cookies".to_string()],
            },
            // AZORult
            StealerPattern {
                family: StealerFamily::AZORult,
                path_patterns: vec!["\\appdata\\local\\temp\\".to_string()],
                cmdline_patterns: vec!["passwords".to_string(), "autofill".to_string()],
                file_patterns: vec!["key4.db".to_string(), "logins.json".to_string()],
            },
            // Lumma Stealer
            StealerPattern {
                family: StealerFamily::Lumma,
                path_patterns: vec!["\\temp\\".to_string(), "\\downloads\\".to_string()],
                cmdline_patterns: vec!["sqlite".to_string(), "chromium".to_string()],
                file_patterns: vec![],
            },
            // StealC
            StealerPattern {
                family: StealerFamily::StealC,
                path_patterns: vec![
                    "\\appdata\\local\\".to_string(),
                    "\\appdata\\roaming\\".to_string(),
                ],
                cmdline_patterns: vec!["browser".to_string(), "credentials".to_string()],
                file_patterns: vec![],
            },
        ]
    }

    #[cfg(target_os = "windows")]
    fn monitor_remote_debugging_abuse(tx: mpsc::Sender<TelemetryEvent>) {
        use sysinfo::{ProcessRefreshKind, RefreshKind, System};

        let mut system = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
        );
        let mut reported: HashSet<(u32, String)> = HashSet::new();

        loop {
            std::thread::sleep(Duration::from_secs(10));
            system.refresh_processes();
            reported.retain(|(pid, _)| system.process(sysinfo::Pid::from_u32(*pid)).is_some());

            for (pid, process) in system.processes() {
                let pid = pid.as_u32();
                let process_name = process.name().to_string();
                let cmdline = process.cmd().join(" ");
                let cmdline_lower = cmdline.to_lowercase();
                let exe_path = process
                    .exe()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();

                let browser = [
                    BrowserType::Chrome,
                    BrowserType::Edge,
                    BrowserType::Brave,
                    BrowserType::Chromium,
                ]
                .into_iter()
                .find(|browser| browser.matches_process(&process_name));

                let Some(browser) = browser else {
                    continue;
                };

                let has_remote_debugging = cmdline_lower.contains("--remote-debugging-port")
                    || cmdline_lower.contains("--remote-debugging-pipe");
                if !has_remote_debugging {
                    continue;
                }

                let mut evidence = vec!["remote debugging enabled on browser process".to_string()];
                if cmdline_lower.contains("--user-data-dir") {
                    evidence.push("custom user-data-dir present".to_string());
                }
                if cmdline_lower.contains("--headless") {
                    evidence.push("headless browser execution".to_string());
                }
                if cmdline_lower.contains("--restore-last-session") {
                    evidence.push("restore-last-session flag present".to_string());
                }

                let signature = if cmdline_lower.contains("--remote-debugging-pipe") {
                    "remote_debugging_pipe".to_string()
                } else {
                    "remote_debugging_port".to_string()
                };

                if !reported.insert((pid, signature.clone())) {
                    continue;
                }

                let event = Self::create_browser_credential_event(
                    browser,
                    BrowserDataType::Cookies,
                    "Browser Session".to_string(),
                    "remote_debugging".to_string(),
                    pid,
                    process_name,
                    exe_path,
                    cmdline.clone(),
                    true,
                    None,
                    Severity::High,
                    DetectionType::BrowserStealer,
                    format!("Chrome/Chromium remote debugging abuse detected ({signature})"),
                    0.88,
                    format!(
                        "{} started with remote debugging enabled. This is commonly abused to extract cookies and session data without decrypting stores directly. Evidence: {}",
                        browser.as_str(),
                        evidence.join(", ")
                    ),
                    vec!["Credential Access".to_string(), "Collection".to_string()],
                    vec!["T1539".to_string(), "T1555.003".to_string()],
                );

                if tx.blocking_send(event).is_err() {
                    warn!("Event channel closed");
                    return;
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn monitor_browser_targeting_processes(
        tx: mpsc::Sender<TelemetryEvent>,
        profiles: Vec<BrowserProfile>,
        whitelist: HashSet<String>,
    ) {
        use sysinfo::{ProcessRefreshKind, RefreshKind, System};

        let mut sensitive_markers: HashSet<String> = HashSet::new();
        for profile in &profiles {
            sensitive_markers.insert(profile.profile_path.to_string_lossy().to_lowercase());
            for data_file in &profile.data_files {
                sensitive_markers.insert(data_file.filename.to_lowercase());
                sensitive_markers.insert(data_file.relative_path.replace('/', "\\").to_lowercase());
            }
        }

        for marker in [
            "login data",
            "network\\cookies",
            "cookies",
            "web data",
            "local state",
            "logins.json",
            "key4.db",
            "cookies.sqlite",
            "devtoolsactiveport",
            "chrome\\user data",
            "edge\\user data",
            "brave-browser\\user data",
            "chromium\\user data",
            "mozilla\\firefox\\profiles",
            "cookiemonster",
            "cookie_monster",
            "app-bound",
            "appbound",
            "abe",
            "elevation_service",
            "chromelevationservice",
        ] {
            sensitive_markers.insert(marker.to_string());
        }

        let suspicious_terms = [
            "login data",
            "cookies",
            "local state",
            "web data",
            "logins.json",
            "key4.db",
            "cookie",
            "password",
            "sqlite",
            "dpapi",
            "decrypt",
            "browser",
            "chromium",
            "chrome",
            "msedge",
            "firefox",
            "cookiemonster",
            "cookie_monster",
            "readprocessmemory",
            "ntreadvirtualmemory",
            "remote-debugging-port",
            "remote-debugging-pipe",
            "remote-debugging-port=9222",
            "devtoolsactiveport",
            "devtools",
            "headless=new",
            "headless",
            "appbound",
            "app-bound",
            "elevation_service",
            "chromelevationservice",
            "cryptunprotectdata",
        ];

        let mut system = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
        );
        let mut reported: HashSet<(u32, String)> = HashSet::new();

        loop {
            std::thread::sleep(Duration::from_secs(10));
            system.refresh_processes();
            reported.retain(|(pid, _)| system.process(sysinfo::Pid::from_u32(*pid)).is_some());

            for (pid, process) in system.processes() {
                let pid = pid.as_u32();
                if pid <= 4 {
                    continue;
                }

                let process_name = process.name().to_string();
                let process_name_lower = process_name.to_lowercase();
                if whitelist.contains(&process_name_lower) {
                    continue;
                }

                if [
                    BrowserType::Chrome,
                    BrowserType::Edge,
                    BrowserType::Firefox,
                    BrowserType::Brave,
                    BrowserType::Chromium,
                ]
                .iter()
                .any(|browser| browser.matches_process(&process_name))
                {
                    continue;
                }

                let exe_path = process
                    .exe()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();
                let cmdline = process.cmd().join(" ");
                let combined_lower = format!(
                    "{} {} {}",
                    exe_path.to_lowercase(),
                    process_name_lower,
                    cmdline.to_lowercase()
                );

                let marker_hits: Vec<String> = sensitive_markers
                    .iter()
                    .filter(|marker| combined_lower.contains(marker.as_str()))
                    .take(8)
                    .cloned()
                    .collect();

                let term_hits: Vec<&str> = suspicious_terms
                    .iter()
                    .copied()
                    .filter(|term| combined_lower.contains(term))
                    .collect();

                let score = marker_hits.len() * 2 + term_hits.len();
                if score < 4 {
                    continue;
                }

                let family = Self::detect_stealer(
                    &process_name,
                    &exe_path,
                    &cmdline,
                    &marker_hits.join(" "),
                );
                let data_type = if combined_lower.contains("cookie")
                    || combined_lower.contains("local state")
                {
                    BrowserDataType::Cookies
                } else {
                    BrowserDataType::Credentials
                };

                let signature = format!(
                    "browser_targeting:{}:{}",
                    marker_hits.join("|"),
                    term_hits.join("|")
                );
                if !reported.insert((pid, signature.clone())) {
                    continue;
                }

                let severity = if family.is_some()
                    || combined_lower.contains("readprocessmemory")
                    || combined_lower.contains("ntreadvirtualmemory")
                {
                    Severity::Critical
                } else {
                    Severity::High
                };

                let mut event = Self::create_browser_credential_event(
                    BrowserType::Chrome,
                    data_type,
                    marker_hits
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "Browser Data".to_string()),
                    "process_scan".to_string(),
                    pid,
                    process_name,
                    exe_path,
                    cmdline.clone(),
                    false,
                    family.map(|f| f.as_str().to_string()),
                    severity,
                    if family.is_some() {
                        DetectionType::BrowserStealer
                    } else {
                        DetectionType::CredentialTheft
                    },
                    "Browser credential/session theft process pattern".to_string(),
                    if family.is_some() { 0.95 } else { 0.84 },
                    format!(
                        "Non-browser process matched browser-targeting heuristics. markers=[{}] terms=[{}]",
                        marker_hits.join(", "),
                        term_hits.join(", ")
                    ),
                    vec!["Credential Access".to_string(), "Collection".to_string()],
                    vec!["T1539".to_string(), "T1555.003".to_string()],
                );

                if family.is_none()
                    && (combined_lower.contains("appbound")
                        || combined_lower.contains("app-bound")
                        || combined_lower.contains("elevation_service")
                        || combined_lower.contains("chromelevationservice"))
                {
                    event
                        .metadata
                        .insert("abe_bypass_signal".to_string(), "true".to_string());
                }

                if tx.blocking_send(event).is_err() {
                    warn!("Event channel closed");
                    return;
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn monitor_chrome_abe_event_log(tx: mpsc::Sender<TelemetryEvent>) {
        use std::process::Command;

        let mut seen_entries: HashSet<String> = HashSet::new();

        loop {
            std::thread::sleep(Duration::from_secs(20));

            let output = Command::new("wevtutil")
                .args([
                    "qe",
                    "Application",
                    "/q:*[System[Provider[@Name='Chrome'] and (EventID=257)]]",
                    "/rd:true",
                    "/c:10",
                    "/f:text",
                ])
                .output();

            let Ok(out) = output else {
                continue;
            };
            if !out.status.success() {
                continue;
            }

            let stdout = String::from_utf8_lossy(&out.stdout);
            for raw_entry in stdout
                .split("\r\n\r\n")
                .filter(|chunk| !chunk.trim().is_empty())
            {
                let entry = raw_entry.trim().to_string();
                if !entry.contains("Event ID: 257") {
                    continue;
                }
                if !seen_entries.insert(entry.clone()) {
                    continue;
                }

                let event = Self::create_browser_credential_event(
                    BrowserType::Chrome,
                    BrowserDataType::Cookies,
                    "Application-Bound Encryption".to_string(),
                    "abe_verification_failed".to_string(),
                    0,
                    "Chrome".to_string(),
                    String::new(),
                    String::new(),
                    true,
                    None,
                    Severity::High,
                    DetectionType::BrowserStealer,
                    "Chrome ABE verification failure".to_string(),
                    0.91,
                    format!(
                        "Chrome emitted Application log Event ID 257, which indicates an App-Bound Encryption verification failure. This is a strong signal of attempted cookie/data access from outside the legitimate browser context. Raw event: {}",
                        entry.replace('\n', " ")
                    ),
                    vec!["Credential Access".to_string(), "Defense Evasion".to_string()],
                    vec!["T1539".to_string(), "T1555.003".to_string()],
                );

                if tx.blocking_send(event).is_err() {
                    warn!("Event channel closed");
                    return;
                }
            }
        }
    }

    fn create_browser_credential_event(
        browser: BrowserType,
        data_type: BrowserDataType,
        data_file: String,
        operation: String,
        pid: u32,
        process_name: String,
        process_path: String,
        process_cmdline: String,
        is_browser_process: bool,
        stealer_family: Option<String>,
        severity: Severity,
        detection_type: DetectionType,
        rule_name: String,
        confidence: f32,
        description: String,
        mitre_tactics: Vec<String>,
        mitre_techniques: Vec<String>,
    ) -> TelemetryEvent {
        let mut event = TelemetryEvent::new(
            EventType::CredentialAccess,
            severity,
            EventPayload::BrowserCredential(BrowserCredentialEvent {
                browser: browser.as_str().to_string(),
                profile_path: String::new(),
                data_file,
                data_type: data_type.as_str().to_string(),
                operation,
                pid,
                process_name: process_name.clone(),
                process_path: process_path.clone(),
                process_cmdline: process_cmdline.clone(),
                is_browser_process,
                stealer_family: stealer_family.clone(),
                process_sha256: Vec::new(),
            }),
        );

        event.add_detection(Detection {
            detection_type,
            rule_name,
            confidence,
            description,
            mitre_tactics,
            mitre_techniques,
        });

        event
            .metadata
            .insert("browser".to_string(), browser.as_str().to_string());
        event
            .metadata
            .insert("process_name".to_string(), process_name);
        event
            .metadata
            .insert("process_path".to_string(), process_path);
        event
            .metadata
            .insert("process_cmdline".to_string(), process_cmdline);
        if let Some(stealer_family) = stealer_family {
            event
                .metadata
                .insert("stealer_family".to_string(), stealer_family);
        }

        event
    }

    /// Detect if a process matches known stealer patterns
    fn detect_stealer(
        process_name: &str,
        process_path: &str,
        process_cmdline: &str,
        accessed_file: &str,
    ) -> Option<StealerFamily> {
        let patterns = Self::get_stealer_patterns();
        let path_lower = process_path.to_lowercase();
        let cmdline_lower = process_cmdline.to_lowercase();
        let file_lower = accessed_file.to_lowercase();

        for pattern in patterns {
            let mut score = 0;

            // Check path patterns
            for p in &pattern.path_patterns {
                if path_lower.contains(p) {
                    score += 2;
                }
            }

            // Check command line patterns
            for c in &pattern.cmdline_patterns {
                if cmdline_lower.contains(c) {
                    score += 3;
                }
            }

            // Check file patterns
            for f in &pattern.file_patterns {
                if file_lower.contains(f) {
                    score += 2;
                }
            }

            // High confidence match
            if score >= 4 {
                return Some(pattern.family);
            }
        }

        // Generic stealer detection heuristics
        let suspicious_indicators = [
            // Running from temp or suspicious locations
            path_lower.contains("\\temp\\"),
            path_lower.contains("\\downloads\\"),
            path_lower.contains("\\public\\"),
            // Suspicious file access patterns
            cmdline_lower.contains("login data"),
            cmdline_lower.contains("cookies"),
            cmdline_lower.contains("logins.json"),
            // PowerShell/script access to browser files
            process_name.to_lowercase().contains("powershell"),
            process_name.to_lowercase().contains("python"),
            process_name.to_lowercase().contains("wscript"),
            process_name.to_lowercase().contains("cscript"),
        ];

        let suspicious_count = suspicious_indicators.iter().filter(|&&x| x).count();
        if suspicious_count >= 2 {
            return Some(StealerFamily::Generic);
        }

        None
    }

    /// Main monitoring loop
    fn monitor_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        _config: AgentConfig,
        profiles: Vec<BrowserProfile>,
        whitelist: HashSet<String>,
    ) -> Result<()> {
        let (notify_tx, notify_rx) = std::sync::mpsc::channel();

        let mut watcher = notify::recommended_watcher(move |res: notify::Result<NotifyEvent>| {
            if let Ok(event) = res {
                let _ = notify_tx.send(event);
            }
        })?;

        // Build a map from file paths to browser data info
        let mut watched_files: HashMap<PathBuf, (BrowserType, BrowserDataType, String)> =
            HashMap::new();

        // Watch all browser profile directories
        for profile in &profiles {
            if profile.profile_path.exists() {
                if let Err(e) = watcher.watch(&profile.profile_path, RecursiveMode::Recursive) {
                    warn!(
                        path = %profile.profile_path.display(),
                        error = %e,
                        "Failed to watch browser profile"
                    );
                } else {
                    debug!(
                        browser = profile.browser.as_str(),
                        path = %profile.profile_path.display(),
                        "Watching browser profile"
                    );
                }

                // Map data files
                for data_file in &profile.data_files {
                    let full_path = profile.profile_path.join(&data_file.relative_path);
                    watched_files.insert(
                        full_path,
                        (
                            data_file.browser,
                            data_file.data_type,
                            data_file.filename.clone(),
                        ),
                    );
                }
            }
        }

        info!(
            watched_files = watched_files.len(),
            "Browser protection monitoring started"
        );

        // Create runtime for async operations
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        // Track recent events to avoid duplicates
        let mut recent_events: HashMap<(u32, String), u64> = HashMap::new();
        let dedup_window_ms = 5000u64;

        for event in notify_rx {
            for path in &event.paths {
                // Check if this is a browser data file
                let (browser, data_type, filename) = if let Some(info) = watched_files.get(path) {
                    info.clone()
                } else {
                    // Check if it's under a watched profile directory
                    let mut found = None;
                    for (watched_path, info) in &watched_files {
                        if path.starts_with(watched_path.parent().unwrap_or(watched_path)) {
                            // Check if filename matches any sensitive file
                            if let Some(fname) = path.file_name() {
                                let fname_str = fname.to_string_lossy().to_lowercase();
                                if Self::is_sensitive_browser_file(&fname_str) {
                                    found = Some((
                                        info.0,
                                        Self::classify_file(&fname_str),
                                        fname.to_string_lossy().to_string(),
                                    ));
                                    break;
                                }
                            }
                        }
                    }
                    match found {
                        Some(f) => f,
                        None => continue,
                    }
                };

                // Determine event type
                let operation = match &event.kind {
                    EventKind::Access(_) => "read",
                    EventKind::Modify(_) => "modify",
                    EventKind::Create(_) => "create",
                    EventKind::Remove(_) => "delete",
                    _ => continue,
                };

                // Try to find the accessing process
                let (pid, process_name, process_path, cmdline) = Self::find_accessing_process(path);

                // Skip if process is whitelisted
                let process_name_lower = process_name.to_lowercase();
                if whitelist.contains(&process_name_lower) {
                    continue;
                }

                // Check if it's the browser itself
                let is_browser_process = browser.matches_process(&process_name);
                if is_browser_process {
                    // Only alert on browser access if it's an unusual operation
                    // (browsers normally access their own files)
                    continue;
                }

                // Deduplication check
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;

                let event_key = (pid, path.to_string_lossy().to_string());
                if let Some(&last_time) = recent_events.get(&event_key) {
                    if now - last_time < dedup_window_ms {
                        continue;
                    }
                }
                recent_events.insert(event_key, now);

                // Cleanup old entries
                recent_events.retain(|_, &mut ts| now - ts < dedup_window_ms * 2);

                // Detect stealer malware
                let stealer_family =
                    Self::detect_stealer(&process_name, &process_path, &cmdline, &filename);

                // Calculate process hash
                let process_sha256 =
                    if !process_path.is_empty() && Path::new(&process_path).exists() {
                        runtime
                            .block_on(crate::analyzers::hash_file(&process_path))
                            .map(|(hash, _)| hash)
                            .unwrap_or_default()
                    } else {
                        Vec::new()
                    };

                // Determine severity
                let severity = if stealer_family.is_some() {
                    Severity::Critical
                } else if data_type == BrowserDataType::Credentials
                    || data_type == BrowserDataType::KeyDatabase
                {
                    Severity::High
                } else if data_type == BrowserDataType::Cookies {
                    Severity::High
                } else {
                    Severity::Medium
                };

                // Create event
                let mut telemetry_event = TelemetryEvent::new(
                    EventType::CredentialAccess,
                    severity.clone(),
                    EventPayload::BrowserCredential(BrowserCredentialEvent {
                        browser: browser.as_str().to_string(),
                        profile_path: path
                            .parent()
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_default(),
                        data_file: filename.clone(),
                        data_type: data_type.as_str().to_string(),
                        operation: operation.to_string(),
                        pid,
                        process_name: process_name.clone(),
                        process_path: process_path.clone(),
                        process_cmdline: cmdline.clone(),
                        is_browser_process: false,
                        stealer_family: stealer_family.map(|f| f.as_str().to_string()),
                        process_sha256,
                    }),
                );

                // Add detection
                let (rule_name, confidence, description) = if let Some(family) = stealer_family {
                    (
                        format!("{}_Stealer_Browser_Access", family.as_str()),
                        0.95,
                        format!(
                            "{} stealer detected accessing {} browser {} file: {} (process: {})",
                            family.as_str(),
                            browser.as_str(),
                            data_type.as_str(),
                            filename,
                            process_name
                        ),
                    )
                } else {
                    (
                        "Suspicious_Browser_Data_Access".to_string(),
                        0.85,
                        format!(
                            "Non-browser process {} (PID: {}) accessed {} browser {} file: {}",
                            process_name,
                            pid,
                            browser.as_str(),
                            data_type.as_str(),
                            filename
                        ),
                    )
                };

                telemetry_event.add_detection(Detection {
                    detection_type: if stealer_family.is_some() {
                        DetectionType::BrowserStealer
                    } else {
                        DetectionType::CredentialTheft
                    },
                    rule_name,
                    confidence,
                    description,
                    mitre_tactics: vec!["Credential Access".to_string()],
                    mitre_techniques: vec![
                        "T1555.003".to_string(), // Credentials from Password Stores: Web Browsers
                        "T1539".to_string(),     // Steal Web Session Cookie
                    ],
                });

                // Add metadata
                telemetry_event
                    .metadata
                    .insert("browser".to_string(), browser.as_str().to_string());
                telemetry_event
                    .metadata
                    .insert("data_type".to_string(), data_type.as_str().to_string());
                telemetry_event.metadata.insert(
                    "accessed_file".to_string(),
                    path.to_string_lossy().to_string(),
                );

                if let Some(family) = stealer_family {
                    telemetry_event
                        .metadata
                        .insert("stealer_family".to_string(), family.as_str().to_string());
                }

                // Send event
                if tx.blocking_send(telemetry_event).is_err() {
                    warn!("Event channel closed");
                    return Ok(());
                }
            }
        }

        Ok(())
    }

    /// Check if a filename is a sensitive browser file
    fn is_sensitive_browser_file(filename: &str) -> bool {
        let sensitive_files = [
            "login data",
            "cookies",
            "web data",
            "history",
            "logins.json",
            "key4.db",
            "key3.db",
            "cookies.sqlite",
            "places.sqlite",
            "formhistory.sqlite",
            "signons.sqlite",
            "local state",
            "cookies.binarycookies",
        ];

        sensitive_files.iter().any(|&s| filename.contains(s))
    }

    /// Classify a file by its name
    fn classify_file(filename: &str) -> BrowserDataType {
        if filename.contains("login")
            || filename.contains("password")
            || filename.contains("signon")
        {
            BrowserDataType::Credentials
        } else if filename.contains("cookie") {
            BrowserDataType::Cookies
        } else if filename.contains("history") || filename.contains("places") {
            BrowserDataType::History
        } else if filename.contains("key") {
            BrowserDataType::KeyDatabase
        } else if filename.contains("web data") || filename.contains("formhistory") {
            BrowserDataType::WebData
        } else if filename.contains("extension") {
            BrowserDataType::Extensions
        } else if filename.contains("local storage") {
            BrowserDataType::LocalStorage
        } else {
            BrowserDataType::WebData
        }
    }

    /// Find the process that accessed a file
    fn find_accessing_process(path: &Path) -> (u32, String, String, String) {
        #[cfg(target_os = "linux")]
        {
            Self::find_accessing_process_linux(path)
        }

        #[cfg(target_os = "windows")]
        {
            Self::find_accessing_process_windows(path)
        }

        #[cfg(target_os = "macos")]
        {
            Self::find_accessing_process_macos(path)
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        {
            (0, String::new(), String::new(), String::new())
        }
    }

    #[cfg(target_os = "linux")]
    fn find_accessing_process_linux(path: &Path) -> (u32, String, String, String) {
        use std::fs;

        let path_str = path.to_string_lossy();

        // Scan /proc for processes with the file open
        let proc_dir = match fs::read_dir("/proc") {
            Ok(d) => d,
            Err(_) => return (0, String::new(), String::new(), String::new()),
        };

        for entry in proc_dir.filter_map(|e| e.ok()) {
            let pid_str = entry.file_name().to_string_lossy().to_string();
            let pid: u32 = match pid_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Check /proc/[pid]/fd
            let fd_path = format!("/proc/{}/fd", pid);
            if let Ok(fd_entries) = fs::read_dir(&fd_path) {
                for fd_entry in fd_entries.filter_map(|e| e.ok()) {
                    if let Ok(link_target) = fs::read_link(fd_entry.path()) {
                        if link_target.to_string_lossy().contains(&*path_str) {
                            let comm_path = format!("/proc/{}/comm", pid);
                            let exe_path = format!("/proc/{}/exe", pid);
                            let cmdline_path = format!("/proc/{}/cmdline", pid);

                            let process_name = fs::read_to_string(&comm_path)
                                .map(|s| s.trim().to_string())
                                .unwrap_or_default();

                            let process_path = fs::read_link(&exe_path)
                                .map(|p| p.to_string_lossy().to_string())
                                .unwrap_or_default();

                            let cmdline = fs::read_to_string(&cmdline_path)
                                .map(|s| s.replace('\0', " ").trim().to_string())
                                .unwrap_or_default();

                            return (pid, process_name, process_path, cmdline);
                        }
                    }
                }
            }
        }

        (0, String::new(), String::new(), String::new())
    }

    #[cfg(target_os = "windows")]
    fn find_accessing_process_windows(path: &Path) -> (u32, String, String, String) {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };
        use windows::Win32::System::ProcessStatus::K32GetProcessImageFileNameW;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

        let path_str = path.to_string_lossy().to_lowercase();

        unsafe {
            // Enumerate all processes
            let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(h) => h,
                Err(_) => return (0, String::new(), String::new(), String::new()),
            };

            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    let pid = entry.th32ProcessID;

                    if pid > 4 {
                        // Try to open process
                        if let Ok(handle) =
                            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
                        {
                            // Get process path
                            let mut path_buf = [0u16; 260];
                            let len = K32GetProcessImageFileNameW(handle, &mut path_buf);

                            if len > 0 {
                                let proc_path = String::from_utf16_lossy(&path_buf[..len as usize]);

                                // Check if process might be accessing our file
                                // (This is a simplified check - in production, use NtQuerySystemInformation)
                                let process_name = String::from_utf16_lossy(
                                    &entry.szExeFile[..entry
                                        .szExeFile
                                        .iter()
                                        .position(|&c| c == 0)
                                        .unwrap_or(0)],
                                );

                                // Get command line using NT API
                                let cmdline = super::win_compat::ntapi::get_process_command_line(
                                    std::mem::transmute::<_, *mut std::ffi::c_void>(handle),
                                )
                                .unwrap_or_default();

                                // Heuristic: Check if cmdline contains the file path
                                if cmdline.to_lowercase().contains(&path_str) {
                                    let _ = CloseHandle(handle);
                                    let _ = CloseHandle(snapshot);
                                    return (pid, process_name, proc_path, cmdline);
                                }
                            }

                            let _ = CloseHandle(handle);
                        }
                    }

                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
        }

        // Fallback: Try to use handle.exe if available
        Self::find_process_handle_exe_windows(path)
    }

    #[cfg(target_os = "windows")]
    fn find_process_handle_exe_windows(path: &Path) -> (u32, String, String, String) {
        use std::process::Command;

        let path_str = path.to_string_lossy();

        let output = Command::new("handle.exe")
            .args(["-nobanner", &path_str])
            .output();

        if let Ok(out) = output {
            if out.status.success() {
                let stdout = String::from_utf8_lossy(&out.stdout);
                for line in stdout.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        if let Some(pid_str) = parts.get(1).and_then(|s| s.strip_prefix("pid:")) {
                            if let Ok(pid) = pid_str.parse::<u32>() {
                                let process_name = parts[0].to_string();
                                return (pid, process_name, String::new(), String::new());
                            }
                        }
                    }
                }
            }
        }

        (0, String::new(), String::new(), String::new())
    }

    #[cfg(target_os = "macos")]
    fn find_accessing_process_macos(path: &Path) -> (u32, String, String, String) {
        use std::process::Command;

        let path_str = path.to_string_lossy();

        // Use lsof to find process
        let output = Command::new("lsof").args(["-F", "pcn", &path_str]).output();

        if let Ok(out) = output {
            if out.status.success() {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let mut pid: Option<u32> = None;
                let mut process_name = String::new();

                for line in stdout.lines() {
                    if line.starts_with('p') {
                        pid = line[1..].parse().ok();
                    } else if line.starts_with('c') {
                        process_name = line[1..].to_string();
                    }
                }

                if let Some(p) = pid {
                    // Get process path using ps
                    let ps_output = Command::new("ps")
                        .args(["-p", &p.to_string(), "-o", "comm="])
                        .output();

                    let process_path = ps_output
                        .ok()
                        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                        .unwrap_or_default();

                    return (p, process_name, process_path, String::new());
                }
            }
        }

        (0, String::new(), String::new(), String::new())
    }

    /// Get next event from collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }

    /// Get list of monitored browser profiles
    pub fn get_monitored_profiles(&self) -> &[BrowserProfile] {
        &self.browser_profiles
    }

    /// Check if a process is whitelisted
    pub fn is_whitelisted(&self, process_name: &str) -> bool {
        self.whitelisted_processes
            .contains(&process_name.to_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_browser_type_matching() {
        assert!(BrowserType::Chrome.matches_process("chrome.exe"));
        assert!(BrowserType::Chrome.matches_process("Chrome.exe"));
        assert!(BrowserType::Firefox.matches_process("firefox"));
        assert!(!BrowserType::Chrome.matches_process("notepad.exe"));
    }

    #[test]
    fn test_stealer_detection() {
        // Should detect generic stealer behavior
        let result = BrowserProtectionCollector::detect_stealer(
            "malware.exe",
            "C:\\Users\\Public\\Downloads\\malware.exe",
            "malware.exe login data cookies",
            "Login Data",
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_sensitive_file_detection() {
        assert!(BrowserProtectionCollector::is_sensitive_browser_file(
            "login data"
        ));
        assert!(BrowserProtectionCollector::is_sensitive_browser_file(
            "cookies"
        ));
        assert!(BrowserProtectionCollector::is_sensitive_browser_file(
            "logins.json"
        ));
        assert!(!BrowserProtectionCollector::is_sensitive_browser_file(
            "readme.txt"
        ));
    }

    #[test]
    fn test_file_classification() {
        assert_eq!(
            BrowserProtectionCollector::classify_file("login data"),
            BrowserDataType::Credentials
        );
        assert_eq!(
            BrowserProtectionCollector::classify_file("cookies"),
            BrowserDataType::Cookies
        );
        assert_eq!(
            BrowserProtectionCollector::classify_file("history"),
            BrowserDataType::History
        );
    }

    #[test]
    fn test_whitelist() {
        let whitelist = BrowserProtectionCollector::build_whitelist();
        assert!(whitelist.contains("chrome.exe"));
        assert!(whitelist.contains("firefox.exe"));
        assert!(whitelist.contains("msmpeng.exe"));
    }
}
