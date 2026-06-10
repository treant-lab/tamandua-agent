//! Office and Email Monitoring Collector
//!
//! Monitors Microsoft Office applications and email clients for suspicious activity:
//! - Outlook/Email: Rule modifications, auto-forwarding, PST/OST access
//! - Office Documents: Macro-enabled files, VBA analysis, DDE/OLE exploitation
//! - Suspicious Behavior: Office spawning shells, network connections, executable creation
//! - Add-in Monitoring: COM add-ins, malicious add-in detection
//! - Template Injection: Remote template loading, template directory monitoring
//! - Collection Detection: Mass email access (T1114), archive creation
//!
//! MITRE ATT&CK:
//! - T1137: Office Application Startup
//! - T1566: Phishing
//! - T1114: Email Collection
//! - T1204.002: User Execution: Malicious File
//! - T1221: Template Injection
//! - T1559.001: Inter-Process Communication: Component Object Model

use super::{Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent};
use crate::config::AgentConfig;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Office/Email activity event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfficeEmailEvent {
    /// Activity type
    pub activity_type: OfficeActivityType,
    /// Source process ID
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// Process path
    pub process_path: String,
    /// User account
    pub user: String,
    /// File path (if applicable)
    pub file_path: Option<String>,
    /// File type
    pub file_type: Option<String>,
    /// Additional details
    pub details: HashMap<String, String>,
    /// Risk score (0.0 - 1.0)
    pub risk_score: f32,
    /// MITRE technique
    pub mitre_technique: String,
}

/// Types of Office/Email activities detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfficeActivityType {
    // Email-related
    EmailRuleCreated,
    EmailRuleModified,
    AutoForwardingEnabled,
    PstOstAccess,
    MailClientCompromise,
    PhishingLinkDetected,
    SuspiciousAttachment,
    EmailSpoofing,
    BecPattern,
    MassEmailAccess,
    EmailArchiveCreation,
    MailFolderExport,

    // Office document threats
    MacroEnabledDocument,
    SuspiciousMacro,
    DdeExploitation,
    OleExploitation,
    OfficeSpawningChild,
    OfficeNetworkConnection,
    OfficeSensitiveAccess,
    OfficeCreatingExecutable,

    // Macro analysis
    MacroAutoOpen,
    MacroShellExec,
    MacroPowerShell,
    MacroDownloadCradle,
    MacroObfuscation,

    // Add-in monitoring
    AddInInstalled,
    MaliciousAddIn,
    ComAddInLoaded,

    // Template injection
    RemoteTemplateLoad,
    TemplateDirectoryChange,
    TemplateAttack,
}

impl OfficeActivityType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EmailRuleCreated => "email_rule_created",
            Self::EmailRuleModified => "email_rule_modified",
            Self::AutoForwardingEnabled => "auto_forwarding_enabled",
            Self::PstOstAccess => "pst_ost_access",
            Self::MailClientCompromise => "mail_client_compromise",
            Self::PhishingLinkDetected => "phishing_link_detected",
            Self::SuspiciousAttachment => "suspicious_attachment",
            Self::EmailSpoofing => "email_spoofing",
            Self::BecPattern => "bec_pattern",
            Self::MassEmailAccess => "mass_email_access",
            Self::EmailArchiveCreation => "email_archive_creation",
            Self::MailFolderExport => "mail_folder_export",
            Self::MacroEnabledDocument => "macro_enabled_document",
            Self::SuspiciousMacro => "suspicious_macro",
            Self::DdeExploitation => "dde_exploitation",
            Self::OleExploitation => "ole_exploitation",
            Self::OfficeSpawningChild => "office_spawning_child",
            Self::OfficeNetworkConnection => "office_network_connection",
            Self::OfficeSensitiveAccess => "office_sensitive_access",
            Self::OfficeCreatingExecutable => "office_creating_executable",
            Self::MacroAutoOpen => "macro_auto_open",
            Self::MacroShellExec => "macro_shell_exec",
            Self::MacroPowerShell => "macro_powershell",
            Self::MacroDownloadCradle => "macro_download_cradle",
            Self::MacroObfuscation => "macro_obfuscation",
            Self::AddInInstalled => "addin_installed",
            Self::MaliciousAddIn => "malicious_addin",
            Self::ComAddInLoaded => "com_addin_loaded",
            Self::RemoteTemplateLoad => "remote_template_load",
            Self::TemplateDirectoryChange => "template_directory_change",
            Self::TemplateAttack => "template_attack",
        }
    }

    pub fn mitre_technique(&self) -> &'static str {
        match self {
            Self::EmailRuleCreated | Self::EmailRuleModified | Self::AutoForwardingEnabled => {
                "T1137.005"
            }
            Self::PstOstAccess
            | Self::MassEmailAccess
            | Self::EmailArchiveCreation
            | Self::MailFolderExport => "T1114",
            Self::MailClientCompromise => "T1114.001",
            Self::PhishingLinkDetected | Self::SuspiciousAttachment => "T1566.001",
            Self::EmailSpoofing | Self::BecPattern => "T1566.002",
            Self::MacroEnabledDocument
            | Self::SuspiciousMacro
            | Self::MacroAutoOpen
            | Self::MacroShellExec
            | Self::MacroPowerShell
            | Self::MacroDownloadCradle
            | Self::MacroObfuscation => "T1204.002",
            Self::DdeExploitation => "T1559.002",
            Self::OleExploitation => "T1559.001",
            Self::OfficeSpawningChild
            | Self::OfficeNetworkConnection
            | Self::OfficeSensitiveAccess
            | Self::OfficeCreatingExecutable => "T1204.002",
            Self::AddInInstalled | Self::MaliciousAddIn | Self::ComAddInLoaded => "T1137.001",
            Self::RemoteTemplateLoad | Self::TemplateDirectoryChange | Self::TemplateAttack => {
                "T1221"
            }
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Self::SuspiciousMacro
            | Self::MacroShellExec
            | Self::MacroPowerShell
            | Self::MacroDownloadCradle
            | Self::MacroObfuscation
            | Self::OfficeSpawningChild
            | Self::OfficeCreatingExecutable
            | Self::MaliciousAddIn
            | Self::DdeExploitation
            | Self::OleExploitation
            | Self::RemoteTemplateLoad
            | Self::TemplateAttack
            | Self::BecPattern => Severity::Critical,

            Self::AutoForwardingEnabled
            | Self::MailClientCompromise
            | Self::PhishingLinkDetected
            | Self::MacroAutoOpen
            | Self::OfficeNetworkConnection
            | Self::MassEmailAccess => Severity::High,

            Self::EmailRuleCreated
            | Self::EmailRuleModified
            | Self::SuspiciousAttachment
            | Self::EmailSpoofing
            | Self::OfficeSensitiveAccess
            | Self::AddInInstalled
            | Self::ComAddInLoaded
            | Self::TemplateDirectoryChange => Severity::Medium,

            Self::PstOstAccess
            | Self::MacroEnabledDocument
            | Self::EmailArchiveCreation
            | Self::MailFolderExport => Severity::Low,
        }
    }
}

/// Suspicious VBA patterns for macro analysis
const SUSPICIOUS_VBA_PATTERNS: &[(&str, &str, f32)] = &[
    // Auto-execution
    ("Auto_Open", "macro_auto_open", 0.6),
    ("AutoOpen", "macro_auto_open", 0.6),
    ("Auto_Close", "macro_auto_close", 0.5),
    ("AutoExec", "macro_auto_exec", 0.6),
    ("Document_Open", "macro_document_open", 0.6),
    ("Workbook_Open", "macro_workbook_open", 0.6),
    // Shell execution
    ("Shell(", "macro_shell_exec", 0.8),
    ("WScript.Shell", "macro_wscript_shell", 0.9),
    ("Shell.Application", "macro_shell_app", 0.8),
    ("Wscript.Run", "macro_wscript_run", 0.9),
    ("CreateObject(\"Shell", "macro_create_shell", 0.9),
    // PowerShell
    ("powershell", "macro_powershell", 0.95),
    ("pwsh", "macro_powershell", 0.95),
    ("IEX(", "macro_iex", 0.9),
    ("Invoke-Expression", "macro_invoke_expr", 0.9),
    ("-enc ", "macro_encoded_cmd", 0.85),
    ("-EncodedCommand", "macro_encoded_cmd", 0.85),
    ("-e ", "macro_encoded_cmd_short", 0.7),
    ("FromBase64String", "macro_base64", 0.8),
    // Download cradles
    ("DownloadFile", "macro_download", 0.85),
    ("DownloadString", "macro_download_string", 0.9),
    ("Net.WebClient", "macro_webclient", 0.8),
    ("XMLHTTP", "macro_xmlhttp", 0.75),
    ("WinHttp", "macro_winhttp", 0.75),
    ("Invoke-WebRequest", "macro_webrequest", 0.85),
    ("wget", "macro_wget", 0.7),
    ("curl", "macro_curl", 0.7),
    ("BitsTransfer", "macro_bitstransfer", 0.8),
    // Obfuscation
    ("Chr(", "macro_chr_obfuscation", 0.5),
    ("ChrW(", "macro_chrw_obfuscation", 0.5),
    ("StrReverse", "macro_strreverse", 0.6),
    ("Replace(", "macro_replace", 0.3),
    ("CallByName", "macro_callbyname", 0.7),
    ("Execute(", "macro_execute", 0.8),
    ("Eval(", "macro_eval", 0.8),
    // Process creation
    ("CreateProcess", "macro_createprocess", 0.85),
    ("WMI", "macro_wmi", 0.7),
    ("Win32_Process", "macro_wmi_process", 0.8),
    ("process call create", "macro_wmi_create", 0.9),
    // Credential theft
    ("CredentialCache", "macro_credential_cache", 0.8),
    ("NetworkCredential", "macro_network_cred", 0.8),
    // Registry
    ("RegWrite", "macro_regwrite", 0.7),
    ("RegRead", "macro_regread", 0.5),
    ("RegDelete", "macro_regdelete", 0.6),
    // File operations
    ("FileSystemObject", "macro_fso", 0.6),
    ("CopyFile", "macro_copyfile", 0.5),
    ("DeleteFile", "macro_deletefile", 0.6),
    ("MoveFile", "macro_movefile", 0.5),
    // Environment
    ("Environ(", "macro_environ", 0.4),
    ("%TEMP%", "macro_temp_path", 0.5),
    ("%APPDATA%", "macro_appdata", 0.5),
    // ActiveX
    ("CreateObject", "macro_createobject", 0.6),
    ("GetObject", "macro_getobject", 0.5),
];

/// Office process names to monitor
const OFFICE_PROCESSES: &[&str] = &[
    "WINWORD.EXE",
    "EXCEL.EXE",
    "POWERPNT.EXE",
    "OUTLOOK.EXE",
    "MSACCESS.EXE",
    "MSPUB.EXE",
    "ONENOTE.EXE",
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "msaccess.exe",
    "mspub.exe",
    "onenote.exe",
    // LibreOffice (cross-platform)
    "soffice.bin",
    "soffice",
    "libreoffice",
    // Thunderbird
    "thunderbird.exe",
    "thunderbird",
];

/// Suspicious child processes for Office applications
const SUSPICIOUS_CHILD_PROCESSES: &[&str] = &[
    "cmd.exe",
    "cmd",
    "powershell.exe",
    "powershell",
    "pwsh.exe",
    "pwsh",
    "wscript.exe",
    "wscript",
    "cscript.exe",
    "cscript",
    "mshta.exe",
    "mshta",
    "certutil.exe",
    "certutil",
    "bitsadmin.exe",
    "bitsadmin",
    "regsvr32.exe",
    "regsvr32",
    "rundll32.exe",
    "rundll32",
    "msiexec.exe",
    "msiexec",
    "schtasks.exe",
    "schtasks",
    "at.exe",
    "bash",
    "sh",
    "python.exe",
    "python",
    "python3",
    "perl.exe",
    "perl",
    "ruby.exe",
    "ruby",
    "java.exe",
    "java",
    "javaw.exe",
];

/// Sensitive directories that Office apps should not normally access
const SENSITIVE_DIRECTORIES: &[&str] = &[
    "\\Windows\\System32\\",
    "\\Windows\\SysWOW64\\",
    "/etc/",
    "/root/",
    "/home/",
    "\\Users\\",
    "\\AppData\\Local\\Microsoft\\Credentials\\",
    "\\AppData\\Roaming\\Microsoft\\Credentials\\",
    "\\AppData\\Local\\Google\\Chrome\\User Data\\",
    "\\AppData\\Local\\Mozilla\\Firefox\\Profiles\\",
    ".ssh/",
    ".gnupg/",
    ".aws/",
    "\\SAM",
    "\\SYSTEM",
    "\\SECURITY",
];

/// Office/Email collector
pub struct OfficeEmailCollector {
    #[allow(dead_code)]
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    #[allow(dead_code)]
    event_tx: mpsc::Sender<TelemetryEvent>,
}

impl OfficeEmailCollector {
    /// Create a new Office/Email collector
    pub fn new(config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(500);

        let collector = Self {
            config: config.clone(),
            event_rx: rx,
            event_tx: tx.clone(),
        };

        // Start platform-specific monitoring
        #[cfg(target_os = "windows")]
        {
            let tx_clone = tx.clone();
            let config_clone = config.clone();
            tokio::spawn(async move {
                Self::windows_monitor_loop(tx_clone, config_clone).await;
            });
        }

        // Start cross-platform monitors
        {
            let tx_clone = tx.clone();
            let config_clone = config.clone();
            tokio::spawn(async move {
                Self::process_monitor_loop(tx_clone, config_clone).await;
            });
        }

        {
            let tx_clone = tx.clone();
            let config_clone = config.clone();
            tokio::spawn(async move {
                Self::file_monitor_loop(tx_clone, config_clone).await;
            });
        }

        collector
    }

    /// Get next event from collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }

    // ==================== Windows-specific monitoring ====================
    #[cfg(target_os = "windows")]
    async fn windows_monitor_loop(tx: mpsc::Sender<TelemetryEvent>, config: AgentConfig) {
        info!("Starting Windows Office/Email monitor");

        // Start email rule monitoring
        let tx_clone = tx.clone();
        let config_clone = config.clone();
        tokio::spawn(async move {
            Self::monitor_outlook_rules(tx_clone, config_clone).await;
        });

        // Start Office add-in monitoring
        let tx_clone = tx.clone();
        let config_clone = config.clone();
        tokio::spawn(async move {
            Self::monitor_office_addins(tx_clone, config_clone).await;
        });

        // Start template directory monitoring
        let tx_clone = tx.clone();
        let config_clone = config.clone();
        tokio::spawn(async move {
            Self::monitor_template_directories(tx_clone, config_clone).await;
        });

        // Monitor PST/OST access
        Self::monitor_pst_ost_access(tx, config).await;
    }

    #[cfg(target_os = "windows")]
    async fn monitor_outlook_rules(tx: mpsc::Sender<TelemetryEvent>, _config: AgentConfig) {
        use std::path::Path;

        info!("Starting Outlook rules monitor");

        // Outlook rules are stored in various locations depending on version
        let rule_paths = [
            // Outlook 2016/2019/365 - stored in profile
            "AppData\\Roaming\\Microsoft\\Outlook\\",
            // Exchange rules - stored on server, but local cache exists
            "AppData\\Local\\Microsoft\\Outlook\\",
        ];

        let mut known_rules: HashSet<String> = HashSet::new();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));

        loop {
            interval.tick().await;

            // Get user profile directory
            let user_profile = std::env::var("USERPROFILE").unwrap_or_default();
            if user_profile.is_empty() {
                continue;
            }

            for rule_path in &rule_paths {
                let full_path = format!("{}\\{}", user_profile, rule_path);
                let path = Path::new(&full_path);

                if !path.exists() {
                    continue;
                }

                // Check for rule files (.rwz files for Outlook rules)
                if let Ok(entries) = std::fs::read_dir(path) {
                    for entry in entries.flatten() {
                        let file_name = entry.file_name().to_string_lossy().to_string();

                        // Check for rule files
                        if file_name.ends_with(".rwz") || file_name.contains("rules") {
                            let file_path = entry.path().to_string_lossy().to_string();

                            if !known_rules.contains(&file_path) {
                                // Check file modification time
                                if let Ok(metadata) = entry.metadata() {
                                    if let Ok(modified) = metadata.modified() {
                                        let age = std::time::SystemTime::now()
                                            .duration_since(modified)
                                            .unwrap_or_default();

                                        // Only alert on recently modified rules (within last hour)
                                        if age.as_secs() < 3600 {
                                            let event = Self::create_office_event(
                                                OfficeActivityType::EmailRuleModified,
                                                0,
                                                "OUTLOOK.EXE".to_string(),
                                                String::new(),
                                                Some(file_path.clone()),
                                                Some("email_rule".to_string()),
                                                HashMap::from([
                                                    ("rule_file".to_string(), file_name.clone()),
                                                    (
                                                        "description".to_string(),
                                                        "Email rule file modified".to_string(),
                                                    ),
                                                ]),
                                                0.7,
                                            );

                                            if tx.send(event).await.is_err() {
                                                warn!("Event channel closed");
                                                return;
                                            }
                                        }
                                    }
                                }

                                known_rules.insert(file_path);
                            }
                        }
                    }
                }
            }

            // Check registry for auto-forwarding rules
            Self::check_auto_forwarding_registry(&tx).await;
        }
    }

    #[cfg(target_os = "windows")]
    async fn check_auto_forwarding_registry(tx: &mpsc::Sender<TelemetryEvent>) {
        use winreg::enums::*;
        use winreg::RegKey;

        // Check for suspicious Outlook settings
        let outlook_keys = [
            "Software\\Microsoft\\Office\\16.0\\Outlook\\Options\\Mail",
            "Software\\Microsoft\\Office\\15.0\\Outlook\\Options\\Mail",
            "Software\\Microsoft\\Office\\14.0\\Outlook\\Options\\Mail",
        ];

        let hkcu = match RegKey::predef(HKEY_CURRENT_USER).open_subkey("") {
            Ok(key) => key,
            Err(_) => return,
        };

        for key_path in &outlook_keys {
            if let Ok(outlook_key) = hkcu.open_subkey(key_path) {
                // Check for auto-reply/forwarding settings
                if let Ok(value) = outlook_key.get_value::<String, _>("AutoForwardAddress") {
                    if !value.is_empty() {
                        let mut details = HashMap::new();
                        details.insert("forward_address".to_string(), value.clone());
                        details.insert(
                            "description".to_string(),
                            "Auto-forwarding address configured".to_string(),
                        );

                        let event = Self::create_office_event(
                            OfficeActivityType::AutoForwardingEnabled,
                            0,
                            "OUTLOOK.EXE".to_string(),
                            String::new(),
                            None,
                            None,
                            details,
                            0.85,
                        );

                        if tx.send(event).await.is_err() {
                            return;
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    async fn monitor_office_addins(tx: mpsc::Sender<TelemetryEvent>, _config: AgentConfig) {
        use winreg::enums::*;
        use winreg::RegKey;

        info!("Starting Office add-in monitor");

        let addin_registry_paths = [
            // Word add-ins
            "Software\\Microsoft\\Office\\Word\\Addins",
            "Software\\Microsoft\\Office\\16.0\\Word\\Addins",
            // Excel add-ins
            "Software\\Microsoft\\Office\\Excel\\Addins",
            "Software\\Microsoft\\Office\\16.0\\Excel\\Addins",
            // Outlook add-ins
            "Software\\Microsoft\\Office\\Outlook\\Addins",
            "Software\\Microsoft\\Office\\16.0\\Outlook\\Addins",
            // PowerPoint add-ins
            "Software\\Microsoft\\Office\\PowerPoint\\Addins",
            "Software\\Microsoft\\Office\\16.0\\PowerPoint\\Addins",
        ];

        let mut known_addins: HashSet<String> = HashSet::new();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));

        loop {
            interval.tick().await;

            for root in &[HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE] {
                let hkey = match RegKey::predef(*root).open_subkey("") {
                    Ok(key) => key,
                    Err(_) => continue,
                };

                for addin_path in &addin_registry_paths {
                    if let Ok(addin_key) = hkey.open_subkey(addin_path) {
                        if let Ok(subkeys) = addin_key.enum_keys().collect::<Result<Vec<_>, _>>() {
                            for subkey_name in subkeys {
                                let addin_id = format!("{}\\{}", addin_path, subkey_name);

                                if !known_addins.contains(&addin_id) {
                                    if let Ok(subkey) = addin_key.open_subkey(&subkey_name) {
                                        let description: String =
                                            subkey.get_value("Description").unwrap_or_default();
                                        let load_behavior: u32 =
                                            subkey.get_value("LoadBehavior").unwrap_or(0);
                                        let manifest: String =
                                            subkey.get_value("Manifest").unwrap_or_default();

                                        let mut details = HashMap::new();
                                        details
                                            .insert("addin_name".to_string(), subkey_name.clone());
                                        details.insert("description".to_string(), description);
                                        details.insert(
                                            "load_behavior".to_string(),
                                            load_behavior.to_string(),
                                        );
                                        details.insert("manifest".to_string(), manifest.clone());

                                        // Check if this is a suspicious add-in
                                        let is_suspicious =
                                            Self::is_suspicious_addin(&subkey_name, &manifest);

                                        let activity_type = if is_suspicious {
                                            OfficeActivityType::MaliciousAddIn
                                        } else {
                                            OfficeActivityType::AddInInstalled
                                        };

                                        let event = Self::create_office_event(
                                            activity_type,
                                            0,
                                            "Office".to_string(),
                                            String::new(),
                                            Some(manifest),
                                            Some("addin".to_string()),
                                            details,
                                            if is_suspicious { 0.9 } else { 0.3 },
                                        );

                                        if tx.send(event).await.is_err() {
                                            warn!("Event channel closed");
                                            return;
                                        }
                                    }

                                    known_addins.insert(addin_id);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn is_suspicious_addin(name: &str, manifest: &str) -> bool {
        let suspicious_indicators = [
            // Suspicious paths
            "\\Temp\\",
            "\\tmp\\",
            "%TEMP%",
            "%TMP%",
            "\\AppData\\Local\\Temp\\",
            // Network locations
            "\\\\",
            "http://",
            "https://",
            // Suspicious extensions
            ".vbs",
            ".js",
            ".ps1",
            ".bat",
            ".cmd",
        ];

        let name_lower = name.to_lowercase();
        let manifest_lower = manifest.to_lowercase();

        // Check for suspicious patterns in manifest path
        for indicator in &suspicious_indicators {
            if manifest_lower.contains(&indicator.to_lowercase()) {
                return true;
            }
        }

        // Check for obfuscated names
        let suspicious_name_patterns = [
            "test", "temp", "debug", "malware", "virus", "trojan", "hack",
        ];

        for pattern in &suspicious_name_patterns {
            if name_lower.contains(pattern) {
                return true;
            }
        }

        false
    }

    #[cfg(target_os = "windows")]
    async fn monitor_template_directories(tx: mpsc::Sender<TelemetryEvent>, _config: AgentConfig) {
        use notify::{Event as NotifyEvent, EventKind, RecursiveMode, Watcher};

        info!("Starting Office template directory monitor");

        let user_profile = std::env::var("USERPROFILE").unwrap_or_default();
        let appdata = std::env::var("APPDATA").unwrap_or_default();

        let template_paths = [
            format!("{}\\AppData\\Roaming\\Microsoft\\Templates", user_profile),
            format!("{}\\Microsoft\\Templates", appdata),
            format!(
                "{}\\AppData\\Roaming\\Microsoft\\Word\\STARTUP",
                user_profile
            ),
            format!(
                "{}\\AppData\\Roaming\\Microsoft\\Excel\\XLSTART",
                user_profile
            ),
            "C:\\Program Files\\Microsoft Office\\root\\Templates".to_string(),
            "C:\\Program Files (x86)\\Microsoft Office\\root\\Templates".to_string(),
        ];

        let (notify_tx, mut notify_rx) =
            tokio::sync::mpsc::channel::<notify::Result<NotifyEvent>>(100);

        let mut watcher = match notify::recommended_watcher(move |res| {
            let _ = notify_tx.blocking_send(res);
        }) {
            Ok(w) => w,
            Err(e) => {
                warn!(error = %e, "Failed to create template watcher");
                return;
            }
        };

        // Watch template directories
        for path in &template_paths {
            let path_obj = std::path::Path::new(path);
            if path_obj.exists() {
                if let Err(e) = watcher.watch(path_obj, RecursiveMode::Recursive) {
                    warn!(path = %path, error = %e, "Failed to watch template directory");
                }
            }
        }

        // Process file events
        while let Some(res) = notify_rx.recv().await {
            if let Ok(event) = res {
                for path in &event.paths {
                    let path_str = path.to_string_lossy().to_string();

                    // Check for template files
                    let is_template = path_str.ends_with(".dotm")
                        || path_str.ends_with(".dotx")
                        || path_str.ends_with(".xltm")
                        || path_str.ends_with(".xltx")
                        || path_str.ends_with(".potm")
                        || path_str.ends_with(".potx");

                    if !is_template {
                        continue;
                    }

                    let activity_type = match &event.kind {
                        EventKind::Create(_) | EventKind::Modify(_) => {
                            // Check if template contains remote references
                            if Self::template_has_remote_reference(&path_str).await {
                                OfficeActivityType::RemoteTemplateLoad
                            } else {
                                OfficeActivityType::TemplateDirectoryChange
                            }
                        }
                        _ => continue,
                    };

                    let mut details = HashMap::new();
                    details.insert("template_path".to_string(), path_str.clone());
                    details.insert("event_type".to_string(), format!("{:?}", event.kind));

                    let telemetry_event = Self::create_office_event(
                        activity_type,
                        0,
                        "Office".to_string(),
                        String::new(),
                        Some(path_str),
                        Some("template".to_string()),
                        details,
                        0.75,
                    );

                    if tx.send(telemetry_event).await.is_err() {
                        warn!("Event channel closed");
                        return;
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    async fn template_has_remote_reference(path: &str) -> bool {
        // Check if template file contains remote template references
        // This requires parsing the Office Open XML format

        use std::fs::File;
        use std::io::Read;

        let file = match File::open(path) {
            Ok(f) => f,
            Err(_) => return false,
        };

        // Read first few KB to check for remote references
        let mut buffer = vec![0u8; 8192];
        let mut reader = std::io::BufReader::new(file);
        let bytes_read = reader.read(&mut buffer).unwrap_or(0);

        if bytes_read == 0 {
            return false;
        }

        let content = String::from_utf8_lossy(&buffer[..bytes_read]);

        // Look for remote template indicators
        let remote_indicators = [
            "http://",
            "https://",
            "\\\\",
            "Target=\"http",
            "attachedTemplate",
            "w:attachedTemplate",
        ];

        for indicator in &remote_indicators {
            if content.contains(indicator) {
                return true;
            }
        }

        false
    }

    #[cfg(target_os = "windows")]
    async fn monitor_pst_ost_access(tx: mpsc::Sender<TelemetryEvent>, _config: AgentConfig) {
        use notify::{Event as NotifyEvent, EventKind, RecursiveMode, Watcher};

        info!("Starting PST/OST access monitor");

        let user_profile = std::env::var("USERPROFILE").unwrap_or_default();

        let outlook_data_paths = [
            format!("{}\\Documents\\Outlook Files", user_profile),
            format!("{}\\AppData\\Local\\Microsoft\\Outlook", user_profile),
        ];

        let (notify_tx, mut notify_rx) =
            tokio::sync::mpsc::channel::<notify::Result<NotifyEvent>>(100);

        let mut watcher = match notify::recommended_watcher(move |res| {
            let _ = notify_tx.blocking_send(res);
        }) {
            Ok(w) => w,
            Err(e) => {
                warn!(error = %e, "Failed to create PST/OST watcher");
                return;
            }
        };

        // Watch Outlook data directories
        for path in &outlook_data_paths {
            let path_obj = std::path::Path::new(path);
            if path_obj.exists() {
                if let Err(e) = watcher.watch(path_obj, RecursiveMode::Recursive) {
                    warn!(path = %path, error = %e, "Failed to watch Outlook data directory");
                }
            }
        }

        let mut access_count: HashMap<String, (u64, std::time::Instant)> = HashMap::new();

        while let Some(res) = notify_rx.recv().await {
            if let Ok(event) = res {
                for path in &event.paths {
                    let path_str = path.to_string_lossy().to_string();
                    let path_lower = path_str.to_lowercase();

                    // Check for PST/OST files
                    if !path_lower.ends_with(".pst") && !path_lower.ends_with(".ost") {
                        continue;
                    }

                    let activity_type = match &event.kind {
                        EventKind::Access(_) | EventKind::Modify(_) => {
                            // Track access frequency for mass access detection
                            let entry = access_count
                                .entry(path_str.clone())
                                .or_insert((0, std::time::Instant::now()));

                            entry.0 += 1;

                            // Reset counter if more than 5 minutes since first access
                            if entry.1.elapsed().as_secs() > 300 {
                                *entry = (1, std::time::Instant::now());
                            }

                            // Mass access detection (more than 100 accesses in 5 minutes)
                            if entry.0 > 100 {
                                OfficeActivityType::MassEmailAccess
                            } else {
                                OfficeActivityType::PstOstAccess
                            }
                        }
                        _ => continue,
                    };

                    let mut details = HashMap::new();
                    details.insert("file_path".to_string(), path_str.clone());
                    details.insert(
                        "file_type".to_string(),
                        if path_lower.ends_with(".pst") {
                            "PST"
                        } else {
                            "OST"
                        }
                        .to_string(),
                    );

                    let telemetry_event = Self::create_office_event(
                        activity_type,
                        0,
                        "Unknown".to_string(),
                        String::new(),
                        Some(path_str),
                        Some("outlook_data".to_string()),
                        details,
                        if activity_type == OfficeActivityType::MassEmailAccess {
                            0.85
                        } else {
                            0.3
                        },
                    );

                    if tx.send(telemetry_event).await.is_err() {
                        warn!("Event channel closed");
                        return;
                    }
                }
            }
        }
    }

    // ==================== Cross-platform monitoring ====================

    /// Monitor Office processes for suspicious child process creation
    async fn process_monitor_loop(tx: mpsc::Sender<TelemetryEvent>, _config: AgentConfig) {
        use sysinfo::{ProcessRefreshKind, System};

        info!("Starting Office process behavior monitor");

        let mut system = System::new_all();
        let mut known_office_children: HashSet<(u32, u32)> = HashSet::new();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(500));

        loop {
            interval.tick().await;

            system.refresh_processes_specifics(ProcessRefreshKind::everything());

            // Find Office processes
            let office_pids: Vec<u32> = system
                .processes()
                .iter()
                .filter(|(_, proc)| {
                    let name = proc.name().to_string();
                    OFFICE_PROCESSES
                        .iter()
                        .any(|op| name.eq_ignore_ascii_case(op))
                })
                .map(|(pid, _)| pid.as_u32())
                .collect();

            // Check for suspicious children of Office processes
            for (pid, process) in system.processes() {
                if let Some(ppid) = process.parent() {
                    let ppid_u32 = ppid.as_u32();

                    if office_pids.contains(&ppid_u32) {
                        let pid_u32 = pid.as_u32();
                        let key = (ppid_u32, pid_u32);

                        if known_office_children.contains(&key) {
                            continue;
                        }

                        let child_name = process.name().to_string();

                        // Check if this is a suspicious child process
                        if SUSPICIOUS_CHILD_PROCESSES
                            .iter()
                            .any(|sp| child_name.eq_ignore_ascii_case(sp))
                        {
                            known_office_children.insert(key);

                            // Get parent process info
                            let parent_name = system
                                .process(ppid)
                                .map(|p| p.name().to_string())
                                .unwrap_or_default();
                            let parent_path = system
                                .process(ppid)
                                .and_then(|p| p.exe().map(|e| e.to_string_lossy().to_string()))
                                .unwrap_or_default();

                            let child_path = process
                                .exe()
                                .map(|e| e.to_string_lossy().to_string())
                                .unwrap_or_default();

                            let child_cmdline = process
                                .cmd()
                                .iter()
                                .map(|s| s.to_string())
                                .collect::<Vec<_>>()
                                .join(" ");

                            let mut details = HashMap::new();
                            details.insert("parent_pid".to_string(), ppid_u32.to_string());
                            details.insert("parent_name".to_string(), parent_name.clone());
                            details.insert("parent_path".to_string(), parent_path.clone());
                            details.insert("child_pid".to_string(), pid_u32.to_string());
                            details.insert("child_name".to_string(), child_name.clone());
                            details.insert("child_path".to_string(), child_path.clone());
                            details.insert("child_cmdline".to_string(), child_cmdline.clone());
                            details.insert(
                                "description".to_string(),
                                format!(
                                    "{} spawned suspicious child process {}",
                                    parent_name, child_name
                                ),
                            );

                            // Check for encoded PowerShell commands
                            let has_encoded_ps = child_cmdline.to_lowercase().contains("-enc")
                                || child_cmdline.to_lowercase().contains("-encodedcommand");

                            let event = Self::create_office_event(
                                OfficeActivityType::OfficeSpawningChild,
                                ppid_u32,
                                parent_name,
                                parent_path,
                                Some(child_path),
                                Some("child_process".to_string()),
                                details,
                                if has_encoded_ps { 0.98 } else { 0.9 },
                            );

                            if tx.send(event).await.is_err() {
                                warn!("Event channel closed");
                                return;
                            }
                        }

                        // Check for Office accessing sensitive directories
                        if let Some(cwd) = process.cwd() {
                            let cwd_str = cwd.to_string_lossy().to_string();
                            if SENSITIVE_DIRECTORIES.iter().any(|sd| cwd_str.contains(sd)) {
                                let parent_name = system
                                    .process(ppid)
                                    .map(|p| p.name().to_string())
                                    .unwrap_or_default();

                                let mut details = HashMap::new();
                                details.insert("working_directory".to_string(), cwd_str.clone());
                                details.insert("parent_process".to_string(), parent_name.clone());
                                details.insert(
                                    "description".to_string(),
                                    format!(
                                        "Office application accessing sensitive directory: {}",
                                        cwd_str
                                    ),
                                );

                                let event = Self::create_office_event(
                                    OfficeActivityType::OfficeSensitiveAccess,
                                    ppid_u32,
                                    parent_name,
                                    String::new(),
                                    Some(cwd_str),
                                    None,
                                    details,
                                    0.75,
                                );

                                if tx.send(event).await.is_err() {
                                    warn!("Event channel closed");
                                    return;
                                }
                            }
                        }
                    }
                }
            }

            // Cleanup old entries
            if known_office_children.len() > 10000 {
                known_office_children.clear();
            }
        }
    }

    /// Monitor for macro-enabled documents and analyze them
    async fn file_monitor_loop(tx: mpsc::Sender<TelemetryEvent>, config: AgentConfig) {
        use notify::{Event as NotifyEvent, EventKind, RecursiveMode, Watcher};

        info!("Starting Office document monitor");

        let watch_paths = Self::get_document_watch_paths();

        let (notify_tx, mut notify_rx) =
            tokio::sync::mpsc::channel::<notify::Result<NotifyEvent>>(100);

        let mut watcher = match notify::recommended_watcher(move |res| {
            let _ = notify_tx.blocking_send(res);
        }) {
            Ok(w) => w,
            Err(e) => {
                warn!(error = %e, "Failed to create document watcher");
                return;
            }
        };

        // Watch document directories
        for path in &watch_paths {
            let path_obj = std::path::Path::new(path);
            if path_obj.exists() {
                if let Err(e) = watcher.watch(path_obj, RecursiveMode::Recursive) {
                    debug!(path = %path, error = %e, "Failed to watch document directory");
                }
            }
        }

        while let Some(res) = notify_rx.recv().await {
            if let Ok(event) = res {
                match &event.kind {
                    EventKind::Create(_) | EventKind::Modify(_) => {
                        for path in &event.paths {
                            let path_str = path.to_string_lossy().to_string();

                            // Check if it's an Office document
                            if let Some(doc_type) = Self::get_document_type(&path_str) {
                                // Analyze the document
                                if let Some(analysis_event) =
                                    Self::analyze_office_document(&path_str, &doc_type, &config)
                                        .await
                                {
                                    if tx.send(analysis_event).await.is_err() {
                                        warn!("Event channel closed");
                                        return;
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    fn get_document_watch_paths() -> Vec<String> {
        let mut paths = Vec::new();

        #[cfg(target_os = "windows")]
        {
            if let Ok(user_profile) = std::env::var("USERPROFILE") {
                paths.push(format!("{}\\Documents", user_profile));
                paths.push(format!("{}\\Downloads", user_profile));
                paths.push(format!("{}\\Desktop", user_profile));
            }
            paths.push("C:\\Users\\Public\\Documents".to_string());
        }

        #[cfg(target_os = "linux")]
        {
            if let Ok(home) = std::env::var("HOME") {
                paths.push(format!("{}/Documents", home));
                paths.push(format!("{}/Downloads", home));
                paths.push(format!("{}/Desktop", home));
            }
            paths.push("/tmp".to_string());
        }

        #[cfg(target_os = "macos")]
        {
            if let Ok(home) = std::env::var("HOME") {
                paths.push(format!("{}/Documents", home));
                paths.push(format!("{}/Downloads", home));
                paths.push(format!("{}/Desktop", home));
            }
        }

        paths
    }

    fn get_document_type(path: &str) -> Option<String> {
        let path_lower = path.to_lowercase();

        // Macro-enabled Office documents
        if path_lower.ends_with(".docm") {
            Some("word_macro".to_string())
        } else if path_lower.ends_with(".xlsm") || path_lower.ends_with(".xlsb") {
            Some("excel_macro".to_string())
        } else if path_lower.ends_with(".pptm") {
            Some("powerpoint_macro".to_string())
        } else if path_lower.ends_with(".dotm") {
            Some("word_template_macro".to_string())
        } else if path_lower.ends_with(".xltm") {
            Some("excel_template_macro".to_string())
        } else if path_lower.ends_with(".potm") {
            Some("powerpoint_template_macro".to_string())
        }
        // Regular Office documents (for DDE/OLE analysis)
        else if path_lower.ends_with(".docx") || path_lower.ends_with(".doc") {
            Some("word".to_string())
        } else if path_lower.ends_with(".xlsx") || path_lower.ends_with(".xls") {
            Some("excel".to_string())
        } else if path_lower.ends_with(".pptx") || path_lower.ends_with(".ppt") {
            Some("powerpoint".to_string())
        } else {
            None
        }
    }

    async fn analyze_office_document(
        path: &str,
        doc_type: &str,
        _config: &AgentConfig,
    ) -> Option<TelemetryEvent> {
        use std::fs::File;
        use std::io::Read;

        let file = match File::open(path) {
            Ok(f) => f,
            Err(_) => return None,
        };

        // Read document content for analysis
        let mut buffer = vec![0u8; 65536]; // Read first 64KB
        let mut reader = std::io::BufReader::new(file);
        let bytes_read = reader.read(&mut buffer).unwrap_or(0);

        if bytes_read == 0 {
            return None;
        }

        let content = String::from_utf8_lossy(&buffer[..bytes_read]);
        let content_lower = content.to_lowercase();

        // Check for DDE attacks
        if Self::check_dde_exploitation(&content, &content_lower) {
            let mut details = HashMap::new();
            details.insert("file_path".to_string(), path.to_string());
            details.insert("doc_type".to_string(), doc_type.to_string());
            details.insert(
                "description".to_string(),
                "DDE exploitation attempt detected".to_string(),
            );

            return Some(Self::create_office_event(
                OfficeActivityType::DdeExploitation,
                0,
                "Office".to_string(),
                String::new(),
                Some(path.to_string()),
                Some(doc_type.to_string()),
                details,
                0.95,
            ));
        }

        // Check for OLE objects
        if Self::check_ole_exploitation(&content, &content_lower) {
            let mut details = HashMap::new();
            details.insert("file_path".to_string(), path.to_string());
            details.insert("doc_type".to_string(), doc_type.to_string());
            details.insert(
                "description".to_string(),
                "Suspicious OLE object detected".to_string(),
            );

            return Some(Self::create_office_event(
                OfficeActivityType::OleExploitation,
                0,
                "Office".to_string(),
                String::new(),
                Some(path.to_string()),
                Some(doc_type.to_string()),
                details,
                0.85,
            ));
        }

        // Check for remote template injection
        if Self::check_remote_template(&content, &content_lower) {
            let mut details = HashMap::new();
            details.insert("file_path".to_string(), path.to_string());
            details.insert("doc_type".to_string(), doc_type.to_string());
            details.insert(
                "description".to_string(),
                "Remote template injection detected".to_string(),
            );

            return Some(Self::create_office_event(
                OfficeActivityType::RemoteTemplateLoad,
                0,
                "Office".to_string(),
                String::new(),
                Some(path.to_string()),
                Some(doc_type.to_string()),
                details,
                0.9,
            ));
        }

        // For macro-enabled documents, perform VBA analysis
        if doc_type.contains("macro") {
            if let Some((activity_type, details, risk_score)) =
                Self::analyze_vba_content(&content, &content_lower, path, doc_type)
            {
                return Some(Self::create_office_event(
                    activity_type,
                    0,
                    "Office".to_string(),
                    String::new(),
                    Some(path.to_string()),
                    Some(doc_type.to_string()),
                    details,
                    risk_score,
                ));
            }

            // If no specific threat found, still report macro-enabled document
            let mut details = HashMap::new();
            details.insert("file_path".to_string(), path.to_string());
            details.insert("doc_type".to_string(), doc_type.to_string());
            details.insert(
                "description".to_string(),
                "Macro-enabled document detected".to_string(),
            );

            return Some(Self::create_office_event(
                OfficeActivityType::MacroEnabledDocument,
                0,
                "Office".to_string(),
                String::new(),
                Some(path.to_string()),
                Some(doc_type.to_string()),
                details,
                0.4,
            ));
        }

        None
    }

    fn check_dde_exploitation(content: &str, content_lower: &str) -> bool {
        // DDE indicators in Office documents
        let dde_patterns = [
            "ddeauto", "dde ", "ddelink", "\\dde", "DDEAUTO", "DDE ", "DDELINK",
        ];

        // Command patterns often used with DDE
        let cmd_patterns = [
            "cmd.exe",
            "powershell",
            "mshta",
            "certutil",
            "bitsadmin",
            "wscript",
            "cscript",
        ];

        let has_dde = dde_patterns.iter().any(|p| content.contains(p));
        let has_cmd = cmd_patterns
            .iter()
            .any(|p| content_lower.contains(&p.to_lowercase()));

        has_dde && has_cmd
    }

    fn check_ole_exploitation(content: &str, content_lower: &str) -> bool {
        // Suspicious OLE indicators
        let ole_patterns = [
            // OLE magic bytes in hex
            "d0cf11e0",
            "D0CF11E0",
            // Package shell objects
            "Package",
            "OLE",
            // Embedded executables
            "MZ", // PE header start (followed by high bytes)
            "4d5a9000",
            // Suspicious CLSID references
            "CLSID",
            // Equation Editor (CVE-2017-11882)
            "Equation.3",
            "EQNEDT32",
        ];

        ole_patterns
            .iter()
            .any(|p| content.contains(p) || content_lower.contains(&p.to_lowercase()))
    }

    fn check_remote_template(content: &str, content_lower: &str) -> bool {
        // Check for remote template references
        let remote_patterns = [
            "attachedTemplate",
            "w:attachedTemplate",
            "Target=\"http",
            "Target=\"https",
            "Target=\"\\\\",
            "TargetMode=\"External\"",
        ];

        remote_patterns
            .iter()
            .any(|p| content.contains(p) || content_lower.contains(&p.to_lowercase()))
    }

    fn analyze_vba_content(
        content: &str,
        content_lower: &str,
        path: &str,
        doc_type: &str,
    ) -> Option<(OfficeActivityType, HashMap<String, String>, f32)> {
        let mut matched_patterns: Vec<(&str, &str, f32)> = Vec::new();

        // Check all suspicious VBA patterns
        for (pattern, name, score) in SUSPICIOUS_VBA_PATTERNS {
            if content.contains(pattern) || content_lower.contains(&pattern.to_lowercase()) {
                matched_patterns.push((pattern, name, *score));
            }
        }

        if matched_patterns.is_empty() {
            return None;
        }

        // Calculate overall risk score
        let max_score = matched_patterns
            .iter()
            .map(|(_, _, s)| *s)
            .fold(0.0f32, |a, b| a.max(b));

        let cumulative_score = matched_patterns
            .iter()
            .map(|(_, _, s)| *s)
            .sum::<f32>()
            .min(1.0);

        let risk_score = (max_score + cumulative_score) / 2.0;

        // Determine activity type based on patterns found
        let activity_type = if matched_patterns
            .iter()
            .any(|(_, n, _)| n.contains("powershell"))
        {
            OfficeActivityType::MacroPowerShell
        } else if matched_patterns.iter().any(|(_, n, _)| n.contains("shell")) {
            OfficeActivityType::MacroShellExec
        } else if matched_patterns
            .iter()
            .any(|(_, n, _)| n.contains("download"))
        {
            OfficeActivityType::MacroDownloadCradle
        } else if matched_patterns
            .iter()
            .any(|(_, n, _)| n.contains("auto_open") || n.contains("autoopen"))
        {
            OfficeActivityType::MacroAutoOpen
        } else if matched_patterns
            .iter()
            .any(|(_, n, _)| n.contains("obfuscation") || n.contains("chr"))
        {
            OfficeActivityType::MacroObfuscation
        } else {
            OfficeActivityType::SuspiciousMacro
        };

        let mut details = HashMap::new();
        details.insert("file_path".to_string(), path.to_string());
        details.insert("doc_type".to_string(), doc_type.to_string());
        details.insert(
            "matched_patterns".to_string(),
            matched_patterns
                .iter()
                .map(|(p, _, _)| *p)
                .collect::<Vec<_>>()
                .join(", "),
        );
        details.insert(
            "pattern_names".to_string(),
            matched_patterns
                .iter()
                .map(|(_, n, _)| *n)
                .collect::<Vec<_>>()
                .join(", "),
        );
        details.insert(
            "description".to_string(),
            format!(
                "Suspicious VBA patterns detected: {}",
                matched_patterns
                    .iter()
                    .map(|(_, n, _)| *n)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );

        Some((activity_type, details, risk_score))
    }

    /// Create a telemetry event for Office/Email activity
    fn create_office_event(
        activity_type: OfficeActivityType,
        pid: u32,
        process_name: String,
        process_path: String,
        file_path: Option<String>,
        file_type: Option<String>,
        details: HashMap<String, String>,
        risk_score: f32,
    ) -> TelemetryEvent {
        let user = Self::get_current_user();
        let mitre_technique = activity_type.mitre_technique().to_string();

        let office_event = OfficeEmailEvent {
            activity_type,
            pid,
            process_name: process_name.clone(),
            process_path: process_path.clone(),
            user: user.clone(),
            file_path: file_path.clone(),
            file_type: file_type.clone(),
            details: details.clone(),
            risk_score,
            mitre_technique: mitre_technique.clone(),
        };

        // Determine the appropriate EventType based on the activity
        let event_type = match activity_type {
            // Email-related events
            OfficeActivityType::PhishingLinkDetected
            | OfficeActivityType::SuspiciousAttachment
            | OfficeActivityType::EmailSpoofing
            | OfficeActivityType::BecPattern
            | OfficeActivityType::EmailRuleCreated
            | OfficeActivityType::EmailRuleModified
            | OfficeActivityType::AutoForwardingEnabled
            | OfficeActivityType::PstOstAccess
            | OfficeActivityType::MailClientCompromise
            | OfficeActivityType::MassEmailAccess
            | OfficeActivityType::EmailArchiveCreation
            | OfficeActivityType::MailFolderExport => EventType::EmailPhishing,

            // Office document threats
            _ => EventType::OfficeDocMacro,
        };

        // Create base event with Custom payload containing the office event
        let mut event = TelemetryEvent::new(
            event_type,
            activity_type.severity(),
            EventPayload::Custom(serde_json::to_value(&office_event).unwrap_or_default()),
        );

        // Add detection
        event.add_detection(Detection {
            detection_type: DetectionType::OfficeEmail,
            rule_name: format!("office_{}", activity_type.as_str()),
            confidence: risk_score,
            description: details
                .get("description")
                .cloned()
                .unwrap_or_else(|| format!("Office activity detected: {}", activity_type.as_str())),
            mitre_tactics: Self::get_mitre_tactics(&activity_type),
            mitre_techniques: vec![mitre_technique],
        });

        // Add metadata
        event.metadata.insert(
            "activity_type".to_string(),
            activity_type.as_str().to_string(),
        );
        event
            .metadata
            .insert("process_name".to_string(), process_name);
        event
            .metadata
            .insert("process_path".to_string(), process_path);
        event.metadata.insert("user".to_string(), user);
        event
            .metadata
            .insert("risk_score".to_string(), risk_score.to_string());

        if let Some(fp) = file_path {
            event.metadata.insert("file_path".to_string(), fp);
        }
        if let Some(ft) = file_type {
            event.metadata.insert("file_type".to_string(), ft);
        }

        for (key, value) in details {
            event.metadata.insert(key, value);
        }

        event
    }

    fn get_mitre_tactics(activity_type: &OfficeActivityType) -> Vec<String> {
        match activity_type {
            OfficeActivityType::EmailRuleCreated
            | OfficeActivityType::EmailRuleModified
            | OfficeActivityType::AutoForwardingEnabled
            | OfficeActivityType::AddInInstalled
            | OfficeActivityType::MaliciousAddIn
            | OfficeActivityType::ComAddInLoaded => {
                vec!["persistence".to_string()]
            }
            OfficeActivityType::PhishingLinkDetected
            | OfficeActivityType::SuspiciousAttachment
            | OfficeActivityType::EmailSpoofing
            | OfficeActivityType::BecPattern => {
                vec!["initial-access".to_string()]
            }
            OfficeActivityType::PstOstAccess
            | OfficeActivityType::MassEmailAccess
            | OfficeActivityType::EmailArchiveCreation
            | OfficeActivityType::MailFolderExport
            | OfficeActivityType::MailClientCompromise => {
                vec!["collection".to_string()]
            }
            OfficeActivityType::MacroEnabledDocument
            | OfficeActivityType::SuspiciousMacro
            | OfficeActivityType::MacroAutoOpen
            | OfficeActivityType::MacroShellExec
            | OfficeActivityType::MacroPowerShell
            | OfficeActivityType::MacroDownloadCradle
            | OfficeActivityType::MacroObfuscation
            | OfficeActivityType::OfficeSpawningChild
            | OfficeActivityType::OfficeCreatingExecutable => {
                vec!["execution".to_string()]
            }
            OfficeActivityType::DdeExploitation | OfficeActivityType::OleExploitation => {
                vec!["execution".to_string(), "initial-access".to_string()]
            }
            OfficeActivityType::OfficeNetworkConnection => {
                vec!["command-and-control".to_string()]
            }
            OfficeActivityType::OfficeSensitiveAccess => {
                vec!["collection".to_string(), "credential-access".to_string()]
            }
            OfficeActivityType::RemoteTemplateLoad
            | OfficeActivityType::TemplateDirectoryChange
            | OfficeActivityType::TemplateAttack => {
                vec!["defense-evasion".to_string(), "execution".to_string()]
            }
        }
    }

    fn get_current_user() -> String {
        #[cfg(target_os = "windows")]
        {
            std::env::var("USERNAME").unwrap_or_else(|_| "unknown".to_string())
        }

        #[cfg(not(target_os = "windows"))]
        {
            std::env::var("USER").unwrap_or_else(|_| "unknown".to_string())
        }
    }
}
