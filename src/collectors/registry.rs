//! Windows Registry Monitor
//!
//! Monitors registry for suspicious modifications that indicate:
//! - Persistence mechanisms (Run keys, services, scheduled tasks)
//! - Credential theft (SAM, LSA secrets access)
//! - Defense evasion (security policy modifications)
//! - Lateral movement (Remote Desktop, WinRM settings)
//!
//! Uses RegNotifyChangeKeyValue for real-time monitoring and polling
//! for detailed value enumeration after changes are detected.
//!
//! MITRE ATT&CK Mappings:
//! - T1547: Boot or Logon Autostart Execution
//! - T1543: Create or Modify System Process
//! - T1546: Event Triggered Execution
//! - T1053: Scheduled Task/Job
//! - T1003: OS Credential Dumping
//! - T1562: Impair Defenses
//! - T1021: Remote Services

// Registry monitor. Scaffolded fields and parameters retained for upcoming
// monitored-key expansion and platform-specific code paths.
#![allow(dead_code, unused_variables)]

use super::{
    Detection, DetectionType, EventPayload, EventType, RegistryEvent, Severity, TelemetryEvent,
};
use crate::config::AgentConfig;
use std::collections::{HashMap, HashSet};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// High-value registry keys for persistence - T1547, T1543, T1546, T1053
const PERSISTENCE_KEYS: &[(&str, &str, &str)] = &[
    // Run keys - T1547.001
    (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "T1547.001",
        "Registry Run Keys",
    ),
    (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "T1547.001",
        "Registry RunOnce Keys",
    ),
    (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
        "T1547.001",
        "Registry RunOnceEx Keys",
    ),
    (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        "T1547.001",
        "Registry RunServices Keys",
    ),
    (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        "T1547.001",
        "Registry RunServicesOnce Keys",
    ),
    (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        "T1547.001",
        "Policies Run Keys",
    ),
    // Services - T1543.003
    (
        r"SYSTEM\CurrentControlSet\Services",
        "T1543.003",
        "Windows Service",
    ),
    (
        r"SYSTEM\ControlSet001\Services",
        "T1543.003",
        "Windows Service (ControlSet001)",
    ),
    (
        r"SYSTEM\ControlSet002\Services",
        "T1543.003",
        "Windows Service (ControlSet002)",
    ),
    // Winlogon - T1547.004
    (
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "T1547.004",
        "Winlogon Helper",
    ),
    (
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",
        "T1547.004",
        "Winlogon Notify",
    ),
    (
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
        "T1547.004",
        "Winlogon Userinit",
    ),
    (
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
        "T1547.004",
        "Winlogon Shell",
    ),
    // Image File Execution Options - T1546.012
    (
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        "T1546.012",
        "IFEO Injection",
    ),
    (
        r"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        "T1546.012",
        "IFEO Injection (32-bit)",
    ),
    // AppInit_DLLs - T1546.010
    (
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        "T1546.010",
        "AppInit DLLs",
    ),
    (
        r"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
        "T1546.010",
        "AppInit DLLs (32-bit)",
    ),
    // Scheduled Tasks - T1053.005
    (
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache",
        "T1053.005",
        "Scheduled Task",
    ),
    (
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks",
        "T1053.005",
        "Scheduled Task Tasks",
    ),
    (
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree",
        "T1053.005",
        "Scheduled Task Tree",
    ),
    // COM Objects - T1546.015
    (r"SOFTWARE\Classes\CLSID", "T1546.015", "COM Hijacking"),
    (
        r"SOFTWARE\Classes\Wow6432Node\CLSID",
        "T1546.015",
        "COM Hijacking (32-bit)",
    ),
    // Shell extensions - T1546
    (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
        "T1546",
        "Shell Extension",
    ),
    (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad",
        "T1546",
        "Shell Service Object",
    ),
    // Explorer Load - T1547.001
    (
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\Load",
        "T1547.001",
        "Windows Load Key",
    ),
    // AppCert DLLs - T1546.009
    (
        r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls",
        "T1546.009",
        "AppCert DLLs",
    ),
    // Known DLLs - T1574.001
    (
        r"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs",
        "T1574.001",
        "Known DLLs",
    ),
    // Boot Execute - T1547.001
    (
        r"SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute",
        "T1547.001",
        "Boot Execute",
    ),
    // Print Monitor - T1547.010
    (
        r"SYSTEM\CurrentControlSet\Control\Print\Monitors",
        "T1547.010",
        "Print Monitor",
    ),
    // Security Providers - T1547.005
    (
        r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SecurityProviders",
        "T1547.005",
        "Security Support Provider",
    ),
    // Netsh Helper - T1546.007
    (r"SOFTWARE\Microsoft\NetSh", "T1546.007", "Netsh Helper DLL"),
];

/// Credential-related registry keys - T1003
const CREDENTIAL_KEYS: &[(&str, &str, &str)] = &[
    (r"SAM", "T1003.002", "SAM Database"),
    (r"SAM\SAM", "T1003.002", "SAM Database"),
    (r"SAM\SAM\Domains", "T1003.002", "SAM Domains"),
    (r"SAM\SAM\Domains\Account", "T1003.002", "SAM Account"),
    (r"SECURITY", "T1003.004", "LSA Secrets"),
    (r"SECURITY\Policy", "T1003.004", "Security Policy"),
    (r"SECURITY\Policy\Secrets", "T1003.004", "LSA Secrets"),
    (r"SECURITY\Cache", "T1003.005", "Cached Credentials"),
    (
        r"SYSTEM\CurrentControlSet\Control\Lsa",
        "T1003.001",
        "LSASS Configuration",
    ),
    (
        r"SYSTEM\CurrentControlSet\Control\Lsa\JD",
        "T1003.001",
        "DPAPI Keys",
    ),
    (
        r"SYSTEM\CurrentControlSet\Control\Lsa\Skew1",
        "T1003.001",
        "DPAPI Skew",
    ),
    (
        r"SYSTEM\CurrentControlSet\Control\Lsa\GBG",
        "T1003.001",
        "DPAPI GBG",
    ),
    (
        r"SYSTEM\CurrentControlSet\Control\Lsa\Data",
        "T1003.001",
        "LSA Data",
    ),
    (
        r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
        "T1003",
        "WDigest Authentication",
    ),
    (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers",
        "T1003",
        "Credential Providers",
    ),
];

/// Security policy registry keys - T1562
const SECURITY_POLICY_KEYS: &[(&str, &str, &str)] = &[
    (
        r"SOFTWARE\Policies\Microsoft\Windows Defender",
        "T1562.001",
        "Windows Defender Policy",
    ),
    (
        r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        "T1562.001",
        "Defender Real-Time Protection",
    ),
    (
        r"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet",
        "T1562.001",
        "Defender SpyNet",
    ),
    (
        r"SOFTWARE\Microsoft\Windows Defender",
        "T1562.001",
        "Windows Defender Settings",
    ),
    (
        r"SOFTWARE\Microsoft\Windows Defender\Features",
        "T1562.001",
        "Defender Features",
    ),
    (
        r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
        "T1562.001",
        "Defender RTP Settings",
    ),
    (
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy",
        "T1562.004",
        "Firewall Policy",
    ),
    (
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
        "T1562.004",
        "Firewall Standard Profile",
    ),
    (
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
        "T1562.004",
        "Firewall Domain Profile",
    ),
    (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "T1548.002",
        "UAC Settings",
    ),
    (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA",
        "T1548.002",
        "UAC Enable",
    ),
    (
        r"SYSTEM\CurrentControlSet\Services\EventLog",
        "T1562.002",
        "Event Log Settings",
    ),
    (
        r"SYSTEM\CurrentControlSet\Services\EventLog\Security",
        "T1562.002",
        "Security Event Log",
    ),
    (
        r"SYSTEM\CurrentControlSet\Services\EventLog\System",
        "T1562.002",
        "System Event Log",
    ),
    (
        r"SYSTEM\CurrentControlSet\Services\EventLog\Application",
        "T1562.002",
        "Application Event Log",
    ),
    (
        r"SOFTWARE\Microsoft\AMSI",
        "T1562.001",
        "AMSI Configuration",
    ),
    (
        r"SOFTWARE\Microsoft\AMSI\Providers",
        "T1562.001",
        "AMSI Providers",
    ),
    (
        r"SOFTWARE\Policies\Microsoft\Windows\PowerShell",
        "T1562.001",
        "PowerShell Policy",
    ),
    (
        r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
        "T1562.001",
        "PowerShell Logging",
    ),
    (
        r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging",
        "T1562.001",
        "PowerShell Module Logging",
    ),
    (
        r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription",
        "T1562.001",
        "PowerShell Transcription",
    ),
    (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        "T1112",
        "Explorer Advanced Settings",
    ),
];

/// Remote access registry keys - T1021
const REMOTE_ACCESS_KEYS: &[(&str, &str, &str)] = &[
    (
        r"SYSTEM\CurrentControlSet\Control\Terminal Server",
        "T1021.001",
        "RDP Settings",
    ),
    (
        r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
        "T1021.001",
        "RDP WinStation",
    ),
    (
        r"SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections",
        "T1021.001",
        "RDP Deny Connections",
    ),
    (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN",
        "T1021.006",
        "WinRM Configuration",
    ),
    (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service",
        "T1021.006",
        "WinRM Service",
    ),
    (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Client",
        "T1021.006",
        "WinRM Client",
    ),
    (
        r"SOFTWARE\Policies\Microsoft\Windows\WinRM",
        "T1021.006",
        "WinRM Policy",
    ),
    (r"SOFTWARE\OpenSSH", "T1021.004", "SSH Configuration"),
    (
        r"SYSTEM\CurrentControlSet\Services\sshd",
        "T1021.004",
        "SSH Service",
    ),
    (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\AdminDebug",
        "T1021.002",
        "Admin Debug (SMB)",
    ),
];

/// Suspicious value patterns that indicate malicious activity
const SUSPICIOUS_PATTERNS: &[(&str, &str)] = &[
    ("powershell", "PowerShell execution"),
    ("pwsh", "PowerShell Core execution"),
    ("cmd.exe", "Command shell execution"),
    ("cmd /c", "Command shell execution"),
    ("cmd /k", "Command shell execution"),
    ("wscript", "Windows Script Host"),
    ("cscript", "Console Script Host"),
    ("mshta", "MSHTA execution"),
    ("rundll32", "Rundll32 usage"),
    ("regsvr32", "Regsvr32 usage"),
    ("certutil", "Certutil usage"),
    ("bitsadmin", "BitsAdmin usage"),
    ("msiexec", "MSI execution"),
    ("-enc", "Encoded PowerShell"),
    ("-encodedcommand", "Encoded command"),
    ("-e ", "Encoded PowerShell short"),
    ("-nop", "No profile PowerShell"),
    ("-noprofile", "No profile PowerShell"),
    ("-w hidden", "Hidden window"),
    ("-windowstyle hidden", "Hidden window"),
    ("downloadstring", "Download operation"),
    ("downloadfile", "Download file"),
    ("invoke-expression", "Dynamic execution"),
    ("iex(", "Dynamic execution short"),
    ("invoke-webrequest", "Web request"),
    ("net.webclient", "Web client"),
    ("bypass", "Execution bypass"),
    ("http://", "HTTP URL"),
    ("https://", "HTTPS URL"),
    ("ftp://", "FTP URL"),
    ("\\\\", "UNC path"),
    ("vbscript:", "VBScript URL"),
    ("javascript:", "JavaScript URL"),
    ("scrobj.dll", "Script Component Runtime"),
    ("comsvcs.dll", "COM+ Services (dumping)"),
    ("mimilib", "Mimikatz library"),
    ("sekurlsa", "Mimikatz module"),
    ("wce.exe", "Windows Credential Editor"),
    ("gsecdump", "Credential dumper"),
    ("procdump", "Process dumper"),
];

/// Registry operation types for detailed tracking
#[derive(Debug, Clone, PartialEq)]
pub enum RegistryOperation {
    KeyCreate,
    KeyDelete,
    ValueSet,
    ValueDelete,
    SecurityChange,
}

impl std::fmt::Display for RegistryOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistryOperation::KeyCreate => write!(f, "key_create"),
            RegistryOperation::KeyDelete => write!(f, "key_delete"),
            RegistryOperation::ValueSet => write!(f, "value_set"),
            RegistryOperation::ValueDelete => write!(f, "value_delete"),
            RegistryOperation::SecurityChange => write!(f, "security_change"),
        }
    }
}

/// Snapshot of registry key values for change detection
#[derive(Debug, Clone)]
struct KeySnapshot {
    values: HashMap<String, ValueData>,
    subkeys: HashSet<String>,
    security_descriptor: Option<String>,
}

/// Registry value data
#[derive(Debug, Clone, PartialEq)]
struct ValueData {
    value_type: u32,
    data: Vec<u8>,
    data_string: String,
}

/// Registry collector with comprehensive monitoring
pub struct RegistryCollector {
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    monitored_keys: HashMap<String, (&'static str, &'static str)>,
}

impl RegistryCollector {
    /// Create a new registry collector
    pub fn new(config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(1000);

        // Build monitored keys map
        let mut monitored_keys = HashMap::new();
        for (key, technique, description) in PERSISTENCE_KEYS
            .iter()
            .chain(CREDENTIAL_KEYS.iter())
            .chain(SECURITY_POLICY_KEYS.iter())
            .chain(REMOTE_ACCESS_KEYS.iter())
        {
            monitored_keys.insert(key.to_lowercase(), (*technique, *description));
        }

        // Start monitoring in background
        let config_clone = config.clone();
        let monitored_keys_clone = monitored_keys.clone();
        std::thread::spawn(move || {
            if let Err(e) = Self::monitor_registry(tx, config_clone, monitored_keys_clone) {
                error!(error = %e, "Registry collector error");
            }
        });

        Self {
            config: config.clone(),
            event_rx: rx,
            monitored_keys,
        }
    }

    #[cfg(target_os = "windows")]
    fn monitor_registry(
        tx: mpsc::Sender<TelemetryEvent>,
        config: AgentConfig,
        monitored_keys: HashMap<String, (&'static str, &'static str)>,
    ) -> anyhow::Result<()> {
        use windows::Win32::Foundation::*;
        use windows::Win32::System::Registry::*;

        use std::ffi::OsString;
        use std::os::windows::ffi::OsStrExt;

        info!(
            "Windows Registry collector started - monitoring {} key patterns",
            monitored_keys.len()
        );

        // Keys to actively monitor with RegNotifyChangeKeyValue
        let keys_to_watch: Vec<(HKEY, &str, bool)> = vec![
            // HKLM persistence keys
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                true,
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                true,
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
                true,
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services",
                false,
            ), // Don't recurse - too many events
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                true,
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
                false,
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Policies\Microsoft\Windows Defender",
                true,
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows Defender",
                true,
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Lsa",
                true,
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
                true,
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Terminal Server",
                true,
            ),
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\AMSI", true),
            // HKCU persistence keys
            (
                HKEY_CURRENT_USER,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                true,
            ),
            (
                HKEY_CURRENT_USER,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                true,
            ),
            (
                HKEY_CURRENT_USER,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
                true,
            ),
            // High-security keys (credential access)
            (HKEY_LOCAL_MACHINE, r"SAM\SAM", false),
            (HKEY_LOCAL_MACHINE, r"SECURITY", false),
        ];

        // Store key snapshots for change detection
        let snapshots: std::sync::Arc<std::sync::Mutex<HashMap<String, KeySnapshot>>> =
            std::sync::Arc::new(std::sync::Mutex::new(HashMap::new()));

        for (root_key, subkey, watch_subtree) in keys_to_watch {
            let tx_clone = tx.clone();
            let monitored_keys_clone = monitored_keys.clone();
            let config_clone = config.clone();
            let snapshots_clone = snapshots.clone();

            std::thread::spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        error!(error = %e, "Failed to create tokio runtime for registry monitor");
                        return;
                    }
                };

                let subkey_wide: Vec<u16> = OsString::from(subkey)
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect();

                unsafe {
                    let mut key_handle = HKEY::default();
                    let result = RegOpenKeyExW(
                        root_key,
                        windows::core::PCWSTR(subkey_wide.as_ptr()),
                        0,
                        KEY_NOTIFY | KEY_READ | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE,
                        &mut key_handle,
                    );

                    if result.is_err() {
                        // Some keys are expected to fail (require SYSTEM privileges)
                        let expected_failures = ["SAM\\SAM", "SECURITY"];
                        let is_expected = expected_failures.iter().any(|k| subkey.contains(k));

                        if is_expected {
                            debug!(key = %subkey, "Cannot access system-protected registry key (requires SYSTEM privileges)");
                        } else {
                            warn!(key = %subkey, "Failed to open registry key for monitoring");
                        }
                        return;
                    }

                    let full_key = Self::format_root_key(root_key, subkey);
                    debug!(key = %full_key, "Started monitoring registry key");

                    // Take initial snapshot
                    if let Ok(snapshot) = Self::take_key_snapshot(key_handle, &full_key) {
                        if let Ok(mut snaps) = snapshots_clone.lock() {
                            snaps.insert(full_key.clone(), snapshot);
                        }
                    }

                    loop {
                        // Build notification flags
                        let mut notify_filter = REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET;

                        // Add security descriptor monitoring for sensitive keys
                        if full_key.to_lowercase().contains("sam")
                            || full_key.to_lowercase().contains("security")
                            || full_key.to_lowercase().contains("lsa")
                        {
                            notify_filter |= REG_NOTIFY_CHANGE_SECURITY;
                        }

                        let wait_result = RegNotifyChangeKeyValue(
                            key_handle,
                            watch_subtree,
                            notify_filter,
                            HANDLE::default(),
                            false,
                        );

                        if wait_result.is_err() {
                            break;
                        }

                        info!(key = %full_key, "Registry change detected");

                        // Take new snapshot and compare
                        if let Ok(new_snapshot) = Self::take_key_snapshot(key_handle, &full_key) {
                            let old_snapshot = {
                                snapshots_clone
                                    .lock()
                                    .ok()
                                    .and_then(|snaps| snaps.get(&full_key).cloned())
                            };

                            // Detect specific changes
                            let changes = Self::detect_changes(
                                old_snapshot.as_ref(),
                                &new_snapshot,
                                &full_key,
                            );

                            // Update snapshot
                            if let Ok(mut snaps) = snapshots_clone.lock() {
                                snaps.insert(full_key.clone(), new_snapshot);
                            }

                            // Create events for each detected change
                            for (operation, value_name, value_data, old_data) in changes {
                                // Try to get the process that made the change
                                let (pid, process_name) = Self::get_modifying_process();

                                if let Some(event) = Self::create_registry_event(
                                    &full_key,
                                    &operation.to_string(),
                                    value_name.as_deref(),
                                    value_data.as_deref(),
                                    old_data.as_deref(),
                                    pid,
                                    &process_name,
                                    &monitored_keys_clone,
                                ) {
                                    let _ = rt.block_on(tx_clone.send(event));
                                }
                            }
                        }
                    }

                    let _ = RegCloseKey(key_handle);
                }
            });
        }

        // Keep main thread alive
        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    }

    #[cfg(target_os = "windows")]
    fn format_root_key(root: windows::Win32::System::Registry::HKEY, subkey: &str) -> String {
        use windows::Win32::System::Registry::*;

        let root_name = if root == HKEY_LOCAL_MACHINE {
            "HKLM"
        } else if root == HKEY_CURRENT_USER {
            "HKCU"
        } else if root == HKEY_CLASSES_ROOT {
            "HKCR"
        } else if root == HKEY_USERS {
            "HKU"
        } else {
            "UNKNOWN"
        };

        format!("{}\\{}", root_name, subkey)
    }

    #[cfg(target_os = "windows")]
    fn take_key_snapshot(
        key_handle: windows::Win32::System::Registry::HKEY,
        key_path: &str,
    ) -> anyhow::Result<KeySnapshot> {
        use windows::Win32::System::Registry::*;

        let mut values = HashMap::new();
        let mut subkeys = HashSet::new();

        unsafe {
            // Enumerate values
            let mut index = 0u32;
            loop {
                let mut name_buf = vec![0u16; 16384];
                let mut name_len = name_buf.len() as u32;
                let mut value_type = 0u32;
                let mut data_buf = vec![0u8; 65536];
                let mut data_len = data_buf.len() as u32;

                let result = RegEnumValueW(
                    key_handle,
                    index,
                    windows::core::PWSTR(name_buf.as_mut_ptr()),
                    &mut name_len,
                    None,
                    Some(&mut value_type),
                    Some(data_buf.as_mut_ptr()),
                    Some(&mut data_len),
                );

                if result.is_err() {
                    break;
                }

                let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                let data = data_buf[..data_len as usize].to_vec();
                let data_string = Self::format_value_data(value_type, &data);

                values.insert(
                    name,
                    ValueData {
                        value_type,
                        data,
                        data_string,
                    },
                );

                index += 1;
            }

            // Enumerate subkeys
            let mut index = 0u32;
            loop {
                let mut name_buf = vec![0u16; 256];
                let mut name_len = name_buf.len() as u32;

                let result = RegEnumKeyExW(
                    key_handle,
                    index,
                    windows::core::PWSTR(name_buf.as_mut_ptr()),
                    &mut name_len,
                    None,
                    windows::core::PWSTR::null(),
                    None,
                    None,
                );

                if result.is_err() {
                    break;
                }

                let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                subkeys.insert(name);

                index += 1;
            }

            // Get security descriptor for sensitive keys
            let security_descriptor = Self::get_key_security_descriptor(key_handle);

            Ok(KeySnapshot {
                values,
                subkeys,
                security_descriptor,
            })
        }
    }

    #[cfg(target_os = "windows")]
    fn get_key_security_descriptor(
        key_handle: windows::Win32::System::Registry::HKEY,
    ) -> Option<String> {
        use windows::Win32::Foundation::*;
        use windows::Win32::Security::Authorization::*;
        use windows::Win32::Security::*;
        use windows::Win32::System::Registry::*;

        unsafe {
            let mut sd_size = 0u32;
            let _ = RegGetKeySecurity(
                key_handle,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                PSECURITY_DESCRIPTOR::default(),
                &mut sd_size,
            );

            if sd_size == 0 {
                return None;
            }

            let mut sd_buf = vec![0u8; sd_size as usize];
            let result = RegGetKeySecurity(
                key_handle,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                PSECURITY_DESCRIPTOR(sd_buf.as_mut_ptr() as *mut _),
                &mut sd_size,
            );

            if result.is_err() {
                return None;
            }

            // Convert to SDDL string
            let mut sddl_ptr: windows::core::PWSTR = windows::core::PWSTR::null();
            let convert_result = ConvertSecurityDescriptorToStringSecurityDescriptorW(
                PSECURITY_DESCRIPTOR(sd_buf.as_ptr() as *mut _),
                SDDL_REVISION_1,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut sddl_ptr,
                None,
            );

            if convert_result.is_ok() && !sddl_ptr.is_null() {
                let sddl = sddl_ptr.to_string().ok();
                let _ = LocalFree(HLOCAL(sddl_ptr.as_ptr() as *mut _));
                sddl
            } else {
                None
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn format_value_data(value_type: u32, data: &[u8]) -> String {
        use windows::Win32::System::Registry::*;

        match REG_VALUE_TYPE(value_type) {
            REG_SZ | REG_EXPAND_SZ => {
                // Convert wide string to String
                if data.len() >= 2 {
                    let wide: Vec<u16> = data
                        .chunks_exact(2)
                        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                        .collect();
                    String::from_utf16_lossy(&wide)
                        .trim_end_matches('\0')
                        .to_string()
                } else {
                    String::new()
                }
            }
            REG_MULTI_SZ => {
                // Multiple null-terminated strings
                if data.len() >= 2 {
                    let wide: Vec<u16> = data
                        .chunks_exact(2)
                        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                        .collect();
                    String::from_utf16_lossy(&wide)
                        .trim_end_matches('\0')
                        .replace('\0', "; ")
                } else {
                    String::new()
                }
            }
            REG_DWORD => {
                if data.len() >= 4 {
                    let value = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                    format!("0x{:08X} ({})", value, value)
                } else {
                    String::new()
                }
            }
            REG_QWORD => {
                if data.len() >= 8 {
                    let value = u64::from_le_bytes([
                        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                    ]);
                    format!("0x{:016X} ({})", value, value)
                } else {
                    String::new()
                }
            }
            REG_BINARY => {
                // Show hex and attempt ASCII interpretation
                let hex: String = data.iter().take(64).map(|b| format!("{:02X}", b)).collect();
                let printable: String = data
                    .iter()
                    .take(32)
                    .map(|&b| {
                        if b >= 0x20 && b < 0x7f {
                            b as char
                        } else {
                            '.'
                        }
                    })
                    .collect();
                if data.len() > 64 {
                    format!("{}... ({}B) [{}...]", hex, data.len(), printable)
                } else {
                    format!("{} [{}]", hex, printable)
                }
            }
            _ => {
                format!("(type:{}) {:?}", value_type, &data[..data.len().min(32)])
            }
        }
    }

    fn detect_changes(
        old: Option<&KeySnapshot>,
        new: &KeySnapshot,
        _key_path: &str,
    ) -> Vec<(
        RegistryOperation,
        Option<String>,
        Option<String>,
        Option<String>,
    )> {
        let mut changes = Vec::new();

        match old {
            Some(old_snapshot) => {
                // Check for new or modified values
                for (name, new_data) in &new.values {
                    match old_snapshot.values.get(name) {
                        Some(old_data) if old_data != new_data => {
                            // Value modified
                            changes.push((
                                RegistryOperation::ValueSet,
                                Some(name.clone()),
                                Some(new_data.data_string.clone()),
                                Some(old_data.data_string.clone()),
                            ));
                        }
                        None => {
                            // New value
                            changes.push((
                                RegistryOperation::ValueSet,
                                Some(name.clone()),
                                Some(new_data.data_string.clone()),
                                None,
                            ));
                        }
                        _ => {}
                    }
                }

                // Check for deleted values
                for name in old_snapshot.values.keys() {
                    if !new.values.contains_key(name) {
                        changes.push((
                            RegistryOperation::ValueDelete,
                            Some(name.clone()),
                            None,
                            Some(old_snapshot.values[name].data_string.clone()),
                        ));
                    }
                }

                // Check for new subkeys
                for name in &new.subkeys {
                    if !old_snapshot.subkeys.contains(name) {
                        changes.push((
                            RegistryOperation::KeyCreate,
                            Some(name.clone()),
                            None,
                            None,
                        ));
                    }
                }

                // Check for deleted subkeys
                for name in &old_snapshot.subkeys {
                    if !new.subkeys.contains(name) {
                        changes.push((
                            RegistryOperation::KeyDelete,
                            Some(name.clone()),
                            None,
                            None,
                        ));
                    }
                }

                // Check for security descriptor changes
                if old_snapshot.security_descriptor != new.security_descriptor {
                    changes.push((
                        RegistryOperation::SecurityChange,
                        None,
                        new.security_descriptor.clone(),
                        old_snapshot.security_descriptor.clone(),
                    ));
                }
            }
            None => {
                // No previous snapshot - just report current state as new if interesting
                // This typically happens on first run, so we don't flood with events
                // Only report if there's something noteworthy (new persistence)
            }
        }

        changes
    }

    #[cfg(target_os = "windows")]
    fn get_modifying_process() -> (u32, String) {
        // Unfortunately, Windows doesn't directly tell us which process modified a registry key
        // through RegNotifyChangeKeyValue. Options:
        // 1. ETW Registry provider (requires elevated and kernel involvement)
        // 2. Sysmon-style driver
        // 3. Best effort: check recent process activity
        //
        // For now, we return 0/unknown, but the ETW collector can provide this info
        (0, "unknown".to_string())
    }

    #[cfg(not(target_os = "windows"))]
    fn monitor_registry(
        _tx: mpsc::Sender<TelemetryEvent>,
        _config: AgentConfig,
        _monitored_keys: HashMap<String, (&'static str, &'static str)>,
    ) -> anyhow::Result<()> {
        info!("Registry collector only available on Windows");
        // Keep thread alive to prevent immediate exit
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    }

    fn create_registry_event(
        key: &str,
        operation: &str,
        value_name: Option<&str>,
        value_data: Option<&str>,
        old_value_data: Option<&str>,
        pid: u32,
        process_name: &str,
        monitored_keys: &HashMap<String, (&'static str, &'static str)>,
    ) -> Option<TelemetryEvent> {
        let key_lower = key.to_lowercase();

        // Find matching monitored key
        let (technique, description) = monitored_keys
            .iter()
            .find(|(k, _)| key_lower.contains(k.as_str()))
            .map(|(_, v)| *v)
            .unwrap_or(("", ""));

        // Determine event type based on operation
        let event_type = match operation {
            "key_create" => EventType::RegistryCreate,
            "key_delete" => EventType::RegistryDelete,
            "value_set" => EventType::RegistrySetValue,
            "value_delete" => EventType::RegistryDelete,
            "security_change" => EventType::RegistrySetValue,
            _ => EventType::RegistrySetValue,
        };

        // Determine severity
        let severity = Self::determine_severity(&key_lower, operation, value_data, old_value_data);

        // Only report significant events
        if technique.is_empty() && severity == Severity::Info {
            return None;
        }

        let mut event = TelemetryEvent::new(
            event_type,
            severity.clone(),
            EventPayload::Registry(RegistryEvent {
                key_path: key.to_string(),
                value_name: value_name.map(String::from),
                value_data: value_data.map(String::from),
                operation: operation.to_string(),
                pid,
                process_name: process_name.to_string(),
            }),
        );

        // Add metadata for old value if this was a modification
        if let Some(old_data) = old_value_data {
            event
                .metadata
                .insert("old_value".to_string(), old_data.to_string());
        }

        // Add security descriptor change details
        if operation == "security_change" {
            event
                .metadata
                .insert("security_change".to_string(), "true".to_string());
        }

        // Add MITRE detection
        if !technique.is_empty() {
            event.add_detection(Detection {
                detection_type: DetectionType::Behavioral,
                rule_name: format!("registry_{}", technique.to_lowercase().replace(".", "_")),
                confidence: 0.85,
                description: format!("Registry modification: {}", description),
                mitre_tactics: Self::get_tactics(technique),
                mitre_techniques: vec![technique.to_string()],
            });
        }

        // Check for suspicious patterns in value data
        if let Some(data) = value_data {
            let data_lower = data.to_lowercase();
            for (pattern, desc) in SUSPICIOUS_PATTERNS {
                if data_lower.contains(pattern) {
                    event.add_detection(Detection {
                        detection_type: DetectionType::Behavioral,
                        rule_name: format!(
                            "registry_suspicious_{}",
                            pattern.replace(['.', '/', '\\', ' '], "_")
                        ),
                        confidence: 0.90,
                        description: format!("Suspicious pattern in registry: {}", desc),
                        mitre_tactics: vec!["Execution".to_string(), "Defense Evasion".to_string()],
                        mitre_techniques: vec!["T1059".to_string(), "T1027".to_string()],
                    });
                    // Don't break - collect all matching patterns
                }
            }
        }

        // Special handling for specific high-severity changes
        if operation == "security_change"
            && (key_lower.contains("sam")
                || key_lower.contains("security")
                || key_lower.contains("lsa"))
        {
            event.severity = Severity::Critical;
            event.add_detection(Detection {
                detection_type: DetectionType::Behavioral,
                rule_name: "registry_security_descriptor_credential_store".to_string(),
                confidence: 0.95,
                description: "Security descriptor changed on credential storage registry key"
                    .to_string(),
                mitre_tactics: vec![
                    "Credential Access".to_string(),
                    "Defense Evasion".to_string(),
                ],
                mitre_techniques: vec!["T1003".to_string(), "T1562".to_string()],
            });
        }

        // Detect defender disabling
        if key_lower.contains("defender")
            && value_data
                .map(|v| v.contains("0x00000001"))
                .unwrap_or(false)
        {
            if value_name
                .map(|v| v.to_lowercase().contains("disable"))
                .unwrap_or(false)
            {
                event.severity = Severity::Critical;
                event.add_detection(Detection {
                    detection_type: DetectionType::Behavioral,
                    rule_name: "registry_defender_disabled".to_string(),
                    confidence: 0.98,
                    description: "Windows Defender component disabled via registry".to_string(),
                    mitre_tactics: vec!["Defense Evasion".to_string()],
                    mitre_techniques: vec!["T1562.001".to_string()],
                });
            }
        }

        Some(event)
    }

    fn determine_severity(
        key: &str,
        operation: &str,
        value_data: Option<&str>,
        _old_value: Option<&str>,
    ) -> Severity {
        // The pattern checks below compare against lowercase literals, so
        // normalize the key first; registry paths arrive in mixed/upper case
        // (e.g. "HKLM\SAM\SAM") and would otherwise never match.
        let key = key.to_lowercase();
        let key = key.as_str();

        // Critical: credential access
        if key.contains("sam") || key.contains("security\\") || key.contains("\\lsa") {
            return Severity::Critical;
        }

        // Critical: disabling security
        if key.contains("defender") || key.contains("firewall") || key.contains("amsi") {
            if operation == "value_set" || operation == "security_change" {
                return Severity::Critical;
            }
            return Severity::High;
        }

        // Critical: Event log tampering
        if key.contains("eventlog") && (operation == "value_set" || operation == "key_delete") {
            return Severity::High;
        }

        // High: persistence with modification
        if (key.contains("\\run")
            || key.contains("services\\")
            || key.contains("winlogon")
            || key.contains("image file execution"))
            && (operation == "key_create" || operation == "value_set")
        {
            // Check for suspicious content
            if let Some(data) = value_data {
                let data_lower = data.to_lowercase();
                if data_lower.contains("powershell")
                    || data_lower.contains("-enc")
                    || data_lower.contains("http")
                    || data_lower.contains("cmd /")
                    || data_lower.contains("wscript")
                    || data_lower.contains("mshta")
                {
                    return Severity::Critical;
                }
            }
            return Severity::High;
        }

        // Medium: other monitored keys with writes
        if operation == "key_create" || operation == "value_set" {
            return Severity::Medium;
        }

        // Low: deletes on non-critical keys
        if operation == "key_delete" || operation == "value_delete" {
            return Severity::Low;
        }

        Severity::Info
    }

    fn get_tactics(technique: &str) -> Vec<String> {
        match technique {
            t if t.starts_with("T1547") || t.starts_with("T1543") || t.starts_with("T1546") => {
                vec![
                    "Persistence".to_string(),
                    "Privilege Escalation".to_string(),
                ]
            }
            t if t.starts_with("T1053") => vec!["Execution".to_string(), "Persistence".to_string()],
            t if t.starts_with("T1003") => vec!["Credential Access".to_string()],
            t if t.starts_with("T1562") => vec!["Defense Evasion".to_string()],
            t if t.starts_with("T1112") => vec!["Defense Evasion".to_string()],
            t if t.starts_with("T1548") => vec![
                "Defense Evasion".to_string(),
                "Privilege Escalation".to_string(),
            ],
            t if t.starts_with("T1021") => vec!["Lateral Movement".to_string()],
            t if t.starts_with("T1574") => vec![
                "Persistence".to_string(),
                "Privilege Escalation".to_string(),
                "Defense Evasion".to_string(),
            ],
            _ => vec![],
        }
    }

    /// Check if a key is a persistence location
    pub fn is_persistence_key(key: &str) -> bool {
        let key_lower = key.to_lowercase();
        PERSISTENCE_KEYS
            .iter()
            .any(|(k, _, _)| key_lower.contains(&k.to_lowercase()))
    }

    /// Check if a key is credential-related
    pub fn is_credential_key(key: &str) -> bool {
        let key_lower = key.to_lowercase();
        CREDENTIAL_KEYS
            .iter()
            .any(|(k, _, _)| key_lower.contains(&k.to_lowercase()))
    }

    /// Check if a key is security-policy related
    pub fn is_security_policy_key(key: &str) -> bool {
        let key_lower = key.to_lowercase();
        SECURITY_POLICY_KEYS
            .iter()
            .any(|(k, _, _)| key_lower.contains(&k.to_lowercase()))
    }

    /// Get next event from collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_persistence_key_detection() {
        assert!(RegistryCollector::is_persistence_key(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\malware"
        ));
        assert!(RegistryCollector::is_persistence_key(
            r"HKLM\SYSTEM\CurrentControlSet\Services\EvilService"
        ));
        assert!(!RegistryCollector::is_persistence_key(
            r"HKLM\SOFTWARE\RandomKey"
        ));
    }

    #[test]
    fn test_credential_key_detection() {
        assert!(RegistryCollector::is_credential_key(
            r"HKLM\SAM\SAM\Domains"
        ));
        assert!(RegistryCollector::is_credential_key(
            r"HKLM\SECURITY\Policy\Secrets"
        ));
        assert!(!RegistryCollector::is_credential_key(r"HKLM\SOFTWARE\Test"));
    }

    #[test]
    fn test_severity_determination() {
        // SAM access should be critical
        let severity =
            RegistryCollector::determine_severity(r"HKLM\SAM\SAM", "value_set", Some("test"), None);
        assert_eq!(severity, Severity::Critical);

        // Defender disable should be critical
        let severity = RegistryCollector::determine_severity(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware",
            "value_set",
            Some("0x00000001"),
            None,
        );
        assert_eq!(severity, Severity::Critical);

        // Run key with PowerShell should be critical
        let severity = RegistryCollector::determine_severity(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "value_set",
            Some("powershell.exe -encodedcommand ..."),
            None,
        );
        assert_eq!(severity, Severity::Critical);
    }

    #[test]
    fn test_suspicious_patterns() {
        let patterns_to_check = [
            "powershell.exe -enc abc123",
            "cmd.exe /c whoami",
            "http://evil.com/payload.exe",
            "rundll32.exe javascript:...",
            "certutil -urlcache -split -f http://...",
        ];

        for pattern in patterns_to_check {
            let pattern_lower = pattern.to_lowercase();
            let matched = SUSPICIOUS_PATTERNS
                .iter()
                .any(|(p, _)| pattern_lower.contains(p));
            assert!(matched, "Pattern '{}' should match", pattern);
        }
    }

    #[test]
    fn test_explorer_advanced_registry_event_maps_to_t1112() {
        let mut monitored_keys = HashMap::new();
        for (key, technique, description) in SECURITY_POLICY_KEYS {
            monitored_keys.insert(key.to_lowercase(), (*technique, *description));
        }

        let event = RegistryCollector::create_registry_event(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "value_set",
            Some("TamanduaBenchMarker"),
            Some("tamandua"),
            None,
            1234,
            "reg.exe",
            &monitored_keys,
        )
        .expect("Explorer Advanced should produce registry telemetry");

        assert_eq!(event.event_type, EventType::RegistrySetValue);
        assert_eq!(event.severity, Severity::Medium);
        assert!(event.detections.iter().any(|detection| {
            detection.rule_name == "registry_t1112"
                && detection.mitre_tactics == ["Defense Evasion"]
                && detection.mitre_techniques == ["T1112"]
        }));
    }
}
