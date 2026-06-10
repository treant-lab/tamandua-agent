//! Comprehensive Credential Theft Detection Collector
//!
//! Detects various credential theft attack vectors including LSASS access:
//!
//! ## Windows Credential Theft Detection
//! - LSASS memory access (T1003.001) - OpenProcess with PROCESS_VM_READ to lsass.exe
//! - SAM Database access (T1003.002)
//! - NTDS.dit access (T1003.003)
//! - DCSync replication attack (T1003.006) - DRS API calls
//! - Security Account Manager registry
//! - Credential Manager/Vault access
//! - Shadow copy SAM access
//!
//! ## Kerberos Attacks
//! - Kerberoasting (T1558.003)
//! - AS-REP Roasting (T1558.004)
//! - Golden/Silver ticket usage (T1558.001)
//! - Pass-the-Hash (T1550.002)
//! - Pass-the-Ticket (T1550.003)
//! - Overpass-the-Hash (T1550.002)
//!
//! ## Application Credentials
//! - Browser credential stores (Chrome Login Data, Firefox logins.json, Edge)
//! - Password managers (KeePass, LastPass)
//! - SSH keys and configs
//! - RDP credentials
//! - PuTTY saved sessions
//! - FileZilla/WinSCP credentials
//!
//! ## Network Credential Theft
//! - LLMNR/NBT-NS poisoning (T1557.001)
//! - NTLM relay detection
//! - Responder-like attacks
//!
//! ## Linux Credential Theft
//! - /etc/shadow access (T1003.008)
//! - SSH key theft (~/.ssh/*)
//! - PAM module modifications
//! - Credential dumping from /proc/*/mem
//! - gnome-keyring access
//! - .netrc, .pgpass files
//!
//! MITRE ATT&CK Techniques:
//! - T1003: OS Credential Dumping
//! - T1003.001: LSASS Memory
//! - T1003.002: Security Account Manager
//! - T1003.003: NTDS
//! - T1003.006: DCSync
//! - T1003.008: /etc/passwd and /etc/shadow
//! - T1552: Unsecured Credentials
//! - T1555: Credentials from Password Stores
//! - T1555.003: Credentials from Web Browsers
//! - T1557: Adversary-in-the-Middle
//! - T1558: Steal or Forge Kerberos Tickets

// Credential theft detector. Registry pattern tables and scaffolded fields retained.
#![allow(dead_code, unused_variables)]

use super::{
    CredentialTheftEvent, Detection, DetectionType, EventPayload, EventType, Severity,
    TelemetryEvent,
};
use crate::config::AgentConfig;
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Credential theft attack categories
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialAttackType {
    /// LSASS memory access
    LsassAccess,
    /// SAM database access
    SamAccess,
    /// NTDS.dit (Active Directory) access
    NtdsAccess,
    /// DCSync replication attack
    DcSync,
    /// Kerberoasting - mass TGS requests
    Kerberoasting,
    /// AS-REP roasting
    AsRepRoasting,
    /// Golden ticket usage
    GoldenTicket,
    /// Silver ticket usage
    SilverTicket,
    /// Pass-the-Hash
    PassTheHash,
    /// Pass-the-Ticket
    PassTheTicket,
    /// Overpass-the-Hash
    OverpassTheHash,
    /// Browser credential theft
    BrowserCredentials,
    /// Password manager access
    PasswordManager,
    /// SSH key theft
    SshKeyTheft,
    /// RDP credential theft
    RdpCredentials,
    /// LLMNR/NBT-NS poisoning
    LlmnrPoisoning,
    /// NTLM relay attack
    NtlmRelay,
    /// Credential Manager/Vault access
    CredentialVault,
    /// Shadow copy credential access
    ShadowCopyAccess,
    /// Linux shadow file access
    LinuxShadow,
    /// Linux /proc/*/mem access
    ProcMemAccess,
    /// PAM module modification
    PamModification,
    /// Generic credential file access
    CredentialFile,
}

impl CredentialAttackType {
    /// Get MITRE technique ID
    pub fn mitre_technique(&self) -> &'static str {
        match self {
            Self::LsassAccess => "T1003.001",
            Self::SamAccess => "T1003.002",
            Self::NtdsAccess => "T1003.003",
            Self::DcSync => "T1003.006",
            Self::Kerberoasting => "T1558.003",
            Self::AsRepRoasting => "T1558.004",
            Self::GoldenTicket => "T1558.001",
            Self::SilverTicket => "T1558.001",
            Self::PassTheHash => "T1550.002",
            Self::PassTheTicket => "T1550.003",
            Self::OverpassTheHash => "T1550.002",
            Self::BrowserCredentials => "T1555.003",
            Self::PasswordManager => "T1555.005",
            Self::SshKeyTheft => "T1552.004",
            Self::RdpCredentials => "T1552.001",
            Self::LlmnrPoisoning => "T1557.001",
            Self::NtlmRelay => "T1557.001",
            Self::CredentialVault => "T1555.004",
            Self::ShadowCopyAccess => "T1003.002",
            Self::LinuxShadow => "T1003.008",
            Self::ProcMemAccess => "T1003.007",
            Self::PamModification => "T1556.003",
            Self::CredentialFile => "T1552.001",
        }
    }

    /// Get attack description
    pub fn description(&self) -> &'static str {
        match self {
            Self::LsassAccess => "LSASS memory access detected - potential credential dumping",
            Self::SamAccess => "SAM database access detected",
            Self::NtdsAccess => "NTDS.dit (Active Directory database) access detected",
            Self::DcSync => "DCSync replication attack detected - domain credential extraction",
            Self::Kerberoasting => "Kerberoasting attack detected (mass TGS requests)",
            Self::AsRepRoasting => "AS-REP Roasting attack detected",
            Self::GoldenTicket => "Golden ticket usage detected",
            Self::SilverTicket => "Silver ticket usage detected",
            Self::PassTheHash => "Pass-the-Hash attack detected",
            Self::PassTheTicket => "Pass-the-Ticket attack detected",
            Self::OverpassTheHash => "Overpass-the-Hash attack detected",
            Self::BrowserCredentials => "Browser credential store access detected",
            Self::PasswordManager => "Password manager database access detected",
            Self::SshKeyTheft => "SSH private key access detected",
            Self::RdpCredentials => "RDP credential file access detected",
            Self::LlmnrPoisoning => "LLMNR/NBT-NS poisoning detected",
            Self::NtlmRelay => "NTLM relay attack detected",
            Self::CredentialVault => "Windows Credential Manager/Vault access detected",
            Self::ShadowCopyAccess => "Shadow copy credential access detected",
            Self::LinuxShadow => "Linux /etc/shadow access detected",
            Self::ProcMemAccess => "/proc/*/mem access detected - potential credential dumping",
            Self::PamModification => {
                "PAM module modification detected - potential credential capture"
            }
            Self::CredentialFile => "Credential file access detected",
        }
    }

    /// Get severity for this attack type
    pub fn severity(&self) -> Severity {
        match self {
            // Critical - Active credential theft from memory or AD
            Self::LsassAccess
            | Self::SamAccess
            | Self::NtdsAccess
            | Self::DcSync
            | Self::GoldenTicket
            | Self::SilverTicket
            | Self::PassTheHash
            | Self::PassTheTicket
            | Self::ProcMemAccess => Severity::Critical,

            // High - Credential theft techniques
            Self::Kerberoasting
            | Self::AsRepRoasting
            | Self::OverpassTheHash
            | Self::LlmnrPoisoning
            | Self::NtlmRelay
            | Self::ShadowCopyAccess
            | Self::LinuxShadow
            | Self::PamModification => Severity::High,

            // Medium - Application credential access
            Self::BrowserCredentials
            | Self::PasswordManager
            | Self::SshKeyTheft
            | Self::RdpCredentials
            | Self::CredentialVault
            | Self::CredentialFile => Severity::Medium,
        }
    }

    /// Get MITRE tactics
    pub fn mitre_tactics(&self) -> Vec<String> {
        match self {
            Self::LsassAccess
            | Self::SamAccess
            | Self::NtdsAccess
            | Self::DcSync
            | Self::LinuxShadow
            | Self::ShadowCopyAccess
            | Self::ProcMemAccess => vec!["credential-access".to_string()],

            Self::Kerberoasting | Self::AsRepRoasting => vec!["credential-access".to_string()],

            Self::GoldenTicket | Self::SilverTicket | Self::PassTheHash | Self::PassTheTicket => {
                vec![
                    "credential-access".to_string(),
                    "lateral-movement".to_string(),
                ]
            }

            Self::OverpassTheHash => vec![
                "credential-access".to_string(),
                "defense-evasion".to_string(),
            ],

            Self::LlmnrPoisoning | Self::NtlmRelay => {
                vec!["credential-access".to_string(), "collection".to_string()]
            }

            Self::PamModification => {
                vec!["credential-access".to_string(), "persistence".to_string()]
            }

            Self::BrowserCredentials
            | Self::PasswordManager
            | Self::SshKeyTheft
            | Self::RdpCredentials
            | Self::CredentialVault
            | Self::CredentialFile => vec!["credential-access".to_string()],
        }
    }

    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LsassAccess => "lsass_access",
            Self::SamAccess => "sam_access",
            Self::NtdsAccess => "ntds_access",
            Self::DcSync => "dcsync",
            Self::Kerberoasting => "kerberoasting",
            Self::AsRepRoasting => "asrep_roasting",
            Self::GoldenTicket => "golden_ticket",
            Self::SilverTicket => "silver_ticket",
            Self::PassTheHash => "pass_the_hash",
            Self::PassTheTicket => "pass_the_ticket",
            Self::OverpassTheHash => "overpass_the_hash",
            Self::BrowserCredentials => "browser_credentials",
            Self::PasswordManager => "password_manager",
            Self::SshKeyTheft => "ssh_key_theft",
            Self::RdpCredentials => "rdp_credentials",
            Self::LlmnrPoisoning => "llmnr_poisoning",
            Self::NtlmRelay => "ntlm_relay",
            Self::CredentialVault => "credential_vault",
            Self::ShadowCopyAccess => "shadow_copy_access",
            Self::LinuxShadow => "linux_shadow",
            Self::ProcMemAccess => "proc_mem_access",
            Self::PamModification => "pam_modification",
            Self::CredentialFile => "credential_file",
        }
    }
}

/// Known Mimikatz and credential tool patterns
const MIMIKATZ_PATTERNS: &[&str] = &[
    "mimikatz",
    "sekurlsa",
    "logonpasswords",
    "lsadump",
    "kerberos::ptt",
    "kerberos::golden",
    "kerberos::silver",
    "privilege::debug",
    // Use Mimikatz-syntax SSP module references to avoid matching legitimate Windows SSP names
    "sekurlsa::wdigest",
    "sekurlsa::livessp",
    "sekurlsa::tspkg",
    "sekurlsa::credman",
    "dpapi::chrome",
    "dpapi::cred",
    "lsass.dmp",
    "procdump -ma lsass",
    // comsvcs.dll abuse patterns - comma context makes these specific to credential dumping
    "comsvcs.dll,minidump",
    "comsvcs.dll,#24", // #24 is the MiniDumpWriteDump ordinal in comsvcs.dll
                       // NOTE: "MiniDumpWriteDump" removed - it is a legitimate Windows API (dbghelp.dll).
                       // Detection of MiniDumpWriteDump targeting lsass.exe is handled by the LSASS access monitor.
];

/// DCSync indicators - DRS API related
const DCSYNC_PATTERNS: &[&str] = &[
    "dcsync",
    "dsgetncchanges",
    "drsuapi",
    // NOTE: "replication" removed - too generic, matches legitimate AD replication tools
    "ms-drsr",
    "drsuapi::drsgetncchanges",
    "secretsdump",
    // Use specific ntdsutil abuse patterns instead of bare "ntdsutil" to avoid false positives
    "ntdsutil ifm",      // Install From Media - used to extract AD database
    "ntdsutil snapshot", // Snapshot creation - used to access AD database offline
    // NOTE: "ifm" removed - 3-letter pattern too generic, "Install From Media" is a legitimate AD operation
    "dsrm",
];

/// Credential file patterns for Windows
#[cfg(target_os = "windows")]
const WINDOWS_CREDENTIAL_PATHS: &[(&str, CredentialAttackType)] = &[
    // SAM database
    (
        r"C:\Windows\System32\config\SAM",
        CredentialAttackType::SamAccess,
    ),
    (
        r"C:\Windows\System32\config\SECURITY",
        CredentialAttackType::SamAccess,
    ),
    (
        r"C:\Windows\System32\config\SYSTEM",
        CredentialAttackType::SamAccess,
    ),
    // NTDS.dit
    (
        r"C:\Windows\NTDS\ntds.dit",
        CredentialAttackType::NtdsAccess,
    ),
    (
        r"C:\Windows\NTDS\ntds.jfm",
        CredentialAttackType::NtdsAccess,
    ),
    // Chrome credentials
    (
        r"AppData\Local\Google\Chrome\User Data\Default\Login Data",
        CredentialAttackType::BrowserCredentials,
    ),
    (
        r"AppData\Local\Google\Chrome\User Data\Default\Cookies",
        CredentialAttackType::BrowserCredentials,
    ),
    (
        r"AppData\Local\Google\Chrome\User Data\Local State",
        CredentialAttackType::BrowserCredentials,
    ),
    // Firefox credentials
    (
        r"AppData\Roaming\Mozilla\Firefox\Profiles",
        CredentialAttackType::BrowserCredentials,
    ),
    (r"logins.json", CredentialAttackType::BrowserCredentials),
    (r"key4.db", CredentialAttackType::BrowserCredentials),
    (r"key3.db", CredentialAttackType::BrowserCredentials),
    (r"cert9.db", CredentialAttackType::BrowserCredentials),
    // Edge credentials
    (
        r"AppData\Local\Microsoft\Edge\User Data\Default\Login Data",
        CredentialAttackType::BrowserCredentials,
    ),
    (
        r"AppData\Local\Microsoft\Edge\User Data\Default\Cookies",
        CredentialAttackType::BrowserCredentials,
    ),
    // Windows Credential Manager
    (
        r"AppData\Local\Microsoft\Credentials",
        CredentialAttackType::CredentialVault,
    ),
    (
        r"AppData\Roaming\Microsoft\Credentials",
        CredentialAttackType::CredentialVault,
    ),
    (
        r"AppData\Local\Microsoft\Vault",
        CredentialAttackType::CredentialVault,
    ),
    (
        r"AppData\Roaming\Microsoft\Vault",
        CredentialAttackType::CredentialVault,
    ),
    (
        r"Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials",
        CredentialAttackType::CredentialVault,
    ),
    // KeePass
    (r".kdbx", CredentialAttackType::PasswordManager),
    (r".kdb", CredentialAttackType::PasswordManager),
    // PuTTY
    (
        r"Software\SimonTatham\PuTTY\Sessions",
        CredentialAttackType::SshKeyTheft,
    ),
    (r".ppk", CredentialAttackType::SshKeyTheft),
    // FileZilla
    (
        r"AppData\Roaming\FileZilla\recentservers.xml",
        CredentialAttackType::CredentialFile,
    ),
    (
        r"AppData\Roaming\FileZilla\sitemanager.xml",
        CredentialAttackType::CredentialFile,
    ),
    // WinSCP
    (
        r"AppData\Local\WinSCP.ini",
        CredentialAttackType::CredentialFile,
    ),
    (r"WinSCP.ini", CredentialAttackType::CredentialFile),
    // RDP files with saved passwords
    (r".rdp", CredentialAttackType::RdpCredentials),
    // mRemoteNG
    (
        r"AppData\Roaming\mRemoteNG\confCons.xml",
        CredentialAttackType::CredentialFile,
    ),
    // VNC
    (r".vnc", CredentialAttackType::CredentialFile),
    // WiFi passwords
    (
        r"ProgramData\Microsoft\Wlansvc\Profiles\Interfaces",
        CredentialAttackType::CredentialFile,
    ),
];

/// Credential file patterns for Linux
#[cfg(target_os = "linux")]
const LINUX_CREDENTIAL_PATHS: &[(&str, CredentialAttackType)] = &[
    // System credentials
    ("/etc/shadow", CredentialAttackType::LinuxShadow),
    ("/etc/gshadow", CredentialAttackType::LinuxShadow),
    ("/etc/passwd", CredentialAttackType::LinuxShadow),
    // SSH keys
    ("/.ssh/id_rsa", CredentialAttackType::SshKeyTheft),
    ("/.ssh/id_dsa", CredentialAttackType::SshKeyTheft),
    ("/.ssh/id_ecdsa", CredentialAttackType::SshKeyTheft),
    ("/.ssh/id_ed25519", CredentialAttackType::SshKeyTheft),
    ("/.ssh/authorized_keys", CredentialAttackType::SshKeyTheft),
    ("/.ssh/known_hosts", CredentialAttackType::SshKeyTheft),
    ("/.ssh/config", CredentialAttackType::SshKeyTheft),
    // GNOME keyring
    (
        "/.local/share/keyrings",
        CredentialAttackType::CredentialVault,
    ),
    // KWallet (KDE)
    (
        "/.local/share/kwalletd",
        CredentialAttackType::CredentialVault,
    ),
    // Network credentials
    ("/.netrc", CredentialAttackType::CredentialFile),
    ("/.pgpass", CredentialAttackType::CredentialFile),
    ("/.my.cnf", CredentialAttackType::CredentialFile),
    // Browser credentials - Chrome
    (
        "/.config/google-chrome/Default/Login Data",
        CredentialAttackType::BrowserCredentials,
    ),
    (
        "/.config/google-chrome/Default/Cookies",
        CredentialAttackType::BrowserCredentials,
    ),
    // Browser credentials - Firefox
    (
        "/.mozilla/firefox",
        CredentialAttackType::BrowserCredentials,
    ),
    // Browser credentials - Chromium
    (
        "/.config/chromium/Default/Login Data",
        CredentialAttackType::BrowserCredentials,
    ),
    // AWS credentials
    ("/.aws/credentials", CredentialAttackType::CredentialFile),
    ("/.aws/config", CredentialAttackType::CredentialFile),
    // GCP credentials
    (
        "/.config/gcloud/credentials.db",
        CredentialAttackType::CredentialFile,
    ),
    (
        "/.config/gcloud/access_tokens.db",
        CredentialAttackType::CredentialFile,
    ),
    // Azure credentials
    (
        "/.azure/accessTokens.json",
        CredentialAttackType::CredentialFile,
    ),
    // Docker credentials
    ("/.docker/config.json", CredentialAttackType::CredentialFile),
    // Kubernetes
    ("/.kube/config", CredentialAttackType::CredentialFile),
    // KeePass
    (".kdbx", CredentialAttackType::PasswordManager),
    (".kdb", CredentialAttackType::PasswordManager),
    // Git credentials
    ("/.git-credentials", CredentialAttackType::CredentialFile),
    ("/.gitconfig", CredentialAttackType::CredentialFile),
    // PAM modules
    ("/etc/pam.d/", CredentialAttackType::PamModification),
    ("/lib/security/", CredentialAttackType::PamModification),
    ("/lib64/security/", CredentialAttackType::PamModification),
];

/// Known credential theft tools and patterns
const CREDENTIAL_TOOLS: &[(&str, CredentialAttackType)] = &[
    // Mimikatz
    ("mimikatz", CredentialAttackType::LsassAccess),
    ("sekurlsa", CredentialAttackType::LsassAccess),
    ("lsadump", CredentialAttackType::SamAccess),
    ("kerberos::ptt", CredentialAttackType::PassTheTicket),
    ("kerberos::golden", CredentialAttackType::GoldenTicket),
    ("kerberos::silver", CredentialAttackType::SilverTicket),
    // secretsdump / DCSync
    ("secretsdump", CredentialAttackType::DcSync),
    ("ntdsutil ifm", CredentialAttackType::NtdsAccess),
    ("ntdsutil snapshot", CredentialAttackType::NtdsAccess),
    ("dcsync", CredentialAttackType::DcSync),
    ("dsgetncchanges", CredentialAttackType::DcSync),
    // Kerberoasting
    ("invoke-kerberoast", CredentialAttackType::Kerberoasting),
    ("rubeus.exe", CredentialAttackType::Kerberoasting),
    ("kerberoast", CredentialAttackType::Kerberoasting),
    ("asreproast", CredentialAttackType::AsRepRoasting),
    // SAM dump
    ("reg save hklm\\sam", CredentialAttackType::SamAccess),
    ("reg save hklm\\security", CredentialAttackType::SamAccess),
    ("reg save hklm\\system", CredentialAttackType::SamAccess),
    ("samdump", CredentialAttackType::SamAccess),
    ("pwdump", CredentialAttackType::SamAccess),
    // Shadow copies - use specific abuse pattern to avoid flagging legitimate vssadmin usage
    (
        "vssadmin create shadow",
        CredentialAttackType::ShadowCopyAccess,
    ),
    ("wmic shadowcopy", CredentialAttackType::ShadowCopyAccess),
    ("diskshadow", CredentialAttackType::ShadowCopyAccess),
    // LLMNR/NBT-NS — use "responder.py" / "responder.exe" to avoid matching Apple mDNSResponder
    ("responder.py", CredentialAttackType::LlmnrPoisoning),
    ("responder.exe", CredentialAttackType::LlmnrPoisoning),
    ("inveigh", CredentialAttackType::LlmnrPoisoning),
    // NTLM relay
    ("ntlmrelay", CredentialAttackType::NtlmRelay),
    ("smbrelay", CredentialAttackType::NtlmRelay),
    ("impacket", CredentialAttackType::NtlmRelay),
    // Browser credential extraction
    ("chromedump", CredentialAttackType::BrowserCredentials),
    ("firefoxdump", CredentialAttackType::BrowserCredentials),
    ("lazagne", CredentialAttackType::BrowserCredentials),
    ("sharpweb", CredentialAttackType::BrowserCredentials),
    // Linux tools
    ("unshadow", CredentialAttackType::LinuxShadow),
    ("john.exe", CredentialAttackType::LinuxShadow),
    ("john-the-ripper", CredentialAttackType::LinuxShadow),
    ("johntheripper", CredentialAttackType::LinuxShadow),
    ("hashcat", CredentialAttackType::LinuxShadow),
    // LSASS dumping tools
    ("procdump", CredentialAttackType::LsassAccess),
    ("sqldumper", CredentialAttackType::LsassAccess),
    ("nanodump", CredentialAttackType::LsassAccess),
    ("dumpert", CredentialAttackType::LsassAccess),
    ("handlekatz", CredentialAttackType::LsassAccess),
    ("physmem2profit", CredentialAttackType::LsassAccess),
    ("pypykatz", CredentialAttackType::LsassAccess),
];

/// Suspicious registry operations for credential theft
#[cfg(target_os = "windows")]
const CREDENTIAL_REGISTRY_PATTERNS: &[(&str, CredentialAttackType)] = &[
    (r"HKLM\SAM", CredentialAttackType::SamAccess),
    (r"HKLM\SECURITY", CredentialAttackType::SamAccess),
    (
        r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        CredentialAttackType::SamAccess,
    ),
    (
        r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
        CredentialAttackType::PassTheHash,
    ),
    // PuTTY sessions
    (
        r"HKCU\Software\SimonTatham\PuTTY\Sessions",
        CredentialAttackType::SshKeyTheft,
    ),
    // WinSCP
    (
        r"HKCU\Software\Martin Prikryl\WinSCP 2\Sessions",
        CredentialAttackType::CredentialFile,
    ),
];

/// Comprehensive Credential Theft Collector
pub struct CredentialTheftCollector {
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
}

impl CredentialTheftCollector {
    /// Create a new credential theft collector
    pub fn new(config: &AgentConfig) -> Result<Self> {
        let (tx, rx) = mpsc::channel(1000);

        info!("Initializing comprehensive credential theft detection");

        // Start monitoring components
        let config_clone = config.clone();
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            Self::monitor_loop(tx_clone, config_clone).await;
        });

        Ok(Self {
            config: config.clone(),
            event_rx: rx,
        })
    }

    /// Main monitoring loop
    async fn monitor_loop(tx: mpsc::Sender<TelemetryEvent>, config: AgentConfig) {
        let mul = config.sub_loop_interval_multiplier;
        info!(
            multiplier = mul,
            "Starting credential theft monitoring loop"
        );

        // Track seen events to avoid duplicates
        let mut seen_events: HashMap<String, u64> = HashMap::new();
        let mut last_seen_cleanup = std::time::Instant::now();
        // Main loop: 500ms base -> scaled by multiplier
        let main_interval_ms = ((500.0 * mul) as u64).max(500);
        let mut interval =
            tokio::time::interval(tokio::time::Duration::from_millis(main_interval_ms));

        // Start platform-specific monitors
        #[cfg(target_os = "windows")]
        {
            // Start LSASS handle monitoring (500ms base -> scaled by multiplier)
            let tx_lsass = tx.clone();
            let lsass_interval_ms = ((500.0 * mul) as u64).max(500);
            tokio::spawn(async move {
                Self::monitor_lsass_access_windows(tx_lsass, lsass_interval_ms).await;
            });

            // Start file access monitor (5s base)
            let tx_file = tx.clone();
            let config_file = config.clone();
            let file_interval_ms = ((5000.0 * mul) as u64).max(5000);
            tokio::spawn(async move {
                Self::monitor_credential_files_windows(tx_file, config_file, file_interval_ms)
                    .await;
            });

            // Start Kerberos monitor (5s base)
            let tx_kerb = tx.clone();
            let kerb_interval_ms = ((5000.0 * mul) as u64).max(5000);
            tokio::spawn(async move {
                Self::monitor_kerberos_windows(tx_kerb, kerb_interval_ms).await;
            });

            // Start DCSync monitor (5s base)
            let tx_dcsync = tx.clone();
            let dcsync_interval_ms = ((5000.0 * mul) as u64).max(5000);
            tokio::spawn(async move {
                Self::monitor_dcsync_windows(tx_dcsync, dcsync_interval_ms).await;
            });

            // Start network credential monitor (LLMNR/NBT-NS) (5s base)
            let tx_net = tx.clone();
            let net_interval_ms = ((5000.0 * mul) as u64).max(5000);
            tokio::spawn(async move {
                Self::monitor_network_credentials_windows(tx_net, net_interval_ms).await;
            });

            // Start registry monitor (5s base)
            let tx_reg = tx.clone();
            let reg_interval_ms = ((5000.0 * mul) as u64).max(5000);
            tokio::spawn(async move {
                Self::monitor_credential_registry_windows(tx_reg, reg_interval_ms).await;
            });
        }

        #[cfg(target_os = "linux")]
        {
            // Start file access monitor (5s base)
            let tx_file = tx.clone();
            let config_file = config.clone();
            let file_interval_ms = ((5000.0 * mul) as u64).max(5000);
            tokio::spawn(async move {
                Self::monitor_credential_files_linux(tx_file, config_file, file_interval_ms).await;
            });

            // Start /proc/*/mem monitoring (1s base -> scaled)
            let tx_procmem = tx.clone();
            let procmem_interval_ms = ((1000.0 * mul) as u64).max(1000);
            tokio::spawn(async move {
                Self::monitor_proc_mem_access_linux(tx_procmem, procmem_interval_ms).await;
            });

            // Start PAM module monitoring (5s base)
            let tx_pam = tx.clone();
            let pam_interval_ms = ((5000.0 * mul) as u64).max(5000);
            tokio::spawn(async move {
                Self::monitor_pam_modifications_linux(tx_pam, pam_interval_ms).await;
            });

            // Start network credential monitor (5s base)
            let tx_net = tx.clone();
            let net_interval_ms = ((5000.0 * mul) as u64).max(5000);
            tokio::spawn(async move {
                Self::monitor_network_credentials_linux(tx_net, net_interval_ms).await;
            });
        }

        #[cfg(target_os = "macos")]
        {
            let tx_file = tx.clone();
            let config_file = config.clone();
            let file_interval_ms = ((5000.0 * mul) as u64).max(5000);
            tokio::spawn(async move {
                Self::monitor_credential_files_macos(tx_file, config_file, file_interval_ms).await;
            });
        }

        // Process monitoring loop (cross-platform)
        loop {
            interval.tick().await;

            // Monitor for credential theft tools in running processes
            if let Some(events) = Self::scan_for_credential_tools().await {
                for event in events {
                    let event_key = Self::get_event_key(&event);
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    // Deduplicate events (60 second window)
                    if let Some(last_seen) = seen_events.get(&event_key) {
                        if now - last_seen < 60 {
                            continue;
                        }
                    }

                    seen_events.insert(event_key, now);

                    if tx.send(event).await.is_err() {
                        warn!("Credential theft event channel closed");
                        return;
                    }
                }
            }

            // Time-based cleanup every 300 seconds
            if last_seen_cleanup.elapsed() > std::time::Duration::from_secs(300) {
                seen_events.clear();
                last_seen_cleanup = std::time::Instant::now();
            }
        }
    }

    /// Generate event key for deduplication
    fn get_event_key(event: &TelemetryEvent) -> String {
        match &event.payload {
            EventPayload::CredentialTheft(c) => {
                format!("cred:{}:{}:{}", c.pid, c.target, c.attack_type)
            }
            _ => event.event_id.clone(),
        }
    }

    /// Known legitimate processes that contain substrings matching tool names
    /// but are NOT credential theft tools. Checked by exact process name (lowercase).
    const PROCESS_WHITELIST: &'static [&'static str] = &[
        "mdnsresponder.exe", // Apple Bonjour mDNS service
        "mdnsresponder",     // macOS/Linux Bonjour
        "dnsresponder",      // macOS DNS
        "systemd-resolved",  // Linux DNS resolver
        "svchost.exe",       // Windows service host (too broad to flag)
        "lsass.exe",         // LSASS itself — monitored separately via LSASS collector
        "services.exe",      // Windows SCM
        "csrss.exe",         // Windows Client/Server Runtime
        "winlogon.exe",      // Windows logon
        // Windows Defender / ATP
        "msmpeng.exe",  // Windows Defender antimalware engine
        "mssense.exe",  // Microsoft Defender for Endpoint (ATP)
        "mpcmdrun.exe", // Defender command-line utility
        // Windows system processes
        "searchindexer.exe",      // Windows Search indexer
        "searchprotocolhost.exe", // Windows Search protocol host
        "wininit.exe",            // Windows initialization
        "smss.exe",               // Session Manager Subsystem
        "taskhostw.exe",          // Task Host Window
        "runtimebroker.exe",      // Runtime Broker
        // Windows Security services
        "securityhealthservice.exe", // Windows Security Health Service
        "sgrmbroker.exe",            // System Guard Runtime Monitor Broker
        // Virtualization guest tools
        "vmtoolsd.exe",    // VMware Tools daemon
        "vmwaretray.exe",  // VMware Tray
        "vboxservice.exe", // VirtualBox Guest Additions service
        "vboxtray.exe",    // VirtualBox Guest Additions tray
    ];

    /// Scan running processes for credential theft tools
    async fn scan_for_credential_tools() -> Option<Vec<TelemetryEvent>> {
        let mut events = Vec::new();
        let processes = Self::get_running_processes().await;

        for (pid, name, cmdline, path) in processes {
            let name_lower = name.to_lowercase();
            let cmdline_lower = cmdline.to_lowercase();
            let path_lower = path.to_lowercase();

            // Skip whitelisted legitimate processes
            if Self::PROCESS_WHITELIST.contains(&name_lower.as_str()) {
                continue;
            }

            // Check for Mimikatz patterns
            for pattern in MIMIKATZ_PATTERNS {
                if cmdline_lower.contains(pattern) || name_lower.contains(pattern) {
                    let event = Self::create_credential_theft_event(
                        CredentialAttackType::LsassAccess,
                        "lsass.exe",
                        &name,
                        pid,
                        &path,
                        &cmdline,
                        &Self::get_current_user(),
                        false,
                        format!("Mimikatz pattern detected: '{}'", pattern),
                    );
                    events.push(event);
                    break;
                }
            }

            // Check for DCSync patterns
            for pattern in DCSYNC_PATTERNS {
                if cmdline_lower.contains(pattern) || name_lower.contains(pattern) {
                    let event = Self::create_credential_theft_event(
                        CredentialAttackType::DcSync,
                        "Active Directory",
                        &name,
                        pid,
                        &path,
                        &cmdline,
                        &Self::get_current_user(),
                        false,
                        format!("DCSync pattern detected: '{}'", pattern),
                    );
                    events.push(event);
                    break;
                }
            }

            // Check for known credential tools
            for (pattern, attack_type) in CREDENTIAL_TOOLS {
                if name_lower.contains(pattern)
                    || cmdline_lower.contains(pattern)
                    || path_lower.contains(pattern)
                {
                    let target = match attack_type {
                        CredentialAttackType::LsassAccess => "lsass.exe",
                        CredentialAttackType::SamAccess => "SAM database",
                        CredentialAttackType::NtdsAccess => "NTDS.dit",
                        CredentialAttackType::DcSync => "Active Directory",
                        CredentialAttackType::BrowserCredentials => "Browser credentials",
                        CredentialAttackType::LinuxShadow => "/etc/shadow",
                        _ => "Credentials",
                    };

                    let event = Self::create_credential_theft_event(
                        *attack_type,
                        target,
                        &name,
                        pid,
                        &path,
                        &cmdline,
                        &Self::get_current_user(),
                        false,
                        format!("Known credential tool detected: '{}'", pattern),
                    );

                    events.push(event);
                    break;
                }
            }
        }

        if events.is_empty() {
            None
        } else {
            Some(events)
        }
    }

    /// Get current username
    fn get_current_user() -> String {
        #[cfg(target_os = "windows")]
        {
            std::env::var("USERNAME").unwrap_or_else(|_| "UNKNOWN".to_string())
        }
        #[cfg(not(target_os = "windows"))]
        {
            std::env::var("USER").unwrap_or_else(|_| "UNKNOWN".to_string())
        }
    }

    /// Get running processes (cross-platform)
    async fn get_running_processes() -> Vec<(u32, String, String, String)> {
        #[cfg(target_os = "windows")]
        {
            Self::get_processes_windows().await
        }

        #[cfg(target_os = "linux")]
        {
            Self::get_processes_linux().await
        }

        #[cfg(target_os = "macos")]
        {
            Self::get_processes_macos().await
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Vec::new()
        }
    }

    /// Create a credential theft event with proper CredentialTheftEvent payload
    fn create_credential_theft_event(
        attack_type: CredentialAttackType,
        target: &str,
        process_name: &str,
        pid: u32,
        process_path: &str,
        process_cmdline: &str,
        username: &str,
        blocked: bool,
        details: String,
    ) -> TelemetryEvent {
        let mut event = TelemetryEvent::new(
            EventType::CredentialTheft,
            attack_type.severity(),
            EventPayload::CredentialTheft(CredentialTheftEvent {
                attack_type: attack_type.as_str().to_string(),
                mitre_technique: attack_type.mitre_technique().to_string(),
                target: target.to_string(),
                process_name: process_name.to_string(),
                pid,
                process_path: process_path.to_string(),
                process_cmdline: process_cmdline.to_string(),
                username: username.to_string(),
                blocked,
                details: details.clone(),
            }),
        );

        event.add_detection(Detection {
            detection_type: DetectionType::CredentialTheft,
            rule_name: format!("credential_theft_{}", attack_type.as_str()),
            confidence: 0.90,
            description: format!("{}: {}", attack_type.description(), details),
            mitre_tactics: attack_type.mitre_tactics(),
            mitre_techniques: vec![attack_type.mitre_technique().to_string()],
        });

        event
            .metadata
            .insert("attack_type".to_string(), attack_type.as_str().to_string());

        event
    }

    // ==================== Windows Implementation ====================
    #[cfg(target_os = "windows")]
    async fn get_processes_windows() -> Vec<(u32, String, String, String)> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };
        use windows::Win32::System::ProcessStatus::K32GetProcessImageFileNameW;
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
        };

        let mut processes = Vec::new();

        unsafe {
            let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(h) => h,
                Err(_) => return processes,
            };

            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    let pid = entry.th32ProcessID;
                    let name = String::from_utf16_lossy(
                        &entry.szExeFile
                            [..entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0)],
                    );

                    // Get path and command line
                    let (path, cmdline) = if let Ok(handle) = OpenProcess(
                        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                        false,
                        pid,
                    ) {
                        let mut path_buf = [0u16; 260];
                        let len = K32GetProcessImageFileNameW(handle, &mut path_buf);
                        let path = if len > 0 {
                            String::from_utf16_lossy(&path_buf[..len as usize])
                        } else {
                            String::new()
                        };

                        // Try to get command line using NT API
                        let cmdline = super::win_compat::ntapi::get_process_command_line(
                            std::mem::transmute(handle),
                        )
                        .unwrap_or_default();

                        let _ = CloseHandle(handle);
                        (path, cmdline)
                    } else {
                        (String::new(), String::new())
                    };

                    processes.push((pid, name, cmdline, path));

                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
        }

        processes
    }

    /// Monitor LSASS access attempts using handle enumeration
    /// This detects processes that have opened handles to LSASS with PROCESS_VM_READ
    #[cfg(target_os = "windows")]
    async fn monitor_lsass_access_windows(tx: mpsc::Sender<TelemetryEvent>, interval_ms: u64) {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };
        use windows::Win32::System::ProcessStatus::K32GetProcessImageFileNameW;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

        info!("Starting LSASS access monitoring");

        // Find LSASS PID
        let lsass_pid = unsafe {
            let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(h) => h,
                Err(_) => {
                    error!("Failed to create process snapshot for LSASS detection");
                    return;
                }
            };

            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            let mut lsass_pid = 0u32;

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    let name = String::from_utf16_lossy(
                        &entry.szExeFile
                            [..entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0)],
                    );

                    if name.to_lowercase() == "lsass.exe" {
                        lsass_pid = entry.th32ProcessID;
                        break;
                    }

                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
            lsass_pid
        };

        if lsass_pid == 0 {
            warn!("Could not find LSASS process");
            return;
        }

        info!(
            lsass_pid = lsass_pid,
            "Found LSASS process, monitoring handles"
        );

        // Legitimate processes that may access LSASS
        let legitimate_accessors: HashSet<&str> = [
            "csrss.exe",
            "services.exe",
            "svchost.exe",
            "wininit.exe",
            "winlogon.exe",
            "smss.exe",
            "MsMpEng.exe",
            "MsSense.exe",
            "SenseIR.exe",
            "SecurityHealthService.exe",
            "System",
            "NisSrv.exe",
            "MpCmdRun.exe",
            "dwm.exe",
            "tamandua-agent.exe",
        ]
        .iter()
        .copied()
        .collect();

        let mut seen_accessors: HashMap<u32, u64> = HashMap::new();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        loop {
            interval.tick().await;

            // Use NtQuerySystemInformation to enumerate handles
            if let Some(accessors) = Self::enumerate_lsass_handles(lsass_pid) {
                for (accessor_pid, accessor_name, access_mask) in accessors {
                    // Skip self
                    if accessor_pid == std::process::id() {
                        continue;
                    }

                    // Skip legitimate accessors
                    if legitimate_accessors.contains(accessor_name.to_lowercase().as_str()) {
                        continue;
                    }

                    // Check for PROCESS_VM_READ (0x0010) or full access (0x1F0FFF)
                    let has_vm_read = (access_mask & 0x0010) != 0;
                    let has_full_access = (access_mask & 0x1F0FFF) == 0x1F0FFF;

                    if !has_vm_read && !has_full_access {
                        continue;
                    }

                    // Deduplicate
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    if let Some(&last_seen) = seen_accessors.get(&accessor_pid) {
                        if now - last_seen < 60 {
                            continue;
                        }
                    }

                    seen_accessors.insert(accessor_pid, now);

                    // Get process details
                    let (path, cmdline) = unsafe {
                        if let Ok(handle) =
                            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, accessor_pid)
                        {
                            let mut path_buf = [0u16; 260];
                            let len = K32GetProcessImageFileNameW(handle, &mut path_buf);
                            let path = if len > 0 {
                                String::from_utf16_lossy(&path_buf[..len as usize])
                            } else {
                                String::new()
                            };

                            let cmdline = super::win_compat::ntapi::get_process_command_line(
                                std::mem::transmute(handle),
                            )
                            .unwrap_or_default();

                            let _ = CloseHandle(handle);
                            (path, cmdline)
                        } else {
                            (String::new(), String::new())
                        }
                    };

                    let access_desc = if has_full_access {
                        "PROCESS_ALL_ACCESS"
                    } else {
                        "PROCESS_VM_READ"
                    };

                    warn!(
                        accessor_pid = accessor_pid,
                        accessor_name = %accessor_name,
                        access_mask = format!("0x{:08X}", access_mask),
                        "LSASS memory access detected"
                    );

                    let event = Self::create_credential_theft_event(
                        CredentialAttackType::LsassAccess,
                        "lsass.exe",
                        &accessor_name,
                        accessor_pid,
                        &path,
                        &cmdline,
                        &Self::get_current_user(),
                        false,
                        format!(
                            "Process opened handle to LSASS with {} (mask: 0x{:08X})",
                            access_desc, access_mask
                        ),
                    );

                    if tx.send(event).await.is_err() {
                        return;
                    }
                }
            }

            // Cleanup old entries
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            seen_accessors.retain(|_, &mut ts| now - ts < 300);
        }
    }

    /// Enumerate handles to LSASS using NtQuerySystemInformation
    #[cfg(target_os = "windows")]
    fn enumerate_lsass_handles(lsass_pid: u32) -> Option<Vec<(u32, String, u32)>> {
        use super::win_compat::ntapi::{
            get_nt_api, PROCESS_BASIC_INFORMATION, STATUS_INFO_LENGTH_MISMATCH, STATUS_SUCCESS,
            SYSTEM_EXTENDED_HANDLE_INFORMATION,
        };
        use std::ffi::c_void;
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{
            GetCurrentProcess, OpenProcess, PROCESS_DUP_HANDLE, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        // Handle enumeration via NtQuerySystemInformation requires elevation.
        // Without it, NtDuplicateObject can crash inside ntdll.dll.
        if !super::win_compat::is_elevated() {
            return None;
        }

        let api = get_nt_api()?;
        let dup_fn = api.nt_duplicate_object?;
        let close_fn = api.nt_close?;

        unsafe {
            // Query system handle information
            let mut buffer_size: u32 = 1024 * 1024; // Start with 1MB
            let mut buffer: Vec<u8>;
            let mut return_length: u32 = 0;
            let mut status: i32;

            loop {
                buffer = vec![0u8; buffer_size as usize];

                status = (api.nt_query_system_information)(
                    SYSTEM_EXTENDED_HANDLE_INFORMATION,
                    buffer.as_mut_ptr() as *mut c_void,
                    buffer_size,
                    &mut return_length,
                );

                if status == STATUS_INFO_LENGTH_MISMATCH as i32 {
                    buffer_size = return_length + 0x10000;
                    if buffer_size > 256 * 1024 * 1024 {
                        return None;
                    }
                    continue;
                }

                break;
            }

            if status != STATUS_SUCCESS {
                return None;
            }

            let handle_info = &*(buffer.as_ptr()
                as *const super::win_compat::ntapi::SystemExtendedHandleInformation);
            let handle_count = handle_info.number_of_handles;

            let mut accessors = Vec::new();

            let handles_offset = std::mem::offset_of!(
                super::win_compat::ntapi::SystemExtendedHandleInformation,
                handles
            );
            let handles_ptr = (buffer.as_ptr() as usize + handles_offset)
                as *const super::win_compat::ntapi::SystemHandleTableEntryInfoEx;

            // Cap iteration at buffer bounds to prevent out-of-bounds reads
            let entry_size =
                std::mem::size_of::<super::win_compat::ntapi::SystemHandleTableEntryInfoEx>();
            let max_entries = if entry_size > 0 && buffer.len() > handles_offset {
                (buffer.len() - handles_offset) / entry_size
            } else {
                0
            };
            let safe_count = handle_count.min(max_entries);

            for i in 0..safe_count {
                let entry = &*handles_ptr.add(i);

                // Skip handles owned by LSASS itself
                if entry.unique_process_id == lsass_pid as usize {
                    continue;
                }

                // Skip System (PID 4) and Idle (PID 0)
                if entry.unique_process_id <= 4 {
                    continue;
                }

                // Only check process handles (type index 7)
                // The access mask filter was too broad and matched non-process handles,
                // causing crashes when NtQueryInformationProcess was called on them.
                if entry.object_type_index == 7 {
                    // Try to verify this handle points to LSASS
                    let owner_handle = match OpenProcess(
                        PROCESS_DUP_HANDLE,
                        false,
                        entry.unique_process_id as u32,
                    ) {
                        Ok(h) => h,
                        Err(_) => continue,
                    };

                    let mut duplicated: *mut c_void = std::ptr::null_mut();
                    let current = GetCurrentProcess();

                    let dup_status = dup_fn(
                        std::mem::transmute::<_, *mut c_void>(owner_handle),
                        entry.handle_value as *mut c_void,
                        std::mem::transmute::<_, *mut c_void>(current),
                        &mut duplicated,
                        PROCESS_QUERY_LIMITED_INFORMATION.0,
                        0,
                        0,
                    );

                    let _ = CloseHandle(owner_handle);

                    // Check for failure, null, AND INVALID_HANDLE_VALUE (-1)
                    let invalid_handle = -1isize as *mut c_void;
                    if dup_status != STATUS_SUCCESS
                        || duplicated.is_null()
                        || duplicated == invalid_handle
                    {
                        if !duplicated.is_null() && duplicated != invalid_handle {
                            let _ = close_fn(duplicated);
                        }
                        continue;
                    }

                    // Query the PID of the target process
                    let mut pbi: super::win_compat::ntapi::ProcessBasicInformation =
                        std::mem::zeroed();
                    let mut ret_len: u32 = 0;

                    let query_status = (api.nt_query_information_process)(
                        duplicated,
                        PROCESS_BASIC_INFORMATION,
                        &mut pbi as *mut _ as *mut c_void,
                        std::mem::size_of::<super::win_compat::ntapi::ProcessBasicInformation>()
                            as u32,
                        &mut ret_len,
                    );

                    let _ = close_fn(duplicated);

                    if query_status == STATUS_SUCCESS && pbi.unique_process_id as u32 == lsass_pid {
                        let accessor_name =
                            Self::get_process_name_by_pid(entry.unique_process_id as u32);
                        accessors.push((
                            entry.unique_process_id as u32,
                            accessor_name,
                            entry.granted_access,
                        ));
                    }
                }
            }

            if accessors.is_empty() {
                None
            } else {
                Some(accessors)
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn get_process_name_by_pid(pid: u32) -> String {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        unsafe {
            let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(h) => h,
                Err(_) => return format!("PID:{}", pid),
            };

            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    if entry.th32ProcessID == pid {
                        let _ = CloseHandle(snapshot);
                        return String::from_utf16_lossy(
                            &entry.szExeFile
                                [..entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0)],
                        );
                    }

                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
            format!("PID:{}", pid)
        }
    }

    /// Monitor for DCSync attacks by watching for DRS API usage
    #[cfg(target_os = "windows")]
    async fn monitor_dcsync_windows(tx: mpsc::Sender<TelemetryEvent>, interval_ms: u64) {
        info!("Starting DCSync detection monitoring");

        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));
        let mut seen_events: HashMap<String, u64> = HashMap::new();

        loop {
            interval.tick().await;

            // Monitor Security Event Log for DCSync indicators
            // Event ID 4662: Directory Service Access with GUID matching replication
            // DS-Replication-Get-Changes: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
            // DS-Replication-Get-Changes-All: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2

            if let Some(events) = Self::get_dcsync_events().await {
                for (account, target_dn, guid, timestamp) in events {
                    let key = format!("dcsync:{}:{}:{}", account, target_dn, timestamp);

                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    if let Some(&last) = seen_events.get(&key) {
                        if now - last < 300 {
                            continue;
                        }
                    }

                    seen_events.insert(key, now);

                    let event = Self::create_credential_theft_event(
                        CredentialAttackType::DcSync,
                        "Active Directory",
                        "Directory Replication Service",
                        0,
                        "",
                        "",
                        &account,
                        false,
                        format!(
                            "DCSync replication detected: Account '{}' performed directory replication with GUID {}",
                            account, guid
                        ),
                    );

                    if tx.send(event).await.is_err() {
                        return;
                    }
                }
            }

            // Cleanup
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            seen_events.retain(|_, &mut ts| now - ts < 600);
        }
    }

    /// Query Windows Security Event Log for DCSync events
    #[cfg(target_os = "windows")]
    async fn get_dcsync_events() -> Option<Vec<(String, String, String, u64)>> {
        use std::process::Command;

        // Query for Event ID 4662 with DCSync GUIDs
        // DS-Replication-Get-Changes: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
        // DS-Replication-Get-Changes-All: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2

        let output = Command::new("wevtutil")
            .args([
                "qe",
                "Security",
                "/q:*[System[(EventID=4662)]]",
                "/c:10",
                "/rd:true",
                "/f:text",
            ])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut events = Vec::new();

        let dcsync_guids = [
            "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
            "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
            "89e95b76-444d-4c62-991a-0facbeda640c",
        ];

        let stdout_lower = stdout.to_lowercase();

        // Check if any DCSync GUIDs are present
        for guid in &dcsync_guids {
            if stdout_lower.contains(&guid.to_lowercase()) {
                // Parse event details
                let mut account = String::new();
                let mut target_dn = String::new();

                for line in stdout.lines() {
                    if line.contains("Account Name:") {
                        if let Some(name) = line.split(':').nth(1) {
                            account = name.trim().to_string();
                        }
                    } else if line.contains("Object Name:") {
                        if let Some(dn) = line.split(':').nth(1) {
                            target_dn = dn.trim().to_string();
                        }
                    }
                }

                if !account.is_empty() {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    events.push((account.clone(), target_dn.clone(), guid.to_string(), now));
                }
            }
        }

        if events.is_empty() {
            None
        } else {
            Some(events)
        }
    }

    #[cfg(target_os = "windows")]
    async fn monitor_credential_files_windows(
        tx: mpsc::Sender<TelemetryEvent>,
        _config: AgentConfig,
        _interval_ms: u64,
    ) {
        use notify::{Event as NotifyEvent, EventKind, RecursiveMode, Watcher};
        use std::path::Path;

        info!("Starting Windows credential file monitoring");

        let (notify_tx, notify_rx) = std::sync::mpsc::channel();
        let tx_clone = tx.clone();

        // Create file watcher
        let mut watcher =
            match notify::recommended_watcher(move |res: notify::Result<NotifyEvent>| {
                if let Ok(event) = res {
                    let _ = notify_tx.send(event);
                }
            }) {
                Ok(w) => w,
                Err(e) => {
                    error!("Failed to create file watcher: {}", e);
                    return;
                }
            };

        // Watch key credential directories
        let watch_paths = [r"C:\Windows\System32\config", r"C:\Windows\NTDS"];

        for path in &watch_paths {
            if Path::new(path).exists() {
                if let Err(e) = watcher.watch(Path::new(path), RecursiveMode::NonRecursive) {
                    warn!("Failed to watch {}: {}", path, e);
                }
            }
        }

        // Watch user profile directories for browser/app credentials
        if let Ok(users_dir) = std::fs::read_dir(r"C:\Users") {
            for entry in users_dir.filter_map(|e| e.ok()) {
                let user_path = entry.path();
                let appdata_paths = [
                    user_path.join("AppData\\Local\\Google\\Chrome\\User Data"),
                    user_path.join("AppData\\Local\\Microsoft\\Edge\\User Data"),
                    user_path.join("AppData\\Roaming\\Mozilla\\Firefox\\Profiles"),
                    user_path.join("AppData\\Local\\Microsoft\\Credentials"),
                    user_path.join("AppData\\Roaming\\Microsoft\\Credentials"),
                    user_path.join(".ssh"),
                ];

                for app_path in &appdata_paths {
                    if app_path.exists() {
                        if let Err(e) = watcher.watch(app_path, RecursiveMode::Recursive) {
                            debug!("Failed to watch {:?}: {}", app_path, e);
                        }
                    }
                }
            }
        }

        // Process events in a blocking task to avoid runtime-in-runtime
        let _ = tokio::task::spawn_blocking(move || {
            for event in notify_rx {
                for path in &event.paths {
                    let path_str = path.to_string_lossy().to_lowercase();

                    // Check if this matches a credential file pattern
                    for (pattern, attack_type) in WINDOWS_CREDENTIAL_PATHS {
                        if path_str.contains(&pattern.to_lowercase()) {
                            let operation = match &event.kind {
                                EventKind::Access(_) => "read",
                                EventKind::Modify(_) => "modify",
                                EventKind::Create(_) => "create",
                                EventKind::Remove(_) => "delete",
                                _ => continue,
                            };

                            // Skip read-only access to browser credential stores.
                            // Browsers (Chrome, Firefox, Edge, Brave) constantly read
                            // their own credential files — this is normal and generates
                            // massive false positives. Only flag write/create/delete ops
                            // which indicate credential theft by a non-browser process.
                            if *attack_type == CredentialAttackType::BrowserCredentials
                                && operation == "read"
                            {
                                continue;
                            }

                            let tel_event = Self::create_credential_theft_event(
                                *attack_type,
                                &path_str,
                                "Unknown",
                                0,
                                "",
                                "",
                                &Self::get_current_user(),
                                false,
                                format!("Credential file {} operation: {}", operation, path_str),
                            );

                            // Use try_send since we're in a blocking context
                            let _ = tx_clone.try_send(tel_event);
                            break;
                        }
                    }
                }
            }
        })
        .await;
    }

    #[cfg(target_os = "windows")]
    async fn monitor_kerberos_windows(tx: mpsc::Sender<TelemetryEvent>, interval_ms: u64) {
        info!("Starting Kerberos attack detection");

        // Track TGS requests per user to detect Kerberoasting
        let mut tgs_requests: HashMap<String, Vec<u64>> = HashMap::new();
        let kerberoasting_threshold = 10; // TGS requests in 60 seconds
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        loop {
            interval.tick().await;

            // Check Windows Security Event Log for Kerberos events
            if let Some(events) = Self::get_kerberos_events().await {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                for (event_id, user, service, _timestamp) in events {
                    match event_id {
                        4769 => {
                            // TGS request - track for Kerberoasting detection
                            let key = format!("{}:{}", user, service);
                            let timestamps = tgs_requests.entry(key.clone()).or_default();
                            timestamps.push(now);

                            // Remove old entries
                            timestamps.retain(|t| now - t < 60);

                            // Check for Kerberoasting
                            if timestamps.len() >= kerberoasting_threshold {
                                let event = Self::create_credential_theft_event(
                                    CredentialAttackType::Kerberoasting,
                                    "Kerberos TGS",
                                    "Unknown",
                                    0,
                                    "",
                                    "",
                                    &user,
                                    false,
                                    format!(
                                        "Kerberoasting detected: {} TGS requests for service {} in 60 seconds",
                                        timestamps.len(), service
                                    ),
                                );

                                if tx.send(event).await.is_err() {
                                    return;
                                }

                                timestamps.clear();
                            }
                        }
                        4771 => {
                            // Pre-auth failure - potential AS-REP roasting
                            let event = Self::create_credential_theft_event(
                                CredentialAttackType::AsRepRoasting,
                                "Kerberos AS-REP",
                                "Unknown",
                                0,
                                "",
                                "",
                                &user,
                                false,
                                format!(
                                    "Potential AS-REP roasting: Pre-authentication failed for user {}",
                                    user
                                ),
                            );

                            if tx.send(event).await.is_err() {
                                return;
                            }
                        }
                        _ => {}
                    }
                }
            }

            // Cleanup old tracking data
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            tgs_requests.retain(|_, timestamps| {
                timestamps.retain(|t| now - t < 300);
                !timestamps.is_empty()
            });
        }
    }

    #[cfg(target_os = "windows")]
    async fn get_kerberos_events() -> Option<Vec<(u32, String, String, u64)>> {
        use std::process::Command;

        let output = Command::new("wevtutil")
            .args([
                "qe",
                "Security",
                "/q:*[System[(EventID=4768 or EventID=4769 or EventID=4771)]]",
                "/c:20",
                "/rd:true",
                "/f:text",
            ])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut events = Vec::new();

        let mut current_event_id: u32 = 0;
        let mut current_user = String::new();
        let mut current_service = String::new();

        for line in stdout.lines() {
            if line.contains("Event ID:") {
                if let Some(id_str) = line.split(':').nth(1) {
                    current_event_id = id_str.trim().parse().unwrap_or(0);
                }
            } else if line.contains("Account Name:") {
                if let Some(name) = line.split(':').nth(1) {
                    current_user = name.trim().to_string();
                }
            } else if line.contains("Service Name:") {
                if let Some(svc) = line.split(':').nth(1) {
                    current_service = svc.trim().to_string();
                }
            }

            if current_event_id != 0 && !current_user.is_empty() {
                events.push((
                    current_event_id,
                    current_user.clone(),
                    current_service.clone(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                ));
                current_event_id = 0;
                current_user.clear();
                current_service.clear();
            }
        }

        if events.is_empty() {
            None
        } else {
            Some(events)
        }
    }

    #[cfg(target_os = "windows")]
    async fn monitor_network_credentials_windows(
        tx: mpsc::Sender<TelemetryEvent>,
        interval_ms: u64,
    ) {
        use windows::Win32::NetworkManagement::IpHelper::{
            GetExtendedUdpTable, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, UDP_TABLE_OWNER_PID,
        };
        use windows::Win32::Networking::WinSock::AF_INET;

        info!("Starting LLMNR/NBT-NS poisoning detection");

        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));
        let mut seen_poisoning: HashSet<String> = HashSet::new();

        loop {
            interval.tick().await;

            // Collect suspicious entries in a synchronous block (no await across raw pointers)
            let suspicious_entries: Vec<(u32, u16, String, String, CredentialAttackType)> = {
                // Check for processes listening on LLMNR/NBT-NS ports
                let mut size: u32 = 0;
                unsafe {
                    let _ = GetExtendedUdpTable(
                        None,
                        &mut size,
                        false,
                        AF_INET.0 as u32,
                        UDP_TABLE_OWNER_PID,
                        0,
                    );
                }

                if size == 0 {
                    continue;
                }

                let mut buffer: Vec<u8> = vec![0u8; size as usize];

                let result = unsafe {
                    GetExtendedUdpTable(
                        Some(buffer.as_mut_ptr() as *mut _),
                        &mut size,
                        false,
                        AF_INET.0 as u32,
                        UDP_TABLE_OWNER_PID,
                        0,
                    )
                };

                if result != 0 {
                    continue;
                }

                let table = unsafe { &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
                let num_entries = table.dwNumEntries as usize;

                if num_entries == 0 {
                    continue;
                }

                // Cap entries at buffer bounds to prevent out-of-bounds reads
                let header_size = std::mem::offset_of!(MIB_UDPTABLE_OWNER_PID, table);
                let entry_size = std::mem::size_of::<MIB_UDPROW_OWNER_PID>();
                let max_entries = if entry_size > 0 && buffer.len() > header_size {
                    (buffer.len() - header_size) / entry_size
                } else {
                    0
                };
                let num_entries = num_entries.min(max_entries);

                let rows_ptr = table.table.as_ptr();
                let mut entries = Vec::new();

                for i in 0..num_entries {
                    let row = unsafe { &*rows_ptr.add(i) };
                    let local_port = u16::from_be(row.dwLocalPort as u16);
                    let pid = row.dwOwningPid;

                    // Check for LLMNR (5355) or NBT-NS (137) ports
                    if local_port == 5355 || local_port == 137 {
                        let process_name = Self::get_process_name_by_pid(pid);
                        let key = format!("{}:{}:{}", pid, process_name, local_port);

                        // Check if legitimate system process
                        let is_legitimate = process_name.to_lowercase() == "svchost.exe"
                            || process_name.to_lowercase() == "dns.exe"
                            || process_name.to_lowercase() == "system";

                        if !is_legitimate && !seen_poisoning.contains(&key) {
                            seen_poisoning.insert(key);

                            let attack_type = if local_port == 5355 {
                                CredentialAttackType::LlmnrPoisoning
                            } else {
                                CredentialAttackType::NtlmRelay
                            };

                            entries.push((
                                pid,
                                local_port,
                                process_name,
                                Self::get_current_user(),
                                attack_type,
                            ));
                        }
                    }
                }
                entries
            };

            // Now send events asynchronously (no raw pointers in scope)
            for (pid, local_port, process_name, current_user, attack_type) in suspicious_entries {
                let event = Self::create_credential_theft_event(
                    attack_type,
                    &format!("UDP port {}", local_port),
                    &process_name,
                    pid,
                    "",
                    "",
                    &current_user,
                    false,
                    format!(
                        "Non-system process {} (PID: {}) listening on {} port {}",
                        process_name,
                        pid,
                        if local_port == 5355 {
                            "LLMNR"
                        } else {
                            "NBT-NS"
                        },
                        local_port
                    ),
                );

                if tx.send(event).await.is_err() {
                    return;
                }
            }

            // Cleanup
            if seen_poisoning.len() > 1000 {
                seen_poisoning.clear();
            }
        }
    }

    #[cfg(target_os = "windows")]
    async fn monitor_credential_registry_windows(
        tx: mpsc::Sender<TelemetryEvent>,
        _interval_ms: u64,
    ) {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStrExt;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::Registry::{
            RegCloseKey, RegNotifyChangeKeyValue, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE,
            KEY_NOTIFY, KEY_READ, REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_CHANGE_NAME,
        };

        info!("Starting credential registry monitoring");

        // Monitor SAM and SECURITY hives
        let keys_to_watch = [
            (HKEY_LOCAL_MACHINE, r"SAM"),
            (HKEY_LOCAL_MACHINE, r"SECURITY"),
            (HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa"),
        ];

        for (root_key, subkey) in keys_to_watch {
            let tx_clone = tx.clone();

            std::thread::spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        error!(error = %e, "Failed to create tokio runtime for credential-theft monitor");
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
                        KEY_NOTIFY | KEY_READ,
                        &mut key_handle,
                    );

                    if result.is_err() {
                        warn!("Failed to open registry key {} for monitoring", subkey);
                        return;
                    }

                    debug!("Monitoring registry key: {}", subkey);

                    loop {
                        let wait_result = RegNotifyChangeKeyValue(
                            key_handle,
                            true,
                            REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                            HANDLE::default(),
                            false,
                        );

                        if wait_result.is_err() {
                            break;
                        }

                        let attack_type = if subkey.contains("SAM") || subkey.contains("SECURITY") {
                            CredentialAttackType::SamAccess
                        } else {
                            CredentialAttackType::PassTheHash
                        };

                        let event = Self::create_credential_theft_event(
                            attack_type,
                            subkey,
                            "Registry Monitor",
                            0,
                            "",
                            "",
                            "SYSTEM",
                            false,
                            format!("Registry key {} was modified", subkey),
                        );

                        let _ = rt.block_on(tx_clone.send(event));
                    }

                    let _ = RegCloseKey(key_handle);
                }
            });
        }

        // Keep main async task alive
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
        }
    }

    // ==================== Linux Implementation ====================
    #[cfg(target_os = "linux")]
    async fn get_processes_linux() -> Vec<(u32, String, String, String)> {
        let mut processes = Vec::new();

        if let Ok(proc_dir) = std::fs::read_dir("/proc") {
            for entry in proc_dir.filter_map(|e| e.ok()) {
                let pid_str = entry.file_name().to_string_lossy().to_string();
                let pid: u32 = match pid_str.parse() {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                let comm_path = format!("/proc/{}/comm", pid);
                let cmdline_path = format!("/proc/{}/cmdline", pid);
                let exe_path = format!("/proc/{}/exe", pid);

                let name = std::fs::read_to_string(&comm_path)
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();

                let cmdline = std::fs::read_to_string(&cmdline_path)
                    .map(|s| s.replace('\0', " ").trim().to_string())
                    .unwrap_or_default();

                let path = std::fs::read_link(&exe_path)
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();

                processes.push((pid, name, cmdline, path));
            }
        }

        processes
    }

    /// Monitor /proc/*/mem access for credential dumping from memory
    #[cfg(target_os = "linux")]
    async fn monitor_proc_mem_access_linux(tx: mpsc::Sender<TelemetryEvent>, interval_ms: u64) {
        info!("Starting /proc/*/mem access monitoring for credential dumping");

        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));
        let mut seen_accesses: HashMap<String, u64> = HashMap::new();

        // Sensitive processes to monitor for memory access
        let sensitive_processes = ["sshd", "sudo", "su", "login", "passwd", "gdm", "lightdm"];

        loop {
            interval.tick().await;

            // Scan /proc for processes
            if let Ok(proc_dir) = std::fs::read_dir("/proc") {
                for entry in proc_dir.filter_map(|e| e.ok()) {
                    let pid_str = entry.file_name().to_string_lossy().to_string();
                    let target_pid: u32 = match pid_str.parse() {
                        Ok(p) => p,
                        Err(_) => continue,
                    };

                    // Get process name
                    let comm_path = format!("/proc/{}/comm", target_pid);
                    let process_name = std::fs::read_to_string(&comm_path)
                        .map(|s| s.trim().to_string())
                        .unwrap_or_default();

                    // Check if this is a sensitive process
                    let is_sensitive = sensitive_processes
                        .iter()
                        .any(|&p| process_name.contains(p));

                    if !is_sensitive {
                        continue;
                    }

                    // Check /proc/[pid]/fd for any process that has the mem file open
                    let fd_path = format!("/proc/{}/fd", target_pid);
                    if let Ok(fd_dir) = std::fs::read_dir(&fd_path) {
                        for fd_entry in fd_dir.filter_map(|e| e.ok()) {
                            if let Ok(link) = std::fs::read_link(fd_entry.path()) {
                                let link_str = link.to_string_lossy();

                                // Check if this fd points to another process's mem
                                if link_str.contains("/proc/") && link_str.contains("/mem") {
                                    // Extract the target PID from the path
                                    if let Some(mem_pid) = link_str
                                        .strip_prefix("/proc/")
                                        .and_then(|s| s.split('/').next())
                                        .and_then(|s| s.parse::<u32>().ok())
                                    {
                                        let key = format!("{}:{}", target_pid, mem_pid);
                                        let now = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_secs();

                                        if let Some(&last) = seen_accesses.get(&key) {
                                            if now - last < 60 {
                                                continue;
                                            }
                                        }

                                        seen_accesses.insert(key, now);

                                        let accessor_comm = format!("/proc/{}/comm", target_pid);
                                        let accessor_name = std::fs::read_to_string(&accessor_comm)
                                            .map(|s| s.trim().to_string())
                                            .unwrap_or_default();

                                        let target_comm = format!("/proc/{}/comm", mem_pid);
                                        let target_name = std::fs::read_to_string(&target_comm)
                                            .map(|s| s.trim().to_string())
                                            .unwrap_or_default();

                                        warn!(
                                            accessor_pid = target_pid,
                                            accessor_name = %accessor_name,
                                            target_pid = mem_pid,
                                            target_name = %target_name,
                                            "/proc/*/mem access detected"
                                        );

                                        let event = Self::create_credential_theft_event(
                                            CredentialAttackType::ProcMemAccess,
                                            &format!("/proc/{}/mem ({})", mem_pid, target_name),
                                            &accessor_name,
                                            target_pid,
                                            "",
                                            "",
                                            &Self::get_current_user(),
                                            false,
                                            format!(
                                                "Process {} (PID: {}) accessing memory of {} (PID: {})",
                                                accessor_name, target_pid, target_name, mem_pid
                                            ),
                                        );

                                        if tx.send(event).await.is_err() {
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Cleanup
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            seen_accesses.retain(|_, &mut ts| now - ts < 300);
        }
    }

    /// Monitor PAM module modifications
    #[cfg(target_os = "linux")]
    async fn monitor_pam_modifications_linux(tx: mpsc::Sender<TelemetryEvent>, interval_ms: u64) {
        use notify::{Event as NotifyEvent, EventKind, RecursiveMode, Watcher};
        use std::path::Path;

        info!("Starting PAM module modification monitoring");

        let (notify_tx, notify_rx) = std::sync::mpsc::channel();
        let tx_clone = tx.clone();

        let mut watcher =
            match notify::recommended_watcher(move |res: notify::Result<NotifyEvent>| {
                if let Ok(event) = res {
                    let _ = notify_tx.send(event);
                }
            }) {
                Ok(w) => w,
                Err(e) => {
                    error!("Failed to create PAM file watcher: {}", e);
                    return;
                }
            };

        // Watch PAM directories
        let pam_paths = [
            "/etc/pam.d",
            "/lib/security",
            "/lib64/security",
            "/lib/x86_64-linux-gnu/security",
        ];

        for path in &pam_paths {
            if Path::new(path).exists() {
                if let Err(e) = watcher.watch(Path::new(path), RecursiveMode::Recursive) {
                    warn!("Failed to watch PAM path {}: {}", path, e);
                }
            }
        }

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        for event in notify_rx {
            for path in &event.paths {
                let path_str = path.to_string_lossy();

                let operation = match &event.kind {
                    EventKind::Create(_) => "create",
                    EventKind::Modify(_) => "modify",
                    EventKind::Remove(_) => "delete",
                    _ => continue,
                };

                // Check if this is a PAM-related file
                if path_str.contains("pam") || path_str.contains("/security/") {
                    warn!(
                        path = %path_str,
                        operation = operation,
                        "PAM module modification detected"
                    );

                    let tel_event = Self::create_credential_theft_event(
                        CredentialAttackType::PamModification,
                        &path_str,
                        "File System",
                        0,
                        "",
                        "",
                        &Self::get_current_user(),
                        false,
                        format!("PAM module {} operation: {}", operation, path_str),
                    );

                    let _ = runtime.block_on(tx_clone.send(tel_event));
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    async fn monitor_credential_files_linux(
        tx: mpsc::Sender<TelemetryEvent>,
        _config: AgentConfig,
        _interval_ms: u64,
    ) {
        use notify::{Event as NotifyEvent, EventKind, RecursiveMode, Watcher};
        use std::path::Path;

        info!("Starting Linux credential file monitoring");

        let (notify_tx, notify_rx) = std::sync::mpsc::channel();
        let tx_clone = tx.clone();

        let mut watcher =
            match notify::recommended_watcher(move |res: notify::Result<NotifyEvent>| {
                if let Ok(event) = res {
                    let _ = notify_tx.send(event);
                }
            }) {
                Ok(w) => w,
                Err(e) => {
                    error!("Failed to create file watcher: {}", e);
                    return;
                }
            };

        // Watch system credential files
        let system_paths = ["/etc/shadow", "/etc/gshadow", "/etc/passwd"];

        for path in &system_paths {
            if Path::new(path).exists() {
                if let Err(e) = watcher.watch(Path::new(path), RecursiveMode::NonRecursive) {
                    warn!("Failed to watch {}: {}", path, e);
                }
            }
        }

        // Watch user home directories for credential files
        if let Ok(home_dir) = std::fs::read_dir("/home") {
            for entry in home_dir.filter_map(|e| e.ok()) {
                let user_path = entry.path();
                let credential_paths = [
                    user_path.join(".ssh"),
                    user_path.join(".gnupg"),
                    user_path.join(".local/share/keyrings"),
                    user_path.join(".mozilla/firefox"),
                    user_path.join(".config/google-chrome"),
                    user_path.join(".aws"),
                    user_path.join(".kube"),
                ];

                for cred_path in &credential_paths {
                    if cred_path.exists() {
                        if let Err(e) = watcher.watch(cred_path, RecursiveMode::Recursive) {
                            debug!("Failed to watch {:?}: {}", cred_path, e);
                        }
                    }
                }

                // Watch specific files
                let specific_files = [
                    user_path.join(".netrc"),
                    user_path.join(".pgpass"),
                    user_path.join(".my.cnf"),
                    user_path.join(".git-credentials"),
                ];

                for file_path in &specific_files {
                    if file_path.exists() {
                        if let Err(e) = watcher.watch(file_path, RecursiveMode::NonRecursive) {
                            debug!("Failed to watch {:?}: {}", file_path, e);
                        }
                    }
                }
            }
        }

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        for event in notify_rx {
            for path in &event.paths {
                let path_str = path.to_string_lossy().to_lowercase();

                for (pattern, attack_type) in LINUX_CREDENTIAL_PATHS {
                    if path_str.contains(&pattern.to_lowercase()) {
                        let operation = match &event.kind {
                            EventKind::Access(_) => "read",
                            EventKind::Modify(_) => "modify",
                            EventKind::Create(_) => "create",
                            EventKind::Remove(_) => "delete",
                            _ => continue,
                        };

                        let tel_event = Self::create_credential_theft_event(
                            *attack_type,
                            &path_str,
                            "File System",
                            0,
                            "",
                            "",
                            &Self::get_current_user(),
                            false,
                            format!("Credential file {} operation: {}", operation, path_str),
                        );

                        let _ = runtime.block_on(tx_clone.send(tel_event));
                        break;
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    async fn monitor_network_credentials_linux(tx: mpsc::Sender<TelemetryEvent>, interval_ms: u64) {
        info!("Starting Linux network credential theft detection");

        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));
        let mut seen_attacks: HashSet<String> = HashSet::new();

        loop {
            interval.tick().await;

            // Check for processes listening on LLMNR/mDNS ports
            if let Ok(content) = tokio::fs::read_to_string("/proc/net/udp").await {
                for line in content.lines().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() < 10 {
                        continue;
                    }

                    let local = parts[1];
                    let inode: u64 = parts[9].parse().unwrap_or(0);

                    if let Some((_, port_hex)) = local.split_once(':') {
                        let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);

                        // Check for suspicious ports
                        if port == 5355 || port == 137 || port == 5353 {
                            if let Some((pid, name)) = Self::find_process_by_inode(inode).await {
                                let key = format!("{}:{}:{}", pid, name, port);

                                // Skip system processes
                                let is_legitimate = name == "avahi-daemon"
                                    || name == "systemd-resolve"
                                    || name == "dnsmasq";

                                if !is_legitimate && !seen_attacks.contains(&key) {
                                    seen_attacks.insert(key);

                                    let event = Self::create_credential_theft_event(
                                        CredentialAttackType::LlmnrPoisoning,
                                        &format!("UDP port {}", port),
                                        &name,
                                        pid,
                                        "",
                                        "",
                                        &Self::get_current_user(),
                                        false,
                                        format!(
                                            "Suspicious process {} (PID: {}) listening on port {}",
                                            name, pid, port
                                        ),
                                    );

                                    if tx.send(event).await.is_err() {
                                        return;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Cleanup
            if seen_attacks.len() > 1000 {
                seen_attacks.clear();
            }
        }
    }

    #[cfg(target_os = "linux")]
    async fn find_process_by_inode(inode: u64) -> Option<(u32, String)> {
        if let Ok(proc_dir) = std::fs::read_dir("/proc") {
            for entry in proc_dir.filter_map(|e| e.ok()) {
                let pid_str = entry.file_name().to_string_lossy().to_string();
                let pid: u32 = match pid_str.parse() {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                let fd_path = format!("/proc/{}/fd", pid);
                if let Ok(fd_dir) = std::fs::read_dir(&fd_path) {
                    for fd_entry in fd_dir.filter_map(|e| e.ok()) {
                        if let Ok(target) = std::fs::read_link(fd_entry.path()) {
                            let target_str = target.to_string_lossy();
                            if target_str.contains(&format!("socket:[{}]", inode)) {
                                let comm_path = format!("/proc/{}/comm", pid);
                                let name = std::fs::read_to_string(&comm_path)
                                    .map(|s| s.trim().to_string())
                                    .unwrap_or_default();
                                return Some((pid, name));
                            }
                        }
                    }
                }
            }
        }
        None
    }

    // ==================== macOS Implementation ====================
    #[cfg(target_os = "macos")]
    async fn get_processes_macos() -> Vec<(u32, String, String, String)> {
        use std::process::Command;

        let mut processes = Vec::new();

        let output = Command::new("ps").args(["-eo", "pid,comm,args"]).output();

        if let Ok(output) = output {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let pid: u32 = parts[0].parse().unwrap_or(0);
                        let name = parts[1].to_string();
                        let cmdline = parts[2..].join(" ");
                        let path = name.clone();

                        processes.push((pid, name, cmdline, path));
                    }
                }
            }
        }

        processes
    }

    #[cfg(target_os = "macos")]
    async fn monitor_credential_files_macos(
        tx: mpsc::Sender<TelemetryEvent>,
        _config: AgentConfig,
        _interval_ms: u64,
    ) {
        use notify::{Event as NotifyEvent, EventKind, RecursiveMode, Watcher};
        use std::path::Path;

        info!("Starting macOS credential file monitoring");

        let (notify_tx, notify_rx) = std::sync::mpsc::channel();
        let tx_clone = tx.clone();

        let mut watcher =
            match notify::recommended_watcher(move |res: notify::Result<NotifyEvent>| {
                if let Ok(event) = res {
                    let _ = notify_tx.send(event);
                }
            }) {
                Ok(w) => w,
                Err(e) => {
                    error!("Failed to create file watcher: {}", e);
                    return;
                }
            };

        // Watch user home directories for credential files
        if let Ok(home_dir) = std::fs::read_dir("/Users") {
            for entry in home_dir.filter_map(|e| e.ok()) {
                let user_path = entry.path();

                let credential_paths = [
                    user_path.join(".ssh"),
                    user_path.join("Library/Keychains"),
                    user_path.join("Library/Application Support/Google/Chrome/Default"),
                    user_path.join("Library/Application Support/Firefox/Profiles"),
                    user_path.join("Library/Safari"),
                    user_path.join(".aws"),
                    user_path.join(".kube"),
                ];

                for cred_path in &credential_paths {
                    if cred_path.exists() {
                        if let Err(e) = watcher.watch(cred_path, RecursiveMode::Recursive) {
                            debug!("Failed to watch {:?}: {}", cred_path, e);
                        }
                    }
                }
            }
        }

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let macos_patterns: Vec<(&str, CredentialAttackType)> = vec![
            ("Keychains", CredentialAttackType::CredentialVault),
            (".ssh", CredentialAttackType::SshKeyTheft),
            ("Login Data", CredentialAttackType::BrowserCredentials),
            ("logins.json", CredentialAttackType::BrowserCredentials),
            (".kdbx", CredentialAttackType::PasswordManager),
            (".aws/credentials", CredentialAttackType::CredentialFile),
        ];

        for event in notify_rx {
            for path in &event.paths {
                let path_str = path.to_string_lossy().to_lowercase();

                for (pattern, attack_type) in &macos_patterns {
                    if path_str.contains(&pattern.to_lowercase()) {
                        let operation = match &event.kind {
                            EventKind::Access(_) => "read",
                            EventKind::Modify(_) => "modify",
                            EventKind::Create(_) => "create",
                            EventKind::Remove(_) => "delete",
                            _ => continue,
                        };

                        let tel_event = Self::create_credential_theft_event(
                            *attack_type,
                            &path_str,
                            "File System",
                            0,
                            "",
                            "",
                            &Self::get_current_user(),
                            false,
                            format!("Credential file {} operation: {}", operation, path_str),
                        );

                        let _ = runtime.block_on(tx_clone.send(tel_event));
                        break;
                    }
                }
            }
        }
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
    fn test_attack_type_mitre_mapping() {
        assert_eq!(
            CredentialAttackType::LsassAccess.mitre_technique(),
            "T1003.001"
        );
        assert_eq!(
            CredentialAttackType::SamAccess.mitre_technique(),
            "T1003.002"
        );
        assert_eq!(CredentialAttackType::DcSync.mitre_technique(), "T1003.006");
        assert_eq!(
            CredentialAttackType::Kerberoasting.mitre_technique(),
            "T1558.003"
        );
        assert_eq!(
            CredentialAttackType::PassTheHash.mitre_technique(),
            "T1550.002"
        );
        assert_eq!(
            CredentialAttackType::ProcMemAccess.mitre_technique(),
            "T1003.007"
        );
        assert_eq!(
            CredentialAttackType::PamModification.mitre_technique(),
            "T1556.003"
        );
    }

    #[test]
    fn test_attack_type_severity() {
        assert_eq!(
            CredentialAttackType::LsassAccess.severity(),
            Severity::Critical
        );
        assert_eq!(CredentialAttackType::DcSync.severity(), Severity::Critical);
        assert_eq!(
            CredentialAttackType::Kerberoasting.severity(),
            Severity::High
        );
        assert_eq!(
            CredentialAttackType::BrowserCredentials.severity(),
            Severity::Medium
        );
    }

    #[test]
    fn test_mimikatz_patterns() {
        let test_cmdline = "mimikatz.exe privilege::debug sekurlsa::logonpasswords";
        let test_lower = test_cmdline.to_lowercase();

        let mut found = false;
        for pattern in MIMIKATZ_PATTERNS {
            if test_lower.contains(pattern) {
                found = true;
                break;
            }
        }
        assert!(found);
    }

    #[test]
    fn test_dcsync_patterns() {
        let test_cmdline = "secretsdump.py -just-dc domain/user@dc";
        let test_lower = test_cmdline.to_lowercase();

        let mut found = false;
        for pattern in DCSYNC_PATTERNS {
            if test_lower.contains(pattern) {
                found = true;
                break;
            }
        }
        assert!(found);
    }

    #[test]
    fn test_credential_tools_patterns() {
        let mimikatz_pattern = CREDENTIAL_TOOLS.iter().find(|(p, _)| *p == "mimikatz");
        assert!(mimikatz_pattern.is_some());

        let secretsdump_pattern = CREDENTIAL_TOOLS.iter().find(|(p, _)| *p == "secretsdump");
        assert!(secretsdump_pattern.is_some());

        let procdump_pattern = CREDENTIAL_TOOLS.iter().find(|(p, _)| *p == "procdump");
        assert!(procdump_pattern.is_some());
    }
}
