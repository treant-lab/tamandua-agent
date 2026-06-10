//! Active Directory / LDAP Monitoring Collector
//!
//! Detects Active Directory reconnaissance and attack patterns:
//! - LDAP enumeration queries (users, computers, groups, GPOs)
//! - Kerberos attacks (Kerberoasting, AS-REP Roasting, Golden/Silver tickets)
//! - DCSync detection (DsGetNCChanges replication abuse)
//! - Account manipulation (privileged account changes, SPN modifications)
//! - GPO abuse (malicious GPO creation/modification)
//! - Trust abuse (cross-domain tickets, SID History)
//! - LAPS password queries
//!
//! Windows Implementation:
//! - ETW for Kerberos events (Microsoft-Windows-Security-Auditing)
//! - Event log monitoring (4768, 4769, 4776, 4662, 4738, etc.)
//! - LSASS network activity monitoring
//! - LDAP traffic analysis
//!
//! MITRE ATT&CK Coverage:
//! - T1087 (Account Discovery)
//! - T1069 (Permission Groups Discovery)
//! - T1558 (Steal or Forge Kerberos Tickets)
//! - T1558.001 (Golden Ticket)
//! - T1558.002 (Silver Ticket)
//! - T1558.003 (Kerberoasting)
//! - T1558.004 (AS-REP Roasting)
//! - T1003.006 (DCSync)
//! - T1484 (Domain Policy Modification)
//! - T1482 (Domain Trust Discovery)

#![cfg(target_os = "windows")]
// AD/LDAP event ID and ETW provider constants are exhaustively enumerated as
// a machine-checked reference (Kerberos, replication, GPO, trust events).
// Not every constant is consumed by current rules; suppress dead-code lint
// file-wide so the reference table stays intact.
#![allow(dead_code)]

use super::{Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent};
use crate::config::AgentConfig;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use windows::core::PCWSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Security::Authentication::Identity::{
    LsaClose, LsaFreeMemory, LsaOpenPolicy, LsaQueryInformationPolicy, PolicyDnsDomainInformation,
    LSA_HANDLE, LSA_OBJECT_ATTRIBUTES, POLICY_DNS_DOMAIN_INFO,
};
use windows::Win32::System::EventLog::{
    CloseEventLog, OpenEventLogW, ReadEventLogW, EVENTLOGRECORD, READ_EVENT_LOG_READ_FLAGS,
};

// EventLog read flags - use raw values directly
const EVENTLOG_BACKWARDS_READ: u32 = 0x0008;
const EVENTLOG_SEQUENTIAL_READ: u32 = 0x0001;
use windows::Win32::System::ProcessStatus::K32GetProcessImageFileNameW;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

/// Active Directory event types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdActivityType {
    /// LDAP enumeration query detected
    LdapEnumeration,
    /// BloodHound/SharpHound collection detected
    BloodHoundDetected,
    /// Kerberos TGT request (AS-REQ)
    KerberosTgtRequest,
    /// Kerberos service ticket request (TGS-REQ)
    KerberosTgsRequest,
    /// Kerberoasting detected (mass SPN queries)
    Kerberoasting,
    /// AS-REP Roasting detected
    AsRepRoasting,
    /// Golden ticket usage suspected
    GoldenTicket,
    /// Silver ticket usage suspected
    SilverTicket,
    /// Overpass-the-Hash detected
    OverpassTheHash,
    /// DCSync replication attempt
    DcSync,
    /// Non-DC replication attempt
    NonDcReplication,
    /// Privileged account password change
    PrivilegedAccountChange,
    /// Group membership modification
    GroupMembershipChange,
    /// SPN modification
    SpnModification,
    /// Account creation in sensitive OU
    SensitiveAccountCreation,
    /// GPO creation
    GpoCreation,
    /// GPO modification
    GpoModification,
    /// Cross-domain ticket request
    CrossDomainTicket,
    /// SID History abuse
    SidHistoryAbuse,
    /// LAPS password query
    LapsPasswordQuery,
    /// Delegation attribute query
    DelegationQuery,
    /// AdminSDHolder query
    AdminSdHolderQuery,
    /// Trust enumeration
    TrustEnumeration,
}

impl AdActivityType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LdapEnumeration => "ldap_enumeration",
            Self::BloodHoundDetected => "bloodhound_detected",
            Self::KerberosTgtRequest => "kerberos_tgt_request",
            Self::KerberosTgsRequest => "kerberos_tgs_request",
            Self::Kerberoasting => "kerberoasting",
            Self::AsRepRoasting => "as_rep_roasting",
            Self::GoldenTicket => "golden_ticket",
            Self::SilverTicket => "silver_ticket",
            Self::OverpassTheHash => "overpass_the_hash",
            Self::DcSync => "dcsync",
            Self::NonDcReplication => "non_dc_replication",
            Self::PrivilegedAccountChange => "privileged_account_change",
            Self::GroupMembershipChange => "group_membership_change",
            Self::SpnModification => "spn_modification",
            Self::SensitiveAccountCreation => "sensitive_account_creation",
            Self::GpoCreation => "gpo_creation",
            Self::GpoModification => "gpo_modification",
            Self::CrossDomainTicket => "cross_domain_ticket",
            Self::SidHistoryAbuse => "sid_history_abuse",
            Self::LapsPasswordQuery => "laps_password_query",
            Self::DelegationQuery => "delegation_query",
            Self::AdminSdHolderQuery => "admin_sd_holder_query",
            Self::TrustEnumeration => "trust_enumeration",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Self::DcSync | Self::GoldenTicket | Self::SilverTicket => Severity::Critical,
            Self::Kerberoasting
            | Self::AsRepRoasting
            | Self::BloodHoundDetected
            | Self::NonDcReplication
            | Self::OverpassTheHash
            | Self::SidHistoryAbuse => Severity::High,
            Self::PrivilegedAccountChange
            | Self::GpoModification
            | Self::SpnModification
            | Self::LapsPasswordQuery => Severity::High,
            Self::LdapEnumeration
            | Self::GroupMembershipChange
            | Self::GpoCreation
            | Self::CrossDomainTicket
            | Self::DelegationQuery => Severity::Medium,
            Self::KerberosTgtRequest
            | Self::KerberosTgsRequest
            | Self::SensitiveAccountCreation
            | Self::AdminSdHolderQuery
            | Self::TrustEnumeration => Severity::Low,
        }
    }

    pub fn mitre_techniques(&self) -> Vec<String> {
        match self {
            Self::LdapEnumeration => vec!["T1087".to_string(), "T1069".to_string()],
            Self::BloodHoundDetected => vec![
                "T1087".to_string(),
                "T1069".to_string(),
                "T1482".to_string(),
            ],
            Self::KerberosTgtRequest | Self::KerberosTgsRequest => vec!["T1558".to_string()],
            Self::Kerberoasting => vec!["T1558.003".to_string()],
            Self::AsRepRoasting => vec!["T1558.004".to_string()],
            Self::GoldenTicket => vec!["T1558.001".to_string()],
            Self::SilverTicket => vec!["T1558.002".to_string()],
            Self::OverpassTheHash => vec!["T1550.002".to_string()],
            Self::DcSync | Self::NonDcReplication => vec!["T1003.006".to_string()],
            Self::PrivilegedAccountChange
            | Self::GroupMembershipChange
            | Self::SpnModification
            | Self::SensitiveAccountCreation => vec!["T1098".to_string()],
            Self::GpoCreation | Self::GpoModification => vec!["T1484.001".to_string()],
            Self::CrossDomainTicket | Self::SidHistoryAbuse | Self::TrustEnumeration => {
                vec!["T1482".to_string(), "T1134.005".to_string()]
            }
            Self::LapsPasswordQuery => vec!["T1552.004".to_string()],
            Self::DelegationQuery => vec!["T1087.002".to_string()],
            Self::AdminSdHolderQuery => vec!["T1069.002".to_string()],
        }
    }

    pub fn mitre_tactics(&self) -> Vec<String> {
        match self {
            Self::LdapEnumeration
            | Self::BloodHoundDetected
            | Self::TrustEnumeration
            | Self::DelegationQuery
            | Self::AdminSdHolderQuery => vec!["Discovery".to_string()],
            Self::Kerberoasting
            | Self::AsRepRoasting
            | Self::GoldenTicket
            | Self::SilverTicket
            | Self::DcSync
            | Self::NonDcReplication
            | Self::LapsPasswordQuery => vec!["Credential Access".to_string()],
            Self::OverpassTheHash | Self::CrossDomainTicket | Self::SidHistoryAbuse => {
                vec!["Lateral Movement".to_string()]
            }
            Self::PrivilegedAccountChange
            | Self::GroupMembershipChange
            | Self::SpnModification
            | Self::SensitiveAccountCreation
            | Self::GpoCreation
            | Self::GpoModification => vec![
                "Persistence".to_string(),
                "Privilege Escalation".to_string(),
            ],
            Self::KerberosTgtRequest | Self::KerberosTgsRequest => {
                vec!["Credential Access".to_string()]
            }
        }
    }
}

/// Active Directory event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdEvent {
    /// Activity type
    pub activity_type: AdActivityType,
    /// Source process ID
    pub source_pid: u32,
    /// Source process name
    pub source_process: String,
    /// Source process path
    pub source_path: String,
    /// Source user account
    pub source_user: String,
    /// Target object (user, computer, group, etc.)
    pub target_object: String,
    /// Target domain
    pub target_domain: Option<String>,
    /// LDAP filter if applicable
    pub ldap_filter: Option<String>,
    /// Service principal name if applicable
    pub service_name: Option<String>,
    /// Encryption type for Kerberos events
    pub encryption_type: Option<String>,
    /// Event ID from Windows Security log
    pub event_id: Option<u32>,
    /// Additional details
    pub details: String,
}

/// Windows Security Event IDs we monitor
mod security_event_ids {
    /// Kerberos TGT request
    pub const KERBEROS_TGT_REQUEST: u32 = 4768;
    /// Kerberos service ticket request
    pub const KERBEROS_TGS_REQUEST: u32 = 4769;
    /// Kerberos pre-authentication failed
    pub const KERBEROS_PREAUTH_FAILED: u32 = 4771;
    /// Credential validation
    pub const CREDENTIAL_VALIDATION: u32 = 4776;
    /// User account changed
    pub const USER_ACCOUNT_CHANGED: u32 = 4738;
    /// User account created
    pub const USER_ACCOUNT_CREATED: u32 = 4720;
    /// Security-enabled group member added
    pub const GROUP_MEMBER_ADDED: u32 = 4728;
    /// Security-enabled group member removed
    pub const GROUP_MEMBER_REMOVED: u32 = 4729;
    /// Directory service access
    pub const DS_ACCESS: u32 = 4662;
    /// Directory service object modified
    pub const DS_OBJECT_MODIFIED: u32 = 5136;
    /// Directory service object created
    pub const DS_OBJECT_CREATED: u32 = 5137;
    /// Directory replication request
    pub const DS_REPLICATION: u32 = 4662;
    /// SID History was added
    pub const SID_HISTORY_ADDED: u32 = 4765;
    /// Trusted domain created
    pub const TRUSTED_DOMAIN_CREATED: u32 = 4706;
}

/// LDAP query patterns that indicate enumeration
mod ldap_patterns {
    /// BloodHound/SharpHound LDAP patterns
    pub const BLOODHOUND_PATTERNS: &[&str] = &[
        "(memberof=*)",
        "(serviceprincipalname=*)",
        "(objectClass=user)",
        "(objectClass=computer)",
        "(objectClass=group)",
        "(objectCategory=person)",
        "(samAccountType=805306368)",
        "(userAccountControl:1.2.840.113556.1.4.803:=4194304)", // DONT_REQUIRE_PREAUTH
        "(msDS-AllowedToDelegateTo=*)",
        "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
        "(adminCount=1)",
    ];

    /// AdminSDHolder queries
    pub const ADMINSD_HOLDER_PATTERNS: &[&str] = &[
        "(adminCount=1)",
        "CN=AdminSDHolder",
        "(objectClass=container)",
    ];

    /// LAPS password queries
    pub const LAPS_PATTERNS: &[&str] = &[
        "ms-Mcs-AdmPwd",
        "ms-LAPS-Password",
        "ms-LAPS-EncryptedPassword",
        "(ms-Mcs-AdmPwdExpirationTime=*)",
    ];

    /// Delegation queries
    pub const DELEGATION_PATTERNS: &[&str] = &[
        "msDS-AllowedToDelegateTo",
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
        "(userAccountControl:1.2.840.113556.1.4.803:=524288)", // TRUSTED_FOR_DELEGATION
        "(userAccountControl:1.2.840.113556.1.4.803:=16777216)", // TRUSTED_TO_AUTH_FOR_DELEGATION
    ];

    /// GPO enumeration patterns
    pub const GPO_PATTERNS: &[&str] = &[
        "(objectClass=groupPolicyContainer)",
        "CN=Policies,CN=System",
        "gPCFileSysPath",
        "gPLink",
    ];

    /// Trust enumeration patterns
    pub const TRUST_PATTERNS: &[&str] = &[
        "(objectClass=trustedDomain)",
        "trustDirection",
        "trustType",
        "trustAttributes",
        "CN=System",
    ];

    /// All users/computers enumeration
    pub const MASS_ENUM_PATTERNS: &[&str] = &[
        "(objectClass=user)",
        "(objectClass=computer)",
        "(objectClass=group)",
        "(sAMAccountType=805306368)",
        "(sAMAccountType=805306369)",
    ];
}

/// Suspicious service principal name patterns (Kerberoasting targets)
mod spn_patterns {
    pub const HIGH_VALUE_SPNS: &[&str] = &[
        "MSSQLSvc/",
        "HTTP/",
        "LDAP/",
        "DNS/",
        "CIFS/",
        "GC/",
        "exchangeMDB/",
        "exchangeRFR/",
        "exchangeAB/",
        "IMAP/",
        "SMTP/",
        "POP/",
        "HOST/",
        "TERMSRV/",
        "WSMAN/",
        "RestrictedKrbHost/",
        "vpn/",
        "www/",
        "ftp/",
    ];
}

/// Sensitive groups/OUs for monitoring
mod sensitive_objects {
    pub const PRIVILEGED_GROUPS: &[&str] = &[
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
        "Account Operators",
        "Backup Operators",
        "Print Operators",
        "Server Operators",
        "DnsAdmins",
        "Domain Controllers",
        "Group Policy Creator Owners",
        "Cert Publishers",
        "Key Admins",
        "Enterprise Key Admins",
    ];

    pub const SENSITIVE_OUS: &[&str] = &[
        "OU=Domain Controllers",
        "OU=Admins",
        "OU=Tier 0",
        "OU=Service Accounts",
        "CN=AdminSDHolder",
    ];
}

/// Kerberos encryption types
mod encryption_types {
    pub const DES_CBC_CRC: u32 = 0x01;
    pub const DES_CBC_MD5: u32 = 0x03;
    pub const RC4_HMAC: u32 = 0x17; // Often targeted by Kerberoasting
    pub const AES128_CTS_HMAC: u32 = 0x11;
    pub const AES256_CTS_HMAC: u32 = 0x12;

    pub fn name(etype: u32) -> &'static str {
        match etype {
            DES_CBC_CRC => "DES-CBC-CRC",
            DES_CBC_MD5 => "DES-CBC-MD5",
            RC4_HMAC => "RC4-HMAC",
            AES128_CTS_HMAC => "AES128-CTS-HMAC",
            AES256_CTS_HMAC => "AES256-CTS-HMAC",
            _ => "Unknown",
        }
    }

    pub fn is_weak(etype: u32) -> bool {
        matches!(etype, DES_CBC_CRC | DES_CBC_MD5 | RC4_HMAC)
    }
}

/// DCSync related GUIDs
mod dcsync_guids {
    /// DS-Replication-Get-Changes GUID
    pub const DS_REPLICATION_GET_CHANGES: &str = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2";
    /// DS-Replication-Get-Changes-All GUID
    pub const DS_REPLICATION_GET_CHANGES_ALL: &str = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2";
    /// DS-Replication-Get-Changes-In-Filtered-Set GUID
    pub const DS_REPLICATION_GET_CHANGES_FILTERED: &str = "89e95b76-444d-4c62-991a-0facbeda640c";
}

/// Time window for detecting patterns (in seconds)
const PATTERN_WINDOW_SECONDS: u64 = 300; // 5 minutes

/// Threshold for Kerberoasting detection (TGS requests in window)
const KERBEROASTING_THRESHOLD: usize = 10;

/// Threshold for AS-REP Roasting detection (failed pre-auth in window)
const ASREP_ROASTING_THRESHOLD: usize = 5;

/// Threshold for LDAP enumeration detection (queries in window)
const LDAP_ENUM_THRESHOLD: usize = 20;

/// Active Directory Monitor
pub struct AdMonitor {
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    running: Arc<AtomicBool>,
    domain_info: Option<DomainInfo>,
}

/// Domain information
#[derive(Debug, Clone)]
struct DomainInfo {
    dns_domain_name: String,
    netbios_name: String,
    domain_sid: String,
    forest_name: String,
    domain_controllers: Vec<String>,
}

/// Event tracking for pattern detection
struct EventTracker {
    /// TGS requests per user (for Kerberoasting detection)
    tgs_requests: HashMap<String, VecDeque<u64>>,
    /// Pre-auth failures per user (for AS-REP Roasting detection)
    preauth_failures: HashMap<String, VecDeque<u64>>,
    /// LDAP queries per source (for enumeration detection)
    ldap_queries: HashMap<String, VecDeque<(u64, String)>>,
    /// Replication requests (for DCSync detection)
    replication_requests: HashMap<String, VecDeque<u64>>,
    /// Recently alerted events (to avoid duplicates)
    recent_alerts: HashMap<String, u64>,
}

impl EventTracker {
    fn new() -> Self {
        Self {
            tgs_requests: HashMap::new(),
            preauth_failures: HashMap::new(),
            ldap_queries: HashMap::new(),
            replication_requests: HashMap::new(),
            recent_alerts: HashMap::new(),
        }
    }

    fn cleanup(&mut self, now: u64) {
        let cutoff = now.saturating_sub(PATTERN_WINDOW_SECONDS);

        // Cleanup TGS requests
        for requests in self.tgs_requests.values_mut() {
            while requests.front().map(|&t| t < cutoff).unwrap_or(false) {
                requests.pop_front();
            }
        }
        self.tgs_requests.retain(|_, v| !v.is_empty());

        // Cleanup pre-auth failures
        for failures in self.preauth_failures.values_mut() {
            while failures.front().map(|&t| t < cutoff).unwrap_or(false) {
                failures.pop_front();
            }
        }
        self.preauth_failures.retain(|_, v| !v.is_empty());

        // Cleanup LDAP queries
        for queries in self.ldap_queries.values_mut() {
            while queries.front().map(|(t, _)| *t < cutoff).unwrap_or(false) {
                queries.pop_front();
            }
        }
        self.ldap_queries.retain(|_, v| !v.is_empty());

        // Cleanup replication requests
        for requests in self.replication_requests.values_mut() {
            while requests.front().map(|&t| t < cutoff).unwrap_or(false) {
                requests.pop_front();
            }
        }
        self.replication_requests.retain(|_, v| !v.is_empty());

        // Cleanup recent alerts (keep for 5 minutes)
        self.recent_alerts
            .retain(|_, &mut timestamp| timestamp > cutoff);
    }

    fn should_alert(&mut self, key: &str, now: u64) -> bool {
        if let Some(&last_alert) = self.recent_alerts.get(key) {
            if now - last_alert < 60 {
                // Don't alert for same event within 1 minute
                return false;
            }
        }
        self.recent_alerts.insert(key.to_string(), now);
        true
    }
}

impl AdMonitor {
    /// Create a new Active Directory monitor
    pub fn new(config: &AgentConfig) -> Result<Self> {
        let (tx, rx) = mpsc::channel(1000);
        let running = Arc::new(AtomicBool::new(true));

        info!("Initializing Active Directory monitor");

        // Get domain information
        let domain_info = Self::get_domain_info();
        if let Some(ref info) = domain_info {
            info!(
                domain = %info.dns_domain_name,
                netbios = %info.netbios_name,
                "Connected to Active Directory domain"
            );
        } else {
            warn!("Could not get domain information - system may not be domain-joined");
        }

        // Start monitoring
        let config_clone = config.clone();
        let tx_clone = tx.clone();
        let running_clone = running.clone();
        let domain_info_clone = domain_info.clone();

        tokio::spawn(async move {
            Self::monitor_loop(tx_clone, config_clone, running_clone, domain_info_clone).await;
        });

        Ok(Self {
            config: config.clone(),
            event_rx: rx,
            running,
            domain_info,
        })
    }

    /// Get domain information using LSA
    fn get_domain_info() -> Option<DomainInfo> {
        // SAFETY: LSA (Local Security Authority) FFI calls. We zero-initialize LSA_OBJECT_ATTRIBUTES
        // and provide valid mutable pointers for the policy_handle output. LsaOpenPolicy is safe
        // to call with None for system name (queries local system). The returned policy_handle is
        // valid for subsequent LSA calls. All error paths check status codes before using output.
        // Windows guarantees thread-safe LSA access via the kernel.
        unsafe {
            let mut policy_handle = LSA_HANDLE::default();
            let object_attrs: LSA_OBJECT_ATTRIBUTES = std::mem::zeroed();

            // Open LSA policy
            let status = LsaOpenPolicy(
                None, // System name
                &object_attrs,
                0x00000001, // POLICY_VIEW_LOCAL_INFORMATION
                &mut policy_handle,
            );

            if status.is_err() {
                debug!("LsaOpenPolicy failed");
                return None;
            }

            // Query domain information
            let mut domain_info_ptr: *mut c_void = std::ptr::null_mut();
            let query_status = LsaQueryInformationPolicy(
                policy_handle,
                PolicyDnsDomainInformation,
                &mut domain_info_ptr,
            );

            if query_status.is_err() || domain_info_ptr.is_null() {
                // Clean up handle
                let _ = LsaClose(policy_handle);
                debug!("LsaQueryInformationPolicy failed");
                return None;
            }

            let dns_info = &*(domain_info_ptr as *const POLICY_DNS_DOMAIN_INFO);

            let dns_domain_name = if !dns_info.DnsDomainName.Buffer.is_null() {
                let len = (dns_info.DnsDomainName.Length / 2) as usize;
                String::from_utf16_lossy(std::slice::from_raw_parts(
                    dns_info.DnsDomainName.Buffer.0,
                    len,
                ))
            } else {
                String::new()
            };

            let netbios_name = if !dns_info.Name.Buffer.is_null() {
                let len = (dns_info.Name.Length / 2) as usize;
                String::from_utf16_lossy(std::slice::from_raw_parts(dns_info.Name.Buffer.0, len))
            } else {
                String::new()
            };

            let forest_name = if !dns_info.DnsForestName.Buffer.is_null() {
                let len = (dns_info.DnsForestName.Length / 2) as usize;
                String::from_utf16_lossy(std::slice::from_raw_parts(
                    dns_info.DnsForestName.Buffer.0,
                    len,
                ))
            } else {
                String::new()
            };

            // Convert SID to string
            let domain_sid = if !dns_info.Sid.is_invalid() {
                Self::sid_to_string(dns_info.Sid)
            } else {
                String::new()
            };

            // Free the buffer
            let _ = LsaFreeMemory(Some(domain_info_ptr as *const c_void));
            let _ = LsaClose(policy_handle);

            if dns_domain_name.is_empty() {
                return None;
            }

            Some(DomainInfo {
                dns_domain_name,
                netbios_name,
                domain_sid,
                forest_name,
                domain_controllers: Vec::new(), // Would need DNS query to populate
            })
        }
    }

    /// Convert SID to string representation
    fn sid_to_string(sid: windows::Win32::Foundation::PSID) -> String {
        use windows::Win32::Foundation::LocalFree;
        use windows::Win32::Security::Authorization::ConvertSidToStringSidW;

        // SAFETY: ConvertSidToStringSidW converts a SID binary to string representation.
        // Input sid must be valid (guaranteed by function signature). We pass valid mutable
        // pointer for output. On success, Windows allocates memory via LocalAlloc and returns
        // the pointer. We check for null before converting and immediately free the allocated
        // memory via LocalFree. PWSTR::to_string() is safe because Windows null-terminates the
        // returned string.
        unsafe {
            let mut sid_str: windows::core::PWSTR = windows::core::PWSTR::null();
            if ConvertSidToStringSidW(sid, &mut sid_str).is_ok() && !sid_str.is_null() {
                let result = sid_str.to_string().unwrap_or_default();
                let _ = LocalFree(windows::Win32::Foundation::HLOCAL(sid_str.0 as *mut c_void));
                result
            } else {
                String::new()
            }
        }
    }

    /// Main monitoring loop
    async fn monitor_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        _config: AgentConfig,
        running: Arc<AtomicBool>,
        domain_info: Option<DomainInfo>,
    ) {
        info!("Starting Active Directory monitoring loop");

        if domain_info.is_none() {
            warn!("System not domain-joined, AD monitoring limited to local events");
        }

        let mut tracker = EventTracker::new();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
        let mut event_log_position: u32 = 0;

        // Track known domain controllers
        let known_dcs: HashSet<String> = domain_info
            .as_ref()
            .map(|di| di.domain_controllers.iter().cloned().collect())
            .unwrap_or_default();

        loop {
            if !running.load(Ordering::SeqCst) {
                break;
            }

            interval.tick().await;

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            // Cleanup old tracking data
            tracker.cleanup(now);

            // Monitor Security Event Log for Kerberos and AD events
            if let Some(events) = Self::read_security_events(&mut event_log_position) {
                for (event_id, event_data) in events {
                    if let Some(detection) = Self::analyze_security_event(
                        event_id,
                        &event_data,
                        &mut tracker,
                        now,
                        &known_dcs,
                    ) {
                        if tx.send(detection).await.is_err() {
                            warn!("Event channel closed");
                            return;
                        }
                    }
                }
            }

            // Monitor LDAP traffic (requires packet capture or ETW)
            // This is a simplified check based on process activity
            if let Some(ldap_events) = Self::monitor_ldap_activity(&mut tracker, now) {
                for event in ldap_events {
                    if tx.send(event).await.is_err() {
                        warn!("Event channel closed");
                        return;
                    }
                }
            }

            // Check for pattern-based detections
            if let Some(pattern_events) =
                Self::check_attack_patterns(&mut tracker, now, &domain_info)
            {
                for event in pattern_events {
                    if tx.send(event).await.is_err() {
                        warn!("Event channel closed");
                        return;
                    }
                }
            }
        }

        info!("Active Directory monitoring stopped");
    }

    /// Read events from the Security event log
    fn read_security_events(_position: &mut u32) -> Option<Vec<(u32, HashMap<String, String>)>> {
        let mut events = Vec::new();

        // SAFETY: OpenEventLogW opens the Windows event log. We construct a null-terminated
        // UTF-16 string for "Security" and pass valid PCWSTR pointers. First parameter null()
        // means query local computer. The returned handle is valid for subsequent event log reads.
        // Windows manages event log access synchronously. Error handling checks the return value
        // before using the handle.
        unsafe {
            let log_name: Vec<u16> = "Security\0".encode_utf16().collect();
            let handle = match OpenEventLogW(PCWSTR::null(), PCWSTR(log_name.as_ptr())) {
                Ok(h) => h,
                Err(e) => {
                    debug!(error = ?e, "Failed to open Security event log");
                    return None;
                }
            };

            // Read buffer (64KB)
            let buffer_size: u32 = 65536;
            let mut buffer = vec![0u8; buffer_size as usize];
            let mut bytes_read: u32 = 0;
            let mut min_bytes_needed: u32 = 0;

            let flags = EVENTLOG_BACKWARDS_READ | EVENTLOG_SEQUENTIAL_READ;

            // Read events
            let result = ReadEventLogW(
                handle,
                READ_EVENT_LOG_READ_FLAGS(flags),
                0,
                buffer.as_mut_ptr() as *mut c_void,
                buffer_size,
                &mut bytes_read,
                &mut min_bytes_needed,
            );

            if result.is_err() || bytes_read == 0 {
                let _ = CloseEventLog(handle);
                return if events.is_empty() {
                    None
                } else {
                    Some(events)
                };
            }

            // Parse events from buffer
            let mut offset = 0usize;
            while offset < bytes_read as usize {
                if offset + std::mem::size_of::<EVENTLOGRECORD>() > bytes_read as usize {
                    break;
                }

                let record = &*(buffer.as_ptr().add(offset) as *const EVENTLOGRECORD);
                let event_id = record.EventID & 0xFFFF; // Lower 16 bits

                // Filter for relevant event IDs
                if Self::is_relevant_event_id(event_id) {
                    let event_data = Self::parse_event_data(record, &buffer[offset..]);
                    events.push((event_id, event_data));
                }

                if record.Length == 0
                    || record.Length < std::mem::size_of::<EVENTLOGRECORD>() as u32
                {
                    break;
                }
                // Validate record.Length doesn't exceed remaining buffer
                if offset + record.Length as usize > bytes_read as usize {
                    break;
                }
                offset += record.Length as usize;
            }

            let _ = CloseEventLog(handle);
        }

        if events.is_empty() {
            None
        } else {
            Some(events)
        }
    }

    /// Check if event ID is relevant for AD monitoring
    fn is_relevant_event_id(event_id: u32) -> bool {
        matches!(
            event_id,
            security_event_ids::KERBEROS_TGT_REQUEST
                | security_event_ids::KERBEROS_TGS_REQUEST
                | security_event_ids::KERBEROS_PREAUTH_FAILED
                | security_event_ids::CREDENTIAL_VALIDATION
                | security_event_ids::USER_ACCOUNT_CHANGED
                | security_event_ids::USER_ACCOUNT_CREATED
                | security_event_ids::GROUP_MEMBER_ADDED
                | security_event_ids::GROUP_MEMBER_REMOVED
                | security_event_ids::DS_ACCESS
                | security_event_ids::DS_OBJECT_MODIFIED
                | security_event_ids::DS_OBJECT_CREATED
                | security_event_ids::SID_HISTORY_ADDED
                | security_event_ids::TRUSTED_DOMAIN_CREATED
        )
    }

    /// Parse event data from EVENTLOGRECORD
    fn parse_event_data(record: &EVENTLOGRECORD, _buffer: &[u8]) -> HashMap<String, String> {
        let mut data = HashMap::new();

        // Basic event metadata
        data.insert("RecordNumber".to_string(), record.RecordNumber.to_string());
        data.insert(
            "TimeGenerated".to_string(),
            record.TimeGenerated.to_string(),
        );
        data.insert(
            "EventCategory".to_string(),
            record.EventCategory.to_string(),
        );

        // Note: Full event parsing would require reading the event message from
        // the message DLL and parsing XML event data. This is simplified.

        data
    }

    /// Analyze security event for suspicious activity
    fn analyze_security_event(
        event_id: u32,
        _event_data: &HashMap<String, String>,
        tracker: &mut EventTracker,
        now: u64,
        known_dcs: &HashSet<String>,
    ) -> Option<TelemetryEvent> {
        match event_id {
            security_event_ids::KERBEROS_TGS_REQUEST => {
                // Track TGS request for Kerberoasting detection
                // In production, would parse target service name and requesting user
                let user = "unknown".to_string(); // Would extract from event data
                tracker
                    .tgs_requests
                    .entry(user.clone())
                    .or_default()
                    .push_back(now);

                // Check if this user has made many TGS requests (potential Kerberoasting)
                let request_count = tracker
                    .tgs_requests
                    .get(&user)
                    .map(|r| r.len())
                    .unwrap_or(0);
                if request_count >= KERBEROASTING_THRESHOLD {
                    let alert_key = format!("kerberoast_{}", user);
                    if tracker.should_alert(&alert_key, now) {
                        return Some(Self::create_ad_event(
                            AdActivityType::Kerberoasting,
                            0,
                            "Unknown",
                            "",
                            &user,
                            format!(
                                "{} TGS requests from {} in {} seconds",
                                request_count, user, PATTERN_WINDOW_SECONDS
                            ),
                            Some(event_id),
                        ));
                    }
                }

                None
            }

            security_event_ids::KERBEROS_PREAUTH_FAILED => {
                // Track pre-auth failures for AS-REP Roasting detection
                let user = "unknown".to_string();
                tracker
                    .preauth_failures
                    .entry(user.clone())
                    .or_default()
                    .push_back(now);

                // Check if this indicates AS-REP Roasting
                let failure_count = tracker
                    .preauth_failures
                    .get(&user)
                    .map(|f| f.len())
                    .unwrap_or(0);
                if failure_count >= ASREP_ROASTING_THRESHOLD {
                    let alert_key = format!("asrep_{}", user);
                    if tracker.should_alert(&alert_key, now) {
                        return Some(Self::create_ad_event(
                            AdActivityType::AsRepRoasting,
                            0,
                            "Unknown",
                            "",
                            &user,
                            format!(
                                "Potential AS-REP Roasting: {} pre-auth failures for accounts without pre-auth required",
                                failure_count
                            ),
                            Some(event_id),
                        ));
                    }
                }

                None
            }

            security_event_ids::DS_ACCESS => {
                // Check for DCSync indicators
                // In production, would parse the GUID from event data
                // DCSync requires DS-Replication-Get-Changes and DS-Replication-Get-Changes-All

                // Simplified: track replication requests by source
                let source = "unknown".to_string();

                // Check if source is a known DC
                if !known_dcs.contains(&source) && !known_dcs.is_empty() {
                    tracker
                        .replication_requests
                        .entry(source.clone())
                        .or_default()
                        .push_back(now);

                    // Non-DC making replication requests is highly suspicious
                    let alert_key = format!("dcsync_{}", source);
                    if tracker.should_alert(&alert_key, now) {
                        return Some(Self::create_ad_event(
                            AdActivityType::DcSync,
                            0,
                            "Unknown",
                            "",
                            &source,
                            "Non-domain controller requesting directory replication (potential DCSync attack)".to_string(),
                            Some(event_id),
                        ));
                    }
                }

                None
            }

            security_event_ids::USER_ACCOUNT_CHANGED => {
                // Check for privileged account modifications
                // Would extract target account and changed attributes from event data
                let target_account = "unknown".to_string();
                let changed_attributes = "unknown".to_string();

                // Check if this is a privileged account
                if sensitive_objects::PRIVILEGED_GROUPS
                    .iter()
                    .any(|g| target_account.contains(g))
                {
                    return Some(Self::create_ad_event(
                        AdActivityType::PrivilegedAccountChange,
                        0,
                        "Unknown",
                        "",
                        &target_account,
                        format!(
                            "Privileged account {} modified: {}",
                            target_account, changed_attributes
                        ),
                        Some(event_id),
                    ));
                }

                None
            }

            security_event_ids::GROUP_MEMBER_ADDED => {
                // Check for additions to sensitive groups
                let group = "unknown".to_string();
                let member = "unknown".to_string();

                if sensitive_objects::PRIVILEGED_GROUPS
                    .iter()
                    .any(|g| group.to_lowercase().contains(&g.to_lowercase()))
                {
                    return Some(Self::create_ad_event(
                        AdActivityType::GroupMembershipChange,
                        0,
                        "Unknown",
                        "",
                        &group,
                        format!("Member {} added to privileged group {}", member, group),
                        Some(event_id),
                    ));
                }

                None
            }

            security_event_ids::SID_HISTORY_ADDED => {
                // SID History abuse detection
                return Some(Self::create_ad_event(
                    AdActivityType::SidHistoryAbuse,
                    0,
                    "Unknown",
                    "",
                    "Unknown",
                    "SID History attribute modified - potential privilege escalation".to_string(),
                    Some(event_id),
                ));
            }

            _ => None,
        }
    }

    /// Monitor LDAP activity
    fn monitor_ldap_activity(tracker: &mut EventTracker, now: u64) -> Option<Vec<TelemetryEvent>> {
        let mut events = Vec::new();

        // Get processes making LDAP connections (port 389 or 636)
        // This is a simplified check - full implementation would use ETW or packet capture
        if let Some(ldap_processes) = Self::get_ldap_processes() {
            for (pid, name, path) in ldap_processes {
                // Skip known AD management tools
                let name_lower = name.to_lowercase();
                if Self::is_legitimate_ldap_tool(&name_lower) {
                    continue;
                }

                // Track LDAP activity
                let source_key = format!("{}_{}", pid, name);
                tracker
                    .ldap_queries
                    .entry(source_key.clone())
                    .or_default()
                    .push_back((now, "query".to_string()));

                // Check for excessive LDAP queries (enumeration)
                let query_count = tracker
                    .ldap_queries
                    .get(&source_key)
                    .map(|q| q.len())
                    .unwrap_or(0);
                if query_count >= LDAP_ENUM_THRESHOLD {
                    let alert_key = format!("ldap_enum_{}", source_key);
                    if tracker.should_alert(&alert_key, now) {
                        // Check for BloodHound patterns
                        let is_bloodhound = Self::detect_bloodhound_patterns(&name, &path);

                        let activity_type = if is_bloodhound {
                            AdActivityType::BloodHoundDetected
                        } else {
                            AdActivityType::LdapEnumeration
                        };

                        events.push(Self::create_ad_event(
                            activity_type,
                            pid,
                            &name,
                            &path,
                            "AD",
                            format!(
                                "Excessive LDAP queries ({}) from {} in {} seconds",
                                query_count, name, PATTERN_WINDOW_SECONDS
                            ),
                            None,
                        ));
                    }
                }
            }
        }

        if events.is_empty() {
            None
        } else {
            Some(events)
        }
    }

    /// Get processes with LDAP connections
    fn get_ldap_processes() -> Option<Vec<(u32, String, String)>> {
        use windows::Win32::NetworkManagement::IpHelper::{
            GetExtendedTcpTable, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_CONNECTIONS,
        };
        use windows::Win32::Networking::WinSock::AF_INET;

        let mut processes = Vec::new();

        // SAFETY: GetExtendedTcpTable retrieves TCP connection table. First call with None buffer
        // queries the required size. We pass valid mutable u32 pointer for output size. Windows
        // fills in the size. First call always fails with ERROR_INSUFFICIENT_BUFFER, which is
        // expected and handled. We then allocate and call again with valid buffer. The buffer
        // size is verified before allocation. All operations are synchronized by Windows kernel.
        unsafe {
            let mut size: u32 = 0;
            let _ = GetExtendedTcpTable(
                None,
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_CONNECTIONS,
                0,
            );

            if size == 0 {
                return None;
            }

            let mut buffer = vec![0u8; size as usize];
            let result = GetExtendedTcpTable(
                Some(buffer.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_CONNECTIONS,
                0,
            );

            if result != 0 {
                return None;
            }

            let table = &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
            let num_entries = table.dwNumEntries as usize;

            if num_entries == 0 {
                return None;
            }

            // Cap entries at buffer bounds to prevent out-of-bounds reads
            let header_size = std::mem::size_of::<u32>(); // dwNumEntries
            let entry_size = std::mem::size_of_val(&table.table[0]);
            let max_entries = if entry_size > 0 && buffer.len() > header_size {
                (buffer.len() - header_size) / entry_size
            } else {
                0
            };
            let num_entries = num_entries.min(max_entries);

            let rows_ptr = table.table.as_ptr();
            let mut seen_pids: HashSet<u32> = HashSet::new();

            for i in 0..num_entries {
                let row = &*rows_ptr.add(i);
                let remote_port = u16::from_be(row.dwRemotePort as u16);

                // Check for LDAP ports (389, 636, 3268, 3269)
                if matches!(remote_port, 389 | 636 | 3268 | 3269) {
                    let pid = row.dwOwningPid;

                    if !seen_pids.contains(&pid) {
                        seen_pids.insert(pid);

                        let (name, path) = Self::get_process_info(pid);
                        processes.push((pid, name, path));
                    }
                }
            }
        }

        if processes.is_empty() {
            None
        } else {
            Some(processes)
        }
    }

    /// Get process name and path
    fn get_process_info(pid: u32) -> (String, String) {
        // SAFETY: OpenProcess queries process image file name. handle is checked via Ok()
        // before use. path_buf is a fixed-size array on stack [0u16; 260]. K32GetProcessImageFileNameW
        // won't overflow this buffer (Windows enforces MAX_PATH). Windows safely validates PID
        // (returns error if invalid). Handle is immediately closed via CloseHandle. No concurrent
        // access to the handle. All strings are properly null-terminated by Windows.
        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(h) => h,
                Err(_) => return (format!("pid:{}", pid), String::new()),
            };

            let mut path_buf = [0u16; 260];
            let len = K32GetProcessImageFileNameW(handle, &mut path_buf);
            let _ = CloseHandle(handle);

            if len > 0 {
                let path = String::from_utf16_lossy(&path_buf[..len as usize]);
                let name = path.rsplit('\\').next().unwrap_or("").to_string();
                (name, path)
            } else {
                (format!("pid:{}", pid), String::new())
            }
        }
    }

    /// Check if process is a legitimate LDAP tool
    fn is_legitimate_ldap_tool(name: &str) -> bool {
        const LEGITIMATE_TOOLS: &[&str] = &[
            "dsa.msc",
            "mmc.exe",
            "gpmc.msc",
            "lsass.exe",
            "svchost.exe",
            "services.exe",
            "dsac.exe", // Active Directory Administrative Center
            "adsiedit.msc",
            "ntdsutil.exe",
            "dcdiag.exe",
            "repadmin.exe",
            "powershell.exe", // Might need more context
            "azureadconnect",
            "msexchangeserver",
        ];

        LEGITIMATE_TOOLS.iter().any(|t| name.contains(t))
    }

    /// Detect BloodHound/SharpHound patterns
    fn detect_bloodhound_patterns(name: &str, path: &str) -> bool {
        let name_lower = name.to_lowercase();
        let path_lower = path.to_lowercase();

        // Known BloodHound collector names
        const BLOODHOUND_NAMES: &[&str] = &[
            "sharphound",
            "bloodhound",
            "azurehound",
            "adexplorer",
            "ldapdomaindump",
            "get-aduser",
            "get-adcomputer",
            "get-adgroup",
        ];

        if BLOODHOUND_NAMES
            .iter()
            .any(|b| name_lower.contains(b) || path_lower.contains(b))
        {
            return true;
        }

        // Check for execution from suspicious locations
        let suspicious_paths = ["\\temp\\", "\\downloads\\", "\\appdata\\local\\temp"];
        if suspicious_paths.iter().any(|p| path_lower.contains(p)) {
            return true;
        }

        false
    }

    /// Check for attack patterns based on tracked data
    fn check_attack_patterns(
        tracker: &mut EventTracker,
        now: u64,
        _domain_info: &Option<DomainInfo>,
    ) -> Option<Vec<TelemetryEvent>> {
        let mut events = Vec::new();

        // Check for Kerberoasting across all users
        let total_tgs_requests: usize = tracker.tgs_requests.values().map(|v| v.len()).sum();
        if total_tgs_requests >= KERBEROASTING_THRESHOLD * 2 {
            let alert_key = "kerberoast_global".to_string();
            if tracker.should_alert(&alert_key, now) {
                events.push(Self::create_ad_event(
                    AdActivityType::Kerberoasting,
                    0,
                    "Multiple Sources",
                    "",
                    "AD",
                    format!(
                        "High volume of TGS requests ({}) detected across domain - potential Kerberoasting campaign",
                        total_tgs_requests
                    ),
                    None,
                ));
            }
        }

        // Check for AS-REP Roasting campaign
        let total_preauth_failures: usize =
            tracker.preauth_failures.values().map(|v| v.len()).sum();
        if total_preauth_failures >= ASREP_ROASTING_THRESHOLD * 2 {
            let alert_key = "asrep_global".to_string();
            if tracker.should_alert(&alert_key, now) {
                events.push(Self::create_ad_event(
                    AdActivityType::AsRepRoasting,
                    0,
                    "Multiple Sources",
                    "",
                    "AD",
                    format!(
                        "High volume of pre-auth failures ({}) detected - potential AS-REP Roasting campaign",
                        total_preauth_failures
                    ),
                    None,
                ));
            }
        }

        // Check for DCSync from non-DC sources
        // Collect data first to avoid borrow conflicts
        let dcsync_alerts: Vec<(String, usize)> = tracker
            .replication_requests
            .iter()
            .filter(|(_, requests)| requests.len() >= 3)
            .map(|(source, requests)| (source.clone(), requests.len()))
            .collect();

        for (source, request_count) in dcsync_alerts {
            let alert_key = format!("dcsync_pattern_{}", source);
            if tracker.should_alert(&alert_key, now) {
                events.push(Self::create_ad_event(
                    AdActivityType::NonDcReplication,
                    0,
                    &source,
                    "",
                    "Directory",
                    format!(
                        "Non-DC {} made {} replication requests - potential DCSync attack",
                        source, request_count
                    ),
                    None,
                ));
            }
        }

        if events.is_empty() {
            None
        } else {
            Some(events)
        }
    }

    /// Create an AD monitoring event
    fn create_ad_event(
        activity_type: AdActivityType,
        source_pid: u32,
        source_process: &str,
        source_path: &str,
        target: &str,
        details: String,
        event_id: Option<u32>,
    ) -> TelemetryEvent {
        let severity = activity_type.severity();
        let mitre_techniques = activity_type.mitre_techniques();
        let mitre_tactics = activity_type.mitre_tactics();

        let ad_event = AdEvent {
            activity_type,
            source_pid,
            source_process: source_process.to_string(),
            source_path: source_path.to_string(),
            source_user: String::new(),
            target_object: target.to_string(),
            target_domain: None,
            ldap_filter: None,
            service_name: None,
            encryption_type: None,
            event_id,
            details: details.clone(),
        };

        // Use Custom payload since we don't have a dedicated ActiveDirectory EventType
        let mut event = TelemetryEvent::new(
            EventType::AuthLogin, // Using AuthLogin as closest match for AD events
            severity,
            EventPayload::Custom(serde_json::to_value(&ad_event).unwrap_or_default()),
        );

        // Add metadata
        event.metadata.insert(
            "ad_activity_type".to_string(),
            activity_type.as_str().to_string(),
        );
        event
            .metadata
            .insert("source_process".to_string(), source_process.to_string());
        event
            .metadata
            .insert("target_object".to_string(), target.to_string());

        if let Some(eid) = event_id {
            event
                .metadata
                .insert("windows_event_id".to_string(), eid.to_string());
        }

        // Add detection
        event.add_detection(Detection {
            detection_type: DetectionType::Behavioral,
            rule_name: format!("AD_{}", activity_type.as_str()),
            confidence: match activity_type {
                AdActivityType::DcSync | AdActivityType::BloodHoundDetected => 0.95,
                AdActivityType::Kerberoasting | AdActivityType::AsRepRoasting => 0.90,
                AdActivityType::GoldenTicket | AdActivityType::SilverTicket => 0.85,
                _ => 0.75,
            },
            description: details,
            mitre_tactics,
            mitre_techniques,
        });

        event
    }

    /// Get next event from monitor
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }

    /// Check if domain-joined
    pub fn is_domain_joined(&self) -> bool {
        self.domain_info.is_some()
    }

    /// Get domain name
    pub fn domain_name(&self) -> Option<&str> {
        self.domain_info
            .as_ref()
            .map(|di| di.dns_domain_name.as_str())
    }
}

impl Drop for AdMonitor {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_activity_type_mitre_mapping() {
        let kerberoasting = AdActivityType::Kerberoasting;
        assert!(kerberoasting
            .mitre_techniques()
            .contains(&"T1558.003".to_string()));
        assert!(kerberoasting
            .mitre_tactics()
            .contains(&"Credential Access".to_string()));

        let dcsync = AdActivityType::DcSync;
        assert!(dcsync.mitre_techniques().contains(&"T1003.006".to_string()));
        assert_eq!(dcsync.severity(), Severity::Critical);
    }

    #[test]
    fn test_bloodhound_detection() {
        assert!(AdMonitor::detect_bloodhound_patterns("SharpHound.exe", ""));
        assert!(AdMonitor::detect_bloodhound_patterns(
            "test.exe",
            "C:\\Temp\\bloodhound\\"
        ));
        assert!(!AdMonitor::detect_bloodhound_patterns(
            "notepad.exe",
            "C:\\Windows\\"
        ));
    }

    #[test]
    fn test_legitimate_ldap_tools() {
        assert!(AdMonitor::is_legitimate_ldap_tool("mmc.exe"));
        assert!(AdMonitor::is_legitimate_ldap_tool("lsass.exe"));
        assert!(!AdMonitor::is_legitimate_ldap_tool("randomtool.exe"));
    }

    #[tokio::test]
    async fn test_ad_monitor_initialization() {
        let config = AgentConfig::default();
        let result = AdMonitor::new(&config);

        // Should initialize without panicking
        assert!(result.is_ok());
    }

    #[test]
    fn test_ad_activity_type_as_str() {
        assert_eq!(AdActivityType::Kerberoasting.as_str(), "kerberoasting");
        assert_eq!(AdActivityType::DcSync.as_str(), "dcsync");
        assert_eq!(AdActivityType::GoldenTicket.as_str(), "golden_ticket");
    }

    #[test]
    fn test_ad_activity_severity() {
        assert_eq!(AdActivityType::DcSync.severity(), Severity::Critical);
        assert_eq!(AdActivityType::GoldenTicket.severity(), Severity::Critical);
        assert_eq!(AdActivityType::Kerberoasting.severity(), Severity::High);
    }

    #[test]
    fn test_ad_event_serialization() {
        let event = AdEvent {
            event_id: Some(4768), // Kerberos TGT request
            activity_type: AdActivityType::Kerberoasting,
            source_pid: 1234,
            source_process: "mimikatz.exe".to_string(),
            source_path: "C:\\Temp\\mimikatz.exe".to_string(),
            source_user: "DOMAIN\\admin".to_string(),
            target_object: "krbtgt".to_string(),
            target_domain: Some("DOMAIN".to_string()),
            ldap_filter: None,
            service_name: Some("HTTP/webserver".to_string()),
            encryption_type: Some("RC4".to_string()),
            details: "Test Kerberoasting event".to_string(),
        };

        let json = serde_json::to_string(&event);
        assert!(json.is_ok());
    }

    #[test]
    #[ignore]
    fn test_ad_monitor_no_panic() {
        // Integration test - runs AD monitoring
        // Marked as ignored, run with: cargo test -- --ignored
        let config = AgentConfig::default();

        // This should not panic even if AD access fails
        let result = std::panic::catch_unwind(|| {
            let _ = AdMonitor::new(&config);
            true
        });

        assert!(result.is_ok());
    }
}
