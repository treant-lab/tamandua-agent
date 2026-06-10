//! Identity Protection Collector
//!
//! Monitors Windows Security Event Log for identity-based attacks:
//! - Authentication events (4624/4625 logon success/failure)
//! - Explicit credential logon (4648)
//! - Special privileges assigned (4672)
//! - User account management (4720/4726 created/deleted)
//! - Group membership changes (4728/4729, 4732/4733, 4756/4757)
//! - Kerberos events (4768/4769 TGT/TGS, 4771 pre-auth failed)
//! - NTLM authentication (4776)
//! - DCSync detection (4662 with replication GUIDs)
//! - Golden/Silver ticket detection patterns
//! - Password spray detection (multiple 4625 from same source)
//!
//! MITRE ATT&CK Coverage:
//! - T1078 (Valid Accounts)
//! - T1558 (Steal/Forge Kerberos Tickets)
//! - T1550 (Use Alternate Authentication Material)
//! - T1003.006 (DCSync)
//! - T1110 (Brute Force / Password Spray)

#![cfg(target_os = "windows")]
// Identity protection collector. EventLog reader constants and per-user
// scaffolding fields are retained for upcoming detection expansions.
#![allow(dead_code, unused_variables)]

use super::{Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent};
use crate::config::AgentConfig;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use windows::core::PCWSTR;
use windows::Win32::System::EventLog::{
    CloseEventLog, GetNumberOfEventLogRecords, OpenEventLogW, ReadEventLogW, EVENTLOGRECORD,
    READ_EVENT_LOG_READ_FLAGS,
};

// EventLog read flags
const EVENTLOG_BACKWARDS_READ: u32 = 0x0008;
const EVENTLOG_SEQUENTIAL_READ: u32 = 0x0001;
const EVENTLOG_FORWARDS_READ: u32 = 0x0004;

/// Identity event types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityEventType {
    /// Successful logon (4624)
    LogonSuccess,
    /// Failed logon (4625)
    LogonFailure,
    /// Explicit credential logon (4648)
    ExplicitCredential,
    /// Special privileges assigned (4672)
    SpecialPrivileges,
    /// User account created (4720)
    UserCreated,
    /// User account deleted (4726)
    UserDeleted,
    /// User added to security-enabled global group (4728)
    UserAddedToGlobalGroup,
    /// User removed from security-enabled global group (4729)
    UserRemovedFromGlobalGroup,
    /// User added to security-enabled local group (4732)
    UserAddedToLocalGroup,
    /// User removed from security-enabled local group (4733)
    UserRemovedFromLocalGroup,
    /// User added to security-enabled universal group (4756)
    UserAddedToUniversalGroup,
    /// User removed from security-enabled universal group (4757)
    UserRemovedFromUniversalGroup,
    /// Kerberos TGT request (4768)
    KerberosTgtRequest,
    /// Kerberos service ticket request (4769)
    KerberosServiceTicket,
    /// Kerberos pre-authentication failed (4771)
    KerberosPreAuthFailed,
    /// NTLM authentication (4776)
    NtlmAuthentication,
    /// Directory service object access - used for DCSync (4662)
    DirectoryServiceAccess,
    /// Password spray attack detected
    PasswordSprayDetected,
    /// DCSync attack detected
    DcSyncDetected,
    /// Golden ticket suspected
    GoldenTicketSuspected,
    /// Silver ticket suspected
    SilverTicketSuspected,
    /// Kerberoasting detected
    KerberoastingDetected,
    /// AS-REP roasting detected
    AsRepRoastingDetected,
    /// Impossible travel detected
    ImpossibleTravel,
    /// Off-hours activity
    OffHoursActivity,
    /// New device/location
    NewDeviceLocation,
}

impl IdentityEventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LogonSuccess => "logon_success",
            Self::LogonFailure => "logon_failure",
            Self::ExplicitCredential => "explicit_credential",
            Self::SpecialPrivileges => "special_privileges",
            Self::UserCreated => "user_created",
            Self::UserDeleted => "user_deleted",
            Self::UserAddedToGlobalGroup => "user_added_to_global_group",
            Self::UserRemovedFromGlobalGroup => "user_removed_from_global_group",
            Self::UserAddedToLocalGroup => "user_added_to_local_group",
            Self::UserRemovedFromLocalGroup => "user_removed_from_local_group",
            Self::UserAddedToUniversalGroup => "user_added_to_universal_group",
            Self::UserRemovedFromUniversalGroup => "user_removed_from_universal_group",
            Self::KerberosTgtRequest => "kerberos_tgt_request",
            Self::KerberosServiceTicket => "kerberos_service_ticket",
            Self::KerberosPreAuthFailed => "kerberos_preauth_failed",
            Self::NtlmAuthentication => "ntlm_authentication",
            Self::DirectoryServiceAccess => "directory_service_access",
            Self::PasswordSprayDetected => "password_spray_detected",
            Self::DcSyncDetected => "dcsync_detected",
            Self::GoldenTicketSuspected => "golden_ticket_suspected",
            Self::SilverTicketSuspected => "silver_ticket_suspected",
            Self::KerberoastingDetected => "kerberoasting_detected",
            Self::AsRepRoastingDetected => "as_rep_roasting_detected",
            Self::ImpossibleTravel => "impossible_travel",
            Self::OffHoursActivity => "off_hours_activity",
            Self::NewDeviceLocation => "new_device_location",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Self::DcSyncDetected | Self::GoldenTicketSuspected | Self::SilverTicketSuspected => {
                Severity::Critical
            }
            Self::PasswordSprayDetected
            | Self::KerberoastingDetected
            | Self::AsRepRoastingDetected
            | Self::ImpossibleTravel => Severity::High,
            Self::ExplicitCredential
            | Self::SpecialPrivileges
            | Self::LogonFailure
            | Self::OffHoursActivity
            | Self::NewDeviceLocation => Severity::Medium,
            Self::UserAddedToGlobalGroup
            | Self::UserAddedToLocalGroup
            | Self::UserAddedToUniversalGroup
            | Self::UserCreated
            | Self::UserDeleted => Severity::Medium,
            Self::LogonSuccess
            | Self::KerberosTgtRequest
            | Self::KerberosServiceTicket
            | Self::NtlmAuthentication => Severity::Low,
            _ => Severity::Info,
        }
    }

    pub fn mitre_techniques(&self) -> Vec<String> {
        match self {
            Self::LogonSuccess | Self::LogonFailure => {
                vec!["T1078".to_string()]
            }
            Self::ExplicitCredential => {
                vec!["T1078".to_string(), "T1021".to_string()]
            }
            Self::SpecialPrivileges => {
                vec!["T1078.002".to_string(), "T1134".to_string()]
            }
            Self::UserCreated | Self::UserDeleted => {
                vec!["T1136".to_string()]
            }
            Self::UserAddedToGlobalGroup
            | Self::UserAddedToLocalGroup
            | Self::UserAddedToUniversalGroup => {
                vec!["T1098".to_string()]
            }
            Self::KerberosTgtRequest | Self::KerberosServiceTicket => {
                vec!["T1558".to_string()]
            }
            Self::KerberosPreAuthFailed => {
                vec!["T1558.004".to_string()]
            }
            Self::NtlmAuthentication => {
                vec!["T1550.002".to_string()]
            }
            Self::PasswordSprayDetected => {
                vec!["T1110.003".to_string()]
            }
            Self::DcSyncDetected => {
                vec!["T1003.006".to_string()]
            }
            Self::GoldenTicketSuspected => {
                vec!["T1558.001".to_string()]
            }
            Self::SilverTicketSuspected => {
                vec!["T1558.002".to_string()]
            }
            Self::KerberoastingDetected => {
                vec!["T1558.003".to_string()]
            }
            Self::AsRepRoastingDetected => {
                vec!["T1558.004".to_string()]
            }
            Self::ImpossibleTravel | Self::NewDeviceLocation => {
                vec!["T1078".to_string()]
            }
            Self::OffHoursActivity => {
                vec!["T1078".to_string()]
            }
            _ => vec![],
        }
    }

    pub fn mitre_tactics(&self) -> Vec<String> {
        match self {
            Self::LogonSuccess | Self::LogonFailure | Self::ExplicitCredential => {
                vec!["Initial Access".to_string(), "Persistence".to_string()]
            }
            Self::SpecialPrivileges => {
                vec!["Privilege Escalation".to_string()]
            }
            Self::UserCreated
            | Self::UserDeleted
            | Self::UserAddedToGlobalGroup
            | Self::UserAddedToLocalGroup
            | Self::UserAddedToUniversalGroup => {
                vec![
                    "Persistence".to_string(),
                    "Privilege Escalation".to_string(),
                ]
            }
            Self::KerberosTgtRequest
            | Self::KerberosServiceTicket
            | Self::KerberosPreAuthFailed
            | Self::NtlmAuthentication
            | Self::DcSyncDetected
            | Self::GoldenTicketSuspected
            | Self::SilverTicketSuspected
            | Self::KerberoastingDetected
            | Self::AsRepRoastingDetected => {
                vec!["Credential Access".to_string()]
            }
            Self::PasswordSprayDetected => {
                vec![
                    "Credential Access".to_string(),
                    "Initial Access".to_string(),
                ]
            }
            Self::ImpossibleTravel | Self::NewDeviceLocation | Self::OffHoursActivity => {
                vec!["Initial Access".to_string()]
            }
            _ => vec![],
        }
    }
}

/// Identity event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityEvent {
    /// Event type
    pub event_type: IdentityEventType,
    /// Windows Event ID
    pub event_id: u32,
    /// Subject account (who performed the action)
    pub subject_account: String,
    /// Subject domain
    pub subject_domain: String,
    /// Subject SID
    pub subject_sid: Option<String>,
    /// Target account (who was affected)
    pub target_account: Option<String>,
    /// Target domain
    pub target_domain: Option<String>,
    /// Target SID
    pub target_sid: Option<String>,
    /// Source IP address (if available)
    pub source_ip: Option<String>,
    /// Source hostname (if available)
    pub source_hostname: Option<String>,
    /// Logon type (for logon events)
    pub logon_type: Option<u32>,
    /// Logon type name
    pub logon_type_name: Option<String>,
    /// Authentication package (Kerberos, NTLM, etc.)
    pub auth_package: Option<String>,
    /// Service name (for Kerberos events)
    pub service_name: Option<String>,
    /// Group name (for group membership changes)
    pub group_name: Option<String>,
    /// Group domain
    pub group_domain: Option<String>,
    /// Failure reason (for failed logons)
    pub failure_reason: Option<String>,
    /// Failure status code
    pub failure_status: Option<String>,
    /// Failure sub-status code
    pub failure_substatus: Option<String>,
    /// Encryption type (for Kerberos)
    pub encryption_type: Option<String>,
    /// Pre-auth type (for Kerberos)
    pub preauth_type: Option<String>,
    /// Certificate information
    pub certificate_info: Option<String>,
    /// Object GUID (for DCSync detection)
    pub object_guid: Option<String>,
    /// Properties accessed (for directory service access)
    pub properties_accessed: Option<Vec<String>>,
    /// Additional details
    pub details: String,
    /// Risk indicators
    pub risk_indicators: Vec<String>,
}

/// Windows Security Event IDs
mod event_ids {
    /// Successful logon
    pub const LOGON_SUCCESS: u32 = 4624;
    /// Failed logon
    pub const LOGON_FAILURE: u32 = 4625;
    /// Explicit credential logon (runas)
    pub const EXPLICIT_CREDENTIAL: u32 = 4648;
    /// Special privileges assigned to logon
    pub const SPECIAL_PRIVILEGES: u32 = 4672;
    /// User account created
    pub const USER_CREATED: u32 = 4720;
    /// User account deleted
    pub const USER_DELETED: u32 = 4726;
    /// User added to security-enabled global group
    pub const USER_ADDED_GLOBAL_GROUP: u32 = 4728;
    /// User removed from security-enabled global group
    pub const USER_REMOVED_GLOBAL_GROUP: u32 = 4729;
    /// User added to security-enabled local group
    pub const USER_ADDED_LOCAL_GROUP: u32 = 4732;
    /// User removed from security-enabled local group
    pub const USER_REMOVED_LOCAL_GROUP: u32 = 4733;
    /// User added to security-enabled universal group
    pub const USER_ADDED_UNIVERSAL_GROUP: u32 = 4756;
    /// User removed from security-enabled universal group
    pub const USER_REMOVED_UNIVERSAL_GROUP: u32 = 4757;
    /// Kerberos TGT requested (AS-REQ)
    pub const KERBEROS_TGT: u32 = 4768;
    /// Kerberos service ticket requested (TGS-REQ)
    pub const KERBEROS_TGS: u32 = 4769;
    /// Kerberos pre-authentication failed
    pub const KERBEROS_PREAUTH_FAILED: u32 = 4771;
    /// NTLM credential validation
    pub const NTLM_AUTH: u32 = 4776;
    /// Directory service object access
    pub const DS_ACCESS: u32 = 4662;
}

/// Logon types
mod logon_types {
    pub const INTERACTIVE: u32 = 2;
    pub const NETWORK: u32 = 3;
    pub const BATCH: u32 = 4;
    pub const SERVICE: u32 = 5;
    pub const UNLOCK: u32 = 7;
    pub const NETWORK_CLEARTEXT: u32 = 8;
    pub const NEW_CREDENTIALS: u32 = 9;
    pub const REMOTE_INTERACTIVE: u32 = 10;
    pub const CACHED_INTERACTIVE: u32 = 11;

    pub fn name(logon_type: u32) -> &'static str {
        match logon_type {
            INTERACTIVE => "Interactive",
            NETWORK => "Network",
            BATCH => "Batch",
            SERVICE => "Service",
            UNLOCK => "Unlock",
            NETWORK_CLEARTEXT => "NetworkCleartext",
            NEW_CREDENTIALS => "NewCredentials",
            REMOTE_INTERACTIVE => "RemoteInteractive",
            CACHED_INTERACTIVE => "CachedInteractive",
            _ => "Unknown",
        }
    }
}

/// DCSync related GUIDs
mod dcsync_guids {
    pub const DS_REPLICATION_GET_CHANGES: &str = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2";
    pub const DS_REPLICATION_GET_CHANGES_ALL: &str = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2";
    pub const DS_REPLICATION_GET_CHANGES_FILTERED: &str = "89e95b76-444d-4c62-991a-0facbeda640c";
}

/// Sensitive/privileged groups to monitor
const SENSITIVE_GROUPS: &[&str] = &[
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Backup Operators",
    "Server Operators",
    "Print Operators",
    "DnsAdmins",
    "Domain Controllers",
    "Group Policy Creator Owners",
    "Cert Publishers",
    "Key Admins",
    "Enterprise Key Admins",
    "DHCP Administrators",
    "Hyper-V Administrators",
];

/// Detection thresholds
const PASSWORD_SPRAY_THRESHOLD: usize = 5; // Failed logons from same source in window
const PASSWORD_SPRAY_WINDOW_SECS: u64 = 300; // 5 minutes
const KERBEROASTING_THRESHOLD: usize = 10; // TGS requests in window
const KERBEROASTING_WINDOW_SECS: u64 = 60; // 1 minute
const ASREP_ROASTING_THRESHOLD: usize = 5; // Pre-auth failures for users without pre-auth
const ASREP_ROASTING_WINDOW_SECS: u64 = 300; // 5 minutes

/// Tracking data for attack detection
struct AttackTracker {
    /// Failed logons by source IP for password spray detection
    failed_logons_by_source: HashMap<String, VecDeque<u64>>,
    /// TGS requests by user for Kerberoasting detection
    tgs_requests_by_user: HashMap<String, VecDeque<u64>>,
    /// Pre-auth failures for AS-REP roasting detection
    preauth_failures: HashMap<String, VecDeque<u64>>,
    /// Recent alerts to avoid duplicates
    recent_alerts: HashMap<String, u64>,
    /// Known user login locations for impossible travel
    user_locations: HashMap<String, Vec<(String, u64)>>,
    /// Known user devices
    user_devices: HashMap<String, Vec<String>>,
}

impl AttackTracker {
    fn new() -> Self {
        Self {
            failed_logons_by_source: HashMap::new(),
            tgs_requests_by_user: HashMap::new(),
            preauth_failures: HashMap::new(),
            recent_alerts: HashMap::new(),
            user_locations: HashMap::new(),
            user_devices: HashMap::new(),
        }
    }

    fn cleanup(&mut self, now: u64) {
        // Cleanup failed logons
        for queue in self.failed_logons_by_source.values_mut() {
            while queue
                .front()
                .map(|&t| now - t > PASSWORD_SPRAY_WINDOW_SECS)
                .unwrap_or(false)
            {
                queue.pop_front();
            }
        }
        self.failed_logons_by_source.retain(|_, v| !v.is_empty());

        // Cleanup TGS requests
        for queue in self.tgs_requests_by_user.values_mut() {
            while queue
                .front()
                .map(|&t| now - t > KERBEROASTING_WINDOW_SECS)
                .unwrap_or(false)
            {
                queue.pop_front();
            }
        }
        self.tgs_requests_by_user.retain(|_, v| !v.is_empty());

        // Cleanup pre-auth failures
        for queue in self.preauth_failures.values_mut() {
            while queue
                .front()
                .map(|&t| now - t > ASREP_ROASTING_WINDOW_SECS)
                .unwrap_or(false)
            {
                queue.pop_front();
            }
        }
        self.preauth_failures.retain(|_, v| !v.is_empty());

        // Cleanup recent alerts (1 hour)
        self.recent_alerts.retain(|_, &mut t| now - t < 3600);

        // Cleanup old location data (24 hours)
        for locations in self.user_locations.values_mut() {
            locations.retain(|(_, t)| now - *t < 86400);
        }
        self.user_locations.retain(|_, v| !v.is_empty());
    }

    fn should_alert(&mut self, key: &str, now: u64) -> bool {
        if let Some(&last) = self.recent_alerts.get(key) {
            if now - last < 300 {
                // Don't alert for same pattern within 5 minutes
                return false;
            }
        }
        self.recent_alerts.insert(key.to_string(), now);
        true
    }
}

/// Identity Protection Collector
pub struct IdentityCollector {
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    running: Arc<AtomicBool>,
}

impl IdentityCollector {
    /// Create a new Identity collector
    pub fn new(config: &AgentConfig) -> Result<Self> {
        let (tx, rx) = mpsc::channel(1000);
        let running = Arc::new(AtomicBool::new(true));

        info!("Initializing Identity Protection collector");

        // Start monitoring
        let config_clone = config.clone();
        let tx_clone = tx;
        let running_clone = running.clone();

        tokio::spawn(async move {
            Self::monitor_loop(tx_clone, config_clone, running_clone).await;
        });

        Ok(Self {
            config: config.clone(),
            event_rx: rx,
            running,
        })
    }

    /// Main monitoring loop
    async fn monitor_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        _config: AgentConfig,
        running: Arc<AtomicBool>,
    ) {
        info!("Starting Identity Protection monitoring loop");

        let mut tracker = AttackTracker::new();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
        let mut last_record_number: u32 = 0;

        // Get initial record count to start from
        if let Some(count) = Self::get_event_log_count() {
            last_record_number = count;
            debug!("Starting from event log record {}", last_record_number);
        }

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

            // Read new security events
            if let Some(events) = Self::read_security_events(&mut last_record_number) {
                for (event_id, event_data) in events {
                    // Process the event
                    if let Some(identity_event) =
                        Self::process_security_event(event_id, &event_data, &mut tracker, now)
                    {
                        // Convert to telemetry event
                        let telemetry_event = Self::to_telemetry_event(identity_event);

                        if tx.send(telemetry_event).await.is_err() {
                            warn!("Event channel closed");
                            return;
                        }
                    }

                    // Check for attack patterns
                    if let Some(attack_events) = Self::check_attack_patterns(&mut tracker, now) {
                        for event in attack_events {
                            let telemetry_event = Self::to_telemetry_event(event);
                            if tx.send(telemetry_event).await.is_err() {
                                warn!("Event channel closed");
                                return;
                            }
                        }
                    }
                }
            }
        }

        info!("Identity Protection monitoring stopped");
    }

    /// Get total event log record count
    fn get_event_log_count() -> Option<u32> {
        unsafe {
            let log_name: Vec<u16> = "Security\0".encode_utf16().collect();
            let handle = match OpenEventLogW(PCWSTR::null(), PCWSTR(log_name.as_ptr())) {
                Ok(h) => h,
                Err(_) => return None,
            };

            let mut count: u32 = 0;
            let result = GetNumberOfEventLogRecords(handle, &mut count);
            let _ = CloseEventLog(handle);

            if result.is_ok() {
                Some(count)
            } else {
                None
            }
        }
    }

    /// Read events from Security event log
    fn read_security_events(last_record: &mut u32) -> Option<Vec<(u32, HashMap<String, String>)>> {
        let mut events = Vec::new();

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

            let flags = EVENTLOG_FORWARDS_READ | EVENTLOG_SEQUENTIAL_READ;

            // Read events
            let result = ReadEventLogW(
                handle,
                READ_EVENT_LOG_READ_FLAGS(flags),
                *last_record,
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
                let event_id = record.EventID & 0xFFFF;

                // Update last record number
                if record.RecordNumber > *last_record {
                    *last_record = record.RecordNumber;
                }

                // Filter for identity-related event IDs
                if Self::is_identity_event(event_id) {
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

    /// Check if event ID is identity-related
    fn is_identity_event(event_id: u32) -> bool {
        matches!(
            event_id,
            event_ids::LOGON_SUCCESS
                | event_ids::LOGON_FAILURE
                | event_ids::EXPLICIT_CREDENTIAL
                | event_ids::SPECIAL_PRIVILEGES
                | event_ids::USER_CREATED
                | event_ids::USER_DELETED
                | event_ids::USER_ADDED_GLOBAL_GROUP
                | event_ids::USER_REMOVED_GLOBAL_GROUP
                | event_ids::USER_ADDED_LOCAL_GROUP
                | event_ids::USER_REMOVED_LOCAL_GROUP
                | event_ids::USER_ADDED_UNIVERSAL_GROUP
                | event_ids::USER_REMOVED_UNIVERSAL_GROUP
                | event_ids::KERBEROS_TGT
                | event_ids::KERBEROS_TGS
                | event_ids::KERBEROS_PREAUTH_FAILED
                | event_ids::NTLM_AUTH
                | event_ids::DS_ACCESS
        )
    }

    /// Extract null-terminated UTF-16 strings embedded in the EVENTLOGRECORD buffer.
    ///
    /// The EVENTLOGRECORD layout in memory is:
    ///   [EVENTLOGRECORD struct][SourceName\0][ComputerName\0][UserSid][Strings...][Data...]
    /// Strings start at byte offset `record.StringOffset` relative to the record start,
    /// and there are `record.NumStrings` consecutive null-terminated wide strings.
    fn extract_record_strings(record: &EVENTLOGRECORD, buffer: &[u8]) -> Vec<String> {
        let mut strings = Vec::new();
        let num_strings = record.NumStrings as usize;
        if num_strings == 0 {
            return strings;
        }

        let string_offset = record.StringOffset as usize;
        let record_len = record.Length as usize;

        // Safety bounds check: StringOffset must be within the record
        if string_offset >= record_len || string_offset >= buffer.len() {
            return strings;
        }

        // Walk through the wide-char strings starting at StringOffset
        let mut pos = string_offset;
        for _ in 0..num_strings {
            if pos + 2 > buffer.len() || pos + 2 > record_len {
                break;
            }

            // Find the null terminator for this UTF-16 string
            let mut end = pos;
            while end + 2 <= buffer.len() && end + 2 <= record_len {
                let lo = buffer[end];
                let hi = buffer[end + 1];
                if lo == 0 && hi == 0 {
                    break;
                }
                end += 2;
            }

            // Decode UTF-16LE bytes to String
            let slice = &buffer[pos..end];
            let wide: Vec<u16> = slice
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            let s = String::from_utf16_lossy(&wide);
            strings.push(s);

            // Advance past the null terminator
            pos = end + 2;
        }

        strings
    }

    /// Map positional insertion strings to named fields based on the Windows Security
    /// Event ID. Each event ID has a well-known parameter order defined by Microsoft.
    ///
    /// References:
    ///   https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/
    fn map_strings_to_fields(event_id: u32, strings: &[String]) -> HashMap<String, String> {
        let mut fields = HashMap::new();

        // Helper to safely get a string by index
        let get = |idx: usize| -> String { strings.get(idx).cloned().unwrap_or_default() };

        match event_id {
            // 4624 - Successful logon
            // Strings: SubjectUserSid(0), SubjectUserName(1), SubjectDomainName(2),
            //   SubjectLogonId(3), TargetUserSid(4), TargetUserName(5),
            //   TargetDomainName(6), TargetLogonId(7), LogonType(8),
            //   LogonProcessName(9), AuthenticationPackageName(10),
            //   WorkstationName(11), LogonGuid(12), TransmittedServices(13),
            //   LmPackageName(14), KeyLength(15), ProcessId(16), ProcessName(17),
            //   IpAddress(18), IpPort(19), ImpersonationLevel(20),
            //   RestrictedAdminMode(21), TargetOutboundUserName(22),
            //   TargetOutboundDomainName(23), VirtualAccount(24),
            //   TargetLinkedLogonId(25), ElevatedToken(26)
            event_ids::LOGON_SUCCESS => {
                fields.insert("SubjectUserSid".into(), get(0));
                fields.insert("SubjectUserName".into(), get(1));
                fields.insert("SubjectDomainName".into(), get(2));
                fields.insert("SubjectLogonId".into(), get(3));
                fields.insert("TargetUserSid".into(), get(4));
                fields.insert("TargetUserName".into(), get(5));
                fields.insert("TargetDomainName".into(), get(6));
                fields.insert("TargetLogonId".into(), get(7));
                fields.insert("LogonType".into(), get(8));
                fields.insert("LogonProcessName".into(), get(9));
                fields.insert("AuthenticationPackageName".into(), get(10));
                fields.insert("WorkstationName".into(), get(11));
                fields.insert("LogonGuid".into(), get(12));
                fields.insert("IpAddress".into(), get(18));
                fields.insert("IpPort".into(), get(19));
                fields.insert("ProcessName".into(), get(17));
                fields.insert("ElevatedToken".into(), get(26));
            }

            // 4625 - Failed logon
            // Strings: SubjectUserSid(0), SubjectUserName(1), SubjectDomainName(2),
            //   SubjectLogonId(3), TargetUserSid(4), TargetUserName(5),
            //   TargetDomainName(6), Status(7), FailureReason(8), SubStatus(9),
            //   LogonType(10), LogonProcessName(11), AuthenticationPackageName(12),
            //   WorkstationName(13), TransmittedServices(14), LmPackageName(15),
            //   KeyLength(16), ProcessId(17), ProcessName(18), IpAddress(19),
            //   IpPort(20)
            event_ids::LOGON_FAILURE => {
                fields.insert("SubjectUserSid".into(), get(0));
                fields.insert("SubjectUserName".into(), get(1));
                fields.insert("SubjectDomainName".into(), get(2));
                fields.insert("SubjectLogonId".into(), get(3));
                fields.insert("TargetUserSid".into(), get(4));
                fields.insert("TargetUserName".into(), get(5));
                fields.insert("TargetDomainName".into(), get(6));
                fields.insert("Status".into(), get(7));
                fields.insert("FailureReason".into(), get(8));
                fields.insert("SubStatus".into(), get(9));
                fields.insert("LogonType".into(), get(10));
                fields.insert("LogonProcessName".into(), get(11));
                fields.insert("AuthenticationPackageName".into(), get(12));
                fields.insert("WorkstationName".into(), get(13));
                fields.insert("IpAddress".into(), get(19));
                fields.insert("IpPort".into(), get(20));
                fields.insert("ProcessName".into(), get(18));
            }

            // 4648 - Explicit credential logon (runas, etc.)
            // Strings: SubjectUserSid(0), SubjectUserName(1), SubjectDomainName(2),
            //   SubjectLogonId(3), LogonGuid(4), TargetUserName(5),
            //   TargetDomainName(6), TargetLogonGuid(7), TargetServerName(8),
            //   TargetInfo(9), ProcessId(10), ProcessName(11), IpAddress(12),
            //   IpPort(13)
            event_ids::EXPLICIT_CREDENTIAL => {
                fields.insert("SubjectUserSid".into(), get(0));
                fields.insert("SubjectUserName".into(), get(1));
                fields.insert("SubjectDomainName".into(), get(2));
                fields.insert("SubjectLogonId".into(), get(3));
                fields.insert("TargetUserName".into(), get(5));
                fields.insert("TargetDomainName".into(), get(6));
                fields.insert("TargetServerName".into(), get(8));
                fields.insert("TargetInfo".into(), get(9));
                fields.insert("ProcessName".into(), get(11));
                fields.insert("IpAddress".into(), get(12));
                fields.insert("IpPort".into(), get(13));
            }

            // 4672 - Special privileges assigned to new logon
            // Strings: SubjectUserSid(0), SubjectUserName(1), SubjectDomainName(2),
            //   SubjectLogonId(3), PrivilegeList(4)
            event_ids::SPECIAL_PRIVILEGES => {
                fields.insert("SubjectUserSid".into(), get(0));
                fields.insert("SubjectUserName".into(), get(1));
                fields.insert("SubjectDomainName".into(), get(2));
                fields.insert("SubjectLogonId".into(), get(3));
                fields.insert("PrivilegeList".into(), get(4));
            }

            // 4720 - User account created
            // Strings: TargetUserName(0), TargetDomainName(1), TargetSid(2),
            //   SubjectUserSid(3), SubjectUserName(4), SubjectDomainName(5),
            //   SubjectLogonId(6), PrivilegeList(7), SamAccountName(8),
            //   DisplayName(9), UserPrincipalName(10), HomeDirectory(11),
            //   HomePath(12), ScriptPath(13), ProfilePath(14),
            //   UserWorkstations(15), PasswordLastSet(16), AccountExpires(17),
            //   PrimaryGroupId(18), AllowedToDelegateTo(19), OldUacValue(20),
            //   NewUacValue(21), UserAccountControl(22), UserParameters(23),
            //   SidHistory(24), LogonHours(25)
            event_ids::USER_CREATED => {
                fields.insert("TargetUserName".into(), get(0));
                fields.insert("TargetDomainName".into(), get(1));
                fields.insert("TargetSid".into(), get(2));
                fields.insert("SubjectUserSid".into(), get(3));
                fields.insert("SubjectUserName".into(), get(4));
                fields.insert("SubjectDomainName".into(), get(5));
                fields.insert("SubjectLogonId".into(), get(6));
                fields.insert("SamAccountName".into(), get(8));
                fields.insert("DisplayName".into(), get(9));
                fields.insert("UserPrincipalName".into(), get(10));
            }

            // 4726 - User account deleted
            // Strings: TargetUserName(0), TargetDomainName(1), TargetSid(2),
            //   SubjectUserSid(3), SubjectUserName(4), SubjectDomainName(5),
            //   SubjectLogonId(6), PrivilegeList(7)
            event_ids::USER_DELETED => {
                fields.insert("TargetUserName".into(), get(0));
                fields.insert("TargetDomainName".into(), get(1));
                fields.insert("TargetSid".into(), get(2));
                fields.insert("SubjectUserSid".into(), get(3));
                fields.insert("SubjectUserName".into(), get(4));
                fields.insert("SubjectDomainName".into(), get(5));
                fields.insert("SubjectLogonId".into(), get(6));
            }

            // 4728/4732/4756 - User added to security-enabled group
            // 4729/4733/4757 - User removed from security-enabled group
            // Strings: MemberName(0), MemberSid(1), TargetUserName(2),
            //   TargetDomainName(3), TargetSid(4), SubjectUserSid(5),
            //   SubjectUserName(6), SubjectDomainName(7), SubjectLogonId(8),
            //   PrivilegeList(9)
            event_ids::USER_ADDED_GLOBAL_GROUP
            | event_ids::USER_REMOVED_GLOBAL_GROUP
            | event_ids::USER_ADDED_LOCAL_GROUP
            | event_ids::USER_REMOVED_LOCAL_GROUP
            | event_ids::USER_ADDED_UNIVERSAL_GROUP
            | event_ids::USER_REMOVED_UNIVERSAL_GROUP => {
                fields.insert("MemberName".into(), get(0));
                fields.insert("MemberSid".into(), get(1));
                fields.insert("TargetUserName".into(), get(2)); // Group name
                fields.insert("TargetDomainName".into(), get(3));
                fields.insert("TargetSid".into(), get(4));
                fields.insert("SubjectUserSid".into(), get(5));
                fields.insert("SubjectUserName".into(), get(6));
                fields.insert("SubjectDomainName".into(), get(7));
                fields.insert("SubjectLogonId".into(), get(8));
            }

            // 4768 - Kerberos TGT request (AS-REQ)
            // Strings: TargetUserName(0), TargetDomainName(1), TargetSid(2),
            //   ServiceName(3), ServiceSid(4), TicketOptions(5),
            //   Status(6), TicketEncryptionType(7), PreAuthType(8),
            //   IpAddress(9), IpPort(10), CertIssuerName(11),
            //   CertSerialNumber(12), CertThumbprint(13)
            event_ids::KERBEROS_TGT => {
                fields.insert("TargetUserName".into(), get(0));
                fields.insert("TargetDomainName".into(), get(1));
                fields.insert("TargetSid".into(), get(2));
                fields.insert("ServiceName".into(), get(3));
                fields.insert("TicketOptions".into(), get(5));
                fields.insert("Status".into(), get(6));
                fields.insert("TicketEncryptionType".into(), get(7));
                fields.insert("PreAuthType".into(), get(8));
                fields.insert("IpAddress".into(), get(9));
                fields.insert("IpPort".into(), get(10));
                fields.insert("CertIssuerName".into(), get(11));
                fields.insert("CertSerialNumber".into(), get(12));
                fields.insert("CertThumbprint".into(), get(13));
            }

            // 4769 - Kerberos service ticket request (TGS-REQ)
            // Strings: TargetUserName(0), TargetDomainName(1),
            //   ServiceName(2), ServiceSid(3), TicketOptions(4),
            //   TicketEncryptionType(5), IpAddress(6), IpPort(7),
            //   Status(8), LogonGuid(9), TransmittedServices(10)
            event_ids::KERBEROS_TGS => {
                fields.insert("TargetUserName".into(), get(0));
                fields.insert("TargetDomainName".into(), get(1));
                fields.insert("ServiceName".into(), get(2));
                fields.insert("TicketOptions".into(), get(4));
                fields.insert("TicketEncryptionType".into(), get(5));
                fields.insert("IpAddress".into(), get(6));
                fields.insert("IpPort".into(), get(7));
                fields.insert("Status".into(), get(8));
            }

            // 4771 - Kerberos pre-authentication failed
            // Strings: TargetUserName(0), TargetSid(1), ServiceName(2),
            //   TicketOptions(3), Status(4), PreAuthType(5),
            //   IpAddress(6), IpPort(7), CertIssuerName(8),
            //   CertSerialNumber(9), CertThumbprint(10)
            event_ids::KERBEROS_PREAUTH_FAILED => {
                fields.insert("TargetUserName".into(), get(0));
                fields.insert("TargetSid".into(), get(1));
                fields.insert("ServiceName".into(), get(2));
                fields.insert("TicketOptions".into(), get(3));
                fields.insert("Status".into(), get(4));
                fields.insert("PreAuthType".into(), get(5));
                fields.insert("IpAddress".into(), get(6));
                fields.insert("IpPort".into(), get(7));
            }

            // 4776 - NTLM credential validation
            // Strings: AuthenticationPackageName(0), LogonAccount(1),
            //   SourceWorkstation(2), Status(3), Workstation(4)
            event_ids::NTLM_AUTH => {
                fields.insert("AuthenticationPackageName".into(), get(0));
                fields.insert("LogonAccount".into(), get(1));
                fields.insert("SourceWorkstation".into(), get(2));
                fields.insert("Status".into(), get(3));
                fields.insert("Workstation".into(), get(4));
            }

            // 4662 - Directory service object access
            // Strings: SubjectUserSid(0), SubjectUserName(1), SubjectDomainName(2),
            //   SubjectLogonId(3), ObjectServer(4), ObjectType(5),
            //   ObjectName(6), OperationType(7), HandleId(8),
            //   AccessList(9), AccessMask(10), Properties(11),
            //   AdditionalInfo(12), AdditionalInfo2(13)
            event_ids::DS_ACCESS => {
                fields.insert("SubjectUserSid".into(), get(0));
                fields.insert("SubjectUserName".into(), get(1));
                fields.insert("SubjectDomainName".into(), get(2));
                fields.insert("SubjectLogonId".into(), get(3));
                fields.insert("ObjectServer".into(), get(4));
                fields.insert("ObjectType".into(), get(5));
                fields.insert("ObjectName".into(), get(6));
                fields.insert("OperationType".into(), get(7));
                fields.insert("AccessList".into(), get(9));
                fields.insert("AccessMask".into(), get(10));
                fields.insert("Properties".into(), get(11));
            }

            _ => {}
        }

        fields
    }

    /// Parse event data from EVENTLOGRECORD.
    ///
    /// Extracts basic record metadata (record number, timestamp, category) plus
    /// all insertion strings, mapped to named fields based on the event ID.
    fn parse_event_data(record: &EVENTLOGRECORD, buffer: &[u8]) -> HashMap<String, String> {
        let mut data = HashMap::new();

        // Basic record metadata
        data.insert("RecordNumber".to_string(), record.RecordNumber.to_string());
        data.insert(
            "TimeGenerated".to_string(),
            record.TimeGenerated.to_string(),
        );
        data.insert(
            "EventCategory".to_string(),
            record.EventCategory.to_string(),
        );

        let event_id = record.EventID & 0xFFFF;

        // Extract the insertion strings from the record buffer
        let strings = Self::extract_record_strings(record, buffer);

        if !strings.is_empty() {
            // Map positional strings to named fields based on event ID
            let named_fields = Self::map_strings_to_fields(event_id, &strings);
            data.extend(named_fields);

            // Also store raw strings for debugging/fallback
            for (i, s) in strings.iter().enumerate() {
                if !s.is_empty() {
                    data.insert(format!("String{}", i), s.clone());
                }
            }
        }

        data
    }

    /// Get a field value from parsed event data, returning a fallback if the key
    /// is absent or the value is empty.
    fn field_or(data: &HashMap<String, String>, key: &str, fallback: &str) -> String {
        data.get(key)
            .filter(|v| !v.is_empty() && *v != "-")
            .cloned()
            .unwrap_or_else(|| fallback.to_string())
    }

    /// Get an optional field value from parsed event data. Returns `None` if the
    /// key is absent, the value is empty, or the value is "-".
    fn field_opt(data: &HashMap<String, String>, key: &str) -> Option<String> {
        data.get(key)
            .filter(|v| !v.is_empty() && *v != "-")
            .cloned()
    }

    /// Parse a numeric logon type string into its u32 value.
    fn parse_logon_type(data: &HashMap<String, String>) -> (Option<u32>, Option<String>) {
        if let Some(lt_str) = Self::field_opt(data, "LogonType") {
            if let Ok(lt) = lt_str.trim().parse::<u32>() {
                let name = logon_types::name(lt).to_string();
                return (Some(lt), Some(name));
            }
        }
        (None, None)
    }

    /// Check whether the Properties field of a 4662 event contains any DCSync
    /// replication GUIDs, indicating a potential DCSync attack.
    fn check_dcsync_properties(data: &HashMap<String, String>) -> (bool, Vec<String>) {
        let mut found_guids = Vec::new();
        if let Some(props) = Self::field_opt(data, "Properties") {
            let props_lower = props.to_lowercase();
            if props_lower.contains(dcsync_guids::DS_REPLICATION_GET_CHANGES) {
                found_guids.push("DS-Replication-Get-Changes".to_string());
            }
            if props_lower.contains(dcsync_guids::DS_REPLICATION_GET_CHANGES_ALL) {
                found_guids.push("DS-Replication-Get-Changes-All".to_string());
            }
            if props_lower.contains(dcsync_guids::DS_REPLICATION_GET_CHANGES_FILTERED) {
                found_guids.push("DS-Replication-Get-Changes-In-Filtered-Set".to_string());
            }
        }
        let is_dcsync = found_guids.len() >= 2; // Need at least two replication rights
        (is_dcsync, found_guids)
    }

    /// Process a security event into an IdentityEvent using parsed event data.
    fn process_security_event(
        event_id: u32,
        event_data: &HashMap<String, String>,
        tracker: &mut AttackTracker,
        now: u64,
    ) -> Option<IdentityEvent> {
        match event_id {
            // ---- 4624: Successful logon ----
            event_ids::LOGON_SUCCESS => {
                let subject_account = Self::field_or(event_data, "SubjectUserName", "Unknown");
                let subject_domain = Self::field_or(event_data, "SubjectDomainName", "Unknown");
                let target_user = Self::field_opt(event_data, "TargetUserName");
                let target_domain = Self::field_opt(event_data, "TargetDomainName");
                let source_ip = Self::field_opt(event_data, "IpAddress");
                let workstation = Self::field_opt(event_data, "WorkstationName");
                let auth_pkg = Self::field_opt(event_data, "AuthenticationPackageName");
                let logon_process = Self::field_opt(event_data, "LogonProcessName");
                let (logon_type, logon_type_name) = Self::parse_logon_type(event_data);

                let display_user = target_user
                    .as_deref()
                    .unwrap_or(&subject_account)
                    .to_string();
                let display_domain = target_domain
                    .as_deref()
                    .unwrap_or(&subject_domain)
                    .to_string();
                let display_ip = source_ip.as_deref().unwrap_or("local");
                let display_lt = logon_type_name.as_deref().unwrap_or("Unknown").to_string();

                let mut risk = Vec::new();
                // Flag network cleartext logons as risky
                if logon_type == Some(logon_types::NETWORK_CLEARTEXT) {
                    risk.push("cleartext_logon".to_string());
                }

                Some(IdentityEvent {
                    event_type: IdentityEventType::LogonSuccess,
                    event_id,
                    subject_account,
                    subject_domain,
                    subject_sid: Self::field_opt(event_data, "SubjectUserSid"),
                    target_account: target_user.clone(),
                    target_domain: target_domain.clone(),
                    target_sid: Self::field_opt(event_data, "TargetUserSid"),
                    source_ip: source_ip.clone(),
                    source_hostname: workstation,
                    logon_type,
                    logon_type_name,
                    auth_package: auth_pkg,
                    service_name: logon_process,
                    group_name: None,
                    group_domain: None,
                    failure_reason: None,
                    failure_status: None,
                    failure_substatus: None,
                    encryption_type: None,
                    preauth_type: None,
                    certificate_info: None,
                    object_guid: None,
                    properties_accessed: None,
                    details: format!(
                        "Successful {} logon: {}\\{} from {}",
                        display_lt, display_domain, display_user, display_ip
                    ),
                    risk_indicators: risk,
                })
            }

            // ---- 4625: Failed logon ----
            event_ids::LOGON_FAILURE => {
                let subject_account = Self::field_or(event_data, "SubjectUserName", "Unknown");
                let subject_domain = Self::field_or(event_data, "SubjectDomainName", "Unknown");
                let target_user = Self::field_opt(event_data, "TargetUserName");
                let target_domain = Self::field_opt(event_data, "TargetDomainName");
                let source_ip = Self::field_opt(event_data, "IpAddress");
                let workstation = Self::field_opt(event_data, "WorkstationName");
                let auth_pkg = Self::field_opt(event_data, "AuthenticationPackageName");
                let failure_status = Self::field_opt(event_data, "Status");
                let failure_substatus = Self::field_opt(event_data, "SubStatus");
                let failure_reason = Self::field_opt(event_data, "FailureReason");
                let (logon_type, logon_type_name) = Self::parse_logon_type(event_data);

                // Track failed logon for password spray detection using source IP
                let source_key = source_ip
                    .clone()
                    .unwrap_or_else(|| "unknown_source".to_string());
                tracker
                    .failed_logons_by_source
                    .entry(source_key)
                    .or_default()
                    .push_back(now);

                let display_user = target_user
                    .as_deref()
                    .unwrap_or(&subject_account)
                    .to_string();
                let display_domain = target_domain
                    .as_deref()
                    .unwrap_or(&subject_domain)
                    .to_string();
                let display_ip = source_ip.as_deref().unwrap_or("unknown");
                let display_status = failure_status.as_deref().unwrap_or("unknown").to_string();

                Some(IdentityEvent {
                    event_type: IdentityEventType::LogonFailure,
                    event_id,
                    subject_account,
                    subject_domain,
                    subject_sid: Self::field_opt(event_data, "SubjectUserSid"),
                    target_account: target_user.clone(),
                    target_domain: target_domain.clone(),
                    target_sid: Self::field_opt(event_data, "TargetUserSid"),
                    source_ip: source_ip.clone(),
                    source_hostname: workstation,
                    logon_type,
                    logon_type_name,
                    auth_package: auth_pkg,
                    service_name: None,
                    group_name: None,
                    group_domain: None,
                    failure_reason,
                    failure_status,
                    failure_substatus,
                    encryption_type: None,
                    preauth_type: None,
                    certificate_info: None,
                    object_guid: None,
                    properties_accessed: None,
                    details: format!(
                        "Failed logon: {}\\{} from {} (status: {})",
                        display_domain, display_user, display_ip, display_status
                    ),
                    risk_indicators: vec!["failed_logon".to_string()],
                })
            }

            // ---- 4648: Explicit credential logon (runas, etc.) ----
            event_ids::EXPLICIT_CREDENTIAL => {
                let subject_account = Self::field_or(event_data, "SubjectUserName", "Unknown");
                let subject_domain = Self::field_or(event_data, "SubjectDomainName", "Unknown");
                let target_user = Self::field_opt(event_data, "TargetUserName");
                let target_domain = Self::field_opt(event_data, "TargetDomainName");
                let source_ip = Self::field_opt(event_data, "IpAddress");
                let target_server = Self::field_opt(event_data, "TargetServerName");
                let process_name = Self::field_opt(event_data, "ProcessName");

                let display_target = target_user.as_deref().unwrap_or("Unknown");
                let display_server = target_server.as_deref().unwrap_or("Unknown");
                let display_process = process_name.as_deref().unwrap_or("Unknown");

                Some(IdentityEvent {
                    event_type: IdentityEventType::ExplicitCredential,
                    event_id,
                    subject_account,
                    subject_domain,
                    subject_sid: Self::field_opt(event_data, "SubjectUserSid"),
                    target_account: target_user.clone(),
                    target_domain: target_domain.clone(),
                    target_sid: None,
                    source_ip,
                    source_hostname: target_server.clone(),
                    logon_type: None,
                    logon_type_name: None,
                    auth_package: None,
                    service_name: process_name.clone(),
                    group_name: None,
                    group_domain: None,
                    failure_reason: None,
                    failure_status: None,
                    failure_substatus: None,
                    encryption_type: None,
                    preauth_type: None,
                    certificate_info: None,
                    object_guid: None,
                    properties_accessed: None,
                    details: format!(
                        "Explicit credential usage: targeting {} on {} via {}",
                        display_target, display_server, display_process
                    ),
                    risk_indicators: vec!["explicit_credential".to_string()],
                })
            }

            // ---- 4672: Special privileges assigned to new logon ----
            event_ids::SPECIAL_PRIVILEGES => {
                let subject_account = Self::field_or(event_data, "SubjectUserName", "Unknown");
                let subject_domain = Self::field_or(event_data, "SubjectDomainName", "Unknown");
                let privilege_list = Self::field_opt(event_data, "PrivilegeList");

                let display_privs = privilege_list
                    .as_deref()
                    .unwrap_or("(not available)")
                    .trim()
                    .replace('\n', ", ");

                Some(IdentityEvent {
                    event_type: IdentityEventType::SpecialPrivileges,
                    event_id,
                    subject_account,
                    subject_domain,
                    subject_sid: Self::field_opt(event_data, "SubjectUserSid"),
                    target_account: None,
                    target_domain: None,
                    target_sid: None,
                    source_ip: None,
                    source_hostname: None,
                    logon_type: None,
                    logon_type_name: None,
                    auth_package: None,
                    service_name: None,
                    group_name: None,
                    group_domain: None,
                    failure_reason: None,
                    failure_status: None,
                    failure_substatus: None,
                    encryption_type: None,
                    preauth_type: None,
                    certificate_info: None,
                    object_guid: None,
                    properties_accessed: privilege_list.map(|p| {
                        p.split('\n')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect()
                    }),
                    details: format!(
                        "Special privileges assigned to new logon: {}",
                        display_privs
                    ),
                    risk_indicators: vec!["privileged_logon".to_string()],
                })
            }

            // ---- 4720: User account created ----
            event_ids::USER_CREATED => {
                let subject_account = Self::field_or(event_data, "SubjectUserName", "Unknown");
                let subject_domain = Self::field_or(event_data, "SubjectDomainName", "Unknown");
                let target_user = Self::field_opt(event_data, "TargetUserName");
                let target_domain = Self::field_opt(event_data, "TargetDomainName");
                let target_sid = Self::field_opt(event_data, "TargetSid");
                let sam_name = Self::field_opt(event_data, "SamAccountName");

                let display_new_user = target_user
                    .as_deref()
                    .or(sam_name.as_deref())
                    .unwrap_or("Unknown");

                Some(IdentityEvent {
                    event_type: IdentityEventType::UserCreated,
                    event_id,
                    subject_account,
                    subject_domain,
                    subject_sid: Self::field_opt(event_data, "SubjectUserSid"),
                    target_account: target_user.clone(),
                    target_domain: target_domain.clone(),
                    target_sid,
                    source_ip: None,
                    source_hostname: None,
                    logon_type: None,
                    logon_type_name: None,
                    auth_package: None,
                    service_name: None,
                    group_name: None,
                    group_domain: None,
                    failure_reason: None,
                    failure_status: None,
                    failure_substatus: None,
                    encryption_type: None,
                    preauth_type: None,
                    certificate_info: None,
                    object_guid: None,
                    properties_accessed: None,
                    details: format!("User account created: {}", display_new_user),
                    risk_indicators: vec!["account_created".to_string()],
                })
            }

            // ---- 4726: User account deleted ----
            event_ids::USER_DELETED => {
                let subject_account = Self::field_or(event_data, "SubjectUserName", "Unknown");
                let subject_domain = Self::field_or(event_data, "SubjectDomainName", "Unknown");
                let target_user = Self::field_opt(event_data, "TargetUserName");
                let target_domain = Self::field_opt(event_data, "TargetDomainName");
                let target_sid = Self::field_opt(event_data, "TargetSid");

                let display_del_user = target_user.as_deref().unwrap_or("Unknown");

                Some(IdentityEvent {
                    event_type: IdentityEventType::UserDeleted,
                    event_id,
                    subject_account,
                    subject_domain,
                    subject_sid: Self::field_opt(event_data, "SubjectUserSid"),
                    target_account: target_user.clone(),
                    target_domain: target_domain.clone(),
                    target_sid,
                    source_ip: None,
                    source_hostname: None,
                    logon_type: None,
                    logon_type_name: None,
                    auth_package: None,
                    service_name: None,
                    group_name: None,
                    group_domain: None,
                    failure_reason: None,
                    failure_status: None,
                    failure_substatus: None,
                    encryption_type: None,
                    preauth_type: None,
                    certificate_info: None,
                    object_guid: None,
                    properties_accessed: None,
                    details: format!("User account deleted: {}", display_del_user),
                    risk_indicators: vec!["account_deleted".to_string()],
                })
            }

            // ---- 4728/4732/4756: User added to security-enabled group ----
            event_ids::USER_ADDED_GLOBAL_GROUP
            | event_ids::USER_ADDED_LOCAL_GROUP
            | event_ids::USER_ADDED_UNIVERSAL_GROUP => {
                let event_type = match event_id {
                    event_ids::USER_ADDED_GLOBAL_GROUP => IdentityEventType::UserAddedToGlobalGroup,
                    event_ids::USER_ADDED_LOCAL_GROUP => IdentityEventType::UserAddedToLocalGroup,
                    event_ids::USER_ADDED_UNIVERSAL_GROUP => {
                        IdentityEventType::UserAddedToUniversalGroup
                    }
                    _ => unreachable!(),
                };

                let subject_account = Self::field_or(event_data, "SubjectUserName", "Unknown");
                let subject_domain = Self::field_or(event_data, "SubjectDomainName", "Unknown");
                let member_name = Self::field_opt(event_data, "MemberName");
                let member_sid = Self::field_opt(event_data, "MemberSid");
                let group_name = Self::field_opt(event_data, "TargetUserName"); // Group name
                let group_domain = Self::field_opt(event_data, "TargetDomainName");
                let group_sid = Self::field_opt(event_data, "TargetSid");

                let display_member = member_name.as_deref().unwrap_or("Unknown");
                let display_group = group_name.as_deref().unwrap_or("Unknown");

                // Check if this is a sensitive/privileged group
                let mut risk = vec!["group_membership_change".to_string()];
                if let Some(ref gn) = group_name {
                    if SENSITIVE_GROUPS.iter().any(|sg| gn.contains(sg)) {
                        risk.push("sensitive_group_change".to_string());
                    }
                }

                Some(IdentityEvent {
                    event_type,
                    event_id,
                    subject_account,
                    subject_domain,
                    subject_sid: Self::field_opt(event_data, "SubjectUserSid"),
                    target_account: member_name.clone(),
                    target_domain: None,
                    target_sid: member_sid,
                    source_ip: None,
                    source_hostname: None,
                    logon_type: None,
                    logon_type_name: None,
                    auth_package: None,
                    service_name: None,
                    group_name: group_name.clone(),
                    group_domain: group_domain.clone(),
                    failure_reason: None,
                    failure_status: None,
                    failure_substatus: None,
                    encryption_type: None,
                    preauth_type: None,
                    certificate_info: None,
                    object_guid: group_sid,
                    properties_accessed: None,
                    details: format!("User {} added to group {}", display_member, display_group),
                    risk_indicators: risk,
                })
            }

            // ---- 4729/4733/4757: User removed from security-enabled group ----
            event_ids::USER_REMOVED_GLOBAL_GROUP
            | event_ids::USER_REMOVED_LOCAL_GROUP
            | event_ids::USER_REMOVED_UNIVERSAL_GROUP => {
                let event_type = match event_id {
                    event_ids::USER_REMOVED_GLOBAL_GROUP => {
                        IdentityEventType::UserRemovedFromGlobalGroup
                    }
                    event_ids::USER_REMOVED_LOCAL_GROUP => {
                        IdentityEventType::UserRemovedFromLocalGroup
                    }
                    event_ids::USER_REMOVED_UNIVERSAL_GROUP => {
                        IdentityEventType::UserRemovedFromUniversalGroup
                    }
                    _ => unreachable!(),
                };

                let subject_account = Self::field_or(event_data, "SubjectUserName", "Unknown");
                let subject_domain = Self::field_or(event_data, "SubjectDomainName", "Unknown");
                let member_name = Self::field_opt(event_data, "MemberName");
                let member_sid = Self::field_opt(event_data, "MemberSid");
                let group_name = Self::field_opt(event_data, "TargetUserName"); // Group name
                let group_domain = Self::field_opt(event_data, "TargetDomainName");
                let group_sid = Self::field_opt(event_data, "TargetSid");

                let display_member = member_name.as_deref().unwrap_or("Unknown");
                let display_group = group_name.as_deref().unwrap_or("Unknown");

                Some(IdentityEvent {
                    event_type,
                    event_id,
                    subject_account,
                    subject_domain,
                    subject_sid: Self::field_opt(event_data, "SubjectUserSid"),
                    target_account: member_name.clone(),
                    target_domain: None,
                    target_sid: member_sid,
                    source_ip: None,
                    source_hostname: None,
                    logon_type: None,
                    logon_type_name: None,
                    auth_package: None,
                    service_name: None,
                    group_name: group_name.clone(),
                    group_domain: group_domain.clone(),
                    failure_reason: None,
                    failure_status: None,
                    failure_substatus: None,
                    encryption_type: None,
                    preauth_type: None,
                    certificate_info: None,
                    object_guid: group_sid,
                    properties_accessed: None,
                    details: format!(
                        "User {} removed from group {}",
                        display_member, display_group
                    ),
                    risk_indicators: vec!["group_membership_change".to_string()],
                })
            }

            // ---- 4768: Kerberos TGT request (AS-REQ) ----
            event_ids::KERBEROS_TGT => {
                let target_user = Self::field_or(event_data, "TargetUserName", "Unknown");
                let target_domain = Self::field_opt(event_data, "TargetDomainName");
                let service_name = Self::field_opt(event_data, "ServiceName");
                let source_ip = Self::field_opt(event_data, "IpAddress");
                let encryption_type = Self::field_opt(event_data, "TicketEncryptionType");
                let preauth_type = Self::field_opt(event_data, "PreAuthType");
                let status = Self::field_opt(event_data, "Status");
                let cert_issuer = Self::field_opt(event_data, "CertIssuerName");
                let cert_thumbprint = Self::field_opt(event_data, "CertThumbprint");
                let cert_info = match (&cert_issuer, &cert_thumbprint) {
                    (Some(issuer), Some(thumb)) => {
                        Some(format!("Issuer: {}, Thumbprint: {}", issuer, thumb))
                    }
                    (Some(issuer), None) => Some(format!("Issuer: {}", issuer)),
                    _ => None,
                };

                let display_svc = service_name.as_deref().unwrap_or("krbtgt");
                let display_ip = source_ip.as_deref().unwrap_or("unknown");

                let mut risk = Vec::new();
                // RC4 encryption type (0x17 = 23) may indicate downgrade attack
                if encryption_type.as_deref() == Some("0x17") {
                    risk.push("rc4_encryption".to_string());
                }

                Some(IdentityEvent {
                    event_type: IdentityEventType::KerberosTgtRequest,
                    event_id,
                    subject_account: target_user.clone(),
                    subject_domain: target_domain
                        .clone()
                        .unwrap_or_else(|| "Unknown".to_string()),
                    subject_sid: Self::field_opt(event_data, "TargetSid"),
                    target_account: Some(target_user.clone()),
                    target_domain: target_domain.clone(),
                    target_sid: Self::field_opt(event_data, "TargetSid"),
                    source_ip: source_ip.clone(),
                    source_hostname: None,
                    logon_type: None,
                    logon_type_name: None,
                    auth_package: Some("Kerberos".to_string()),
                    service_name: service_name.clone().or_else(|| Some("krbtgt".to_string())),
                    group_name: None,
                    group_domain: None,
                    failure_reason: status.clone(),
                    failure_status: status,
                    failure_substatus: None,
                    encryption_type,
                    preauth_type,
                    certificate_info: cert_info,
                    object_guid: None,
                    properties_accessed: None,
                    details: format!(
                        "Kerberos TGT request (AS-REQ): {} for {} from {}",
                        target_user, display_svc, display_ip
                    ),
                    risk_indicators: risk,
                })
            }

            // ---- 4769: Kerberos service ticket request (TGS-REQ) ----
            event_ids::KERBEROS_TGS => {
                let target_user = Self::field_or(event_data, "TargetUserName", "Unknown");
                let target_domain = Self::field_opt(event_data, "TargetDomainName");
                let service_name = Self::field_opt(event_data, "ServiceName");
                let source_ip = Self::field_opt(event_data, "IpAddress");
                let encryption_type = Self::field_opt(event_data, "TicketEncryptionType");
                let status = Self::field_opt(event_data, "Status");

                // Track TGS request for Kerberoasting detection using actual user
                let user_key = target_user.clone();
                tracker
                    .tgs_requests_by_user
                    .entry(user_key)
                    .or_default()
                    .push_back(now);

                let display_svc = service_name.as_deref().unwrap_or("Unknown");
                let display_ip = source_ip.as_deref().unwrap_or("unknown");

                let mut risk = Vec::new();
                // RC4 encryption type (0x17 = 23) is a strong Kerberoasting indicator
                if encryption_type.as_deref() == Some("0x17") {
                    risk.push("rc4_ticket_encryption".to_string());
                    risk.push("kerberoasting_indicator".to_string());
                }

                Some(IdentityEvent {
                    event_type: IdentityEventType::KerberosServiceTicket,
                    event_id,
                    subject_account: target_user.clone(),
                    subject_domain: target_domain
                        .clone()
                        .unwrap_or_else(|| "Unknown".to_string()),
                    subject_sid: None,
                    target_account: Some(target_user.clone()),
                    target_domain: target_domain.clone(),
                    target_sid: None,
                    source_ip: source_ip.clone(),
                    source_hostname: None,
                    logon_type: None,
                    logon_type_name: None,
                    auth_package: Some("Kerberos".to_string()),
                    service_name: service_name.clone(),
                    group_name: None,
                    group_domain: None,
                    failure_reason: status.clone(),
                    failure_status: status,
                    failure_substatus: None,
                    encryption_type,
                    preauth_type: None,
                    certificate_info: None,
                    object_guid: None,
                    properties_accessed: None,
                    details: format!(
                        "Kerberos service ticket request (TGS-REQ): {} for {} from {}",
                        target_user, display_svc, display_ip
                    ),
                    risk_indicators: risk,
                })
            }

            // ---- 4771: Kerberos pre-authentication failed ----
            event_ids::KERBEROS_PREAUTH_FAILED => {
                let target_user = Self::field_or(event_data, "TargetUserName", "Unknown");
                let source_ip = Self::field_opt(event_data, "IpAddress");
                let status = Self::field_opt(event_data, "Status");
                let preauth_type = Self::field_opt(event_data, "PreAuthType");
                let service_name = Self::field_opt(event_data, "ServiceName");

                // Track for AS-REP Roasting detection using actual user
                let user_key = target_user.clone();
                tracker
                    .preauth_failures
                    .entry(user_key)
                    .or_default()
                    .push_back(now);

                let display_ip = source_ip.as_deref().unwrap_or("unknown");
                let display_status = status.as_deref().unwrap_or("unknown").to_string();

                Some(IdentityEvent {
                    event_type: IdentityEventType::KerberosPreAuthFailed,
                    event_id,
                    subject_account: target_user.clone(),
                    subject_domain: "Unknown".to_string(),
                    subject_sid: Self::field_opt(event_data, "TargetSid"),
                    target_account: Some(target_user.clone()),
                    target_domain: None,
                    target_sid: Self::field_opt(event_data, "TargetSid"),
                    source_ip: source_ip.clone(),
                    source_hostname: None,
                    logon_type: None,
                    logon_type_name: None,
                    auth_package: Some("Kerberos".to_string()),
                    service_name,
                    group_name: None,
                    group_domain: None,
                    failure_reason: Some(format!(
                        "Pre-authentication failed (status: {})",
                        display_status
                    )),
                    failure_status: status,
                    failure_substatus: None,
                    encryption_type: None,
                    preauth_type,
                    certificate_info: None,
                    object_guid: None,
                    properties_accessed: None,
                    details: format!(
                        "Kerberos pre-authentication failed: {} from {} (status: {})",
                        target_user, display_ip, display_status
                    ),
                    risk_indicators: vec!["kerberos_preauth_failed".to_string()],
                })
            }

            // ---- 4776: NTLM credential validation ----
            event_ids::NTLM_AUTH => {
                let logon_account = Self::field_or(event_data, "LogonAccount", "Unknown");
                let auth_pkg = Self::field_opt(event_data, "AuthenticationPackageName");
                let source_workstation = Self::field_opt(event_data, "SourceWorkstation");
                let status = Self::field_opt(event_data, "Status");
                let workstation = Self::field_opt(event_data, "Workstation");

                let display_source = source_workstation.as_deref().unwrap_or("unknown");
                let display_status = status.as_deref().unwrap_or("unknown").to_string();

                let mut risk = vec!["ntlm_auth".to_string()];
                // Non-zero status means authentication failure
                if status
                    .as_deref()
                    .filter(|s| *s != "0x0" && *s != "0x00000000")
                    .is_some()
                {
                    risk.push("ntlm_auth_failure".to_string());
                }

                Some(IdentityEvent {
                    event_type: IdentityEventType::NtlmAuthentication,
                    event_id,
                    subject_account: logon_account.clone(),
                    subject_domain: "Unknown".to_string(),
                    subject_sid: None,
                    target_account: Some(logon_account.clone()),
                    target_domain: None,
                    target_sid: None,
                    source_ip: None,
                    source_hostname: source_workstation.clone().or(workstation),
                    logon_type: None,
                    logon_type_name: None,
                    auth_package: auth_pkg.or_else(|| Some("NTLM".to_string())),
                    service_name: None,
                    group_name: None,
                    group_domain: None,
                    failure_reason: None,
                    failure_status: status,
                    failure_substatus: None,
                    encryption_type: None,
                    preauth_type: None,
                    certificate_info: None,
                    object_guid: None,
                    properties_accessed: None,
                    details: format!(
                        "NTLM authentication: {} from {} (status: {})",
                        logon_account, display_source, display_status
                    ),
                    risk_indicators: risk,
                })
            }

            // ---- 4662: Directory service object access (DCSync detection) ----
            event_ids::DS_ACCESS => {
                let subject_account = Self::field_or(event_data, "SubjectUserName", "Unknown");
                let subject_domain = Self::field_or(event_data, "SubjectDomainName", "Unknown");
                let object_type = Self::field_opt(event_data, "ObjectType");
                let object_name = Self::field_opt(event_data, "ObjectName");
                let properties_raw = Self::field_opt(event_data, "Properties");
                let operation_type = Self::field_opt(event_data, "OperationType");

                // Check for DCSync replication GUIDs in properties
                let (is_dcsync, dcsync_guids_found) = Self::check_dcsync_properties(event_data);

                let mut risk = vec!["ds_access".to_string()];
                let event_type;
                let details;

                if is_dcsync {
                    event_type = IdentityEventType::DcSyncDetected;
                    risk.push("dcsync".to_string());
                    risk.push("credential_theft".to_string());
                    details = format!(
                        "DCSync attack detected: {}\\{} accessed replication rights [{}]",
                        subject_domain,
                        subject_account,
                        dcsync_guids_found.join(", ")
                    );
                } else {
                    event_type = IdentityEventType::DirectoryServiceAccess;
                    let display_obj = object_name.as_deref().unwrap_or("Unknown");
                    let display_op = operation_type.as_deref().unwrap_or("Unknown");
                    details = format!(
                        "Directory service access: {}\\{} {} on {}",
                        subject_domain, subject_account, display_op, display_obj
                    );
                }

                // Parse properties into a list
                let properties_list = properties_raw.map(|p| {
                    p.split('\n')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<String>>()
                });

                Some(IdentityEvent {
                    event_type,
                    event_id,
                    subject_account,
                    subject_domain,
                    subject_sid: Self::field_opt(event_data, "SubjectUserSid"),
                    target_account: None,
                    target_domain: None,
                    target_sid: None,
                    source_ip: None,
                    source_hostname: None,
                    logon_type: None,
                    logon_type_name: None,
                    auth_package: None,
                    service_name: None,
                    group_name: None,
                    group_domain: None,
                    failure_reason: None,
                    failure_status: None,
                    failure_substatus: None,
                    encryption_type: None,
                    preauth_type: None,
                    certificate_info: None,
                    object_guid: object_type,
                    properties_accessed: properties_list,
                    details,
                    risk_indicators: risk,
                })
            }

            _ => None,
        }
    }

    /// Check for attack patterns based on tracked data
    fn check_attack_patterns(tracker: &mut AttackTracker, now: u64) -> Option<Vec<IdentityEvent>> {
        let mut events = Vec::new();

        // Check for password spray - collect candidates first to avoid borrow conflict
        let spray_candidates: Vec<(String, usize)> = tracker
            .failed_logons_by_source
            .iter()
            .filter(|(_, failures)| failures.len() >= PASSWORD_SPRAY_THRESHOLD)
            .map(|(source, failures)| (source.clone(), failures.len()))
            .collect();

        for (source, failure_count) in spray_candidates {
            let alert_key = format!("password_spray_{}", source);
            if tracker.should_alert(&alert_key, now) {
                events.push(IdentityEvent {
                    event_type: IdentityEventType::PasswordSprayDetected,
                    event_id: 0,
                    subject_account: "Multiple".to_string(),
                    subject_domain: "Unknown".to_string(),
                    subject_sid: None,
                    target_account: None,
                    target_domain: None,
                    target_sid: None,
                    source_ip: Some(source.clone()),
                    source_hostname: None,
                    logon_type: None,
                    logon_type_name: None,
                    auth_package: None,
                    service_name: None,
                    group_name: None,
                    group_domain: None,
                    failure_reason: None,
                    failure_status: None,
                    failure_substatus: None,
                    encryption_type: None,
                    preauth_type: None,
                    certificate_info: None,
                    object_guid: None,
                    properties_accessed: None,
                    details: format!(
                        "Password spray attack detected: {} failed logon attempts from {} in {} seconds",
                        failure_count,
                        source,
                        PASSWORD_SPRAY_WINDOW_SECS
                    ),
                    risk_indicators: vec!["password_spray".to_string(), "brute_force".to_string()],
                });
            }
        }

        // Check for Kerberoasting
        let total_tgs: usize = tracker.tgs_requests_by_user.values().map(|v| v.len()).sum();
        if total_tgs >= KERBEROASTING_THRESHOLD {
            let alert_key = "kerberoasting_global".to_string();
            if tracker.should_alert(&alert_key, now) {
                events.push(IdentityEvent {
                    event_type: IdentityEventType::KerberoastingDetected,
                    event_id: 0,
                    subject_account: "Multiple".to_string(),
                    subject_domain: "Unknown".to_string(),
                    subject_sid: None,
                    target_account: None,
                    target_domain: None,
                    target_sid: None,
                    source_ip: None,
                    source_hostname: None,
                    logon_type: None,
                    logon_type_name: None,
                    auth_package: Some("Kerberos".to_string()),
                    service_name: None,
                    group_name: None,
                    group_domain: None,
                    failure_reason: None,
                    failure_status: None,
                    failure_substatus: None,
                    encryption_type: None,
                    preauth_type: None,
                    certificate_info: None,
                    object_guid: None,
                    properties_accessed: None,
                    details: format!(
                        "Potential Kerberoasting attack: {} TGS requests in {} seconds",
                        total_tgs, KERBEROASTING_WINDOW_SECS
                    ),
                    risk_indicators: vec![
                        "kerberoasting".to_string(),
                        "credential_theft".to_string(),
                    ],
                });
            }
        }

        // Check for AS-REP Roasting
        let total_preauth_failures: usize =
            tracker.preauth_failures.values().map(|v| v.len()).sum();
        if total_preauth_failures >= ASREP_ROASTING_THRESHOLD {
            let alert_key = "asrep_roasting_global".to_string();
            if tracker.should_alert(&alert_key, now) {
                events.push(IdentityEvent {
                    event_type: IdentityEventType::AsRepRoastingDetected,
                    event_id: 0,
                    subject_account: "Multiple".to_string(),
                    subject_domain: "Unknown".to_string(),
                    subject_sid: None,
                    target_account: None,
                    target_domain: None,
                    target_sid: None,
                    source_ip: None,
                    source_hostname: None,
                    logon_type: None,
                    logon_type_name: None,
                    auth_package: Some("Kerberos".to_string()),
                    service_name: None,
                    group_name: None,
                    group_domain: None,
                    failure_reason: None,
                    failure_status: None,
                    failure_substatus: None,
                    encryption_type: None,
                    preauth_type: None,
                    certificate_info: None,
                    object_guid: None,
                    properties_accessed: None,
                    details: format!(
                        "Potential AS-REP Roasting attack: {} pre-auth failures in {} seconds",
                        total_preauth_failures, ASREP_ROASTING_WINDOW_SECS
                    ),
                    risk_indicators: vec![
                        "asrep_roasting".to_string(),
                        "credential_theft".to_string(),
                    ],
                });
            }
        }

        if events.is_empty() {
            None
        } else {
            Some(events)
        }
    }

    /// Convert IdentityEvent to TelemetryEvent
    fn to_telemetry_event(identity_event: IdentityEvent) -> TelemetryEvent {
        let severity = identity_event.event_type.severity();
        let mitre_techniques = identity_event.event_type.mitre_techniques();
        let mitre_tactics = identity_event.event_type.mitre_tactics();

        let event_type = match identity_event.event_type {
            IdentityEventType::LogonSuccess => EventType::AuthLogin,
            IdentityEventType::LogonFailure => EventType::AuthFailed,
            _ => EventType::AuthLogin, // Use AuthLogin as base for identity events
        };

        let mut event = TelemetryEvent::new(
            event_type,
            severity.clone(),
            EventPayload::Custom(serde_json::to_value(&identity_event).unwrap_or_default()),
        );

        // Add metadata
        event.metadata.insert(
            "identity_event_type".to_string(),
            identity_event.event_type.as_str().to_string(),
        );
        event.metadata.insert(
            "windows_event_id".to_string(),
            identity_event.event_id.to_string(),
        );
        event.metadata.insert(
            "subject_account".to_string(),
            identity_event.subject_account.clone(),
        );

        if let Some(ref source_ip) = identity_event.source_ip {
            event
                .metadata
                .insert("source_ip".to_string(), source_ip.clone());
        }

        if let Some(ref auth_package) = identity_event.auth_package {
            event
                .metadata
                .insert("auth_package".to_string(), auth_package.clone());
        }

        // Add detection for attack events
        if matches!(
            identity_event.event_type,
            IdentityEventType::PasswordSprayDetected
                | IdentityEventType::DcSyncDetected
                | IdentityEventType::GoldenTicketSuspected
                | IdentityEventType::SilverTicketSuspected
                | IdentityEventType::KerberoastingDetected
                | IdentityEventType::AsRepRoastingDetected
        ) {
            event.add_detection(Detection {
                detection_type: DetectionType::Behavioral,
                rule_name: format!("Identity_{}", identity_event.event_type.as_str()),
                confidence: match identity_event.event_type {
                    IdentityEventType::DcSyncDetected => 0.95,
                    IdentityEventType::GoldenTicketSuspected
                    | IdentityEventType::SilverTicketSuspected => 0.85,
                    IdentityEventType::KerberoastingDetected
                    | IdentityEventType::AsRepRoastingDetected => 0.90,
                    IdentityEventType::PasswordSprayDetected => 0.85,
                    _ => 0.75,
                },
                description: identity_event.details.clone(),
                mitre_tactics,
                mitre_techniques,
            });
        }

        event
    }

    /// Get next event from collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }
}

impl Drop for IdentityCollector {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_event_type_mitre_mapping() {
        let password_spray = IdentityEventType::PasswordSprayDetected;
        assert!(password_spray
            .mitre_techniques()
            .contains(&"T1110.003".to_string()));

        let dcsync = IdentityEventType::DcSyncDetected;
        assert!(dcsync.mitre_techniques().contains(&"T1003.006".to_string()));
        assert_eq!(dcsync.severity(), Severity::Critical);
    }

    #[test]
    fn test_identity_event_type_severity() {
        assert_eq!(
            IdentityEventType::DcSyncDetected.severity(),
            Severity::Critical
        );
        assert_eq!(
            IdentityEventType::GoldenTicketSuspected.severity(),
            Severity::Critical
        );
        assert_eq!(
            IdentityEventType::PasswordSprayDetected.severity(),
            Severity::High
        );
        assert_eq!(IdentityEventType::LogonSuccess.severity(), Severity::Low);
    }

    #[test]
    fn test_attack_tracker_cleanup() {
        let mut tracker = AttackTracker::new();
        let now = 1000u64;

        tracker
            .failed_logons_by_source
            .entry("test".to_string())
            .or_default()
            .push_back(now - 1000); // Old entry

        tracker
            .failed_logons_by_source
            .entry("test".to_string())
            .or_default()
            .push_back(now - 100); // Recent entry

        tracker.cleanup(now);

        // Old entry should be removed, recent should remain
        assert_eq!(
            tracker.failed_logons_by_source.get("test").map(|v| v.len()),
            Some(1)
        );
    }

    #[test]
    fn test_field_or_returns_value_when_present() {
        let mut data = HashMap::new();
        data.insert("SubjectUserName".to_string(), "admin".to_string());
        assert_eq!(
            IdentityCollector::field_or(&data, "SubjectUserName", "Unknown"),
            "admin"
        );
    }

    #[test]
    fn test_field_or_returns_fallback_when_missing() {
        let data = HashMap::new();
        assert_eq!(
            IdentityCollector::field_or(&data, "SubjectUserName", "Unknown"),
            "Unknown"
        );
    }

    #[test]
    fn test_field_or_returns_fallback_for_empty_value() {
        let mut data = HashMap::new();
        data.insert("SubjectUserName".to_string(), "".to_string());
        assert_eq!(
            IdentityCollector::field_or(&data, "SubjectUserName", "Unknown"),
            "Unknown"
        );
    }

    #[test]
    fn test_field_or_returns_fallback_for_dash() {
        let mut data = HashMap::new();
        data.insert("IpAddress".to_string(), "-".to_string());
        assert_eq!(
            IdentityCollector::field_or(&data, "IpAddress", "none"),
            "none"
        );
    }

    #[test]
    fn test_field_opt_returns_some_when_present() {
        let mut data = HashMap::new();
        data.insert("IpAddress".to_string(), "192.168.1.100".to_string());
        assert_eq!(
            IdentityCollector::field_opt(&data, "IpAddress"),
            Some("192.168.1.100".to_string())
        );
    }

    #[test]
    fn test_field_opt_returns_none_when_missing() {
        let data = HashMap::new();
        assert_eq!(IdentityCollector::field_opt(&data, "IpAddress"), None);
    }

    #[test]
    fn test_field_opt_returns_none_for_empty() {
        let mut data = HashMap::new();
        data.insert("IpAddress".to_string(), "".to_string());
        assert_eq!(IdentityCollector::field_opt(&data, "IpAddress"), None);
    }

    #[test]
    fn test_field_opt_returns_none_for_dash() {
        let mut data = HashMap::new();
        data.insert("IpAddress".to_string(), "-".to_string());
        assert_eq!(IdentityCollector::field_opt(&data, "IpAddress"), None);
    }

    #[test]
    fn test_parse_logon_type_interactive() {
        let mut data = HashMap::new();
        data.insert("LogonType".to_string(), "2".to_string());
        let (lt, lt_name) = IdentityCollector::parse_logon_type(&data);
        assert_eq!(lt, Some(2));
        assert_eq!(lt_name, Some("Interactive".to_string()));
    }

    #[test]
    fn test_parse_logon_type_network() {
        let mut data = HashMap::new();
        data.insert("LogonType".to_string(), "3".to_string());
        let (lt, lt_name) = IdentityCollector::parse_logon_type(&data);
        assert_eq!(lt, Some(3));
        assert_eq!(lt_name, Some("Network".to_string()));
    }

    #[test]
    fn test_parse_logon_type_remote_interactive() {
        let mut data = HashMap::new();
        data.insert("LogonType".to_string(), "10".to_string());
        let (lt, lt_name) = IdentityCollector::parse_logon_type(&data);
        assert_eq!(lt, Some(10));
        assert_eq!(lt_name, Some("RemoteInteractive".to_string()));
    }

    #[test]
    fn test_parse_logon_type_missing() {
        let data = HashMap::new();
        let (lt, lt_name) = IdentityCollector::parse_logon_type(&data);
        assert_eq!(lt, None);
        assert_eq!(lt_name, None);
    }

    #[test]
    fn test_check_dcsync_properties_detected() {
        let mut data = HashMap::new();
        data.insert(
            "Properties".to_string(),
            format!(
                "{{{}}}\n{{{}}}",
                dcsync_guids::DS_REPLICATION_GET_CHANGES,
                dcsync_guids::DS_REPLICATION_GET_CHANGES_ALL
            ),
        );
        let (is_dcsync, guids) = IdentityCollector::check_dcsync_properties(&data);
        assert!(is_dcsync);
        assert!(guids.contains(&"DS-Replication-Get-Changes".to_string()));
        assert!(guids.contains(&"DS-Replication-Get-Changes-All".to_string()));
    }

    #[test]
    fn test_check_dcsync_properties_not_enough_guids() {
        let mut data = HashMap::new();
        data.insert(
            "Properties".to_string(),
            format!("{{{}}}", dcsync_guids::DS_REPLICATION_GET_CHANGES),
        );
        let (is_dcsync, _) = IdentityCollector::check_dcsync_properties(&data);
        assert!(!is_dcsync); // Need at least 2 replication rights
    }

    #[test]
    fn test_check_dcsync_properties_empty() {
        let data = HashMap::new();
        let (is_dcsync, guids) = IdentityCollector::check_dcsync_properties(&data);
        assert!(!is_dcsync);
        assert!(guids.is_empty());
    }

    #[test]
    fn test_map_strings_to_fields_logon_success() {
        // Build the 27 insertion strings for Event 4624
        let mut strings = vec!["".to_string(); 27];
        strings[1] = "SYSTEM".to_string(); // SubjectUserName
        strings[2] = "NT AUTHORITY".to_string(); // SubjectDomainName
        strings[5] = "admin".to_string(); // TargetUserName
        strings[6] = "CONTOSO".to_string(); // TargetDomainName
        strings[8] = "3".to_string(); // LogonType
        strings[10] = "Kerberos".to_string(); // AuthenticationPackageName
        strings[11] = "WORKSTATION1".to_string(); // WorkstationName
        strings[18] = "192.168.1.50".to_string(); // IpAddress

        let fields = IdentityCollector::map_strings_to_fields(event_ids::LOGON_SUCCESS, &strings);
        assert_eq!(fields.get("SubjectUserName"), Some(&"SYSTEM".to_string()));
        assert_eq!(
            fields.get("SubjectDomainName"),
            Some(&"NT AUTHORITY".to_string())
        );
        assert_eq!(fields.get("TargetUserName"), Some(&"admin".to_string()));
        assert_eq!(fields.get("TargetDomainName"), Some(&"CONTOSO".to_string()));
        assert_eq!(fields.get("LogonType"), Some(&"3".to_string()));
        assert_eq!(
            fields.get("AuthenticationPackageName"),
            Some(&"Kerberos".to_string())
        );
        assert_eq!(
            fields.get("WorkstationName"),
            Some(&"WORKSTATION1".to_string())
        );
        assert_eq!(fields.get("IpAddress"), Some(&"192.168.1.50".to_string()));
    }

    #[test]
    fn test_map_strings_to_fields_logon_failure() {
        let mut strings = vec!["".to_string(); 21];
        strings[5] = "attacker".to_string(); // TargetUserName
        strings[6] = "CONTOSO".to_string(); // TargetDomainName
        strings[7] = "0xC000006D".to_string(); // Status
        strings[8] = "Unknown user name or bad password.".to_string(); // FailureReason
        strings[9] = "0xC000006A".to_string(); // SubStatus
        strings[10] = "3".to_string(); // LogonType
        strings[19] = "10.0.0.5".to_string(); // IpAddress

        let fields = IdentityCollector::map_strings_to_fields(event_ids::LOGON_FAILURE, &strings);
        assert_eq!(fields.get("TargetUserName"), Some(&"attacker".to_string()));
        assert_eq!(fields.get("Status"), Some(&"0xC000006D".to_string()));
        assert_eq!(
            fields.get("FailureReason"),
            Some(&"Unknown user name or bad password.".to_string())
        );
        assert_eq!(fields.get("IpAddress"), Some(&"10.0.0.5".to_string()));
        assert_eq!(fields.get("LogonType"), Some(&"3".to_string()));
    }

    #[test]
    fn test_map_strings_to_fields_kerberos_tgs() {
        let mut strings = vec!["".to_string(); 11];
        strings[0] = "admin@CONTOSO.COM".to_string(); // TargetUserName
        strings[1] = "CONTOSO.COM".to_string(); // TargetDomainName
        strings[2] = "MSSQLSvc/db01.contoso.com:1433".to_string(); // ServiceName
        strings[5] = "0x17".to_string(); // TicketEncryptionType (RC4)
        strings[6] = "::ffff:192.168.1.50".to_string(); // IpAddress

        let fields = IdentityCollector::map_strings_to_fields(event_ids::KERBEROS_TGS, &strings);
        assert_eq!(
            fields.get("TargetUserName"),
            Some(&"admin@CONTOSO.COM".to_string())
        );
        assert_eq!(
            fields.get("ServiceName"),
            Some(&"MSSQLSvc/db01.contoso.com:1433".to_string())
        );
        assert_eq!(
            fields.get("TicketEncryptionType"),
            Some(&"0x17".to_string())
        );
        assert_eq!(
            fields.get("IpAddress"),
            Some(&"::ffff:192.168.1.50".to_string())
        );
    }

    #[test]
    fn test_map_strings_to_fields_ds_access() {
        let mut strings = vec!["".to_string(); 14];
        strings[1] = "attacker".to_string(); // SubjectUserName
        strings[2] = "CONTOSO".to_string(); // SubjectDomainName
        strings[5] = "domainDNS".to_string(); // ObjectType
        strings[6] = "DC=contoso,DC=com".to_string(); // ObjectName
        strings[11] = format!(
            "{{{}}}\n{{{}}}",
            dcsync_guids::DS_REPLICATION_GET_CHANGES,
            dcsync_guids::DS_REPLICATION_GET_CHANGES_ALL
        ); // Properties

        let fields = IdentityCollector::map_strings_to_fields(event_ids::DS_ACCESS, &strings);
        assert_eq!(fields.get("SubjectUserName"), Some(&"attacker".to_string()));
        assert_eq!(fields.get("ObjectType"), Some(&"domainDNS".to_string()));
        assert!(fields
            .get("Properties")
            .unwrap()
            .contains(dcsync_guids::DS_REPLICATION_GET_CHANGES));
    }

    #[test]
    fn test_map_strings_to_fields_group_membership() {
        let mut strings = vec!["".to_string(); 10];
        strings[0] = "CN=jdoe,CN=Users,DC=contoso,DC=com".to_string(); // MemberName
        strings[1] = "S-1-5-21-123456-654321-111111-1234".to_string(); // MemberSid
        strings[2] = "Domain Admins".to_string(); // TargetUserName (Group name)
        strings[3] = "CONTOSO".to_string(); // TargetDomainName
        strings[6] = "admin".to_string(); // SubjectUserName
        strings[7] = "CONTOSO".to_string(); // SubjectDomainName

        let fields =
            IdentityCollector::map_strings_to_fields(event_ids::USER_ADDED_GLOBAL_GROUP, &strings);
        assert_eq!(
            fields.get("MemberName"),
            Some(&"CN=jdoe,CN=Users,DC=contoso,DC=com".to_string())
        );
        assert_eq!(
            fields.get("TargetUserName"),
            Some(&"Domain Admins".to_string())
        );
        assert_eq!(fields.get("SubjectUserName"), Some(&"admin".to_string()));
    }

    #[test]
    fn test_map_strings_to_fields_ntlm_auth() {
        let mut strings = vec!["".to_string(); 5];
        strings[0] = "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0".to_string();
        strings[1] = "jdoe".to_string();
        strings[2] = "WORKSTATION1".to_string();
        strings[3] = "0x0".to_string();

        let fields = IdentityCollector::map_strings_to_fields(event_ids::NTLM_AUTH, &strings);
        assert_eq!(fields.get("LogonAccount"), Some(&"jdoe".to_string()));
        assert_eq!(
            fields.get("SourceWorkstation"),
            Some(&"WORKSTATION1".to_string())
        );
        assert_eq!(fields.get("Status"), Some(&"0x0".to_string()));
    }

    #[test]
    fn test_process_logon_success_extracts_fields() {
        let mut data = HashMap::new();
        data.insert("SubjectUserName".to_string(), "SYSTEM".to_string());
        data.insert("SubjectDomainName".to_string(), "NT AUTHORITY".to_string());
        data.insert("TargetUserName".to_string(), "admin".to_string());
        data.insert("TargetDomainName".to_string(), "CONTOSO".to_string());
        data.insert("IpAddress".to_string(), "192.168.1.50".to_string());
        data.insert("LogonType".to_string(), "10".to_string());
        data.insert(
            "AuthenticationPackageName".to_string(),
            "Negotiate".to_string(),
        );

        let mut tracker = AttackTracker::new();
        let event = IdentityCollector::process_security_event(
            event_ids::LOGON_SUCCESS,
            &data,
            &mut tracker,
            1000,
        )
        .unwrap();

        assert_eq!(event.event_type, IdentityEventType::LogonSuccess);
        assert_eq!(event.subject_account, "SYSTEM");
        assert_eq!(event.subject_domain, "NT AUTHORITY");
        assert_eq!(event.target_account, Some("admin".to_string()));
        assert_eq!(event.target_domain, Some("CONTOSO".to_string()));
        assert_eq!(event.source_ip, Some("192.168.1.50".to_string()));
        assert_eq!(event.logon_type, Some(10));
        assert_eq!(event.logon_type_name, Some("RemoteInteractive".to_string()));
        assert_eq!(event.auth_package, Some("Negotiate".to_string()));
        assert!(event.details.contains("CONTOSO"));
        assert!(event.details.contains("admin"));
    }

    #[test]
    fn test_process_logon_failure_tracks_source_ip() {
        let mut data = HashMap::new();
        data.insert("TargetUserName".to_string(), "victim".to_string());
        data.insert("IpAddress".to_string(), "10.0.0.99".to_string());
        data.insert("Status".to_string(), "0xC000006D".to_string());
        data.insert("SubStatus".to_string(), "0xC000006A".to_string());
        data.insert("LogonType".to_string(), "3".to_string());

        let mut tracker = AttackTracker::new();
        let event = IdentityCollector::process_security_event(
            event_ids::LOGON_FAILURE,
            &data,
            &mut tracker,
            1000,
        )
        .unwrap();

        assert_eq!(event.event_type, IdentityEventType::LogonFailure);
        assert_eq!(event.source_ip, Some("10.0.0.99".to_string()));
        assert_eq!(event.failure_status, Some("0xC000006D".to_string()));
        assert_eq!(event.failure_substatus, Some("0xC000006A".to_string()));
        // Should track by source IP, not "unknown_source"
        assert!(tracker.failed_logons_by_source.contains_key("10.0.0.99"));
        assert!(!tracker
            .failed_logons_by_source
            .contains_key("unknown_source"));
    }

    #[test]
    fn test_process_kerberos_tgs_rc4_risk() {
        let mut data = HashMap::new();
        data.insert("TargetUserName".to_string(), "admin".to_string());
        data.insert("ServiceName".to_string(), "MSSQLSvc/db01:1433".to_string());
        data.insert("TicketEncryptionType".to_string(), "0x17".to_string());
        data.insert("IpAddress".to_string(), "192.168.1.50".to_string());

        let mut tracker = AttackTracker::new();
        let event = IdentityCollector::process_security_event(
            event_ids::KERBEROS_TGS,
            &data,
            &mut tracker,
            1000,
        )
        .unwrap();

        assert_eq!(event.event_type, IdentityEventType::KerberosServiceTicket);
        assert_eq!(event.service_name, Some("MSSQLSvc/db01:1433".to_string()));
        assert_eq!(event.encryption_type, Some("0x17".to_string()));
        assert!(event
            .risk_indicators
            .contains(&"rc4_ticket_encryption".to_string()));
        assert!(event
            .risk_indicators
            .contains(&"kerberoasting_indicator".to_string()));
        // Should track by actual user, not "unknown_user"
        assert!(tracker.tgs_requests_by_user.contains_key("admin"));
    }

    #[test]
    fn test_process_ds_access_dcsync_detected() {
        let mut data = HashMap::new();
        data.insert("SubjectUserName".to_string(), "attacker".to_string());
        data.insert("SubjectDomainName".to_string(), "CONTOSO".to_string());
        data.insert("ObjectType".to_string(), "domainDNS".to_string());
        data.insert("ObjectName".to_string(), "DC=contoso,DC=com".to_string());
        data.insert(
            "Properties".to_string(),
            format!(
                "{{{}}}\n{{{}}}",
                dcsync_guids::DS_REPLICATION_GET_CHANGES,
                dcsync_guids::DS_REPLICATION_GET_CHANGES_ALL
            ),
        );

        let mut tracker = AttackTracker::new();
        let event = IdentityCollector::process_security_event(
            event_ids::DS_ACCESS,
            &data,
            &mut tracker,
            1000,
        )
        .unwrap();

        // Should detect DCSync, not just generic DS access
        assert_eq!(event.event_type, IdentityEventType::DcSyncDetected);
        assert!(event.risk_indicators.contains(&"dcsync".to_string()));
        assert!(event
            .risk_indicators
            .contains(&"credential_theft".to_string()));
        assert!(event.details.contains("DCSync attack detected"));
    }

    #[test]
    fn test_process_group_add_sensitive_group_risk() {
        let mut data = HashMap::new();
        data.insert("SubjectUserName".to_string(), "rogue_admin".to_string());
        data.insert("SubjectDomainName".to_string(), "CONTOSO".to_string());
        data.insert(
            "MemberName".to_string(),
            "CN=backdoor,CN=Users,DC=contoso,DC=com".to_string(),
        );
        data.insert("TargetUserName".to_string(), "Domain Admins".to_string()); // Sensitive group
        data.insert("TargetDomainName".to_string(), "CONTOSO".to_string());

        let mut tracker = AttackTracker::new();
        let event = IdentityCollector::process_security_event(
            event_ids::USER_ADDED_GLOBAL_GROUP,
            &data,
            &mut tracker,
            1000,
        )
        .unwrap();

        assert_eq!(event.event_type, IdentityEventType::UserAddedToGlobalGroup);
        assert_eq!(event.group_name, Some("Domain Admins".to_string()));
        assert!(event
            .risk_indicators
            .contains(&"sensitive_group_change".to_string()));
    }

    #[test]
    fn test_process_ntlm_auth_failure_status() {
        let mut data = HashMap::new();
        data.insert("LogonAccount".to_string(), "jdoe".to_string());
        data.insert("SourceWorkstation".to_string(), "EVIL-PC".to_string());
        data.insert("Status".to_string(), "0xC000006D".to_string());

        let mut tracker = AttackTracker::new();
        let event = IdentityCollector::process_security_event(
            event_ids::NTLM_AUTH,
            &data,
            &mut tracker,
            1000,
        )
        .unwrap();

        assert_eq!(event.event_type, IdentityEventType::NtlmAuthentication);
        assert_eq!(event.subject_account, "jdoe");
        assert_eq!(event.source_hostname, Some("EVIL-PC".to_string()));
        assert!(event
            .risk_indicators
            .contains(&"ntlm_auth_failure".to_string()));
    }
}
