//! Event Normalization for Linux auditd → Common Schema
//!
//! Maps Linux audit events to unified TelemetryEvent structures that match
//! Windows ETW event schemas, providing cross-platform visibility parity.
//!
//! ## ETW Provider Equivalents
//!
//! | Windows ETW Provider              | Linux Audit Equivalent                    |
//! |-----------------------------------|-------------------------------------------|
//! | Microsoft-Windows-Security-Auditing | audit syscalls (execve, open, connect)  |
//! | Microsoft-Windows-Sysmon          | audit file, process, network monitors    |
//! | Microsoft-Windows-PowerShell      | audit execve with script interpreter     |
//! | Microsoft-Windows-WMI-Activity    | audit process creation/exec monitoring   |
//! | Microsoft-Windows-Kernel-File     | audit file syscalls (open, unlink, etc.) |
//! | Microsoft-Windows-Kernel-Network  | audit socket syscalls (connect, bind)    |
//! | Microsoft-Windows-Kernel-Process  | audit process syscalls (execve, fork)    |
//!
//! ## Field Mappings
//!
//! ### Process Events (SYSCALL=execve, execveat)
//! - `pid` → audit.pid
//! - `ppid` → audit.ppid
//! - `name` → comm field
//! - `path` → exe field
//! - `cmdline` → a0-aN arguments concatenated
//! - `user` → auid/uid fields
//! - `is_elevated` → euid==0 or suid==1
//! - `parent_name` / `parent_path` → resolved from ppid
//!
//! ### File Events (SYSCALL=open, openat, unlink, unlinkat, rename, renameat)
//! - `path` → name field
//! - `operation` → syscall name (open=create/read, unlink=delete, rename=rename)
//! - `pid` → audit.pid
//! - `process_name` → comm field
//! - `user` → auid/uid fields
//!
//! ### Network Events (SYSCALL=connect, bind, accept, sendto, recvfrom)
//! - `source_ip` → local address from sockaddr
//! - `source_port` → local port from sockaddr
//! - `dest_ip` → remote address from sockaddr
//! - `dest_port` → remote port from sockaddr
//! - `protocol` → determined from socket type (SOCK_STREAM=TCP, SOCK_DGRAM=UDP)
//! - `pid` → audit.pid
//! - `process_name` → comm field
//!
//! ### Authentication Events (TYPE=USER_LOGIN, USER_AUTH, CRED_ACQ)
//! - `user` → acct field
//! - `success` → res field (success/fail)
//! - `source_ip` → addr field
//! - `auth_method` → determined from executable (sshd, login, su, sudo)
//!
//! ## Timestamp Normalization
//! - Linux: audit records use Unix epoch seconds.milliseconds
//! - Windows: ETW uses Windows FILETIME (100ns intervals since 1601-01-01)
//! - Normalized: Unix epoch milliseconds (u64)

use super::super::{
    EventPayload, EventType, FileEvent, NetworkEvent, ProcessEvent, Severity, TelemetryEvent,
};
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};
use uuid::Uuid;

/// Normalized audit record representation
#[derive(Debug, Clone)]
pub struct AuditRecord {
    pub record_type: String,
    pub timestamp: u64,
    pub syscall: Option<String>,
    pub pid: Option<u32>,
    pub ppid: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub euid: Option<u32>,
    pub egid: Option<u32>,
    pub auid: Option<u32>, // Audit UID (original login user)
    pub comm: Option<String>,
    pub exe: Option<String>,
    pub cwd: Option<String>,
    pub args: Vec<String>,
    pub key: Option<String>, // Audit rule key for correlation
    pub success: Option<bool>,
    pub exit_code: Option<i32>,
    // File operation fields
    pub path: Option<String>,
    pub inode: Option<u64>,
    pub mode: Option<u32>,
    pub ouid: Option<u32>, // Object UID
    pub ogid: Option<u32>, // Object GID
    // Network operation fields
    pub saddr: Option<String>, // Socket address
    pub family: Option<u16>,   // AF_INET, AF_INET6
    pub socktype: Option<u16>, // SOCK_STREAM, SOCK_DGRAM
    // Authentication fields
    pub acct: Option<String>,
    pub terminal: Option<String>,
    pub addr: Option<String>,
    pub res: Option<String>,
    // Raw fields for debugging
    pub raw_fields: HashMap<String, String>,
}

impl AuditRecord {
    /// Create a new audit record from raw field map
    pub fn from_fields(fields: HashMap<String, String>) -> Result<Self> {
        let timestamp = fields
            .get("time")
            .and_then(|t| t.parse::<f64>().ok())
            .map(|t| (t * 1000.0) as u64)
            .unwrap_or_else(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0)
            });

        Ok(Self {
            record_type: fields.get("type").cloned().unwrap_or_default(),
            timestamp,
            syscall: fields.get("syscall").cloned(),
            pid: fields.get("pid").and_then(|s| s.parse().ok()),
            ppid: fields.get("ppid").and_then(|s| s.parse().ok()),
            uid: fields.get("uid").and_then(|s| s.parse().ok()),
            gid: fields.get("gid").and_then(|s| s.parse().ok()),
            euid: fields.get("euid").and_then(|s| s.parse().ok()),
            egid: fields.get("egid").and_then(|s| s.parse().ok()),
            auid: fields.get("auid").and_then(|s| s.parse().ok()),
            comm: fields.get("comm").cloned(),
            exe: fields.get("exe").cloned(),
            cwd: fields.get("cwd").cloned(),
            args: extract_args(&fields),
            key: fields.get("key").cloned(),
            success: fields
                .get("success")
                .map(|s| s == "yes" || s == "1" || s == "true"),
            exit_code: fields.get("exit").and_then(|s| s.parse().ok()),
            path: fields.get("name").cloned(),
            inode: fields.get("inode").and_then(|s| s.parse().ok()),
            mode: fields.get("mode").and_then(|s| parse_octal(s)),
            ouid: fields.get("ouid").and_then(|s| s.parse().ok()),
            ogid: fields.get("ogid").and_then(|s| s.parse().ok()),
            saddr: fields.get("saddr").cloned(),
            family: fields.get("family").and_then(|s| s.parse().ok()),
            socktype: fields.get("socktype").and_then(|s| s.parse().ok()),
            acct: fields.get("acct").cloned(),
            terminal: fields.get("terminal").cloned(),
            addr: fields.get("addr").cloned(),
            res: fields.get("res").cloned(),
            raw_fields: fields,
        })
    }
}

/// Extract command line arguments from audit fields (a0, a1, a2, ...)
fn extract_args(fields: &HashMap<String, String>) -> Vec<String> {
    let mut args = Vec::new();
    let mut i = 0;
    loop {
        let key = format!("a{}", i);
        if let Some(arg) = fields.get(&key) {
            args.push(decode_hex_string(arg));
            i += 1;
        } else {
            break;
        }
    }
    args
}

/// Decode hex-encoded audit strings (e.g., "616263" -> "abc")
fn decode_hex_string(s: &str) -> String {
    if s.len() % 2 != 0 {
        return s.to_string();
    }
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect();
    String::from_utf8(bytes).unwrap_or_else(|_| s.to_string())
}

/// Parse octal mode string (e.g., "0644")
fn parse_octal(s: &str) -> Option<u32> {
    u32::from_str_radix(s.trim_start_matches("0o").trim_start_matches('0'), 8).ok()
}

/// Event normalizer that converts auditd records to TelemetryEvents
pub struct EventNormalizer {
    /// Cache for process names to avoid repeated lookups
    process_cache: HashMap<u32, String>,
}

impl EventNormalizer {
    pub fn new() -> Self {
        Self {
            process_cache: HashMap::new(),
        }
    }

    /// Normalize an audit record to a TelemetryEvent
    pub fn normalize(&mut self, record: AuditRecord) -> Result<Option<TelemetryEvent>> {
        match record.record_type.as_str() {
            "SYSCALL" => self.normalize_syscall(record),
            "PATH" => Ok(None), // PATH records are supplementary, merged in syscall handling
            "EXECVE" => Ok(None), // EXECVE records are supplementary
            "CWD" => Ok(None),  // CWD records are supplementary
            "USER_LOGIN" | "USER_AUTH" | "CRED_ACQ" => self.normalize_auth(record),
            "SOCKADDR" => Ok(None), // SOCKADDR records are supplementary
            _ => {
                debug!("Ignoring audit record type: {}", record.record_type);
                Ok(None)
            }
        }
    }

    /// Normalize SYSCALL-type records
    fn normalize_syscall(&mut self, record: AuditRecord) -> Result<Option<TelemetryEvent>> {
        let syscall = record.syscall.as_deref().unwrap_or("unknown");

        match syscall {
            "execve" | "execveat" => self.normalize_process_create(record),
            "open" | "openat" | "creat" => self.normalize_file_open(record),
            "unlink" | "unlinkat" => self.normalize_file_delete(record),
            "rename" | "renameat" | "renameat2" => self.normalize_file_rename(record),
            "connect" => self.normalize_network_connect(record),
            "bind" => self.normalize_network_bind(record),
            "accept" | "accept4" => self.normalize_network_accept(record),
            _ => {
                debug!("Ignoring syscall: {}", syscall);
                Ok(None)
            }
        }
    }

    /// Normalize process creation events (execve/execveat)
    fn normalize_process_create(&mut self, record: AuditRecord) -> Result<Option<TelemetryEvent>> {
        let pid = record.pid.ok_or_else(|| anyhow!("Missing PID"))?;
        let ppid = record.ppid.unwrap_or(0);
        let name = record.comm.clone().unwrap_or_else(|| "unknown".to_string());
        let path = record
            .exe
            .clone()
            .unwrap_or_else(|| format!("/proc/{}/exe", pid));
        let cmdline = record.args.join(" ");
        let user = resolve_username(record.auid.or(record.uid).unwrap_or(0));
        let is_elevated = record.euid.unwrap_or(record.uid.unwrap_or(1000)) == 0;

        // Cache process name for parent lookups
        self.process_cache.insert(pid, name.clone());

        let parent_name = record
            .ppid
            .and_then(|ppid| self.process_cache.get(&ppid).cloned())
            .or_else(|| read_process_name(ppid));
        let parent_path = record.ppid.map(|ppid| format!("/proc/{}/exe", ppid));

        let event = TelemetryEvent {
            event_id: Uuid::new_v4().to_string(),
            event_type: EventType::ProcessCreate,
            timestamp: record.timestamp,
            severity: if is_elevated {
                Severity::Medium
            } else {
                Severity::Info
            },
            payload: EventPayload::Process(ProcessEvent {
                pid,
                ppid,
                name: name.clone(),
                path: path.clone(),
                cmdline,
                user,
                sha256: vec![], // Computed separately by file analyzer
                entropy: 0.0,   // Computed separately
                is_elevated,
                parent_name,
                parent_path,
                is_signed: false, // Computed separately
                signer: None,
                start_time: record.timestamp,
                session_id: record.auid,
                integrity_level: None,
            }),
            detections: vec![],
            metadata: HashMap::new(),
        };

        Ok(Some(event))
    }

    /// Normalize file open events
    fn normalize_file_open(&mut self, record: AuditRecord) -> Result<Option<TelemetryEvent>> {
        let path = record.path.ok_or_else(|| anyhow!("Missing path"))?;
        let pid = record.pid.ok_or_else(|| anyhow!("Missing PID"))?;
        let process_name = record.comm.clone().unwrap_or_else(|| "unknown".to_string());
        let process_path = record
            .exe
            .clone()
            .unwrap_or_else(|| format!("/proc/{}/exe", pid));
        let user = resolve_username(record.auid.or(record.uid).unwrap_or(0));

        // Determine event type based on flags (from a0 argument or raw fields)
        let event_type = if record
            .raw_fields
            .get("a1")
            .map(|flags| flags.contains("O_CREAT"))
            .unwrap_or(false)
        {
            EventType::FileCreate
        } else {
            EventType::FileModify // Treat open as potential modification
        };

        let event = TelemetryEvent {
            event_id: Uuid::new_v4().to_string(),
            event_type,
            timestamp: record.timestamp,
            severity: Severity::Info,
            payload: EventPayload::File(FileEvent {
                path: path.clone(),
                operation: "open".to_string(),
                pid,
                process_name,
                process_path,
                user,
                sha256: None,
                md5: None,
                size: None,
                is_signed: None,
                signer: None,
                entropy: None,
                old_path: None,
            }),
            detections: vec![],
            metadata: HashMap::new(),
        };

        Ok(Some(event))
    }

    /// Normalize file delete events
    fn normalize_file_delete(&mut self, record: AuditRecord) -> Result<Option<TelemetryEvent>> {
        let path = record.path.ok_or_else(|| anyhow!("Missing path"))?;
        let pid = record.pid.ok_or_else(|| anyhow!("Missing PID"))?;
        let process_name = record.comm.clone().unwrap_or_else(|| "unknown".to_string());
        let process_path = record
            .exe
            .clone()
            .unwrap_or_else(|| format!("/proc/{}/exe", pid));
        let user = resolve_username(record.auid.or(record.uid).unwrap_or(0));

        let event = TelemetryEvent {
            event_id: Uuid::new_v4().to_string(),
            event_type: EventType::FileDelete,
            timestamp: record.timestamp,
            severity: Severity::Low,
            payload: EventPayload::File(FileEvent {
                path: path.clone(),
                operation: "delete".to_string(),
                pid,
                process_name,
                process_path,
                user,
                sha256: None,
                md5: None,
                size: None,
                is_signed: None,
                signer: None,
                entropy: None,
                old_path: None,
            }),
            detections: vec![],
            metadata: HashMap::new(),
        };

        Ok(Some(event))
    }

    /// Normalize file rename events
    fn normalize_file_rename(&mut self, record: AuditRecord) -> Result<Option<TelemetryEvent>> {
        let path = record.path.ok_or_else(|| anyhow!("Missing path"))?;
        let pid = record.pid.ok_or_else(|| anyhow!("Missing PID"))?;
        let process_name = record.comm.clone().unwrap_or_else(|| "unknown".to_string());
        let process_path = record
            .exe
            .clone()
            .unwrap_or_else(|| format!("/proc/{}/exe", pid));
        let user = resolve_username(record.auid.or(record.uid).unwrap_or(0));

        // Note: auditd doesn't provide both old/new paths in a single record
        // The old path would be in a0, new path in a1 (need EXECVE record correlation)
        let old_path = record.raw_fields.get("a0").map(|s| decode_hex_string(s));

        let event = TelemetryEvent {
            event_id: Uuid::new_v4().to_string(),
            event_type: EventType::FileRename,
            timestamp: record.timestamp,
            severity: Severity::Info,
            payload: EventPayload::File(FileEvent {
                path: path.clone(),
                operation: "rename".to_string(),
                pid,
                process_name,
                process_path,
                user,
                sha256: None,
                md5: None,
                size: None,
                is_signed: None,
                signer: None,
                entropy: None,
                old_path,
            }),
            detections: vec![],
            metadata: HashMap::new(),
        };

        Ok(Some(event))
    }

    /// Normalize network connect events
    fn normalize_network_connect(&mut self, record: AuditRecord) -> Result<Option<TelemetryEvent>> {
        let pid = record.pid.ok_or_else(|| anyhow!("Missing PID"))?;
        let process_name = record.comm.clone().unwrap_or_else(|| "unknown".to_string());
        let process_path = record
            .exe
            .clone()
            .unwrap_or_else(|| format!("/proc/{}/exe", pid));
        let user = resolve_username(record.auid.or(record.uid).unwrap_or(0));

        // Parse socket address from saddr field (supplementary SOCKADDR record)
        let (dest_ip, dest_port) = parse_sockaddr(record.saddr.as_deref())?;

        // Determine protocol from socket type
        let protocol = match record.socktype {
            Some(1) => "TCP".to_string(), // SOCK_STREAM
            Some(2) => "UDP".to_string(), // SOCK_DGRAM
            _ => "unknown".to_string(),
        };

        let mut network_event = NetworkEvent {
            pid,
            process_name,
            protocol,
            local_ip: "0.0.0.0".to_string(), // Local IP requires additional lookup
            local_port: 0,                   // Ephemeral port, requires additional lookup
            remote_ip: dest_ip,
            remote_port: dest_port,
            direction: "outbound".to_string(),
            bytes_sent: 0,
            bytes_received: 0,
            ..Default::default()
        };
        network_event.apply_common_enrichment();

        let event = TelemetryEvent {
            event_id: Uuid::new_v4().to_string(),
            event_type: EventType::NetworkConnect,
            timestamp: record.timestamp,
            severity: Severity::Info,
            payload: EventPayload::Network(network_event),
            detections: vec![],
            metadata: HashMap::new(),
        };

        Ok(Some(event))
    }

    /// Normalize network bind events
    fn normalize_network_bind(&mut self, record: AuditRecord) -> Result<Option<TelemetryEvent>> {
        let pid = record.pid.ok_or_else(|| anyhow!("Missing PID"))?;
        let process_name = record.comm.clone().unwrap_or_else(|| "unknown".to_string());
        let process_path = record
            .exe
            .clone()
            .unwrap_or_else(|| format!("/proc/{}/exe", pid));
        let user = resolve_username(record.auid.or(record.uid).unwrap_or(0));

        let (source_ip, source_port) = parse_sockaddr(record.saddr.as_deref())?;

        let protocol = match record.socktype {
            Some(1) => "TCP".to_string(),
            Some(2) => "UDP".to_string(),
            _ => "unknown".to_string(),
        };

        let mut network_event = NetworkEvent {
            pid,
            process_name,
            protocol,
            local_ip: source_ip,
            local_port: source_port,
            remote_ip: "0.0.0.0".to_string(),
            remote_port: 0,
            direction: "inbound".to_string(),
            bytes_sent: 0,
            bytes_received: 0,
            ..Default::default()
        };
        network_event.apply_common_enrichment();

        let event = TelemetryEvent {
            event_id: Uuid::new_v4().to_string(),
            event_type: EventType::NetworkListen,
            timestamp: record.timestamp,
            severity: Severity::Medium,
            payload: EventPayload::Network(network_event),
            detections: vec![],
            metadata: HashMap::new(),
        };

        Ok(Some(event))
    }

    /// Normalize network accept events
    fn normalize_network_accept(&mut self, record: AuditRecord) -> Result<Option<TelemetryEvent>> {
        // Accept events indicate an incoming connection was established
        self.normalize_network_bind(record)
    }

    /// Normalize authentication events
    fn normalize_auth(&mut self, record: AuditRecord) -> Result<Option<TelemetryEvent>> {
        let user = record.acct.clone().unwrap_or_else(|| "unknown".to_string());
        let success = record.res.as_ref().map(|r| r == "success").unwrap_or(false);
        let source_ip = record.addr.clone().unwrap_or_else(|| "local".to_string());

        let event_type = if success {
            EventType::AuthLogin
        } else {
            EventType::AuthFailed
        };

        // Create a minimal process event for auth (no dedicated auth event type)
        let event = TelemetryEvent {
            event_id: Uuid::new_v4().to_string(),
            event_type,
            timestamp: record.timestamp,
            severity: if success {
                Severity::Info
            } else {
                Severity::Medium
            },
            payload: EventPayload::Process(ProcessEvent {
                pid: record.pid.unwrap_or(0),
                ppid: record.ppid.unwrap_or(0),
                name: "login".to_string(),
                path: "/usr/bin/login".to_string(),
                cmdline: format!("user={} from={}", user, source_ip),
                user: user.clone(),
                sha256: vec![],
                entropy: 0.0,
                is_elevated: false,
                parent_name: None,
                parent_path: None,
                is_signed: false,
                signer: None,
                start_time: record.timestamp,
                session_id: record.auid,
                integrity_level: None,
            }),
            detections: vec![],
            metadata: [
                ("auth_success".to_string(), success.to_string()),
                ("source_ip".to_string(), source_ip),
            ]
            .iter()
            .cloned()
            .collect(),
        };

        Ok(Some(event))
    }
}

impl Default for EventNormalizer {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse socket address from audit saddr field
/// Format: "02001F907F0000010000000000000000" (hex-encoded sockaddr_in)
fn parse_sockaddr(saddr: Option<&str>) -> Result<(String, u16)> {
    let saddr = saddr.ok_or_else(|| anyhow!("Missing socket address"))?;
    if saddr.len() < 8 {
        return Err(anyhow!("Invalid socket address length"));
    }

    // First 2 bytes: address family (02 = AF_INET, 0a = AF_INET6)
    let family = u16::from_str_radix(&saddr[0..4], 16)
        .map_err(|e| anyhow!("Failed to parse address family: {}", e))?;

    match family {
        2 => {
            // AF_INET (IPv4)
            if saddr.len() < 16 {
                return Err(anyhow!("Truncated IPv4 socket address"));
            }
            // Next 2 bytes: port (big-endian)
            let port = u16::from_str_radix(&saddr[4..8], 16)
                .map_err(|e| anyhow!("Failed to parse port: {}", e))?;
            // Next 4 bytes: IPv4 address (4 octets)
            let ip_bytes: Vec<u8> = (8..16)
                .step_by(2)
                .filter_map(|i| u8::from_str_radix(&saddr[i..i + 2], 16).ok())
                .collect();
            if ip_bytes.len() != 4 {
                return Err(anyhow!("Invalid IPv4 address"));
            }
            let ip = format!(
                "{}.{}.{}.{}",
                ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]
            );
            Ok((ip, port))
        }
        10 => {
            // AF_INET6 (IPv6)
            if saddr.len() < 48 {
                return Err(anyhow!("Truncated IPv6 socket address"));
            }
            let port = u16::from_str_radix(&saddr[4..8], 16)
                .map_err(|e| anyhow!("Failed to parse port: {}", e))?;
            // Parse IPv6 address (next 16 bytes = 32 hex chars)
            let ip_str = &saddr[16..48]; // Skip port and flowinfo
            let ip = format!(
                "{}:{}:{}:{}:{}:{}:{}:{}",
                &ip_str[0..4],
                &ip_str[4..8],
                &ip_str[8..12],
                &ip_str[12..16],
                &ip_str[16..20],
                &ip_str[20..24],
                &ip_str[24..28],
                &ip_str[28..32]
            );
            Ok((ip, port))
        }
        _ => Err(anyhow!("Unsupported address family: {}", family)),
    }
}

/// Resolve UID to username
fn resolve_username(uid: u32) -> String {
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
            for line in passwd.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 3 {
                    if let Ok(line_uid) = parts[2].parse::<u32>() {
                        if line_uid == uid {
                            return parts[0].to_string();
                        }
                    }
                }
            }
        }
    }
    format!("{}", uid)
}

/// Read process name from /proc/[pid]/comm
fn read_process_name(pid: u32) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        fs::read_to_string(format!("/proc/{}/comm", pid))
            .ok()
            .map(|s| s.trim().to_string())
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sockaddr_ipv4() {
        // AF_INET (2), port 8080 (0x1F90), IP 127.0.0.1
        let saddr = "02001F907F0000010000000000000000";
        let (ip, port) = parse_sockaddr(Some(saddr)).unwrap();
        assert_eq!(ip, "127.0.0.1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_decode_hex_string() {
        assert_eq!(decode_hex_string("48656c6c6f"), "Hello");
        assert_eq!(decode_hex_string("2f62696e2f6c73"), "/bin/ls");
    }

    #[test]
    fn test_parse_octal() {
        assert_eq!(parse_octal("0644"), Some(0o644));
        assert_eq!(parse_octal("644"), Some(0o644));
        assert_eq!(parse_octal("0o755"), Some(0o755));
    }

    #[test]
    fn test_extract_args() {
        let mut fields = HashMap::new();
        fields.insert("a0".to_string(), "2f62696e2f6c73".to_string()); // /bin/ls
        fields.insert("a1".to_string(), "2d6c61".to_string()); // -la
        fields.insert("a2".to_string(), "2f746d70".to_string()); // /tmp

        let args = extract_args(&fields);
        assert_eq!(args, vec!["/bin/ls", "-la", "/tmp"]);
    }
}
