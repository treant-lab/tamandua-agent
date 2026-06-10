//! Lateral Movement Detection Collector
//!
//! Detects lateral movement techniques including:
//! - Remote execution (PsExec, WMI, PowerShell remoting, WinRM, SSH, RDP)
//! - Remote service operations (service creation, scheduled tasks, registry)
//! - SMB activity (admin shares, named pipes)
//! - Authentication events (logon types, NTLM, Kerberos)
//! - Process ancestry analysis (services.exe, wmiprvse.exe, wsmprovhost.exe)
//! - Network indicators (internal scanning, port sweeps)
//!
//! MITRE ATT&CK:
//! - T1021: Remote Services
//!   - T1021.001: Remote Desktop Protocol
//!   - T1021.002: SMB/Windows Admin Shares
//!   - T1021.003: Distributed Component Object Model
//!   - T1021.004: SSH
//!   - T1021.006: Windows Remote Management
//! - T1570: Lateral Tool Transfer
//! - T1072: Software Deployment Tools
//! - T1047: Windows Management Instrumentation
//! - T1053: Scheduled Task/Job

// Lateral movement detector. EventLog reader constants and scaffolded
// intermediate assignments are intentionally kept for upcoming Windows
// Security event log integrations.
#![allow(dead_code, unused_variables, unused_assignments)]

use super::{
    Detection, DetectionType, EventPayload, EventType, NetworkEvent, Severity, TelemetryEvent,
};
use crate::config::AgentConfig;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};

/// Lateral movement event types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LateralMovementType {
    /// PsExec/PaExec execution
    PsExec,
    /// WMI remote execution
    WmiExecution,
    /// PowerShell remoting (Enter-PSSession, Invoke-Command)
    PowerShellRemoting,
    /// WinRM connection
    WinRM,
    /// SSH lateral movement
    Ssh,
    /// RDP connection
    Rdp,
    /// DCOM execution
    Dcom,
    /// Remote service creation
    RemoteService,
    /// Remote scheduled task
    RemoteScheduledTask,
    /// Remote registry modification
    RemoteRegistry,
    /// Admin share access (C$, ADMIN$, IPC$)
    AdminShareAccess,
    /// SMB file operation
    SmbFileOperation,
    /// SMB named pipe activity
    SmbNamedPipe,
    /// Network logon (Type 3)
    NetworkLogon,
    /// Remote interactive logon (Type 10)
    RemoteInteractiveLogon,
    /// NTLM authentication to unusual host
    NtlmAuthentication,
    /// Kerberos TGS request for unusual service
    KerberosTgs,
    /// Suspicious process ancestry
    SuspiciousAncestry,
    /// Internal network scanning
    InternalScanning,
    /// Port sweep detection
    PortSweep,
    /// Ansible/Puppet/Chef execution
    ConfigManagement,
    /// Generic remote command execution
    RemoteCommand,
    /// Pass-the-Hash attack indicator
    PassTheHash,
    /// Pass-the-Ticket attack indicator
    PassTheTicket,
    /// NTLM relay attack indicator
    NtlmRelay,
    /// Impacket tool usage
    ImpacketTool,
    /// rsh/rexec remote shell (Linux)
    RemoteShell,
    /// CrackMapExec/NetExec usage
    CrackMapExec,
    /// Cobalt Strike beacon lateral movement
    CobaltStrikeLateral,
}

impl LateralMovementType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PsExec => "psexec",
            Self::WmiExecution => "wmi_execution",
            Self::PowerShellRemoting => "powershell_remoting",
            Self::WinRM => "winrm",
            Self::Ssh => "ssh",
            Self::Rdp => "rdp",
            Self::Dcom => "dcom",
            Self::RemoteService => "remote_service",
            Self::RemoteScheduledTask => "remote_scheduled_task",
            Self::RemoteRegistry => "remote_registry",
            Self::AdminShareAccess => "admin_share_access",
            Self::SmbFileOperation => "smb_file_operation",
            Self::SmbNamedPipe => "smb_named_pipe",
            Self::NetworkLogon => "network_logon",
            Self::RemoteInteractiveLogon => "remote_interactive_logon",
            Self::NtlmAuthentication => "ntlm_authentication",
            Self::KerberosTgs => "kerberos_tgs",
            Self::SuspiciousAncestry => "suspicious_ancestry",
            Self::InternalScanning => "internal_scanning",
            Self::PortSweep => "port_sweep",
            Self::ConfigManagement => "config_management",
            Self::RemoteCommand => "remote_command",
            Self::PassTheHash => "pass_the_hash",
            Self::PassTheTicket => "pass_the_ticket",
            Self::NtlmRelay => "ntlm_relay",
            Self::ImpacketTool => "impacket_tool",
            Self::RemoteShell => "remote_shell",
            Self::CrackMapExec => "crackmapexec",
            Self::CobaltStrikeLateral => "cobalt_strike_lateral",
        }
    }

    pub fn mitre_technique(&self) -> &'static str {
        match self {
            Self::PsExec => "T1021.002",
            Self::WmiExecution => "T1047",
            Self::PowerShellRemoting => "T1021.006",
            Self::WinRM => "T1021.006",
            Self::Ssh => "T1021.004",
            Self::Rdp => "T1021.001",
            Self::Dcom => "T1021.003",
            Self::RemoteService => "T1021.002",
            Self::RemoteScheduledTask => "T1053",
            Self::RemoteRegistry => "T1021.002",
            Self::AdminShareAccess => "T1021.002",
            Self::SmbFileOperation => "T1570",
            Self::SmbNamedPipe => "T1021.002",
            Self::NetworkLogon => "T1021",
            Self::RemoteInteractiveLogon => "T1021.001",
            Self::NtlmAuthentication => "T1021",
            Self::KerberosTgs => "T1021",
            Self::SuspiciousAncestry => "T1021",
            Self::InternalScanning => "T1046",
            Self::PortSweep => "T1046",
            Self::ConfigManagement => "T1072",
            Self::RemoteCommand => "T1021",
            Self::PassTheHash => "T1550.002",
            Self::PassTheTicket => "T1550.003",
            Self::NtlmRelay => "T1557.001",
            Self::ImpacketTool => "T1021.002",
            Self::RemoteShell => "T1021.004",
            Self::CrackMapExec => "T1021.002",
            Self::CobaltStrikeLateral => "T1021.002",
        }
    }

    pub fn mitre_tactics(&self) -> Vec<&'static str> {
        match self {
            Self::InternalScanning | Self::PortSweep => vec!["discovery"],
            Self::SmbFileOperation => vec!["lateral-movement", "collection"],
            Self::PassTheHash | Self::PassTheTicket => {
                vec!["credential-access", "lateral-movement"]
            }
            Self::NtlmRelay => vec!["credential-access", "lateral-movement"],
            _ => vec!["lateral-movement"],
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Self::PsExec | Self::WmiExecution | Self::PowerShellRemoting => Severity::High,
            Self::RemoteService | Self::RemoteScheduledTask => Severity::High,
            Self::AdminShareAccess | Self::SmbNamedPipe => Severity::High,
            Self::InternalScanning | Self::PortSweep => Severity::High,
            Self::SuspiciousAncestry => Severity::High,
            Self::PassTheHash | Self::PassTheTicket => Severity::Critical,
            Self::NtlmRelay => Severity::Critical,
            Self::ImpacketTool | Self::CrackMapExec => Severity::Critical,
            Self::CobaltStrikeLateral => Severity::Critical,
            Self::RemoteShell => Severity::High,
            Self::Rdp | Self::Ssh | Self::WinRM => Severity::Medium,
            Self::NetworkLogon | Self::RemoteInteractiveLogon => Severity::Medium,
            Self::NtlmAuthentication | Self::KerberosTgs => Severity::Medium,
            Self::ConfigManagement => Severity::Low,
            _ => Severity::Medium,
        }
    }
}

/// Lateral movement detection event
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LateralMovementEvent {
    /// Type of lateral movement detected
    pub movement_type: LateralMovementType,
    /// Source process ID
    pub source_pid: u32,
    /// Source process name
    pub source_name: String,
    /// Source process path
    pub source_path: String,
    /// Source process command line
    pub source_cmdline: String,
    /// Source user
    pub source_user: String,
    /// Target host (IP or hostname)
    pub target_host: Option<String>,
    /// Target port
    pub target_port: Option<u16>,
    /// Target user (if applicable)
    pub target_user: Option<String>,
    /// Target share/resource (if applicable)
    pub target_resource: Option<String>,
    /// Additional details
    pub details: String,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
}

/// Connection tracking for scanning detection
#[derive(Debug, Clone)]
struct ConnectionTracker {
    /// Connections per source IP -> set of (dest_ip, port)
    connections: HashMap<String, HashSet<(String, u16)>>,
    /// Timestamp of first connection per source
    first_seen: HashMap<String, u64>,
    /// Count of unique destinations per source
    dest_count: HashMap<String, usize>,
}

impl ConnectionTracker {
    fn new() -> Self {
        Self {
            connections: HashMap::new(),
            first_seen: HashMap::new(),
            dest_count: HashMap::new(),
        }
    }

    fn add_connection(
        &mut self,
        source: &str,
        dest: &str,
        port: u16,
    ) -> Option<LateralMovementType> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let entry = self.connections.entry(source.to_string()).or_default();
        let key = (dest.to_string(), port);

        if entry.insert(key) {
            // New unique connection
            if !self.first_seen.contains_key(source) {
                self.first_seen.insert(source.to_string(), now);
            }

            let unique_dests: HashSet<_> = entry.iter().map(|(d, _)| d.clone()).collect();
            self.dest_count
                .insert(source.to_string(), unique_dests.len());

            // Check for scanning patterns
            let first_seen = self.first_seen.get(source).unwrap_or(&now);
            let time_window = now - first_seen;

            // Port sweep: many connections to same host on different ports
            let ports_to_single_dest: Vec<_> = entry
                .iter()
                .filter(|(d, _)| d == dest)
                .map(|(_, p)| *p)
                .collect();

            if ports_to_single_dest.len() >= 10 && time_window < 60 {
                return Some(LateralMovementType::PortSweep);
            }

            // Internal scanning: connections to many internal hosts
            if unique_dests.len() >= 20 && time_window < 300 {
                // Check if destinations are internal IPs
                let internal_count = unique_dests
                    .iter()
                    .filter(|ip| Self::is_internal_ip(ip))
                    .count();

                if internal_count >= 15 {
                    return Some(LateralMovementType::InternalScanning);
                }
            }
        }

        None
    }

    fn is_internal_ip(ip: &str) -> bool {
        if let Ok(addr) = ip.parse::<IpAddr>() {
            match addr {
                IpAddr::V4(v4) => {
                    let octets = v4.octets();
                    // 10.0.0.0/8
                    octets[0] == 10
                        // 172.16.0.0/12
                        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                        // 192.168.0.0/16
                        || (octets[0] == 192 && octets[1] == 168)
                        // 127.0.0.0/8 (loopback)
                        || octets[0] == 127
                }
                IpAddr::V6(v6) => {
                    v6.is_loopback() || v6.segments()[0] == 0xfe80 // link-local
                }
            }
        } else {
            false
        }
    }

    fn cleanup_old(&mut self, max_age_secs: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let old_sources: Vec<_> = self
            .first_seen
            .iter()
            .filter(|(_, ts)| now - *ts > max_age_secs)
            .map(|(k, _)| k.clone())
            .collect();

        for source in old_sources {
            self.connections.remove(&source);
            self.first_seen.remove(&source);
            self.dest_count.remove(&source);
        }
    }
}

/// Lateral movement collector
pub struct LateralMovementCollector {
    #[allow(dead_code)]
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    #[allow(dead_code)]
    event_tx: mpsc::Sender<TelemetryEvent>,
}

impl LateralMovementCollector {
    /// Create a new lateral movement collector
    pub fn new(config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(1000);

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

        #[cfg(target_os = "linux")]
        {
            let tx_clone = tx.clone();
            let config_clone = config.clone();
            tokio::spawn(async move {
                Self::linux_monitor_loop(tx_clone, config_clone).await;
            });
        }

        #[cfg(target_os = "macos")]
        {
            let tx_clone = tx.clone();
            let config_clone = config.clone();
            tokio::spawn(async move {
                Self::macos_monitor_loop(tx_clone, config_clone).await;
            });
        }

        // Start network scanning detection (cross-platform)
        let tx_network = tx.clone();
        tokio::spawn(async move {
            Self::network_scanning_monitor(tx_network).await;
        });

        collector
    }

    /// Get next event from collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }

    /// Create telemetry event from lateral movement detection
    fn create_lateral_movement_event(lm: &LateralMovementEvent) -> TelemetryEvent {
        let mut event = TelemetryEvent::new(
            EventType::LateralMovement,
            lm.movement_type.severity(),
            EventPayload::Network(NetworkEvent {
                pid: lm.source_pid,
                process_name: lm.source_name.clone(),
                local_ip: String::new(),
                local_port: 0,
                remote_ip: lm.target_host.clone().unwrap_or_default(),
                remote_port: lm.target_port.unwrap_or(0),
                protocol: "tcp".to_string(),
                direction: "outbound".to_string(),
                bytes_sent: 0,
                bytes_received: 0,
                ..Default::default()
            }),
        );

        // Add detection
        event.add_detection(Detection {
            detection_type: DetectionType::LateralMovement,
            rule_name: format!("lateral_movement_{}", lm.movement_type.as_str()),
            confidence: lm.confidence,
            description: lm.details.clone(),
            mitre_tactics: lm
                .movement_type
                .mitre_tactics()
                .iter()
                .map(|s| s.to_string())
                .collect(),
            mitre_techniques: vec![lm.movement_type.mitre_technique().to_string()],
        });

        // Add metadata
        event.metadata.insert(
            "lateral_movement_type".to_string(),
            lm.movement_type.as_str().to_string(),
        );
        event
            .metadata
            .insert("source_pid".to_string(), lm.source_pid.to_string());
        event
            .metadata
            .insert("source_name".to_string(), lm.source_name.clone());
        event
            .metadata
            .insert("source_path".to_string(), lm.source_path.clone());
        event
            .metadata
            .insert("source_cmdline".to_string(), lm.source_cmdline.clone());
        event
            .metadata
            .insert("source_user".to_string(), lm.source_user.clone());

        if let Some(host) = &lm.target_host {
            event
                .metadata
                .insert("target_host".to_string(), host.clone());
        }
        if let Some(port) = lm.target_port {
            event
                .metadata
                .insert("target_port".to_string(), port.to_string());
        }
        if let Some(user) = &lm.target_user {
            event
                .metadata
                .insert("target_user".to_string(), user.clone());
        }
        if let Some(resource) = &lm.target_resource {
            event
                .metadata
                .insert("target_resource".to_string(), resource.clone());
        }

        event
    }

    // ==================== Network Scanning Monitor (Cross-Platform) ====================
    async fn network_scanning_monitor(tx: mpsc::Sender<TelemetryEvent>) {
        info!("Starting network scanning detection monitor");

        let tracker = Arc::new(Mutex::new(ConnectionTracker::new()));

        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
        let mut cleanup_counter = 0u32;

        loop {
            interval.tick().await;

            // Get current connections
            let connections = Self::get_current_connections().await;

            let mut tracker_guard = tracker.lock().await;

            for (source_ip, dest_ip, port, pid, process_name) in connections {
                if let Some(scan_type) = tracker_guard.add_connection(&source_ip, &dest_ip, port) {
                    let lm_event = LateralMovementEvent {
                        movement_type: scan_type,
                        source_pid: pid,
                        source_name: process_name.clone(),
                        source_path: String::new(),
                        source_cmdline: String::new(),
                        source_user: String::new(),
                        target_host: Some(dest_ip.clone()),
                        target_port: Some(port),
                        target_user: None,
                        target_resource: None,
                        details: match scan_type {
                            LateralMovementType::PortSweep => {
                                format!(
                                    "Port sweep detected: {} scanning multiple ports on {}",
                                    process_name, dest_ip
                                )
                            }
                            LateralMovementType::InternalScanning => {
                                format!(
                                    "Internal network scanning detected from {} ({}) to multiple internal hosts",
                                    source_ip, process_name
                                )
                            }
                            _ => format!("Network scanning activity detected"),
                        },
                        confidence: 0.85,
                    };

                    let event = Self::create_lateral_movement_event(&lm_event);
                    if tx.send(event).await.is_err() {
                        warn!("Event channel closed");
                        return;
                    }
                }
            }

            // Cleanup old tracking data every 60 iterations (5 minutes)
            cleanup_counter += 1;
            if cleanup_counter >= 60 {
                tracker_guard.cleanup_old(600); // 10 minute window
                cleanup_counter = 0;
            }
        }
    }

    async fn get_current_connections() -> Vec<(String, String, u16, u32, String)> {
        // Returns: (source_ip, dest_ip, dest_port, pid, process_name)
        let mut results = Vec::new();

        #[cfg(target_os = "linux")]
        {
            if let Ok(content) = tokio::fs::read_to_string("/proc/net/tcp").await {
                for line in content.lines().skip(1) {
                    if let Some((local, remote, pid, name)) =
                        Self::parse_linux_connection(line).await
                    {
                        results.push((local, remote.0, remote.1, pid, name));
                    }
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            results = Self::get_windows_connections().await;
        }

        #[cfg(target_os = "macos")]
        {
            results = Self::get_macos_connections().await;
        }

        results
    }

    #[cfg(target_os = "linux")]
    async fn parse_linux_connection(line: &str) -> Option<(String, (String, u16), u32, String)> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            return None;
        }

        let local = parts[1];
        let remote = parts[2];
        let inode: u64 = parts[9].parse().ok()?;

        let (local_ip, _) = Self::parse_hex_address(local)?;
        let (remote_ip, remote_port) = Self::parse_hex_address(remote)?;

        // Skip localhost and listening sockets
        if remote_port == 0 || remote_ip == "0.0.0.0" || remote_ip == "127.0.0.1" {
            return None;
        }

        // Get PID from inode (simplified - full implementation would scan /proc/*/fd)
        let (pid, name) = Self::get_process_from_inode(inode).await;

        Some((local_ip, (remote_ip, remote_port), pid, name))
    }

    #[cfg(target_os = "linux")]
    fn parse_hex_address(hex: &str) -> Option<(String, u16)> {
        let parts: Vec<&str> = hex.split(':').collect();
        if parts.len() != 2 {
            return None;
        }

        let ip_hex = parts[0];
        let port_hex = parts[1];

        if ip_hex.len() == 8 {
            let ip = u32::from_str_radix(ip_hex, 16).ok()?;
            let ip = format!(
                "{}.{}.{}.{}",
                ip & 0xff,
                (ip >> 8) & 0xff,
                (ip >> 16) & 0xff,
                (ip >> 24) & 0xff
            );

            let port = u16::from_str_radix(port_hex, 16).ok()?;
            Some((ip, port))
        } else {
            None
        }
    }

    #[cfg(target_os = "linux")]
    async fn get_process_from_inode(inode: u64) -> (u32, String) {
        // Scan /proc for socket inodes
        if let Ok(mut entries) = tokio::fs::read_dir("/proc").await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();

                if let Ok(pid) = name_str.parse::<u32>() {
                    let fd_path = format!("/proc/{}/fd", pid);

                    if let Ok(mut fd_entries) = tokio::fs::read_dir(&fd_path).await {
                        while let Ok(Some(fd_entry)) = fd_entries.next_entry().await {
                            if let Ok(target) = tokio::fs::read_link(fd_entry.path()).await {
                                let target_str = target.to_string_lossy();
                                if target_str.contains(&format!("socket:[{}]", inode)) {
                                    let comm =
                                        tokio::fs::read_to_string(format!("/proc/{}/comm", pid))
                                            .await
                                            .map(|s| s.trim().to_string())
                                            .unwrap_or_else(|_| "unknown".to_string());
                                    return (pid, comm);
                                }
                            }
                        }
                    }
                }
            }
        }

        (0, "unknown".to_string())
    }

    // ==================== Windows Implementation ====================
    #[cfg(target_os = "windows")]
    async fn windows_monitor_loop(tx: mpsc::Sender<TelemetryEvent>, _config: AgentConfig) {
        info!("Starting Windows lateral movement monitor");

        // Start multiple detection tasks
        let tx_process = tx.clone();
        tokio::spawn(async move {
            Self::windows_process_monitor(tx_process).await;
        });

        let tx_smb = tx.clone();
        tokio::spawn(async move {
            Self::windows_smb_monitor(tx_smb).await;
        });

        let tx_auth = tx.clone();
        tokio::spawn(async move {
            Self::windows_auth_monitor(tx_auth).await;
        });

        // Keep the main loop alive
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
        }
    }

    #[cfg(target_os = "windows")]
    async fn windows_process_monitor(tx: mpsc::Sender<TelemetryEvent>) {
        use sysinfo::{ProcessRefreshKind, System};

        info!("Starting Windows process-based lateral movement detection");

        let mut system = System::new_all();
        let mut known_pids: HashSet<u32> = HashSet::new();

        // Initialize known PIDs
        system.refresh_processes_specifics(ProcessRefreshKind::everything());
        for (pid, _) in system.processes() {
            known_pids.insert(pid.as_u32());
        }

        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(500));

        loop {
            interval.tick().await;

            system.refresh_processes_specifics(ProcessRefreshKind::everything());

            let current_pids: HashSet<u32> =
                system.processes().keys().map(|p| p.as_u32()).collect();

            // Check new processes for lateral movement indicators
            for pid in current_pids.difference(&known_pids) {
                if let Some(process) = system.process(sysinfo::Pid::from_u32(*pid)) {
                    let name = process.name().to_string().to_lowercase();
                    let cmdline = process
                        .cmd()
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                        .join(" ")
                        .to_lowercase();
                    let path = process
                        .exe()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_default();
                    let parent_pid = process.parent().map(|p| p.as_u32()).unwrap_or(0);

                    // Get parent name
                    let parent_name =
                        if let Some(parent) = system.process(sysinfo::Pid::from_u32(parent_pid)) {
                            parent.name().to_string().to_lowercase()
                        } else {
                            String::new()
                        };

                    // Detect various lateral movement patterns
                    if let Some(lm_event) = Self::detect_windows_lateral_movement(
                        *pid,
                        &name,
                        &cmdline,
                        &path,
                        &parent_name,
                        parent_pid,
                    ) {
                        let event = Self::create_lateral_movement_event(&lm_event);
                        if tx.send(event).await.is_err() {
                            warn!("Event channel closed");
                            return;
                        }
                    }
                }
            }

            known_pids = current_pids;
        }
    }

    #[cfg(target_os = "windows")]
    fn detect_windows_lateral_movement(
        pid: u32,
        name: &str,
        cmdline: &str,
        path: &str,
        parent_name: &str,
        _parent_pid: u32,
    ) -> Option<LateralMovementEvent> {
        // PsExec/PaExec detection
        if name.contains("psexe") || name.contains("paexe") {
            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::PsExec,
                source_pid: pid,
                source_name: name.to_string(),
                source_path: path.to_string(),
                source_cmdline: cmdline.to_string(),
                source_user: String::new(),
                target_host: Self::extract_target_host(cmdline),
                target_port: Some(445),
                target_user: None,
                target_resource: None,
                details: format!("PsExec execution detected: {}", cmdline),
                confidence: 0.95,
            });
        }

        // PSEXESVC service (server-side PsExec indicator)
        if name == "psexesvc.exe" || name == "paexesvc.exe" {
            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::PsExec,
                source_pid: pid,
                source_name: name.to_string(),
                source_path: path.to_string(),
                source_cmdline: cmdline.to_string(),
                source_user: String::new(),
                target_host: None,
                target_port: None,
                target_user: None,
                target_resource: None,
                details: "PsExec service detected - this host received a remote PsExec connection"
                    .to_string(),
                confidence: 0.95,
            });
        }

        // WMI remote execution
        if (name == "wmic.exe" && cmdline.contains("/node:"))
            || (name == "wmiprvse.exe" && parent_name == "svchost.exe")
        {
            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::WmiExecution,
                source_pid: pid,
                source_name: name.to_string(),
                source_path: path.to_string(),
                source_cmdline: cmdline.to_string(),
                source_user: String::new(),
                target_host: Self::extract_wmi_target(cmdline),
                target_port: Some(135),
                target_user: None,
                target_resource: None,
                details: format!("WMI remote execution detected: {}", cmdline),
                confidence: 0.90,
            });
        }

        // PowerShell remoting
        if name == "powershell.exe" || name == "pwsh.exe" {
            if cmdline.contains("enter-pssession")
                || cmdline.contains("invoke-command")
                || cmdline.contains("-computername")
                || cmdline.contains("new-pssession")
            {
                return Some(LateralMovementEvent {
                    movement_type: LateralMovementType::PowerShellRemoting,
                    source_pid: pid,
                    source_name: name.to_string(),
                    source_path: path.to_string(),
                    source_cmdline: cmdline.to_string(),
                    source_user: String::new(),
                    target_host: Self::extract_ps_target(cmdline),
                    target_port: Some(5985),
                    target_user: None,
                    target_resource: None,
                    details: format!("PowerShell remoting detected: {}", cmdline),
                    confidence: 0.90,
                });
            }
        }

        // WinRM provider host (server-side PS remoting indicator)
        if name == "wsmprovhost.exe" {
            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::PowerShellRemoting,
                source_pid: pid,
                source_name: name.to_string(),
                source_path: path.to_string(),
                source_cmdline: cmdline.to_string(),
                source_user: String::new(),
                target_host: None,
                target_port: None,
                target_user: None,
                target_resource: None,
                details: "WinRM session host detected - this host received a remote PS connection"
                    .to_string(),
                confidence: 0.85,
            });
        }

        // WinRM client
        if name == "winrs.exe" || (name == "cmd.exe" && cmdline.contains("winrs")) {
            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::WinRM,
                source_pid: pid,
                source_name: name.to_string(),
                source_path: path.to_string(),
                source_cmdline: cmdline.to_string(),
                source_user: String::new(),
                target_host: Self::extract_target_host(cmdline),
                target_port: Some(5985),
                target_user: None,
                target_resource: None,
                details: format!("WinRM execution detected: {}", cmdline),
                confidence: 0.90,
            });
        }

        // RDP client (mstsc.exe)
        if name == "mstsc.exe" {
            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::Rdp,
                source_pid: pid,
                source_name: name.to_string(),
                source_path: path.to_string(),
                source_cmdline: cmdline.to_string(),
                source_user: String::new(),
                target_host: Self::extract_rdp_target(cmdline),
                target_port: Some(3389),
                target_user: None,
                target_resource: None,
                details: format!("RDP client launched: {}", cmdline),
                confidence: 0.70,
            });
        }

        // Remote scheduled task creation
        if name == "schtasks.exe" && (cmdline.contains("/s ") || cmdline.contains("/s:")) {
            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::RemoteScheduledTask,
                source_pid: pid,
                source_name: name.to_string(),
                source_path: path.to_string(),
                source_cmdline: cmdline.to_string(),
                source_user: String::new(),
                target_host: Self::extract_schtasks_target(cmdline),
                target_port: Some(135),
                target_user: None,
                target_resource: None,
                details: format!("Remote scheduled task creation detected: {}", cmdline),
                confidence: 0.90,
            });
        }

        // Remote service creation
        if name == "sc.exe" && cmdline.contains("\\\\") {
            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::RemoteService,
                source_pid: pid,
                source_name: name.to_string(),
                source_path: path.to_string(),
                source_cmdline: cmdline.to_string(),
                source_user: String::new(),
                target_host: Self::extract_unc_target(cmdline),
                target_port: Some(445),
                target_user: None,
                target_resource: None,
                details: format!("Remote service operation detected: {}", cmdline),
                confidence: 0.90,
            });
        }

        // Remote registry
        if name == "reg.exe" && cmdline.contains("\\\\") {
            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::RemoteRegistry,
                source_pid: pid,
                source_name: name.to_string(),
                source_path: path.to_string(),
                source_cmdline: cmdline.to_string(),
                source_user: String::new(),
                target_host: Self::extract_unc_target(cmdline),
                target_port: Some(445),
                target_user: None,
                target_resource: None,
                details: format!("Remote registry operation detected: {}", cmdline),
                confidence: 0.85,
            });
        }

        // Net use to admin shares
        if name == "net.exe" || name == "net1.exe" {
            if cmdline.contains("\\\\")
                && (cmdline.contains("c$")
                    || cmdline.contains("admin$")
                    || cmdline.contains("ipc$"))
            {
                return Some(LateralMovementEvent {
                    movement_type: LateralMovementType::AdminShareAccess,
                    source_pid: pid,
                    source_name: name.to_string(),
                    source_path: path.to_string(),
                    source_cmdline: cmdline.to_string(),
                    source_user: String::new(),
                    target_host: Self::extract_unc_target(cmdline),
                    target_port: Some(445),
                    target_user: None,
                    target_resource: Self::extract_share_name(cmdline),
                    details: format!("Admin share access detected: {}", cmdline),
                    confidence: 0.90,
                });
            }
        }

        // Suspicious parent-child relationships
        // Services.exe spawning unusual children
        if parent_name == "services.exe" {
            let suspicious_children = [
                "cmd.exe",
                "powershell.exe",
                "pwsh.exe",
                "wscript.exe",
                "cscript.exe",
                "mshta.exe",
                "rundll32.exe",
            ];

            if suspicious_children.iter().any(|c| name.contains(c)) {
                return Some(LateralMovementEvent {
                    movement_type: LateralMovementType::SuspiciousAncestry,
                    source_pid: pid,
                    source_name: name.to_string(),
                    source_path: path.to_string(),
                    source_cmdline: cmdline.to_string(),
                    source_user: String::new(),
                    target_host: None,
                    target_port: None,
                    target_user: None,
                    target_resource: None,
                    details: format!(
                        "Suspicious process ancestry: {} spawned by services.exe (possible remote execution)",
                        name
                    ),
                    confidence: 0.85,
                });
            }
        }

        // wmiprvse.exe spawning suspicious children
        if parent_name == "wmiprvse.exe" {
            let suspicious_children = [
                "cmd.exe",
                "powershell.exe",
                "pwsh.exe",
                "wscript.exe",
                "cscript.exe",
                "mshta.exe",
            ];

            if suspicious_children.iter().any(|c| name.contains(c)) {
                return Some(LateralMovementEvent {
                    movement_type: LateralMovementType::WmiExecution,
                    source_pid: pid,
                    source_name: name.to_string(),
                    source_path: path.to_string(),
                    source_cmdline: cmdline.to_string(),
                    source_user: String::new(),
                    target_host: None,
                    target_port: None,
                    target_user: None,
                    target_resource: None,
                    details: format!(
                        "WMI-based execution detected: {} spawned by wmiprvse.exe",
                        name
                    ),
                    confidence: 0.90,
                });
            }
        }

        // ==================== Pass-the-Hash Detection ====================
        // Detect sekurlsa::pth patterns from mimikatz
        if cmdline.contains("sekurlsa::pth") || cmdline.contains("sekurlsa::logonpasswords") {
            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::PassTheHash,
                source_pid: pid,
                source_name: name.to_string(),
                source_path: path.to_string(),
                source_cmdline: cmdline.to_string(),
                source_user: String::new(),
                target_host: None,
                target_port: None,
                target_user: None,
                target_resource: None,
                details: format!("Pass-the-Hash attack detected via mimikatz: {}", cmdline),
                confidence: 0.98,
            });
        }

        // Detect runas with /netonly flag (common PtH technique)
        if name == "runas.exe" && cmdline.contains("/netonly") {
            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::PassTheHash,
                source_pid: pid,
                source_name: name.to_string(),
                source_path: path.to_string(),
                source_cmdline: cmdline.to_string(),
                source_user: String::new(),
                target_host: None,
                target_port: None,
                target_user: None,
                target_resource: None,
                details: format!("Potential Pass-the-Hash via runas /netonly: {}", cmdline),
                confidence: 0.75,
            });
        }

        // ==================== Pass-the-Ticket Detection ====================
        // Detect kerberos::ptt from mimikatz or rubeus
        if cmdline.contains("kerberos::ptt")
            || cmdline.contains("kerberos::golden")
            || cmdline.contains("ptt /ticket:")
            || cmdline.contains("asktgt")
            || cmdline.contains("asktgs")
        {
            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::PassTheTicket,
                source_pid: pid,
                source_name: name.to_string(),
                source_path: path.to_string(),
                source_cmdline: cmdline.to_string(),
                source_user: String::new(),
                target_host: None,
                target_port: None,
                target_user: None,
                target_resource: None,
                details: format!("Pass-the-Ticket attack detected: {}", cmdline),
                confidence: 0.95,
            });
        }

        // ==================== Impacket Tools Detection ====================
        // Detect common Impacket tool patterns
        let impacket_indicators = [
            "wmiexec",
            "smbexec",
            "psexec.py",
            "atexec",
            "dcomexec",
            "secretsdump",
            "ntlmrelayx",
            "responder",
            "getST",
            "getTGT",
            "GetUserSPNs",
            "GetNPUsers",
        ];

        if impacket_indicators
            .iter()
            .any(|i| cmdline.contains(i) || name.contains(i))
        {
            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::ImpacketTool,
                source_pid: pid,
                source_name: name.to_string(),
                source_path: path.to_string(),
                source_cmdline: cmdline.to_string(),
                source_user: String::new(),
                target_host: Self::extract_target_host(cmdline),
                target_port: Some(445),
                target_user: None,
                target_resource: None,
                details: format!("Impacket tool execution detected: {}", cmdline),
                confidence: 0.95,
            });
        }

        // ==================== CrackMapExec/NetExec Detection ====================
        if name.contains("crackmapexec")
            || name.contains("cme")
            || name.contains("netexec")
            || name.contains("nxc")
            || cmdline.contains("crackmapexec")
            || cmdline.contains("netexec")
        {
            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::CrackMapExec,
                source_pid: pid,
                source_name: name.to_string(),
                source_path: path.to_string(),
                source_cmdline: cmdline.to_string(),
                source_user: String::new(),
                target_host: Self::extract_target_host(cmdline),
                target_port: Some(445),
                target_user: None,
                target_resource: None,
                details: format!("CrackMapExec/NetExec execution detected: {}", cmdline),
                confidence: 0.95,
            });
        }

        // ==================== NTLM Relay Detection ====================
        // Detect ntlmrelayx or responder patterns
        if cmdline.contains("ntlmrelayx")
            || cmdline.contains("responder")
            || cmdline.contains("inveigh")
            || cmdline.contains("multirelay")
        {
            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::NtlmRelay,
                source_pid: pid,
                source_name: name.to_string(),
                source_path: path.to_string(),
                source_cmdline: cmdline.to_string(),
                source_user: String::new(),
                target_host: None,
                target_port: None,
                target_user: None,
                target_resource: None,
                details: format!("NTLM relay attack tool detected: {}", cmdline),
                confidence: 0.95,
            });
        }

        // ==================== Cobalt Strike Lateral Movement ====================
        // Detect common Cobalt Strike lateral movement patterns
        if cmdline.contains("jump ")
            || cmdline.contains("remote-exec")
            || (parent_name == "rundll32.exe" && cmdline.contains("beacon"))
            || cmdline.contains("psexec_psh")
            || cmdline.contains("winrm64")
        {
            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::CobaltStrikeLateral,
                source_pid: pid,
                source_name: name.to_string(),
                source_path: path.to_string(),
                source_cmdline: cmdline.to_string(),
                source_user: String::new(),
                target_host: Self::extract_target_host(cmdline),
                target_port: None,
                target_user: None,
                target_resource: None,
                details: format!("Cobalt Strike lateral movement detected: {}", cmdline),
                confidence: 0.90,
            });
        }

        // ==================== DCOM Lateral Movement ====================
        if (name == "mmc.exe" && cmdline.contains("-embedding"))
            || cmdline.contains("dcomexec")
            || (cmdline.contains("dcom") && cmdline.contains("exec"))
        {
            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::Dcom,
                source_pid: pid,
                source_name: name.to_string(),
                source_path: path.to_string(),
                source_cmdline: cmdline.to_string(),
                source_user: String::new(),
                target_host: Self::extract_target_host(cmdline),
                target_port: Some(135),
                target_user: None,
                target_resource: None,
                details: format!("DCOM lateral movement detected: {}", cmdline),
                confidence: 0.85,
            });
        }

        // ==================== SMB Named Pipe Lateral Movement ====================
        // Detect named pipe access patterns used in lateral movement
        if cmdline.contains("\\\\.\\pipe\\") || cmdline.contains("\\\\*\\pipe\\") {
            let suspicious_pipes = [
                "psexecsvc",
                "paexecsvc",
                "remcom",
                "csexecsvc",
                "svcctl",
                "srvsvc",
                "samr",
                "lsarpc",
                "netlogon",
            ];

            if suspicious_pipes.iter().any(|p| cmdline.contains(p)) {
                return Some(LateralMovementEvent {
                    movement_type: LateralMovementType::SmbNamedPipe,
                    source_pid: pid,
                    source_name: name.to_string(),
                    source_path: path.to_string(),
                    source_cmdline: cmdline.to_string(),
                    source_user: String::new(),
                    target_host: Self::extract_target_host(cmdline),
                    target_port: Some(445),
                    target_user: None,
                    target_resource: None,
                    details: format!("SMB named pipe lateral movement detected: {}", cmdline),
                    confidence: 0.85,
                });
            }
        }

        None
    }

    #[cfg(target_os = "windows")]
    fn extract_target_host(cmdline: &str) -> Option<String> {
        // Extract hostname/IP from various command line patterns
        // Pattern: \\hostname or \\IP
        if let Some(start) = cmdline.find("\\\\") {
            let rest = &cmdline[start + 2..];
            let end = rest
                .find(|c: char| c == '\\' || c == ' ' || c == '"')
                .unwrap_or(rest.len());
            let host = &rest[..end];
            if !host.is_empty() {
                return Some(host.to_string());
            }
        }

        None
    }

    #[cfg(target_os = "windows")]
    fn extract_wmi_target(cmdline: &str) -> Option<String> {
        // Extract from /node:hostname pattern
        if let Some(start) = cmdline.find("/node:") {
            let rest = &cmdline[start + 6..];
            let end = rest
                .find(|c: char| c == ' ' || c == '"')
                .unwrap_or(rest.len());
            let host = &rest[..end];
            if !host.is_empty() {
                return Some(host.to_string());
            }
        }

        None
    }

    #[cfg(target_os = "windows")]
    fn extract_ps_target(cmdline: &str) -> Option<String> {
        // Extract from -ComputerName hostname pattern
        let patterns = ["-computername ", "-cn "];

        for pattern in patterns {
            if let Some(start) = cmdline.find(pattern) {
                let rest = &cmdline[start + pattern.len()..];
                let end = rest
                    .find(|c: char| c == ' ' || c == '"' || c == ',')
                    .unwrap_or(rest.len());
                let host = &rest[..end];
                if !host.is_empty() {
                    return Some(host.to_string());
                }
            }
        }

        None
    }

    #[cfg(target_os = "windows")]
    fn extract_rdp_target(cmdline: &str) -> Option<String> {
        // Extract from /v:hostname pattern
        if let Some(start) = cmdline.find("/v:") {
            let rest = &cmdline[start + 3..];
            let end = rest
                .find(|c: char| c == ' ' || c == '"')
                .unwrap_or(rest.len());
            let host = &rest[..end];
            if !host.is_empty() {
                return Some(host.to_string());
            }
        }

        // Plain hostname after mstsc
        let parts: Vec<&str> = cmdline.split_whitespace().collect();
        if parts.len() >= 2 && !parts[1].starts_with('/') && !parts[1].starts_with('-') {
            return Some(parts[1].to_string());
        }

        None
    }

    #[cfg(target_os = "windows")]
    fn extract_schtasks_target(cmdline: &str) -> Option<String> {
        // Extract from /s hostname pattern
        let patterns = ["/s ", "/s:"];

        for pattern in patterns {
            if let Some(start) = cmdline.find(pattern) {
                let rest = &cmdline[start + pattern.len()..];
                let rest = rest.trim_start();
                let end = rest
                    .find(|c: char| c == ' ' || c == '"' || c == '/')
                    .unwrap_or(rest.len());
                let host = &rest[..end];
                if !host.is_empty() {
                    return Some(host.to_string());
                }
            }
        }

        None
    }

    #[cfg(target_os = "windows")]
    fn extract_unc_target(cmdline: &str) -> Option<String> {
        Self::extract_target_host(cmdline)
    }

    #[cfg(target_os = "windows")]
    fn extract_share_name(cmdline: &str) -> Option<String> {
        // Extract share name from UNC path like \\host\share
        if let Some(start) = cmdline.find("\\\\") {
            let rest = &cmdline[start + 2..];
            if let Some(share_start) = rest.find('\\') {
                let share_rest = &rest[share_start + 1..];
                let end = share_rest
                    .find(|c: char| c == '\\' || c == ' ' || c == '"')
                    .unwrap_or(share_rest.len());
                let share = &share_rest[..end];
                if !share.is_empty() {
                    return Some(share.to_string());
                }
            }
        }

        None
    }

    #[cfg(target_os = "windows")]
    async fn windows_smb_monitor(tx: mpsc::Sender<TelemetryEvent>) {
        info!("Starting Windows SMB lateral movement monitor");

        // Monitor SMB connections on ports 445 and 139
        let smb_ports: HashSet<u16> = [445, 139].into_iter().collect();
        let mut known_connections: HashSet<String> = HashSet::new();

        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(2));

        loop {
            interval.tick().await;

            let connections = Self::get_windows_connections().await;

            for (source_ip, dest_ip, port, pid, process_name) in connections {
                if smb_ports.contains(&port) {
                    let conn_key = format!("{}:{}-{}:{}", source_ip, pid, dest_ip, port);

                    if !known_connections.contains(&conn_key) {
                        known_connections.insert(conn_key);

                        // Check if connecting to admin shares
                        let lm_event = LateralMovementEvent {
                            movement_type: LateralMovementType::SmbFileOperation,
                            source_pid: pid,
                            source_name: process_name.clone(),
                            source_path: String::new(),
                            source_cmdline: String::new(),
                            source_user: String::new(),
                            target_host: Some(dest_ip.clone()),
                            target_port: Some(port),
                            target_user: None,
                            target_resource: None,
                            details: format!(
                                "SMB connection detected: {} ({}) -> {}:{}",
                                process_name, pid, dest_ip, port
                            ),
                            confidence: 0.60,
                        };

                        let event = Self::create_lateral_movement_event(&lm_event);
                        if tx.send(event).await.is_err() {
                            warn!("Event channel closed");
                            return;
                        }
                    }
                }
            }

            // Cleanup old connections
            if known_connections.len() > 10000 {
                known_connections.clear();
            }
        }
    }

    #[cfg(target_os = "windows")]
    async fn windows_auth_monitor(tx: mpsc::Sender<TelemetryEvent>) {
        use windows::core::PCWSTR;
        use windows::Win32::System::EventLog::{
            CloseEventLog, GetNumberOfEventLogRecords, OpenEventLogW,
        };

        const EVENTLOG_FORWARDS_READ: u32 = 0x0004;
        const EVENTLOG_SEQUENTIAL_READ: u32 = 0x0001;

        /// Security event IDs relevant to lateral movement detection
        const EVENT_LOGON_SUCCESS: u32 = 4624;
        const EVENT_LOGON_FAILURE: u32 = 4625;
        const EVENT_EXPLICIT_CREDENTIALS: u32 = 4648;

        info!("Starting Windows authentication lateral movement monitor (Event Log)");

        // Track the last record number we have processed to avoid re-reading old events
        let mut last_record: u32 = 0;

        // Seed last_record to the current max so we only process new events
        unsafe {
            let log_name: Vec<u16> = "Security\0".encode_utf16().collect();
            if let Ok(handle) = OpenEventLogW(PCWSTR::null(), PCWSTR(log_name.as_ptr())) {
                let mut count: u32 = 0;
                let _ = GetNumberOfEventLogRecords(handle, &mut count);
                last_record = count;
                let _ = CloseEventLog(handle);
            }
        }

        // Track failed logons for brute-force detection: source_ip -> Vec<timestamp>
        let mut failed_logon_tracker: HashMap<String, Vec<u64>> = HashMap::new();

        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));

        loop {
            interval.tick().await;

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            // Read new events from the Security event log
            let events = unsafe { Self::read_auth_events(&mut last_record) };

            let events = match events {
                Some(e) => e,
                None => continue,
            };

            for (event_id, event_data) in events {
                let lm_event = match event_id {
                    EVENT_LOGON_SUCCESS => Self::analyze_logon_success(&event_data),
                    EVENT_LOGON_FAILURE => {
                        Self::analyze_logon_failure(&event_data, &mut failed_logon_tracker, now)
                    }
                    EVENT_EXPLICIT_CREDENTIALS => Self::analyze_explicit_credentials(&event_data),
                    _ => None,
                };

                if let Some(lm) = lm_event {
                    let event = Self::create_lateral_movement_event(&lm);
                    if tx.send(event).await.is_err() {
                        warn!("Event channel closed in auth monitor");
                        return;
                    }
                }
            }

            // Prune old entries from the failed logon tracker (older than 10 min)
            failed_logon_tracker.retain(|_, timestamps| {
                timestamps.retain(|&ts| now.saturating_sub(ts) < 600);
                !timestamps.is_empty()
            });
        }
    }

    // ==================== Event Log Reading Helpers ====================

    /// Read authentication-relevant events from the Windows Security event log.
    ///
    /// Uses the legacy Event Log API (OpenEventLogW / ReadEventLogW) matching
    /// the pattern established in identity.rs and ad_monitor.rs.
    ///
    /// Filters for event IDs: 4624 (Successful Logon), 4625 (Failed Logon),
    /// 4648 (Explicit Credentials).
    #[cfg(target_os = "windows")]
    unsafe fn read_auth_events(
        last_record: &mut u32,
    ) -> Option<Vec<(u32, HashMap<String, String>)>> {
        use std::ffi::c_void;
        use windows::core::PCWSTR;
        use windows::Win32::System::EventLog::{
            CloseEventLog, OpenEventLogW, ReadEventLogW, EVENTLOGRECORD, READ_EVENT_LOG_READ_FLAGS,
        };

        const EVENTLOG_FORWARDS_READ: u32 = 0x0004;
        const EVENTLOG_SEQUENTIAL_READ: u32 = 0x0001;

        let mut events = Vec::new();

        let log_name: Vec<u16> = "Security\0".encode_utf16().collect();
        let handle = match OpenEventLogW(PCWSTR::null(), PCWSTR(log_name.as_ptr())) {
            Ok(h) => h,
            Err(e) => {
                tracing::debug!(error = ?e, "Failed to open Security event log for auth monitor");
                return None;
            }
        };

        // Read buffer (64KB)
        let buffer_size: u32 = 65536;
        let mut buffer = vec![0u8; buffer_size as usize];
        let mut bytes_read: u32 = 0;
        let mut min_bytes_needed: u32 = 0;

        let flags = EVENTLOG_FORWARDS_READ | EVENTLOG_SEQUENTIAL_READ;

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
            let event_id = record.EventID & 0xFFFF; // Lower 16 bits

            // Update last record number
            if record.RecordNumber > *last_record {
                *last_record = record.RecordNumber;
            }

            // Filter for lateral-movement-relevant authentication event IDs
            if matches!(event_id, 4624 | 4625 | 4648) {
                let event_data = Self::parse_auth_event_data(event_id, record, &buffer[offset..]);
                events.push((event_id, event_data));
            }

            if record.Length == 0 || record.Length < std::mem::size_of::<EVENTLOGRECORD>() as u32 {
                break;
            }
            // Validate record.Length doesn't exceed remaining buffer
            if offset + record.Length as usize > bytes_read as usize {
                break;
            }
            offset += record.Length as usize;
        }

        let _ = CloseEventLog(handle);

        if events.is_empty() {
            None
        } else {
            Some(events)
        }
    }

    /// Parse event data from an EVENTLOGRECORD into a named field map.
    ///
    /// Extracts insertion strings from the record and maps them to named fields
    /// based on the event ID, following the Microsoft-documented field ordering.
    #[cfg(target_os = "windows")]
    fn parse_auth_event_data(
        event_id: u32,
        record: &windows::Win32::System::EventLog::EVENTLOGRECORD,
        buffer: &[u8],
    ) -> HashMap<String, String> {
        let mut data = HashMap::new();

        // Basic metadata
        data.insert("RecordNumber".to_string(), record.RecordNumber.to_string());
        data.insert(
            "TimeGenerated".to_string(),
            record.TimeGenerated.to_string(),
        );
        data.insert(
            "EventCategory".to_string(),
            record.EventCategory.to_string(),
        );

        // Extract the insertion strings from the record
        let strings = Self::extract_auth_record_strings(record, buffer);

        if strings.is_empty() {
            return data;
        }

        // Helper to safely get a string by index
        let get = |idx: usize| -> String { strings.get(idx).cloned().unwrap_or_default() };

        // Map positional strings to named fields based on event ID.
        // Field orders are defined by Microsoft:
        // https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/
        match event_id {
            // 4624 - Successful logon
            // Strings: SubjectUserSid(0), SubjectUserName(1), SubjectDomainName(2),
            //   SubjectLogonId(3), TargetUserSid(4), TargetUserName(5),
            //   TargetDomainName(6), TargetLogonId(7), LogonType(8),
            //   LogonProcessName(9), AuthenticationPackageName(10),
            //   WorkstationName(11), LogonGuid(12), TransmittedServices(13),
            //   LmPackageName(14), KeyLength(15), ProcessId(16), ProcessName(17),
            //   IpAddress(18), IpPort(19)
            4624 => {
                data.insert("SubjectUserName".into(), get(1));
                data.insert("SubjectDomainName".into(), get(2));
                data.insert("TargetUserSid".into(), get(4));
                data.insert("TargetUserName".into(), get(5));
                data.insert("TargetDomainName".into(), get(6));
                data.insert("TargetLogonId".into(), get(7));
                data.insert("LogonType".into(), get(8));
                data.insert("LogonProcessName".into(), get(9));
                data.insert("AuthenticationPackageName".into(), get(10));
                data.insert("WorkstationName".into(), get(11));
                data.insert("ProcessName".into(), get(17));
                data.insert("IpAddress".into(), get(18));
                data.insert("IpPort".into(), get(19));
            }

            // 4625 - Failed logon
            // Strings: SubjectUserSid(0), SubjectUserName(1), SubjectDomainName(2),
            //   SubjectLogonId(3), TargetUserSid(4), TargetUserName(5),
            //   TargetDomainName(6), Status(7), FailureReason(8), SubStatus(9),
            //   LogonType(10), LogonProcessName(11), AuthenticationPackageName(12),
            //   WorkstationName(13), TransmittedServices(14), LmPackageName(15),
            //   KeyLength(16), ProcessId(17), ProcessName(18), IpAddress(19),
            //   IpPort(20)
            4625 => {
                data.insert("SubjectUserName".into(), get(1));
                data.insert("SubjectDomainName".into(), get(2));
                data.insert("TargetUserName".into(), get(5));
                data.insert("TargetDomainName".into(), get(6));
                data.insert("Status".into(), get(7));
                data.insert("FailureReason".into(), get(8));
                data.insert("SubStatus".into(), get(9));
                data.insert("LogonType".into(), get(10));
                data.insert("LogonProcessName".into(), get(11));
                data.insert("AuthenticationPackageName".into(), get(12));
                data.insert("WorkstationName".into(), get(13));
                data.insert("ProcessName".into(), get(18));
                data.insert("IpAddress".into(), get(19));
                data.insert("IpPort".into(), get(20));
            }

            // 4648 - Explicit credential logon (runas, PtH, credential relay)
            // Strings: SubjectUserSid(0), SubjectUserName(1), SubjectDomainName(2),
            //   SubjectLogonId(3), LogonGuid(4), TargetUserName(5),
            //   TargetDomainName(6), TargetLogonGuid(7), TargetServerName(8),
            //   TargetInfo(9), ProcessId(10), ProcessName(11), IpAddress(12),
            //   IpPort(13)
            4648 => {
                data.insert("SubjectUserName".into(), get(1));
                data.insert("SubjectDomainName".into(), get(2));
                data.insert("TargetUserName".into(), get(5));
                data.insert("TargetDomainName".into(), get(6));
                data.insert("TargetServerName".into(), get(8));
                data.insert("TargetInfo".into(), get(9));
                data.insert("ProcessName".into(), get(11));
                data.insert("IpAddress".into(), get(12));
                data.insert("IpPort".into(), get(13));
            }

            _ => {}
        }

        // Store raw insertion strings for debugging
        for (i, s) in strings.iter().enumerate() {
            if !s.is_empty() {
                data.insert(format!("String{}", i), s.clone());
            }
        }

        data
    }

    /// Extract null-terminated UTF-16 insertion strings from an EVENTLOGRECORD.
    ///
    /// The EVENTLOGRECORD layout in memory:
    ///   [EVENTLOGRECORD struct][SourceName\0][ComputerName\0][UserSid][Strings...][Data...]
    /// Strings start at byte offset `record.StringOffset` relative to the record
    /// start, with `record.NumStrings` consecutive null-terminated wide strings.
    #[cfg(target_os = "windows")]
    fn extract_auth_record_strings(
        record: &windows::Win32::System::EventLog::EVENTLOGRECORD,
        buffer: &[u8],
    ) -> Vec<String> {
        let mut strings = Vec::new();
        let num_strings = record.NumStrings as usize;
        if num_strings == 0 {
            return strings;
        }

        let string_offset = record.StringOffset as usize;
        let record_len = record.Length as usize;

        // Safety: StringOffset must be within the record
        if string_offset >= record_len || string_offset >= buffer.len() {
            return strings;
        }

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

    // ==================== Event Analysis Functions ====================

    /// Get a field value from parsed event data, returning empty string if absent.
    #[cfg(target_os = "windows")]
    fn auth_field(data: &HashMap<String, String>, key: &str) -> String {
        data.get(key)
            .filter(|v| !v.is_empty() && v.as_str() != "-")
            .cloned()
            .unwrap_or_default()
    }

    /// Analyze a 4624 (Successful Logon) event for lateral movement indicators.
    ///
    /// LogonType 3 (Network) from a remote IP indicates potential lateral movement.
    /// LogonType 10 (RemoteInteractive) indicates an RDP session.
    #[cfg(target_os = "windows")]
    fn analyze_logon_success(event_data: &HashMap<String, String>) -> Option<LateralMovementEvent> {
        let logon_type_str = Self::auth_field(event_data, "LogonType");
        let logon_type: u32 = logon_type_str.trim().parse().ok()?;

        let target_user = Self::auth_field(event_data, "TargetUserName");
        let target_domain = Self::auth_field(event_data, "TargetDomainName");
        let ip_address = Self::auth_field(event_data, "IpAddress");
        let workstation = Self::auth_field(event_data, "WorkstationName");
        let auth_package = Self::auth_field(event_data, "AuthenticationPackageName");

        // Skip machine accounts (ending with $), loopback, and empty/local IPs
        if target_user.ends_with('$') {
            return None;
        }
        if ip_address.is_empty()
            || ip_address == "-"
            || ip_address == "127.0.0.1"
            || ip_address == "::1"
        {
            return None;
        }

        match logon_type {
            // LogonType 3: Network logon from a remote IP
            3 => {
                let details = format!(
                    "Network logon (Type 3): {}\\{} from {} (workstation: {}, auth: {})",
                    target_domain,
                    target_user,
                    ip_address,
                    if workstation.is_empty() {
                        "unknown"
                    } else {
                        &workstation
                    },
                    if auth_package.is_empty() {
                        "unknown"
                    } else {
                        &auth_package
                    },
                );

                // NTLM network logons from remote IPs are more suspicious
                let confidence = if auth_package.to_uppercase() == "NTLM" {
                    0.80
                } else {
                    0.65
                };

                Some(LateralMovementEvent {
                    movement_type: LateralMovementType::NetworkLogon,
                    source_pid: 0,
                    source_name: "lsass.exe".to_string(),
                    source_path: String::new(),
                    source_cmdline: String::new(),
                    source_user: format!("{}\\{}", target_domain, target_user),
                    target_host: Some(ip_address),
                    target_port: None,
                    target_user: Some(target_user),
                    target_resource: if !workstation.is_empty() {
                        Some(workstation)
                    } else {
                        None
                    },
                    details,
                    confidence,
                })
            }
            // LogonType 10: Remote Interactive (RDP)
            10 => {
                let details = format!(
                    "Remote interactive logon (Type 10 / RDP): {}\\{} from {}",
                    target_domain, target_user, ip_address,
                );

                Some(LateralMovementEvent {
                    movement_type: LateralMovementType::RemoteInteractiveLogon,
                    source_pid: 0,
                    source_name: "lsass.exe".to_string(),
                    source_path: String::new(),
                    source_cmdline: String::new(),
                    source_user: format!("{}\\{}", target_domain, target_user),
                    target_host: Some(ip_address),
                    target_port: Some(3389),
                    target_user: Some(target_user),
                    target_resource: None,
                    details,
                    confidence: 0.75,
                })
            }
            _ => None,
        }
    }

    /// Analyze a 4625 (Failed Logon) event for brute-force / password spray detection.
    ///
    /// Tracks failed logon attempts per source IP. If a threshold is exceeded
    /// within a 10-minute window, emits a lateral movement alert.
    #[cfg(target_os = "windows")]
    fn analyze_logon_failure(
        event_data: &HashMap<String, String>,
        tracker: &mut HashMap<String, Vec<u64>>,
        now: u64,
    ) -> Option<LateralMovementEvent> {
        const BRUTE_FORCE_THRESHOLD: usize = 10;
        const TIME_WINDOW_SECS: u64 = 600; // 10 minutes

        let target_user = Self::auth_field(event_data, "TargetUserName");
        let target_domain = Self::auth_field(event_data, "TargetDomainName");
        let ip_address = Self::auth_field(event_data, "IpAddress");
        let status = Self::auth_field(event_data, "Status");
        let sub_status = Self::auth_field(event_data, "SubStatus");
        let failure_reason = Self::auth_field(event_data, "FailureReason");

        // Skip events with no useful source IP
        if ip_address.is_empty()
            || ip_address == "-"
            || ip_address == "127.0.0.1"
            || ip_address == "::1"
        {
            return None;
        }

        // Record this failed attempt
        let entry = tracker.entry(ip_address.clone()).or_default();
        entry.push(now);

        // Remove timestamps outside the window
        entry.retain(|&ts| now.saturating_sub(ts) < TIME_WINDOW_SECS);

        let failure_count = entry.len();

        if failure_count >= BRUTE_FORCE_THRESHOLD {
            let details = format!(
                "Brute-force / password spray detected: {} failed logon attempts from {} \
                 in {} seconds (last target: {}\\{}, status: {}, sub: {}, reason: {})",
                failure_count,
                ip_address,
                TIME_WINDOW_SECS,
                target_domain,
                target_user,
                status,
                sub_status,
                failure_reason,
            );

            // Clear tracker for this IP so we don't re-alert on every subsequent event
            entry.clear();

            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::NetworkLogon,
                source_pid: 0,
                source_name: "lsass.exe".to_string(),
                source_path: String::new(),
                source_cmdline: String::new(),
                source_user: format!("{}\\{}", target_domain, target_user),
                target_host: Some(ip_address),
                target_port: None,
                target_user: Some(target_user),
                target_resource: None,
                details,
                confidence: 0.90,
            });
        }

        None
    }

    /// Analyze a 4648 (Explicit Credentials) event for pass-the-hash or
    /// credential relay indicators.
    ///
    /// This event fires when a process explicitly provides alternate credentials
    /// (e.g., runas /netonly, PtH tools, scheduled tasks with stored creds).
    #[cfg(target_os = "windows")]
    fn analyze_explicit_credentials(
        event_data: &HashMap<String, String>,
    ) -> Option<LateralMovementEvent> {
        let subject_user = Self::auth_field(event_data, "SubjectUserName");
        let subject_domain = Self::auth_field(event_data, "SubjectDomainName");
        let target_user = Self::auth_field(event_data, "TargetUserName");
        let target_domain = Self::auth_field(event_data, "TargetDomainName");
        let target_server = Self::auth_field(event_data, "TargetServerName");
        let process_name = Self::auth_field(event_data, "ProcessName");

        // Skip machine accounts and empty subjects
        if subject_user.is_empty()
            || subject_user.ends_with('$')
            || target_user.is_empty()
            || target_user.ends_with('$')
        {
            return None;
        }

        // Skip benign system processes
        let process_lower = process_name.to_lowercase();
        if process_lower.contains("\\windows\\system32\\svchost.exe")
            || process_lower.contains("\\windows\\system32\\lsass.exe")
            || process_lower.contains("\\windows\\system32\\services.exe")
        {
            return None;
        }

        // Flag when different user credentials are used (subject != target)
        let different_user = subject_user.to_lowercase() != target_user.to_lowercase()
            || subject_domain.to_lowercase() != target_domain.to_lowercase();

        if !different_user && target_server.is_empty() {
            return None;
        }

        let confidence = if different_user { 0.85 } else { 0.65 };

        let details = format!(
            "Explicit credential usage (Event 4648): {}\\{} used {}\\{} credentials to access {} (process: {})",
            subject_domain,
            subject_user,
            target_domain,
            target_user,
            if target_server.is_empty() { "local" } else { &target_server },
            process_name,
        );

        Some(LateralMovementEvent {
            movement_type: LateralMovementType::PassTheHash,
            source_pid: 0,
            source_name: process_name,
            source_path: String::new(),
            source_cmdline: String::new(),
            source_user: format!("{}\\{}", subject_domain, subject_user),
            target_host: if !target_server.is_empty() {
                Some(target_server)
            } else {
                None
            },
            target_port: None,
            target_user: Some(format!("{}\\{}", target_domain, target_user)),
            target_resource: None,
            details,
            confidence,
        })
    }

    #[cfg(target_os = "windows")]
    async fn get_windows_connections() -> Vec<(String, String, u16, u32, String)> {
        use std::net::Ipv4Addr;
        use windows::Win32::NetworkManagement::IpHelper::{
            GetExtendedTcpTable, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
        };
        use windows::Win32::Networking::WinSock::AF_INET;

        let mut results = Vec::new();

        let mut size: u32 = 0;
        unsafe {
            let _ = GetExtendedTcpTable(
                None,
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
        }

        if size > 0 {
            let mut buffer: Vec<u8> = vec![0u8; size as usize];

            let result = unsafe {
                GetExtendedTcpTable(
                    Some(buffer.as_mut_ptr() as *mut _),
                    &mut size,
                    false,
                    AF_INET.0 as u32,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            };

            if result == 0 {
                let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
                let num_entries = table.dwNumEntries as usize;

                if num_entries > 0 {
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

                    for i in 0..num_entries {
                        let row = unsafe { &*rows_ptr.add(i) };

                        let local_ip = Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes());
                        let remote_ip = Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes());
                        let remote_port = u16::from_be(row.dwRemotePort as u16);
                        let pid = row.dwOwningPid;

                        if remote_port == 0 || remote_ip.is_loopback() || remote_ip.is_unspecified()
                        {
                            continue;
                        }

                        let process_name = Self::get_windows_process_name(pid);

                        results.push((
                            local_ip.to_string(),
                            remote_ip.to_string(),
                            remote_port,
                            pid,
                            process_name,
                        ));
                    }
                }
            }
        }

        results
    }

    #[cfg(target_os = "windows")]
    fn get_windows_process_name(pid: u32) -> String {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::ProcessStatus::GetModuleBaseNameW;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

        if pid == 0 || pid == 4 {
            return if pid == 0 {
                "System Idle".to_string()
            } else {
                "System".to_string()
            };
        }

        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(h) => h,
                Err(_) => return format!("pid:{}", pid),
            };

            let mut name_buf = [0u16; 260];
            let len = GetModuleBaseNameW(handle, None, &mut name_buf);
            let _ = CloseHandle(handle);

            if len > 0 {
                String::from_utf16_lossy(&name_buf[..len as usize])
            } else {
                format!("pid:{}", pid)
            }
        }
    }

    // ==================== Linux Implementation ====================
    #[cfg(target_os = "linux")]
    async fn linux_monitor_loop(tx: mpsc::Sender<TelemetryEvent>, _config: AgentConfig) {
        info!("Starting Linux lateral movement monitor");

        // Start multiple detection tasks
        let tx_process = tx.clone();
        tokio::spawn(async move {
            Self::linux_process_monitor(tx_process).await;
        });

        let tx_ssh = tx.clone();
        tokio::spawn(async move {
            Self::linux_ssh_monitor(tx_ssh).await;
        });

        let tx_auth = tx.clone();
        tokio::spawn(async move {
            Self::linux_auth_monitor(tx_auth).await;
        });

        // Keep the main loop alive
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
        }
    }

    #[cfg(target_os = "linux")]
    async fn linux_process_monitor(tx: mpsc::Sender<TelemetryEvent>) {
        use sysinfo::{ProcessRefreshKind, System};

        info!("Starting Linux process-based lateral movement detection");

        let mut system = System::new_all();
        let mut known_pids: HashSet<u32> = HashSet::new();

        // Initialize known PIDs
        system.refresh_processes_specifics(ProcessRefreshKind::everything());
        for (pid, _) in system.processes() {
            known_pids.insert(pid.as_u32());
        }

        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(500));

        loop {
            interval.tick().await;

            system.refresh_processes_specifics(ProcessRefreshKind::everything());

            let current_pids: HashSet<u32> =
                system.processes().keys().map(|p| p.as_u32()).collect();

            // Check new processes for lateral movement indicators
            for pid in current_pids.difference(&known_pids) {
                if let Some(process) = system.process(sysinfo::Pid::from_u32(*pid)) {
                    let name = process.name().to_string().to_lowercase();
                    let cmdline = process
                        .cmd()
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                        .join(" ");
                    let path = process
                        .exe()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_default();
                    let parent_pid = process.parent().map(|p| p.as_u32()).unwrap_or(0);

                    // Get parent name
                    let parent_name =
                        if let Some(parent) = system.process(sysinfo::Pid::from_u32(parent_pid)) {
                            parent.name().to_string().to_lowercase()
                        } else {
                            String::new()
                        };

                    // Detect various lateral movement patterns
                    if let Some(lm_event) = Self::detect_linux_lateral_movement(
                        *pid,
                        &name,
                        &cmdline,
                        &path,
                        &parent_name,
                    ) {
                        let event = Self::create_lateral_movement_event(&lm_event);
                        if tx.send(event).await.is_err() {
                            warn!("Event channel closed");
                            return;
                        }
                    }
                }
            }

            known_pids = current_pids;
        }
    }

    #[cfg(target_os = "linux")]
    fn detect_linux_lateral_movement(
        pid: u32,
        name: &str,
        cmdline: &str,
        path: &str,
        parent_name: &str,
    ) -> Option<LateralMovementEvent> {
        let cmdline_lower = cmdline.to_lowercase();

        // SSH client usage
        if name == "ssh" || name.starts_with("ssh ") {
            // Filter out expected SSH usage (like git)
            if !cmdline_lower.contains("git") {
                return Some(LateralMovementEvent {
                    movement_type: LateralMovementType::Ssh,
                    source_pid: pid,
                    source_name: name.to_string(),
                    source_path: path.to_string(),
                    source_cmdline: cmdline.to_string(),
                    source_user: Self::get_linux_process_user(pid),
                    target_host: Self::extract_ssh_target(cmdline),
                    target_port: Self::extract_ssh_port(cmdline),
                    target_user: Self::extract_ssh_user(cmdline),
                    target_resource: None,
                    details: format!("SSH connection initiated: {}", cmdline),
                    confidence: 0.70,
                });
            }
        }

        // sshd spawning shells (incoming SSH session)
        if parent_name == "sshd" {
            let shell_names = ["bash", "sh", "zsh", "fish", "ksh", "csh", "tcsh"];
            if shell_names.iter().any(|s| name.contains(s)) {
                return Some(LateralMovementEvent {
                    movement_type: LateralMovementType::Ssh,
                    source_pid: pid,
                    source_name: name.to_string(),
                    source_path: path.to_string(),
                    source_cmdline: cmdline.to_string(),
                    source_user: Self::get_linux_process_user(pid),
                    target_host: None,
                    target_port: None,
                    target_user: None,
                    target_resource: None,
                    details: format!("Incoming SSH session detected: {} spawned by sshd", name),
                    confidence: 0.75,
                });
            }
        }

        // Ansible execution
        if name == "ansible" || name == "ansible-playbook" || cmdline_lower.contains("ansible") {
            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::ConfigManagement,
                source_pid: pid,
                source_name: name.to_string(),
                source_path: path.to_string(),
                source_cmdline: cmdline.to_string(),
                source_user: Self::get_linux_process_user(pid),
                target_host: Self::extract_ansible_target(cmdline),
                target_port: Some(22),
                target_user: None,
                target_resource: None,
                details: format!("Ansible execution detected: {}", cmdline),
                confidence: 0.65,
            });
        }

        // Puppet agent
        if name == "puppet" || name.starts_with("puppet ") {
            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::ConfigManagement,
                source_pid: pid,
                source_name: name.to_string(),
                source_path: path.to_string(),
                source_cmdline: cmdline.to_string(),
                source_user: Self::get_linux_process_user(pid),
                target_host: None,
                target_port: None,
                target_user: None,
                target_resource: None,
                details: format!("Puppet execution detected: {}", cmdline),
                confidence: 0.50,
            });
        }

        // Chef client
        if name == "chef-client" || name == "chef-solo" {
            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::ConfigManagement,
                source_pid: pid,
                source_name: name.to_string(),
                source_path: path.to_string(),
                source_cmdline: cmdline.to_string(),
                source_user: Self::get_linux_process_user(pid),
                target_host: None,
                target_port: None,
                target_user: None,
                target_resource: None,
                details: format!("Chef execution detected: {}", cmdline),
                confidence: 0.50,
            });
        }

        // Salt minion
        if name == "salt-minion" || name == "salt-call" {
            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::ConfigManagement,
                source_pid: pid,
                source_name: name.to_string(),
                source_path: path.to_string(),
                source_cmdline: cmdline.to_string(),
                source_user: Self::get_linux_process_user(pid),
                target_host: None,
                target_port: None,
                target_user: None,
                target_resource: None,
                details: format!("SaltStack execution detected: {}", cmdline),
                confidence: 0.50,
            });
        }

        // pssh/parallel-ssh
        if name == "pssh" || name == "parallel-ssh" || cmdline_lower.contains("pssh") {
            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::RemoteCommand,
                source_pid: pid,
                source_name: name.to_string(),
                source_path: path.to_string(),
                source_cmdline: cmdline.to_string(),
                source_user: Self::get_linux_process_user(pid),
                target_host: None,
                target_port: Some(22),
                target_user: None,
                target_resource: None,
                details: format!("Parallel SSH execution detected: {}", cmdline),
                confidence: 0.85,
            });
        }

        // rsync (can indicate lateral file transfer)
        if name == "rsync" && cmdline.contains("@") && cmdline.contains(":") {
            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::SmbFileOperation, // Reusing for file transfer
                source_pid: pid,
                source_name: name.to_string(),
                source_path: path.to_string(),
                source_cmdline: cmdline.to_string(),
                source_user: Self::get_linux_process_user(pid),
                target_host: Self::extract_rsync_target(cmdline),
                target_port: Some(22),
                target_user: None,
                target_resource: None,
                details: format!("Remote rsync transfer detected: {}", cmdline),
                confidence: 0.65,
            });
        }

        // scp file transfer
        if name == "scp" {
            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::SmbFileOperation,
                source_pid: pid,
                source_name: name.to_string(),
                source_path: path.to_string(),
                source_cmdline: cmdline.to_string(),
                source_user: Self::get_linux_process_user(pid),
                target_host: Self::extract_scp_target(cmdline),
                target_port: Some(22),
                target_user: None,
                target_resource: None,
                details: format!("SCP file transfer detected: {}", cmdline),
                confidence: 0.70,
            });
        }

        // ==================== rsh/rexec Detection (Legacy Remote Shell) ====================
        // These are insecure legacy protocols often exploited for lateral movement
        if name == "rsh" || name == "rexec" || name == "rlogin" {
            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::RemoteShell,
                source_pid: pid,
                source_name: name.to_string(),
                source_path: path.to_string(),
                source_cmdline: cmdline.to_string(),
                source_user: Self::get_linux_process_user(pid),
                target_host: Self::extract_rsh_target(cmdline),
                target_port: Some(if name == "rsh" {
                    514
                } else if name == "rexec" {
                    512
                } else {
                    513
                }),
                target_user: None,
                target_resource: None,
                details: format!(
                    "Legacy remote shell ({}) detected - high risk: {}",
                    name, cmdline
                ),
                confidence: 0.90,
            });
        }

        // Detect rsh daemon spawning shells (incoming rsh connection)
        if parent_name == "rshd" || parent_name == "rexecd" || parent_name == "rlogind" {
            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::RemoteShell,
                source_pid: pid,
                source_name: name.to_string(),
                source_path: path.to_string(),
                source_cmdline: cmdline.to_string(),
                source_user: Self::get_linux_process_user(pid),
                target_host: None,
                target_port: None,
                target_user: None,
                target_resource: None,
                details: format!(
                    "Incoming rsh/rexec session detected: {} spawned by {}",
                    name, parent_name
                ),
                confidence: 0.90,
            });
        }

        // ==================== Impacket Tools Detection on Linux ====================
        let impacket_tools = [
            "wmiexec.py",
            "smbexec.py",
            "psexec.py",
            "atexec.py",
            "dcomexec.py",
            "secretsdump.py",
            "ntlmrelayx.py",
            "getST.py",
            "getTGT.py",
            "GetUserSPNs.py",
            "GetNPUsers.py",
            "smbclient.py",
            "rpcdump.py",
            "reg.py",
            "services.py",
            "lookupsid.py",
            "samrdump.py",
        ];

        if impacket_tools
            .iter()
            .any(|t| name.contains(t) || cmdline_lower.contains(t))
        {
            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::ImpacketTool,
                source_pid: pid,
                source_name: name.to_string(),
                source_path: path.to_string(),
                source_cmdline: cmdline.to_string(),
                source_user: Self::get_linux_process_user(pid),
                target_host: Self::extract_impacket_target(cmdline),
                target_port: Some(445),
                target_user: None,
                target_resource: None,
                details: format!("Impacket tool execution detected: {}", cmdline),
                confidence: 0.95,
            });
        }

        // ==================== CrackMapExec/NetExec Detection ====================
        if name == "crackmapexec"
            || name == "cme"
            || name == "netexec"
            || name == "nxc"
            || cmdline_lower.contains("crackmapexec")
            || cmdline_lower.contains("netexec")
        {
            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::CrackMapExec,
                source_pid: pid,
                source_name: name.to_string(),
                source_path: path.to_string(),
                source_cmdline: cmdline.to_string(),
                source_user: Self::get_linux_process_user(pid),
                target_host: None,
                target_port: Some(445),
                target_user: None,
                target_resource: None,
                details: format!("CrackMapExec/NetExec execution detected: {}", cmdline),
                confidence: 0.95,
            });
        }

        // ==================== NTLM Relay Attack Tools ====================
        if cmdline_lower.contains("ntlmrelayx")
            || cmdline_lower.contains("responder")
            || name == "responder"
            || cmdline_lower.contains("multirelay")
        {
            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::NtlmRelay,
                source_pid: pid,
                source_name: name.to_string(),
                source_path: path.to_string(),
                source_cmdline: cmdline.to_string(),
                source_user: Self::get_linux_process_user(pid),
                target_host: None,
                target_port: None,
                target_user: None,
                target_resource: None,
                details: format!("NTLM relay attack tool detected: {}", cmdline),
                confidence: 0.95,
            });
        }

        // ==================== Evil-WinRM Detection ====================
        if name.contains("evil-winrm") || cmdline_lower.contains("evil-winrm") {
            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::WinRM,
                source_pid: pid,
                source_name: name.to_string(),
                source_path: path.to_string(),
                source_cmdline: cmdline.to_string(),
                source_user: Self::get_linux_process_user(pid),
                target_host: Self::extract_evil_winrm_target(cmdline),
                target_port: Some(5985),
                target_user: None,
                target_resource: None,
                details: format!("Evil-WinRM lateral movement detected: {}", cmdline),
                confidence: 0.95,
            });
        }

        // ==================== Metasploit Detection ====================
        if cmdline_lower.contains("msfconsole")
            || cmdline_lower.contains("msfvenom")
            || cmdline_lower.contains("exploit/")
            || cmdline_lower.contains("auxiliary/scanner")
        {
            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::RemoteCommand,
                source_pid: pid,
                source_name: name.to_string(),
                source_path: path.to_string(),
                source_cmdline: cmdline.to_string(),
                source_user: Self::get_linux_process_user(pid),
                target_host: None,
                target_port: None,
                target_user: None,
                target_resource: None,
                details: format!("Metasploit framework detected: {}", cmdline),
                confidence: 0.90,
            });
        }

        // ==================== Samba/SMB Client Detection ====================
        if name == "smbclient" || name == "smbmap" || name == "smbget" {
            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::SmbFileOperation,
                source_pid: pid,
                source_name: name.to_string(),
                source_path: path.to_string(),
                source_cmdline: cmdline.to_string(),
                source_user: Self::get_linux_process_user(pid),
                target_host: Self::extract_smb_target(cmdline),
                target_port: Some(445),
                target_user: None,
                target_resource: None,
                details: format!("SMB client activity detected: {}", cmdline),
                confidence: 0.75,
            });
        }

        // ==================== Linux to Windows RDP ====================
        if name == "xfreerdp" || name == "rdesktop" || name == "freerdp" {
            return Some(LateralMovementEvent {
                movement_type: LateralMovementType::Rdp,
                source_pid: pid,
                source_name: name.to_string(),
                source_path: path.to_string(),
                source_cmdline: cmdline.to_string(),
                source_user: Self::get_linux_process_user(pid),
                target_host: Self::extract_rdp_target_linux(cmdline),
                target_port: Some(3389),
                target_user: None,
                target_resource: None,
                details: format!("RDP connection from Linux detected: {}", cmdline),
                confidence: 0.75,
            });
        }

        None
    }

    #[cfg(target_os = "linux")]
    fn extract_rsh_target(cmdline: &str) -> Option<String> {
        // rsh/rexec format: rsh hostname command
        let parts: Vec<&str> = cmdline.split_whitespace().collect();
        for (i, part) in parts.iter().enumerate() {
            if i > 0 && !part.starts_with('-') {
                return Some(part.to_string());
            }
        }
        None
    }

    #[cfg(target_os = "linux")]
    fn extract_impacket_target(cmdline: &str) -> Option<String> {
        // Impacket format: tool.py user:pass@target or tool.py target
        let parts: Vec<&str> = cmdline.split_whitespace().collect();
        for part in parts.iter().skip(1) {
            if part.contains('@') {
                // user:pass@target format
                if let Some(target) = part.split('@').last() {
                    return Some(target.to_string());
                }
            } else if !part.starts_with('-') && !part.contains('=') {
                // Plain target
                return Some(part.to_string());
            }
        }
        None
    }

    #[cfg(target_os = "linux")]
    fn extract_evil_winrm_target(cmdline: &str) -> Option<String> {
        // evil-winrm -i target -u user -p pass
        let parts: Vec<&str> = cmdline.split_whitespace().collect();
        for (i, part) in parts.iter().enumerate() {
            if *part == "-i" || *part == "--ip" {
                return parts.get(i + 1).map(|s| s.to_string());
            }
        }
        None
    }

    #[cfg(target_os = "linux")]
    fn extract_smb_target(cmdline: &str) -> Option<String> {
        // smbclient //host/share or -L host
        let parts: Vec<&str> = cmdline.split_whitespace().collect();
        for (i, part) in parts.iter().enumerate() {
            if part.starts_with("//") {
                // //host/share format
                let host = part.trim_start_matches("//");
                return host.split('/').next().map(|s| s.to_string());
            }
            if *part == "-L" {
                return parts.get(i + 1).map(|s| s.to_string());
            }
        }
        None
    }

    #[cfg(target_os = "linux")]
    fn extract_rdp_target_linux(cmdline: &str) -> Option<String> {
        // xfreerdp /v:host or rdesktop host
        let parts: Vec<&str> = cmdline.split_whitespace().collect();
        for part in &parts {
            if part.starts_with("/v:") {
                return Some(part.trim_start_matches("/v:").to_string());
            }
        }
        // Last non-option argument for rdesktop
        for part in parts.iter().rev() {
            if !part.starts_with('-') && !part.contains('=') {
                return Some(part.to_string());
            }
        }
        None
    }

    #[cfg(target_os = "linux")]
    fn get_linux_process_user(pid: u32) -> String {
        std::fs::read_to_string(format!("/proc/{}/status", pid))
            .ok()
            .and_then(|content| {
                content
                    .lines()
                    .find(|line| line.starts_with("Uid:"))
                    .and_then(|line| {
                        let uid: u32 = line.split_whitespace().nth(1)?.parse().ok()?;
                        // Try to resolve username
                        unsafe {
                            let pwd = libc::getpwuid(uid);
                            if !pwd.is_null() {
                                let name_ptr = (*pwd).pw_name;
                                if !name_ptr.is_null() {
                                    return std::ffi::CStr::from_ptr(name_ptr)
                                        .to_str()
                                        .ok()
                                        .map(|s| s.to_string());
                                }
                            }
                        }
                        Some(uid.to_string())
                    })
            })
            .unwrap_or_else(|| "unknown".to_string())
    }

    #[cfg(target_os = "linux")]
    fn extract_ssh_target(cmdline: &str) -> Option<String> {
        // SSH patterns: ssh user@host, ssh host, ssh -l user host
        let parts: Vec<&str> = cmdline.split_whitespace().collect();

        for (i, part) in parts.iter().enumerate() {
            // Skip the ssh command itself and options
            if *part == "ssh" || part.starts_with('-') {
                continue;
            }

            // user@host pattern
            if part.contains('@') {
                let host = part.split('@').last()?;
                // Remove port if present
                let host = host.split(':').next()?;
                return Some(host.to_string());
            }

            // Check if this looks like a hostname (not an option value)
            if i > 0 {
                let prev = parts.get(i - 1)?;
                if !prev.ends_with('l')
                    && !prev.ends_with('p')
                    && !prev.ends_with('i')
                    && !prev.ends_with('F')
                {
                    return Some(part.to_string());
                }
            }
        }

        None
    }

    #[cfg(target_os = "linux")]
    fn extract_ssh_port(cmdline: &str) -> Option<u16> {
        let parts: Vec<&str> = cmdline.split_whitespace().collect();

        for (i, part) in parts.iter().enumerate() {
            if *part == "-p" {
                return parts.get(i + 1)?.parse().ok();
            }
        }

        Some(22) // Default SSH port
    }

    #[cfg(target_os = "linux")]
    fn extract_ssh_user(cmdline: &str) -> Option<String> {
        let parts: Vec<&str> = cmdline.split_whitespace().collect();

        // Check user@host pattern
        for part in &parts {
            if part.contains('@') {
                return Some(part.split('@').next()?.to_string());
            }
        }

        // Check -l user pattern
        for (i, part) in parts.iter().enumerate() {
            if *part == "-l" {
                return parts.get(i + 1).map(|s| s.to_string());
            }
        }

        None
    }

    #[cfg(target_os = "linux")]
    fn extract_ansible_target(cmdline: &str) -> Option<String> {
        let parts: Vec<&str> = cmdline.split_whitespace().collect();

        for (i, part) in parts.iter().enumerate() {
            if *part == "-i" || *part == "--inventory" {
                return parts.get(i + 1).map(|s| s.to_string());
            }
        }

        None
    }

    #[cfg(target_os = "linux")]
    fn extract_rsync_target(cmdline: &str) -> Option<String> {
        // Pattern: rsync ... user@host:/path or host:/path
        let parts: Vec<&str> = cmdline.split_whitespace().collect();

        for part in &parts {
            if part.contains(':') && !part.starts_with('-') {
                let host_part = if part.contains('@') {
                    part.split('@').last()?
                } else {
                    part
                };

                return Some(host_part.split(':').next()?.to_string());
            }
        }

        None
    }

    #[cfg(target_os = "linux")]
    fn extract_scp_target(cmdline: &str) -> Option<String> {
        // Similar to rsync
        Self::extract_rsync_target(cmdline)
    }

    #[cfg(target_os = "linux")]
    async fn linux_ssh_monitor(tx: mpsc::Sender<TelemetryEvent>) {
        use std::fs::File;
        use std::io::{BufRead, BufReader, Seek, SeekFrom};

        info!("Starting Linux SSH connection monitor");

        // Monitor auth.log or secure log for SSH connections
        let log_paths = ["/var/log/auth.log", "/var/log/secure", "/var/log/syslog"];

        let log_path = log_paths.iter().find(|p| std::path::Path::new(p).exists());

        let log_path = match log_path {
            Some(p) => *p,
            None => {
                debug!("No auth log found, SSH monitoring disabled");
                return;
            }
        };

        let mut file = match File::open(log_path) {
            Ok(f) => f,
            Err(_) => {
                debug!("Cannot open auth log: {}", log_path);
                return;
            }
        };

        // Seek to end
        if file.seek(SeekFrom::End(0)).is_err() {
            return;
        }

        let mut reader = BufReader::new(file);
        let mut line = String::new();

        loop {
            match reader.read_line(&mut line) {
                Ok(0) => {
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                }
                Ok(_) => {
                    if let Some(lm_event) = Self::parse_ssh_log_line(&line) {
                        let event = Self::create_lateral_movement_event(&lm_event);
                        if tx.send(event).await.is_err() {
                            warn!("Event channel closed");
                            return;
                        }
                    }
                    line.clear();
                }
                Err(_) => {
                    // File may have been rotated
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

                    // Try to reopen
                    if let Ok(new_file) = File::open(log_path) {
                        reader = BufReader::new(new_file);
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn parse_ssh_log_line(line: &str) -> Option<LateralMovementEvent> {
        // Parse sshd log entries
        // Example: "Accepted publickey for user from 192.168.1.100 port 52842 ssh2"
        // Example: "Accepted password for user from 192.168.1.100 port 52842 ssh2"

        if !line.contains("sshd") {
            return None;
        }

        if line.contains("Accepted") {
            // Successful SSH login
            let parts: Vec<&str> = line.split_whitespace().collect();

            let mut user = None;
            let mut source_ip = None;
            let mut source_port = None;

            for (i, part) in parts.iter().enumerate() {
                if *part == "for" {
                    user = parts.get(i + 1).map(|s| s.to_string());
                }
                if *part == "from" {
                    source_ip = parts.get(i + 1).map(|s| s.to_string());
                }
                if *part == "port" {
                    source_port = parts.get(i + 1).and_then(|s| s.parse().ok());
                }
            }

            if let (Some(user), Some(ip)) = (user, source_ip) {
                return Some(LateralMovementEvent {
                    movement_type: LateralMovementType::Ssh,
                    source_pid: 0,
                    source_name: "sshd".to_string(),
                    source_path: "/usr/sbin/sshd".to_string(),
                    source_cmdline: String::new(),
                    source_user: user.clone(),
                    target_host: Some(ip),
                    target_port: source_port,
                    target_user: Some(user),
                    target_resource: None,
                    details: format!("SSH login detected: {}", line.trim()),
                    confidence: 0.80,
                });
            }
        }

        if line.contains("Failed password") || line.contains("Failed publickey") {
            // Failed SSH login attempt (could indicate brute force)
            let parts: Vec<&str> = line.split_whitespace().collect();

            let mut user = None;
            let mut source_ip = None;

            for (i, part) in parts.iter().enumerate() {
                if *part == "for" {
                    user = parts.get(i + 1).map(|s| s.to_string());
                }
                if *part == "from" {
                    source_ip = parts.get(i + 1).map(|s| s.to_string());
                }
            }

            if let (Some(_user), Some(ip)) = (user, source_ip) {
                return Some(LateralMovementEvent {
                    movement_type: LateralMovementType::Ssh,
                    source_pid: 0,
                    source_name: "sshd".to_string(),
                    source_path: "/usr/sbin/sshd".to_string(),
                    source_cmdline: String::new(),
                    source_user: String::new(),
                    target_host: Some(ip),
                    target_port: None,
                    target_user: None,
                    target_resource: None,
                    details: format!("Failed SSH login attempt: {}", line.trim()),
                    confidence: 0.60,
                });
            }
        }

        None
    }

    #[cfg(target_os = "linux")]
    async fn linux_auth_monitor(tx: mpsc::Sender<TelemetryEvent>) {
        info!("Starting Linux authentication monitor");

        // Monitor for su/sudo usage and other authentication events
        // This complements the SSH monitor for local privilege escalation

        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));

        loop {
            interval.tick().await;

            // Placeholder for wtmp/btmp parsing
            // Full implementation would parse these binary files for login records
        }
    }

    // ==================== macOS Implementation ====================
    #[cfg(target_os = "macos")]
    async fn macos_monitor_loop(tx: mpsc::Sender<TelemetryEvent>, _config: AgentConfig) {
        info!("Starting macOS lateral movement monitor");

        // Start process monitoring
        let tx_process = tx.clone();
        tokio::spawn(async move {
            Self::macos_process_monitor(tx_process).await;
        });

        // Keep the main loop alive
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
        }
    }

    #[cfg(target_os = "macos")]
    async fn macos_process_monitor(tx: mpsc::Sender<TelemetryEvent>) {
        use sysinfo::{ProcessRefreshKind, System};

        info!("Starting macOS process-based lateral movement detection");

        let mut system = System::new_all();
        let mut known_pids: HashSet<u32> = HashSet::new();

        // Initialize known PIDs
        system.refresh_processes_specifics(ProcessRefreshKind::everything());
        for (pid, _) in system.processes() {
            known_pids.insert(pid.as_u32());
        }

        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(500));

        loop {
            interval.tick().await;

            system.refresh_processes_specifics(ProcessRefreshKind::everything());

            let current_pids: HashSet<u32> =
                system.processes().keys().map(|p| p.as_u32()).collect();

            // Check new processes for lateral movement indicators
            for pid in current_pids.difference(&known_pids) {
                if let Some(process) = system.process(sysinfo::Pid::from_u32(*pid)) {
                    let name = process.name().to_string().to_lowercase();
                    let cmdline = process
                        .cmd()
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                        .join(" ");
                    let path = process
                        .exe()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_default();
                    let parent_pid = process.parent().map(|p| p.as_u32()).unwrap_or(0);

                    // Get parent name
                    let parent_name =
                        if let Some(parent) = system.process(sysinfo::Pid::from_u32(parent_pid)) {
                            parent.name().to_string().to_lowercase()
                        } else {
                            String::new()
                        };

                    // Use Linux detection logic (mostly applicable to macOS)
                    #[cfg(target_os = "linux")]
                    if let Some(lm_event) = Self::detect_linux_lateral_movement(
                        *pid,
                        &name,
                        &cmdline,
                        &path,
                        &parent_name,
                    ) {
                        let event = Self::create_lateral_movement_event(&lm_event);
                        if tx.send(event).await.is_err() {
                            warn!("Event channel closed");
                            return;
                        }
                    }

                    // macOS-specific: Apple Remote Desktop
                    if name == "ardagent" || name.contains("remote desktop") {
                        let lm_event = LateralMovementEvent {
                            movement_type: LateralMovementType::Rdp,
                            source_pid: *pid,
                            source_name: name.clone(),
                            source_path: path.clone(),
                            source_cmdline: cmdline.clone(),
                            source_user: String::new(),
                            target_host: None,
                            target_port: Some(5900),
                            target_user: None,
                            target_resource: None,
                            details: format!("Apple Remote Desktop activity detected: {}", name),
                            confidence: 0.75,
                        };

                        let event = Self::create_lateral_movement_event(&lm_event);
                        if tx.send(event).await.is_err() {
                            warn!("Event channel closed");
                            return;
                        }
                    }

                    // Screen sharing
                    if name.contains("screensharingd") || name.contains("vnc") {
                        let lm_event = LateralMovementEvent {
                            movement_type: LateralMovementType::Rdp,
                            source_pid: *pid,
                            source_name: name.clone(),
                            source_path: path.clone(),
                            source_cmdline: cmdline.clone(),
                            source_user: String::new(),
                            target_host: None,
                            target_port: Some(5900),
                            target_user: None,
                            target_resource: None,
                            details: format!("Screen sharing activity detected: {}", name),
                            confidence: 0.70,
                        };

                        let event = Self::create_lateral_movement_event(&lm_event);
                        if tx.send(event).await.is_err() {
                            warn!("Event channel closed");
                            return;
                        }
                    }
                }
            }

            known_pids = current_pids;
        }
    }

    #[cfg(target_os = "macos")]
    async fn get_macos_connections() -> Vec<(String, String, u16, u32, String)> {
        use std::process::Command;

        let mut results = Vec::new();

        // Use lsof to get network connections
        let output = match Command::new("lsof")
            .args(["-i", "-n", "-P", "-F", "pcnPt"])
            .output()
        {
            Ok(o) => o,
            Err(_) => return results,
        };

        if !output.status.success() {
            return results;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut current_pid: u32 = 0;
        let mut current_name = String::new();

        for line in stdout.lines() {
            if line.is_empty() {
                continue;
            }

            let field_type = line.chars().next().unwrap_or(' ');
            let value = &line[1..];

            match field_type {
                'p' => current_pid = value.parse().unwrap_or(0),
                'c' => current_name = value.to_string(),
                'n' => {
                    if let Some((local, remote)) = value.split_once("->") {
                        if let (Some((lip, _lport)), Some((rip, rport))) = (
                            Self::parse_macos_addr(local),
                            Self::parse_macos_addr(remote),
                        ) {
                            results.push((lip, rip, rport, current_pid, current_name.clone()));
                        }
                    }
                }
                _ => {}
            }
        }

        results
    }

    #[cfg(target_os = "macos")]
    fn parse_macos_addr(addr: &str) -> Option<(String, u16)> {
        if addr.starts_with('[') {
            // IPv6
            if let Some(bracket_end) = addr.find(']') {
                let ip = &addr[1..bracket_end];
                let port_str = addr.get(bracket_end + 2..)?;
                let port = port_str.parse().ok()?;
                return Some((ip.to_string(), port));
            }
        } else {
            // IPv4
            if let Some(colon_pos) = addr.rfind(':') {
                let ip = &addr[..colon_pos];
                let port = addr[colon_pos + 1..].parse().ok()?;
                return Some((ip.to_string(), port));
            }
        }
        None
    }
}
