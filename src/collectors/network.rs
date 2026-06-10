//! Network event collector
//!
//! Monitors network connections and DNS queries.

// Network collector. Scaffolded fields and helper functions retained for
// upcoming platform-specific dispatch.
#![allow(dead_code, unused_variables)]

use super::{
    governor_aware_interval::GovernorAwareInterval, EventPayload, EventType, NetworkEvent,
    Severity, TelemetryEvent,
};
use crate::config::AgentConfig;
use crate::resource_governor::GovernorHandle;
use std::collections::HashSet;
use tokio::sync::mpsc;
use tracing::{error, info, trace, warn};

#[cfg(target_os = "windows")]
use std::net::Ipv4Addr;

/// Network collector
pub struct NetworkCollector {
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
}

impl NetworkCollector {
    /// Create a new network collector
    ///
    /// `governor_handle`: Optional handle to resource governor for pressure-aware interval scaling
    pub fn new(config: &AgentConfig) -> Self {
        Self::with_governor(config, None)
    }

    /// Create a network collector with optional governor handle for pressure-aware scaling
    pub fn with_governor(config: &AgentConfig, governor_handle: Option<GovernorHandle>) -> Self {
        let (tx, rx) = mpsc::channel(1000);

        // Start monitoring in background
        let config_clone = config.clone();
        tokio::spawn(async move {
            Self::monitor_loop(tx, config_clone, governor_handle).await;
        });

        Self {
            config: config.clone(),
            event_rx: rx,
        }
    }

    async fn monitor_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        _config: AgentConfig,
        governor_handle: Option<GovernorHandle>,
    ) {
        let mut known_connections: HashSet<String> = HashSet::new();
        // Use configurable network poll interval from collector_tuning.
        // Controlled by the performance profile (aggressive=500ms, balanced=1s, lightweight=10s).
        let poll_ms = _config.collector_tuning.network_poll_interval_ms;
        let mut interval = GovernorAwareInterval::new(
            tokio::time::Duration::from_millis(poll_ms.max(200)),
            governor_handle.clone(),
        );
        info!(
            base_interval_ms = poll_ms.max(200),
            governor_enabled = governor_handle.is_some(),
            "Network collector started (pressure-aware interval scaling)"
        );

        loop {
            interval.tick().await;

            // Get current connections
            let connections = Self::get_connections().await;

            for conn in &connections {
                let conn_key = format!(
                    "{}:{}-{}:{}",
                    conn.local_ip, conn.local_port, conn.remote_ip, conn.remote_port
                );

                if !known_connections.contains(&conn_key) {
                    let event = TelemetryEvent::new(
                        EventType::NetworkConnect,
                        Severity::Info,
                        EventPayload::Network(conn.clone()),
                    );

                    if tx.send(event).await.is_err() {
                        warn!("Event channel closed");
                        return;
                    }

                    known_connections.insert(conn_key);
                }
            }

            // Clean up old connections
            let current_keys: HashSet<String> = connections
                .iter()
                .map(|c| {
                    format!(
                        "{}:{}-{}:{}",
                        c.local_ip, c.local_port, c.remote_ip, c.remote_port
                    )
                })
                .collect();

            known_connections.retain(|k| current_keys.contains(k));
        }
    }

    async fn get_connections() -> Vec<NetworkEvent> {
        // Platform-specific connection enumeration
        #[cfg(target_os = "linux")]
        {
            return Self::get_connections_linux().await;
        }

        #[cfg(target_os = "windows")]
        {
            return Self::get_connections_windows().await;
        }

        #[cfg(target_os = "macos")]
        {
            return Self::get_connections_macos().await;
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        {
            return Vec::new();
        }
    }

    #[cfg(target_os = "linux")]
    async fn get_connections_linux() -> Vec<NetworkEvent> {
        // Build inode -> (pid, process_name) map from /proc/*/fd
        let inode_map = Self::build_socket_inode_map().await;

        let mut connections = Vec::new();

        if let Ok(content) = tokio::fs::read_to_string("/proc/net/tcp").await {
            for line in content.lines().skip(1) {
                if let Some(conn) = Self::parse_proc_net_line(line, "tcp", &inode_map) {
                    connections.push(conn);
                }
            }
        }

        if let Ok(content) = tokio::fs::read_to_string("/proc/net/tcp6").await {
            for line in content.lines().skip(1) {
                if let Some(conn) = Self::parse_proc_net_line(line, "tcp", &inode_map) {
                    connections.push(conn);
                }
            }
        }

        if let Ok(content) = tokio::fs::read_to_string("/proc/net/udp").await {
            for line in content.lines().skip(1) {
                if let Some(conn) = Self::parse_proc_net_line(line, "udp", &inode_map) {
                    connections.push(conn);
                }
            }
        }

        trace!("Found {} active connections on Linux", connections.len());
        connections
    }

    #[cfg(target_os = "linux")]
    async fn build_socket_inode_map() -> std::collections::HashMap<u64, (u64, String)> {
        use std::collections::HashMap;

        let mut inode_map: HashMap<u64, (u64, String)> = HashMap::new();

        // Read /proc to get all PIDs
        let proc_dir = match tokio::fs::read_dir("/proc").await {
            Ok(d) => d,
            Err(_) => return inode_map,
        };

        let mut entries = proc_dir;
        while let Ok(Some(entry)) = entries.next_entry().await {
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();

            // Check if it's a PID directory (numeric name)
            let pid: u64 = match name.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Get process name from /proc/[pid]/comm
            let comm_path = format!("/proc/{}/comm", pid);
            let process_name = match tokio::fs::read_to_string(&comm_path).await {
                Ok(name) => name.trim().to_string(),
                Err(_) => format!("pid:{}", pid),
            };

            // Read /proc/[pid]/fd directory
            let fd_path = format!("/proc/{}/fd", pid);
            let fd_dir = match tokio::fs::read_dir(&fd_path).await {
                Ok(d) => d,
                Err(_) => continue,
            };

            let mut fd_entries = fd_dir;
            while let Ok(Some(fd_entry)) = fd_entries.next_entry().await {
                let fd_path = fd_entry.path();

                // Read symlink target
                if let Ok(target) = tokio::fs::read_link(&fd_path).await {
                    let target_str = target.to_string_lossy();

                    // Check if it's a socket: "socket:[12345]"
                    if target_str.starts_with("socket:[") && target_str.ends_with(']') {
                        if let Ok(inode) = target_str[8..target_str.len() - 1].parse::<u64>() {
                            inode_map.insert(inode, (pid, process_name.clone()));
                        }
                    }
                }
            }
        }

        debug!("Built socket inode map with {} entries", inode_map.len());
        inode_map
    }

    #[cfg(target_os = "linux")]
    fn parse_proc_net_line(
        line: &str,
        protocol: &str,
        inode_map: &std::collections::HashMap<u64, (u64, String)>,
    ) -> Option<NetworkEvent> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            return None;
        }

        let local = parts[1];
        let remote = parts[2];
        let _state = parts[3];
        let inode: u64 = parts[9].parse().unwrap_or(0);

        let (local_ip, local_port) = Self::parse_hex_address(local)?;
        let (remote_ip, remote_port) = Self::parse_hex_address(remote)?;

        // Skip listening sockets and localhost
        if remote_port == 0 || remote_ip == "0.0.0.0" || remote_ip == "127.0.0.1" {
            return None;
        }

        // Lookup PID from inode
        let (pid, process_name) = inode_map.get(&inode).cloned().unwrap_or((0, String::new()));

        Some(NetworkEvent {
            pid: pid as u32,
            process_name,
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            protocol: protocol.to_string(),
            direction: if local_port < 1024 {
                "inbound"
            } else {
                "outbound"
            }
            .to_string(),
            bytes_sent: 0,
            bytes_received: 0,
            ..Default::default()
        })
    }

    #[cfg(target_os = "linux")]
    fn parse_hex_address(hex: &str) -> Option<(String, u16)> {
        let parts: Vec<&str> = hex.split(':').collect();
        if parts.len() != 2 {
            return None;
        }

        let ip_hex = parts[0];
        let port_hex = parts[1];

        // Parse IP (stored in little-endian)
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

    #[cfg(target_os = "windows")]
    async fn get_connections_windows() -> Vec<NetworkEvent> {
        let mut connections = Vec::new();

        // TCP connections
        use windows::Win32::NetworkManagement::IpHelper::{
            GetExtendedTcpTable, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
        };

        use windows::Win32::Networking::WinSock::AF_INET;

        // First call to get buffer size
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
            // Allocate buffer
            let mut buffer: Vec<u8> = vec![0u8; size as usize];

            // Second call to get actual data
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

            if result != 0 {
                error!("GetExtendedTcpTable failed with error: {:?}", result);
            } else {
                // Parse the table
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

                    // Get pointer to first row
                    let rows_ptr = table.table.as_ptr();

                    for i in 0..num_entries {
                        let row = unsafe { &*rows_ptr.add(i) };

                        // Convert IP addresses from network byte order
                        let local_ip = Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes());
                        let remote_ip = Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes());

                        // Ports are in network byte order (big-endian)
                        let local_port = u16::from_be(row.dwLocalPort as u16);
                        let remote_port = u16::from_be(row.dwRemotePort as u16);

                        // Skip listening sockets and localhost connections
                        if remote_port == 0 || remote_ip.is_loopback() || remote_ip.is_unspecified()
                        {
                            continue;
                        }

                        // Get process name from PID
                        let pid = row.dwOwningPid;
                        let process_name = Self::get_process_name_windows(pid);

                        connections.push(NetworkEvent {
                            pid: pid as u32,
                            process_name,
                            local_ip: local_ip.to_string(),
                            local_port,
                            remote_ip: remote_ip.to_string(),
                            remote_port,
                            protocol: "tcp".to_string(),
                            direction: if local_port < 1024 {
                                "inbound"
                            } else {
                                "outbound"
                            }
                            .to_string(),
                            bytes_sent: 0,
                            bytes_received: 0,
                            ..Default::default()
                        });
                    }
                }
            }
        }

        trace!(
            "Found {} active TCP connections on Windows",
            connections.len()
        );

        // UDP connections
        connections.extend(Self::get_udp_connections_windows().await);

        connections
    }

    #[cfg(target_os = "windows")]
    fn get_process_name_windows(pid: u32) -> String {
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

    #[cfg(target_os = "windows")]
    async fn get_udp_connections_windows() -> Vec<NetworkEvent> {
        use windows::Win32::NetworkManagement::IpHelper::{
            GetExtendedUdpTable, MIB_UDPTABLE_OWNER_PID, UDP_TABLE_OWNER_PID,
        };

        use windows::Win32::Networking::WinSock::AF_INET;

        let mut connections = Vec::new();

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
            return connections;
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
            return connections;
        }

        let table = unsafe { &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
        let num_entries = table.dwNumEntries as usize;

        if num_entries == 0 {
            return connections;
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

        for i in 0..num_entries {
            let row = unsafe { &*rows_ptr.add(i) };

            let local_ip = Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes());
            let local_port = u16::from_be(row.dwLocalPort as u16);
            let pid = row.dwOwningPid;

            // Skip localhost UDP bindings
            if local_ip.is_loopback() {
                continue;
            }

            let process_name = Self::get_process_name_windows(pid);

            connections.push(NetworkEvent {
                pid: pid as u32,
                process_name,
                local_ip: local_ip.to_string(),
                local_port,
                remote_ip: "0.0.0.0".to_string(),
                remote_port: 0,
                protocol: "udp".to_string(),
                direction: "listening".to_string(),
                bytes_sent: 0,
                bytes_received: 0,
                ..Default::default()
            });
        }

        connections
    }

    #[cfg(target_os = "macos")]
    async fn get_connections_macos() -> Vec<NetworkEvent> {
        use std::process::Command;
        use std::sync::atomic::{AtomicBool, Ordering};

        static LSOF_WARNED: AtomicBool = AtomicBool::new(false);

        let native_connections: Vec<NetworkEvent> = macos_network::get_active_connections()
            .into_iter()
            .map(Into::into)
            .collect();
        if !native_connections.is_empty() {
            trace!(
                "Found {} active connections on macOS via libproc",
                native_connections.len()
            );
            return native_connections;
        }

        // Use lsof to get network connections with PID, protocol, address, and TCP state.
        let output = match Command::new("lsof")
            .args(["-i", "-n", "-P", "-F", "pcnPT"])
            .output()
        {
            Ok(o) => o,
            Err(e) => {
                if LSOF_WARNED.swap(true, Ordering::Relaxed) {
                    debug!("Failed to run lsof, falling back to netstat: {}", e);
                } else {
                    warn!("Failed to run lsof, falling back to netstat: {}", e);
                }
                return Self::get_connections_macos_netstat().await;
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if LSOF_WARNED.swap(true, Ordering::Relaxed) {
                debug!(
                    status = ?output.status.code(),
                    stderr = %stderr.trim(),
                    "lsof failed, falling back to netstat for macOS network connections"
                );
            } else {
                warn!(
                    status = ?output.status.code(),
                    stderr = %stderr.trim(),
                    "lsof failed, falling back to netstat for macOS network connections"
                );
            }
            return Self::get_connections_macos_netstat().await;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let connections = Self::parse_macos_lsof_output(&stdout);

        trace!("Found {} active connections on macOS", connections.len());
        connections
    }

    #[cfg(target_os = "macos")]
    async fn get_connections_macos_netstat() -> Vec<NetworkEvent> {
        use std::process::Command;
        use std::sync::atomic::{AtomicBool, Ordering};

        static NETSTAT_TCP_WARNED: AtomicBool = AtomicBool::new(false);
        static NETSTAT_UDP_WARNED: AtomicBool = AtomicBool::new(false);

        let mut connections = Vec::new();

        for protocol in ["tcp", "udp"] {
            let warned = if protocol == "tcp" {
                &NETSTAT_TCP_WARNED
            } else {
                &NETSTAT_UDP_WARNED
            };
            let output = match Command::new("netstat")
                .args(["-anv", "-p", protocol])
                .output()
            {
                Ok(output) => output,
                Err(e) => {
                    if warned.swap(true, Ordering::Relaxed) {
                        debug!(error = %e, protocol, "Failed to run netstat fallback");
                    } else {
                        warn!(error = %e, protocol, "Failed to run netstat fallback");
                    }
                    continue;
                }
            };

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if warned.swap(true, Ordering::Relaxed) {
                    debug!(
                        status = ?output.status.code(),
                        stderr = %stderr.trim(),
                        protocol,
                        "netstat fallback failed"
                    );
                } else {
                    warn!(
                        status = ?output.status.code(),
                        stderr = %stderr.trim(),
                        protocol,
                        "netstat fallback failed"
                    );
                }
                continue;
            }

            let stdout = String::from_utf8_lossy(&output.stdout);
            connections.extend(Self::parse_macos_netstat_output(&stdout));
        }

        trace!(
            "Found {} active connections on macOS via netstat fallback",
            connections.len()
        );
        connections
    }

    fn parse_macos_netstat_output(output: &str) -> Vec<NetworkEvent> {
        output
            .lines()
            .filter_map(Self::parse_macos_netstat_line)
            .collect()
    }

    fn parse_macos_netstat_line(line: &str) -> Option<NetworkEvent> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            return None;
        }

        let protocol = parts
            .first()?
            .trim_end_matches(|c: char| c.is_ascii_digit());
        if protocol != "tcp" && protocol != "udp" {
            return None;
        }

        let (local_ip, local_port) = Self::parse_macos_netstat_addr(parts.get(3)?)?;
        let (remote_ip, remote_port) = Self::parse_macos_netstat_addr(parts.get(4)?)?;
        if remote_port == 0 || Self::is_macos_ignored_remote_ip(&remote_ip) {
            return None;
        }

        let state = if protocol == "tcp" {
            parts.get(5).map(|value| (*value).to_string())
        } else {
            None
        };

        // `netstat -anv` exposes PID but not process name. The PID column is after
        // rhiwat/shiwat; UDP omits the state column, so its index is one lower.
        let pid_index = if protocol == "tcp" { 8 } else { 7 };
        let pid = parts
            .get(pid_index)
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(0);

        Some(NetworkEvent {
            pid,
            process_name: if pid == 0 {
                "unknown".to_string()
            } else {
                format!("pid:{}", pid)
            },
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            protocol: protocol.to_string(),
            direction: if local_port < 1024 {
                "inbound"
            } else {
                "outbound"
            }
            .to_string(),
            state,
            bytes_sent: 0,
            bytes_received: 0,
            ..Default::default()
        })
    }

    fn parse_macos_netstat_addr(addr: &str) -> Option<(String, u16)> {
        let addr = addr.trim();
        if addr == "*.*" || addr == "*" {
            return Some(("*".to_string(), 0));
        }

        let (ip, port) = addr.rsplit_once('.')?;
        let port = port.parse().ok()?;
        Some((ip.to_string(), port))
    }

    fn parse_macos_lsof_output(output: &str) -> Vec<NetworkEvent> {
        let mut connections = Vec::new();
        let mut current_pid: u64 = 0;
        let mut current_name = String::new();
        let mut current_protocol = String::new();
        let mut current_name_field: Option<String> = None;
        let mut current_state: Option<String> = None;

        for line in output.lines() {
            if line.is_empty() {
                continue;
            }

            let field_type = line.chars().next().unwrap_or(' ');
            let value = &line[1..];

            match field_type {
                'p' => {
                    Self::push_macos_lsof_connection(
                        &mut connections,
                        current_pid,
                        &current_name,
                        &current_protocol,
                        current_name_field.take(),
                        current_state.take(),
                    );
                    current_pid = value.parse().unwrap_or(0);
                    current_protocol.clear();
                }
                'c' => current_name = value.to_string(),
                'P' => {
                    Self::push_macos_lsof_connection(
                        &mut connections,
                        current_pid,
                        &current_name,
                        &current_protocol,
                        current_name_field.take(),
                        current_state.take(),
                    );
                    current_protocol = value.to_ascii_lowercase();
                }
                'n' => {
                    Self::push_macos_lsof_connection(
                        &mut connections,
                        current_pid,
                        &current_name,
                        &current_protocol,
                        current_name_field.take(),
                        current_state.take(),
                    );
                    current_name_field = Some(value.to_string());
                }
                'T' => current_state = Self::parse_macos_lsof_tcp_state(value).or(current_state),
                _ => {}
            }
        }

        Self::push_macos_lsof_connection(
            &mut connections,
            current_pid,
            &current_name,
            &current_protocol,
            current_name_field,
            current_state,
        );

        connections
    }

    fn push_macos_lsof_connection(
        connections: &mut Vec<NetworkEvent>,
        pid: u64,
        process_name: &str,
        protocol: &str,
        name_field: Option<String>,
        state: Option<String>,
    ) {
        let Some(name_field) = name_field else {
            return;
        };

        let Some((local, remote)) = name_field.split_once("->") else {
            return;
        };

        let (Some((local_ip, local_port)), Some((remote_ip, remote_port))) = (
            Self::parse_macos_addr(local),
            Self::parse_macos_addr(remote),
        ) else {
            return;
        };

        if remote_port == 0 || Self::is_macos_ignored_remote_ip(&remote_ip) {
            return;
        }

        connections.push(NetworkEvent {
            pid: pid as u32,
            process_name: process_name.to_string(),
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            protocol: protocol.to_string(),
            direction: if local_port < 1024 {
                "inbound"
            } else {
                "outbound"
            }
            .to_string(),
            state,
            bytes_sent: 0,
            bytes_received: 0,
            ..Default::default()
        });
    }

    fn parse_macos_lsof_tcp_state(value: &str) -> Option<String> {
        value
            .strip_prefix("ST=")
            .map(str::trim)
            .filter(|state| !state.is_empty())
            .map(ToString::to_string)
    }

    fn is_macos_ignored_remote_ip(ip: &str) -> bool {
        matches!(ip, "0.0.0.0" | "::" | "127.0.0.1" | "::1" | "*")
    }

    fn parse_macos_addr(addr: &str) -> Option<(String, u16)> {
        let addr = addr.trim();
        let addr = addr.split_once(' ').map(|(addr, _)| addr).unwrap_or(addr);

        // Handle IPv4: "192.168.1.1:443" or IPv6: "[::1]:443"
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

    /// Get next event from collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::NetworkCollector;

    #[test]
    fn parses_macos_lsof_output_with_tcp_state() {
        let output = "\
p123
cSafari
PTCP
n192.168.1.10:54832->142.250.190.78:443
TST=ESTABLISHED
p456
cSlack
PUDP
n192.168.1.10:53521->8.8.8.8:53
";

        let connections = NetworkCollector::parse_macos_lsof_output(output);

        assert_eq!(connections.len(), 2);
        assert_eq!(connections[0].pid, 123);
        assert_eq!(connections[0].process_name, "Safari");
        assert_eq!(connections[0].remote_ip, "142.250.190.78");
        assert_eq!(connections[0].remote_port, 443);
        assert_eq!(connections[0].protocol, "tcp");
        assert_eq!(connections[0].state.as_deref(), Some("ESTABLISHED"));
        assert_eq!(connections[0].sni, None);
        assert_eq!(connections[0].ja3, None);
        assert_eq!(connections[0].certificate, None);

        assert_eq!(connections[1].process_name, "Slack");
        assert_eq!(connections[1].remote_ip, "8.8.8.8");
        assert_eq!(connections[1].remote_port, 53);
        assert_eq!(connections[1].protocol, "udp");
        assert_eq!(connections[1].state, None);
    }

    #[test]
    fn skips_macos_lsof_loopback_and_listeners() {
        let output = "\
p123
cLocal
PTCP
n127.0.0.1:5000->127.0.0.1:6000
TST=ESTABLISHED
p456
cServer
PTCP
n*:8080
TST=LISTEN
";

        let connections = NetworkCollector::parse_macos_lsof_output(output);

        assert!(connections.is_empty());
    }

    #[test]
    fn parses_macos_netstat_fallback_output() {
        let output = "\
Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)      rhiwat  shiwat    pid   epid state  options
tcp4       0      0  192.168.12.117.56981   168.205.203.166.8443   ESTABLISHED 3428168  131072  67544      0 00182 00000000
udp6       0      0  2804:149c:2:c255.62470 2800:3f0:4001:80.443               1048576   29040   1677      0 00102 00000000
udp4       0      0  *.*                    *.*                                 786896    9216  67312      0 00000 00000000
";

        let connections = NetworkCollector::parse_macos_netstat_output(output);

        assert_eq!(connections.len(), 2);
        assert_eq!(connections[0].pid, 67544);
        assert_eq!(connections[0].protocol, "tcp");
        assert_eq!(connections[0].remote_ip, "168.205.203.166");
        assert_eq!(connections[0].remote_port, 8443);
        assert_eq!(connections[0].state.as_deref(), Some("ESTABLISHED"));

        assert_eq!(connections[1].pid, 1677);
        assert_eq!(connections[1].protocol, "udp");
        assert_eq!(connections[1].remote_port, 443);
    }
}

// ============================================================================
// macOS Network Monitoring using libproc
// ============================================================================

/// macOS-specific network monitoring using libproc APIs
/// Provides process-to-socket correlation without requiring external tools
#[cfg(target_os = "macos")]
pub mod macos_network {
    use super::{EventPayload, EventType, NetworkEvent, Severity, TelemetryEvent};
    use std::ffi::CStr;
    use std::mem::MaybeUninit;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use tracing::{debug, trace, warn};

    // libproc constants
    const PROC_PIDLISTFDS: i32 = 1;
    const PROC_PIDFDSOCKETINFO: i32 = 3;
    const PROX_FDTYPE_SOCKET: i32 = 2;

    // Socket info families
    const AF_INET: i32 = 2;
    const AF_INET6: i32 = 30;

    // Socket kinds
    const SOCKINFO_TCP: i32 = 1;
    const SOCKINFO_IN: i32 = 2;

    // TCP states
    const TCPS_ESTABLISHED: i32 = 4;
    const TCPS_SYN_SENT: i32 = 2;
    const TCPS_SYN_RECEIVED: i32 = 3;
    const TCPS_FIN_WAIT_1: i32 = 5;
    const TCPS_FIN_WAIT_2: i32 = 6;
    const TCPS_TIME_WAIT: i32 = 10;
    const TCPS_CLOSED: i32 = 0;
    const TCPS_CLOSE_WAIT: i32 = 7;
    const TCPS_LAST_ACK: i32 = 8;
    const TCPS_LISTEN: i32 = 1;
    const TCPS_CLOSING: i32 = 9;

    /// File descriptor info structure
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct ProcFdInfo {
        pub proc_fd: i32,
        pub proc_fdtype: u32,
    }

    /// Socket info structure
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct SocketFdInfo {
        pub pfi: ProcFileInfo,
        pub psi: SocketInfo,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct ProcFileInfo {
        pub fi_openflags: u32,
        pub fi_status: u32,
        pub fi_offset: i64,
        pub fi_type: i32,
        pub fi_guardflags: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct SocketInfo {
        pub soi_stat: SoiStat,
        pub soi_so: u64,
        pub soi_pcb: u64,
        pub soi_type: i32,
        pub soi_protocol: i32,
        pub soi_family: i32,
        pub soi_options: i16,
        pub soi_linger: i16,
        pub soi_state: i16,
        pub soi_qlen: i16,
        pub soi_incqlen: i16,
        pub soi_qlimit: i16,
        pub soi_timeo: i16,
        pub soi_error: u16,
        pub soi_oobmark: u32,
        pub soi_rcv: SockBufInfo,
        pub soi_snd: SockBufInfo,
        pub soi_kind: i32,
        pub soi_proto: SoiProtoUnion,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct SoiStat {
        pub vst_dev: u32,
        pub vst_mode: u16,
        pub vst_nlink: u16,
        pub vst_ino: u64,
        pub vst_uid: u32,
        pub vst_gid: u32,
        pub vst_atime: i64,
        pub vst_atimensec: i64,
        pub vst_mtime: i64,
        pub vst_mtimensec: i64,
        pub vst_ctime: i64,
        pub vst_ctimensec: i64,
        pub vst_birthtime: i64,
        pub vst_birthtimensec: i64,
        pub vst_size: i64,
        pub vst_blocks: i64,
        pub vst_blksize: i32,
        pub vst_flags: u32,
        pub vst_gen: u32,
        pub vst_rdev: u32,
        pub vst_qspare: [i64; 2],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct SockBufInfo {
        pub sbi_cc: u32,
        pub sbi_hiwat: u32,
        pub sbi_mbcnt: u32,
        pub sbi_mbmax: u32,
        pub sbi_lowat: u32,
        pub sbi_flags: i16,
        pub sbi_timeo: i16,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub union SoiProtoUnion {
        pub pri_in: InSockInfo,
        pub pri_tcp: TcpSockInfo,
        pub pri_un: UnSockInfo,
        pub pri_ndrv: NdrvInfo,
        pub pri_kern_event: KernEventInfo,
        pub pri_kern_ctl: KernCtlInfo,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct InSockInfo {
        pub insi_fport: i32,
        pub insi_lport: i32,
        pub insi_gencnt: u64,
        pub insi_flags: u32,
        pub insi_flow: u32,
        pub insi_vflag: u8,
        pub insi_ip_ttl: u8,
        pub rfu_1: u32,
        pub insi_faddr: InAddr,
        pub insi_laddr: InAddr,
        pub insi_v4: In4In6Addr,
        pub insi_v6: In4In6Addr,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct TcpSockInfo {
        pub tcpsi_ini: InSockInfo,
        pub tcpsi_state: i32,
        pub tcpsi_timer: [i32; 4],
        pub tcpsi_mss: i32,
        pub tcpsi_flags: u32,
        pub rfu_1: u32,
        pub tcpsi_tp: u64,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct UnSockInfo {
        pub unsi_conn_so: u64,
        pub unsi_conn_pcb: u64,
        pub unsi_addr: UnSockAddr,
        pub unsi_caddr: UnSockAddr,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct UnSockAddr {
        pub ua_sun: [u8; 255],
        pub ua_dummy: [u8; 1],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct NdrvInfo {
        pub ndrvsi_if_family: u32,
        pub ndrvsi_if_unit: u32,
        pub ndrvsi_if_name: [u8; 16],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct KernEventInfo {
        pub kesi_vendor_code_filter: u32,
        pub kesi_class_filter: u32,
        pub kesi_subclass_filter: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct KernCtlInfo {
        pub kcsi_id: u32,
        pub kcsi_reg_unit: u32,
        pub kcsi_flags: u32,
        pub kcsi_recvbufsize: u32,
        pub kcsi_sendbufsize: u32,
        pub kcsi_unit: u32,
        pub kcsi_name: [u8; 96],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub union InAddr {
        pub ina_46: In4In6Addr,
        pub ina_6: [u8; 16],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct In4In6Addr {
        pub i46a_pad32: [u32; 3],
        pub i46a_addr4: [u8; 4],
    }

    // libproc function declarations
    extern "C" {
        fn proc_pidinfo(
            pid: i32,
            flavor: i32,
            arg: u64,
            buffer: *mut libc::c_void,
            buffersize: i32,
        ) -> i32;

        fn proc_name(pid: i32, buffer: *mut libc::c_void, buffersize: u32) -> i32;
    }

    /// Get process name using libproc
    pub fn get_process_name(pid: i32) -> Option<String> {
        let mut buffer = [0u8; 256];

        let result = unsafe { proc_name(pid, buffer.as_mut_ptr() as *mut libc::c_void, 256) };

        if result <= 0 {
            return None;
        }

        let name = unsafe { CStr::from_ptr(buffer.as_ptr() as *const libc::c_char) };
        Some(name.to_string_lossy().to_string())
    }

    /// Get all file descriptors for a process
    pub fn get_process_fds(pid: i32) -> Vec<ProcFdInfo> {
        // First call to get buffer size
        let buffer_size = unsafe { proc_pidinfo(pid, PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };

        if buffer_size <= 0 {
            return Vec::new();
        }

        let num_fds = buffer_size as usize / std::mem::size_of::<ProcFdInfo>();
        let mut fds = vec![
            ProcFdInfo {
                proc_fd: 0,
                proc_fdtype: 0
            };
            num_fds
        ];

        let result = unsafe {
            proc_pidinfo(
                pid,
                PROC_PIDLISTFDS,
                0,
                fds.as_mut_ptr() as *mut libc::c_void,
                buffer_size,
            )
        };

        if result <= 0 {
            return Vec::new();
        }

        let actual_count = result as usize / std::mem::size_of::<ProcFdInfo>();
        fds.truncate(actual_count);
        fds
    }

    /// Get socket info for a specific file descriptor
    pub fn get_socket_info(pid: i32, fd: i32) -> Option<SocketFdInfo> {
        let mut info = MaybeUninit::<SocketFdInfo>::uninit();

        let result = unsafe {
            proc_pidinfo(
                pid,
                PROC_PIDFDSOCKETINFO,
                fd as u64,
                info.as_mut_ptr() as *mut libc::c_void,
                std::mem::size_of::<SocketFdInfo>() as i32,
            )
        };

        if result <= 0 {
            return None;
        }

        Some(unsafe { info.assume_init() })
    }

    /// Get all network connections for a process
    pub fn get_process_connections(pid: i32) -> Vec<NetworkConnectionInfo> {
        let mut connections = Vec::new();
        let process_name = get_process_name(pid).unwrap_or_else(|| format!("pid:{}", pid));
        let fds = get_process_fds(pid);

        for fd_info in fds {
            // Only process socket FDs
            if fd_info.proc_fdtype != PROX_FDTYPE_SOCKET as u32 {
                continue;
            }

            if let Some(socket_info) = get_socket_info(pid, fd_info.proc_fd) {
                // Only process IPv4/IPv6 TCP/UDP sockets
                if socket_info.psi.soi_family != AF_INET && socket_info.psi.soi_family != AF_INET6 {
                    continue;
                }

                let conn = match socket_info.psi.soi_kind {
                    SOCKINFO_TCP => {
                        let tcp = unsafe { socket_info.psi.soi_proto.pri_tcp };
                        parse_tcp_connection(pid, &process_name, &tcp)
                    }
                    SOCKINFO_IN => {
                        let in_sock = unsafe { socket_info.psi.soi_proto.pri_in };
                        parse_udp_connection(pid, &process_name, &in_sock)
                    }
                    _ => None,
                };

                if let Some(c) = conn {
                    connections.push(c);
                }
            }
        }

        connections
    }

    fn parse_tcp_connection(
        pid: i32,
        process_name: &str,
        tcp: &TcpSockInfo,
    ) -> Option<NetworkConnectionInfo> {
        let in_info = &tcp.tcpsi_ini;

        // Get local address
        let local_ip = get_ip_string(&in_info.insi_laddr, in_info.insi_vflag);
        let local_port = (in_info.insi_lport as u16).to_be();

        // Get remote address
        let remote_ip = get_ip_string(&in_info.insi_faddr, in_info.insi_vflag);
        let remote_port = (in_info.insi_fport as u16).to_be();

        // Skip listening sockets for connection events
        let state = tcp_state_string(tcp.tcpsi_state);

        Some(NetworkConnectionInfo {
            pid: pid as u32,
            process_name: process_name.to_string(),
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            protocol: "tcp".to_string(),
            state,
            direction: if tcp.tcpsi_state == TCPS_LISTEN {
                "listening".to_string()
            } else if local_port < 1024 {
                "inbound".to_string()
            } else {
                "outbound".to_string()
            },
        })
    }

    fn parse_udp_connection(
        pid: i32,
        process_name: &str,
        in_sock: &InSockInfo,
    ) -> Option<NetworkConnectionInfo> {
        let local_ip = get_ip_string(&in_sock.insi_laddr, in_sock.insi_vflag);
        let local_port = (in_sock.insi_lport as u16).to_be();

        let remote_ip = get_ip_string(&in_sock.insi_faddr, in_sock.insi_vflag);
        let remote_port = (in_sock.insi_fport as u16).to_be();

        Some(NetworkConnectionInfo {
            pid: pid as u32,
            process_name: process_name.to_string(),
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            protocol: "udp".to_string(),
            state: "none".to_string(),
            direction: if remote_port == 0 {
                "listening".to_string()
            } else {
                "outbound".to_string()
            },
        })
    }

    fn get_ip_string(addr: &InAddr, vflag: u8) -> String {
        // vflag: 1 = IPv4, 2 = IPv6
        if vflag == 1 {
            let bytes = unsafe { addr.ina_46.i46a_addr4 };
            Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string()
        } else {
            let bytes = unsafe { addr.ina_6 };
            Ipv6Addr::from(bytes).to_string()
        }
    }

    fn tcp_state_string(state: i32) -> String {
        match state {
            TCPS_CLOSED => "CLOSED",
            TCPS_LISTEN => "LISTEN",
            TCPS_SYN_SENT => "SYN_SENT",
            TCPS_SYN_RECEIVED => "SYN_RECEIVED",
            TCPS_ESTABLISHED => "ESTABLISHED",
            TCPS_CLOSE_WAIT => "CLOSE_WAIT",
            TCPS_FIN_WAIT_1 => "FIN_WAIT_1",
            TCPS_CLOSING => "CLOSING",
            TCPS_LAST_ACK => "LAST_ACK",
            TCPS_FIN_WAIT_2 => "FIN_WAIT_2",
            TCPS_TIME_WAIT => "TIME_WAIT",
            _ => "UNKNOWN",
        }
        .to_string()
    }

    /// Network connection information
    #[derive(Debug, Clone)]
    pub struct NetworkConnectionInfo {
        pub pid: u32,
        pub process_name: String,
        pub local_ip: String,
        pub local_port: u16,
        pub remote_ip: String,
        pub remote_port: u16,
        pub protocol: String,
        pub state: String,
        pub direction: String,
    }

    impl From<NetworkConnectionInfo> for NetworkEvent {
        fn from(conn: NetworkConnectionInfo) -> Self {
            NetworkEvent {
                pid: conn.pid,
                process_name: conn.process_name,
                local_ip: conn.local_ip,
                local_port: conn.local_port,
                remote_ip: conn.remote_ip,
                remote_port: conn.remote_port,
                protocol: conn.protocol,
                direction: conn.direction,
                state: if conn.state.is_empty() || conn.state == "none" {
                    None
                } else {
                    Some(conn.state)
                },
                bytes_sent: 0,
                bytes_received: 0,
                ..Default::default()
            }
        }
    }

    /// Get all network connections on the system
    pub fn get_all_connections() -> Vec<NetworkConnectionInfo> {
        use super::super::process::macos_process;

        let mut all_connections = Vec::new();
        let pids = macos_process::get_all_pids();

        for pid in pids {
            let conns = get_process_connections(pid);
            all_connections.extend(conns);
        }

        all_connections
    }

    /// Filter to get only active connections (non-listening, non-localhost)
    pub fn get_active_connections() -> Vec<NetworkConnectionInfo> {
        get_all_connections()
            .into_iter()
            .filter(|c| {
                c.state != "LISTEN"
                    && c.remote_port != 0
                    && c.remote_ip != "0.0.0.0"
                    && c.remote_ip != "::"
                    && c.remote_ip != "127.0.0.1"
                    && c.remote_ip != "::1"
            })
            .collect()
    }
}
