//! Live Response Network Connection Manager
//!
//! Provides real-time network connection enumeration and management for incident response.
//! Features:
//! - Active connection tracking (TCP/UDP)
//! - Process mapping (which process owns each connection)
//! - Connection state monitoring (ESTABLISHED, LISTEN, etc.)
//! - Connection termination
//! - Bandwidth tracking
//! - Historical connection tracking

use crate::transport::CommandResult;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info};

/// Network connection information with extended details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    /// Process ID owning the connection
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// Local IP address
    pub local_ip: String,
    /// Local port
    pub local_port: u16,
    /// Remote IP address
    pub remote_ip: String,
    /// Remote port
    pub remote_port: u16,
    /// Protocol (tcp, udp)
    pub protocol: String,
    /// Connection state (ESTABLISHED, LISTEN, SYN_SENT, etc.)
    pub state: String,
    /// Connection direction (inbound, outbound, listening)
    pub direction: String,
    /// Bytes sent (if available)
    pub bytes_sent: u64,
    /// Bytes received (if available)
    pub bytes_received: u64,
    /// When this connection was first seen (Unix timestamp)
    pub first_seen: u64,
    /// When this connection was last seen (Unix timestamp)
    pub last_seen: u64,
    /// Process executable path
    pub process_path: Option<String>,
    /// Whether the process is elevated/privileged
    pub is_elevated: bool,
}

/// Connection identifier (used as hash key)
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct ConnectionId {
    local_ip: String,
    local_port: u16,
    remote_ip: String,
    remote_port: u16,
    protocol: String,
}

impl ConnectionId {
    fn from_connection(conn: &NetworkConnection) -> Self {
        Self {
            local_ip: conn.local_ip.clone(),
            local_port: conn.local_port,
            remote_ip: conn.remote_ip.clone(),
            remote_port: conn.remote_port,
            protocol: conn.protocol.clone(),
        }
    }
}

/// Network connection history tracker
pub struct ConnectionTracker {
    /// Active connections (current snapshot)
    active: HashMap<ConnectionId, NetworkConnection>,
    /// Historical connections (kept for 24h)
    history: Vec<NetworkConnection>,
    /// Maximum history entries
    max_history: usize,
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self {
            active: HashMap::new(),
            history: Vec::new(),
            max_history: 10_000,
        }
    }

    /// Update tracker with new connection snapshot
    pub fn update(&mut self, connections: Vec<NetworkConnection>) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut new_active = HashMap::new();

        for mut conn in connections {
            let id = ConnectionId::from_connection(&conn);

            // If connection exists, preserve first_seen and accumulate bytes
            if let Some(existing) = self.active.get(&id) {
                conn.first_seen = existing.first_seen;
                conn.bytes_sent = existing.bytes_sent.max(conn.bytes_sent);
                conn.bytes_received = existing.bytes_received.max(conn.bytes_received);
            } else {
                conn.first_seen = now;
            }

            conn.last_seen = now;
            new_active.insert(id, conn);
        }

        // Find closed connections and move them to history
        for (id, conn) in &self.active {
            if !new_active.contains_key(id) {
                self.history.push(conn.clone());
            }
        }

        // Trim history if needed
        if self.history.len() > self.max_history {
            let to_remove = self.history.len() - self.max_history;
            self.history.drain(0..to_remove);
        }

        self.active = new_active;
    }

    /// Get active connections
    pub fn get_active(&self) -> Vec<NetworkConnection> {
        self.active.values().cloned().collect()
    }

    /// Get historical connections
    pub fn get_history(&self, since: u64) -> Vec<NetworkConnection> {
        self.history
            .iter()
            .filter(|c| c.last_seen >= since)
            .cloned()
            .collect()
    }

    /// Clear history older than threshold
    pub fn cleanup_history(&mut self, before: u64) {
        self.history.retain(|c| c.last_seen >= before);
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Enumerate all active network connections
pub async fn enumerate_connections() -> Result<Vec<NetworkConnection>, String> {
    #[cfg(target_os = "windows")]
    {
        enumerate_connections_windows().await
    }

    #[cfg(target_os = "linux")]
    {
        enumerate_connections_linux().await
    }

    #[cfg(target_os = "macos")]
    {
        enumerate_connections_macos().await
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        Err("Platform not supported".to_string())
    }
}

#[cfg(target_os = "windows")]
async fn enumerate_connections_windows() -> Result<Vec<NetworkConnection>, String> {
    use std::net::Ipv4Addr;
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    };
    use windows::Win32::Networking::WinSock::AF_INET;

    let mut connections = Vec::new();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Get TCP connections
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
                let header_size = std::mem::size_of::<u32>();
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
                    let local_port = u16::from_be(row.dwLocalPort as u16);
                    let remote_port = u16::from_be(row.dwRemotePort as u16);
                    let pid = row.dwOwningPid;

                    let (process_name, process_path) = get_process_info_windows(pid);
                    let state = get_tcp_state_string(row.dwState as i32);
                    let is_elevated = is_process_elevated_windows(pid);

                    connections.push(NetworkConnection {
                        pid: pid as u32,
                        process_name,
                        local_ip: local_ip.to_string(),
                        local_port,
                        remote_ip: remote_ip.to_string(),
                        remote_port,
                        protocol: "tcp".to_string(),
                        state,
                        direction: if local_port < 1024 {
                            "inbound".to_string()
                        } else {
                            "outbound".to_string()
                        },
                        bytes_sent: 0,
                        bytes_received: 0,
                        first_seen: now,
                        last_seen: now,
                        process_path,
                        is_elevated,
                    });
                }
            }
        }
    }

    // Get UDP connections
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedUdpTable, MIB_UDPTABLE_OWNER_PID, UDP_TABLE_OWNER_PID,
    };

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

    if size > 0 {
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

        if result == 0 {
            let table = unsafe { &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
            let num_entries = table.dwNumEntries as usize;

            if num_entries > 0 {
                let header_size = std::mem::size_of::<u32>();
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

                    let (process_name, process_path) = get_process_info_windows(pid);
                    let is_elevated = is_process_elevated_windows(pid);

                    connections.push(NetworkConnection {
                        pid: pid as u32,
                        process_name,
                        local_ip: local_ip.to_string(),
                        local_port,
                        remote_ip: "0.0.0.0".to_string(),
                        remote_port: 0,
                        protocol: "udp".to_string(),
                        state: "NONE".to_string(),
                        direction: "listening".to_string(),
                        bytes_sent: 0,
                        bytes_received: 0,
                        first_seen: now,
                        last_seen: now,
                        process_path,
                        is_elevated,
                    });
                }
            }
        }
    }

    debug!("Enumerated {} connections on Windows", connections.len());
    Ok(connections)
}

#[cfg(target_os = "windows")]
fn get_process_info_windows(pid: u32) -> (String, Option<String>) {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::ProcessStatus::{GetModuleBaseNameW, GetModuleFileNameExW};
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    if pid == 0 || pid == 4 {
        return (
            if pid == 0 {
                "System Idle".to_string()
            } else {
                "System".to_string()
            },
            None,
        );
    }

    unsafe {
        let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) => h,
            Err(_) => return (format!("pid:{}", pid), None),
        };

        let mut name_buf = [0u16; 260];
        let name_len = GetModuleBaseNameW(handle, None, &mut name_buf);

        let mut path_buf = [0u16; 1024];
        let path_len = GetModuleFileNameExW(handle, None, &mut path_buf);

        let _ = CloseHandle(handle);

        let name = if name_len > 0 {
            String::from_utf16_lossy(&name_buf[..name_len as usize])
        } else {
            format!("pid:{}", pid)
        };

        let path = if path_len > 0 {
            Some(String::from_utf16_lossy(&path_buf[..path_len as usize]))
        } else {
            None
        };

        (name, path)
    }
}

#[cfg(target_os = "windows")]
fn is_process_elevated_windows(pid: u32) -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION,
    };

    if pid == 0 || pid == 4 {
        return true; // System processes are always elevated
    }

    unsafe {
        let process_handle = match OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let mut token_handle = Default::default();
        if OpenProcessToken(process_handle, TOKEN_QUERY, &mut token_handle).is_err() {
            let _ = CloseHandle(process_handle);
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut return_length: u32 = 0;
        let result = GetTokenInformation(
            token_handle,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );

        let _ = CloseHandle(token_handle);
        let _ = CloseHandle(process_handle);

        result.is_ok() && elevation.TokenIsElevated != 0
    }
}

#[cfg(target_os = "windows")]
fn get_tcp_state_string(state: i32) -> String {
    // MIB_TCP_STATE enumeration
    match state {
        1 => "CLOSED".to_string(),
        2 => "LISTEN".to_string(),
        3 => "SYN_SENT".to_string(),
        4 => "SYN_RECEIVED".to_string(),
        5 => "ESTABLISHED".to_string(),
        6 => "FIN_WAIT_1".to_string(),
        7 => "FIN_WAIT_2".to_string(),
        8 => "CLOSE_WAIT".to_string(),
        9 => "CLOSING".to_string(),
        10 => "LAST_ACK".to_string(),
        11 => "TIME_WAIT".to_string(),
        12 => "DELETE_TCB".to_string(),
        _ => format!("UNKNOWN({})", state),
    }
}

#[cfg(target_os = "linux")]
async fn enumerate_connections_linux() -> Result<Vec<NetworkConnection>, String> {
    use std::collections::HashMap;

    let mut connections = Vec::new();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Build inode -> (pid, process_name, process_path) map
    let inode_map = build_socket_inode_map_linux().await;

    // Parse /proc/net/tcp
    if let Ok(content) = tokio::fs::read_to_string("/proc/net/tcp").await {
        for line in content.lines().skip(1) {
            if let Some(conn) = parse_proc_net_line_extended(line, "tcp", &inode_map, now) {
                connections.push(conn);
            }
        }
    }

    // Parse /proc/net/tcp6
    if let Ok(content) = tokio::fs::read_to_string("/proc/net/tcp6").await {
        for line in content.lines().skip(1) {
            if let Some(conn) = parse_proc_net_line_extended(line, "tcp", &inode_map, now) {
                connections.push(conn);
            }
        }
    }

    // Parse /proc/net/udp
    if let Ok(content) = tokio::fs::read_to_string("/proc/net/udp").await {
        for line in content.lines().skip(1) {
            if let Some(conn) = parse_proc_net_line_extended(line, "udp", &inode_map, now) {
                connections.push(conn);
            }
        }
    }

    debug!("Enumerated {} connections on Linux", connections.len());
    Ok(connections)
}

#[cfg(target_os = "linux")]
async fn build_socket_inode_map_linux() -> HashMap<u64, (u64, String, Option<String>)> {
    use std::collections::HashMap;

    let mut inode_map: HashMap<u64, (u64, String, Option<String>)> = HashMap::new();

    let proc_dir = match tokio::fs::read_dir("/proc").await {
        Ok(d) => d,
        Err(_) => return inode_map,
    };

    let mut entries = proc_dir;
    while let Ok(Some(entry)) = entries.next_entry().await {
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();

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

        // Get process path from /proc/[pid]/exe
        let exe_path = format!("/proc/{}/exe", pid);
        let process_path = tokio::fs::read_link(&exe_path)
            .await
            .ok()
            .map(|p| p.to_string_lossy().to_string());

        // Read /proc/[pid]/fd directory
        let fd_path = format!("/proc/{}/fd", pid);
        let fd_dir = match tokio::fs::read_dir(&fd_path).await {
            Ok(d) => d,
            Err(_) => continue,
        };

        let mut fd_entries = fd_dir;
        while let Ok(Some(fd_entry)) = fd_entries.next_entry().await {
            let fd_path = fd_entry.path();

            if let Ok(target) = tokio::fs::read_link(&fd_path).await {
                let target_str = target.to_string_lossy();

                if target_str.starts_with("socket:[") && target_str.ends_with(']') {
                    if let Ok(inode) = target_str[8..target_str.len() - 1].parse::<u64>() {
                        inode_map.insert(inode, (pid, process_name.clone(), process_path.clone()));
                    }
                }
            }
        }
    }

    debug!("Built socket inode map with {} entries", inode_map.len());
    inode_map
}

#[cfg(target_os = "linux")]
fn parse_proc_net_line_extended(
    line: &str,
    protocol: &str,
    inode_map: &HashMap<u64, (u64, String, Option<String>)>,
    now: u64,
) -> Option<NetworkConnection> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 10 {
        return None;
    }

    let local = parts[1];
    let remote = parts[2];
    let state_hex = parts[3];
    let inode: u64 = parts[9].parse().unwrap_or(0);

    let (local_ip, local_port) = parse_hex_address(local)?;
    let (remote_ip, remote_port) = parse_hex_address(remote)?;

    let state = if protocol == "tcp" {
        get_tcp_state_from_hex(state_hex)
    } else {
        "NONE".to_string()
    };

    let (pid, process_name, process_path) =
        inode_map
            .get(&inode)
            .cloned()
            .unwrap_or((0, format!("inode:{}", inode), None));

    let is_elevated = is_process_elevated_linux(pid as u32);

    Some(NetworkConnection {
        pid: pid as u32,
        process_name,
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        protocol: protocol.to_string(),
        state,
        direction: if local_port < 1024 {
            "inbound".to_string()
        } else if remote_port == 0 {
            "listening".to_string()
        } else {
            "outbound".to_string()
        },
        bytes_sent: 0,
        bytes_received: 0,
        first_seen: now,
        last_seen: now,
        process_path,
        is_elevated,
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

    if ip_hex.len() == 8 {
        // IPv4
        let ip = u32::from_str_radix(ip_hex, 16).ok()?;
        let ip_str = format!(
            "{}.{}.{}.{}",
            ip & 0xff,
            (ip >> 8) & 0xff,
            (ip >> 16) & 0xff,
            (ip >> 24) & 0xff
        );
        let port = u16::from_str_radix(port_hex, 16).ok()?;
        Some((ip_str, port))
    } else if ip_hex.len() == 32 {
        // IPv6 - simplified parsing
        let port = u16::from_str_radix(port_hex, 16).ok()?;
        Some(("::".to_string(), port)) // Simplified IPv6
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn get_tcp_state_from_hex(hex: &str) -> String {
    let state = u8::from_str_radix(hex, 16).unwrap_or(0);
    match state {
        0x01 => "ESTABLISHED".to_string(),
        0x02 => "SYN_SENT".to_string(),
        0x03 => "SYN_RECV".to_string(),
        0x04 => "FIN_WAIT1".to_string(),
        0x05 => "FIN_WAIT2".to_string(),
        0x06 => "TIME_WAIT".to_string(),
        0x07 => "CLOSE".to_string(),
        0x08 => "CLOSE_WAIT".to_string(),
        0x09 => "LAST_ACK".to_string(),
        0x0A => "LISTEN".to_string(),
        0x0B => "CLOSING".to_string(),
        _ => format!("UNKNOWN({})", state),
    }
}

#[cfg(target_os = "linux")]
fn is_process_elevated_linux(pid: u32) -> bool {
    // Check if process is running as root (UID 0)
    let status_path = format!("/proc/{}/status", pid);
    if let Ok(content) = std::fs::read_to_string(&status_path) {
        for line in content.lines() {
            if line.starts_with("Uid:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(uid) = parts[1].parse::<u32>() {
                        return uid == 0;
                    }
                }
            }
        }
    }
    false
}

#[cfg(target_os = "macos")]
async fn enumerate_connections_macos() -> Result<Vec<NetworkConnection>, String> {
    use crate::collectors::network::macos_network;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let raw_connections = macos_network::get_all_connections();

    let connections: Vec<NetworkConnection> = raw_connections
        .into_iter()
        .map(|c| {
            let process_path = get_process_path_macos(c.pid as i32);
            let is_elevated = is_process_elevated_macos(c.pid as i32);

            NetworkConnection {
                pid: c.pid,
                process_name: c.process_name,
                local_ip: c.local_ip,
                local_port: c.local_port,
                remote_ip: c.remote_ip,
                remote_port: c.remote_port,
                protocol: c.protocol,
                state: c.state,
                direction: c.direction,
                bytes_sent: 0,
                bytes_received: 0,
                first_seen: now,
                last_seen: now,
                process_path,
                is_elevated,
            }
        })
        .collect();

    debug!("Enumerated {} connections on macOS", connections.len());
    Ok(connections)
}

#[cfg(target_os = "macos")]
fn get_process_path_macos(pid: i32) -> Option<String> {
    use std::ffi::CStr;
    use std::os::raw::c_char;

    const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;

    extern "C" {
        fn proc_pidpath(pid: i32, buffer: *mut c_char, buffersize: u32) -> i32;
    }

    let mut buffer = vec![0u8; PROC_PIDPATHINFO_MAXSIZE];
    let result = unsafe {
        proc_pidpath(
            pid,
            buffer.as_mut_ptr() as *mut c_char,
            PROC_PIDPATHINFO_MAXSIZE as u32,
        )
    };

    if result > 0 {
        let path = unsafe { CStr::from_ptr(buffer.as_ptr() as *const c_char) };
        Some(path.to_string_lossy().to_string())
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn is_process_elevated_macos(pid: i32) -> bool {
    use std::process::Command;

    // Use ps to check if process is running as root
    let output = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "uid="])
        .output();

    if let Ok(out) = output {
        let uid = String::from_utf8_lossy(&out.stdout).trim().to_string();
        uid == "0"
    } else {
        false
    }
}

/// Terminate a network connection
pub async fn terminate_connection(payload: &serde_json::Value) -> CommandResult {
    let local_ip = payload
        .get("local_ip")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let local_port = payload
        .get("local_port")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u16;
    let remote_ip = payload
        .get("remote_ip")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let remote_port = payload
        .get("remote_port")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u16;
    let protocol = payload
        .get("protocol")
        .and_then(|v| v.as_str())
        .unwrap_or("tcp");

    if local_ip.is_empty() || remote_ip.is_empty() {
        return CommandResult {
            success: false,
            error_message: Some("Invalid connection parameters".to_string()),
            result_data: None,
        };
    }

    info!(
        local = format!("{}:{}", local_ip, local_port),
        remote = format!("{}:{}", remote_ip, remote_port),
        protocol = protocol,
        "Terminating network connection"
    );

    #[cfg(target_os = "windows")]
    {
        // Use SetTcpEntry to force close connection
        CommandResult {
            success: false,
            error_message: Some(
                "Connection termination not yet implemented on Windows".to_string(),
            ),
            result_data: None,
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Use ss -K (kill) to terminate connection
        use std::process::Command;

        let filter = format!("dst {}:{}", remote_ip, remote_port);
        let output = Command::new("ss")
            .args(["-K", "dst", &format!("{}:{}", remote_ip, remote_port)])
            .output();

        match output {
            Ok(out) if out.status.success() => CommandResult {
                success: true,
                error_message: None,
                result_data: Some(serde_json::json!({
                    "terminated": true,
                    "connection": format!("{}:{} -> {}:{}", local_ip, local_port, remote_ip, remote_port)
                })),
            },
            Ok(out) => CommandResult {
                success: false,
                error_message: Some(format!(
                    "Failed to terminate: {}",
                    String::from_utf8_lossy(&out.stderr)
                )),
                result_data: None,
            },
            Err(e) => CommandResult {
                success: false,
                error_message: Some(format!("Command failed: {}", e)),
                result_data: None,
            },
        }
    }

    #[cfg(target_os = "macos")]
    {
        CommandResult {
            success: false,
            error_message: Some("Connection termination not yet implemented on macOS".to_string()),
            result_data: None,
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        CommandResult {
            success: false,
            error_message: Some("Platform not supported".to_string()),
            result_data: None,
        }
    }
}

/// Get connection statistics
pub async fn get_connection_stats(connections: &[NetworkConnection]) -> serde_json::Value {
    let total = connections.len();
    let tcp_count = connections.iter().filter(|c| c.protocol == "tcp").count();
    let udp_count = connections.iter().filter(|c| c.protocol == "udp").count();
    let established = connections
        .iter()
        .filter(|c| c.state == "ESTABLISHED")
        .count();
    let listening = connections.iter().filter(|c| c.state == "LISTEN").count();

    // Count unique remote IPs
    let unique_remotes: std::collections::HashSet<_> = connections
        .iter()
        .filter(|c| c.remote_ip != "0.0.0.0" && c.remote_ip != "::")
        .map(|c| &c.remote_ip)
        .collect();

    // Count unique processes
    let unique_processes: std::collections::HashSet<_> =
        connections.iter().map(|c| c.pid).collect();

    serde_json::json!({
        "total_connections": total,
        "tcp_connections": tcp_count,
        "udp_connections": udp_count,
        "established_connections": established,
        "listening_connections": listening,
        "unique_remote_ips": unique_remotes.len(),
        "unique_processes": unique_processes.len(),
    })
}
