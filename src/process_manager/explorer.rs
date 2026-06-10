//! Process Explorer Module
//!
//! Provides comprehensive process enumeration with:
//! - Full process tree with parent-child relationships
//! - Detailed process information (PID, PPID, name, path, cmdline, user, start time)
//! - Resource metrics (memory usage, CPU %, handle count, thread count)
//! - Digital signature status
//! - Network connections per process

use super::{ProcessManagerError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use sysinfo::{Pid, Process, ProcessRefreshKind, System};
use tracing::{debug, info, warn};

#[cfg(target_os = "windows")]
use windows::Win32::{
    Foundation::{CloseHandle, HANDLE},
    NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    },
    System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    },
    System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX},
    System::Threading::{
        GetProcessHandleCount, GetProcessTimes, OpenProcess, PROCESS_QUERY_INFORMATION,
        PROCESS_QUERY_LIMITED_INFORMATION,
    },
};

/// Detailed process information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessDetails {
    /// Process ID
    pub pid: u32,
    /// Parent process ID
    pub ppid: Option<u32>,
    /// Process name
    pub name: String,
    /// Full executable path
    pub path: Option<String>,
    /// Command line arguments
    pub cmdline: Vec<String>,
    /// User running the process
    pub user: Option<String>,
    /// Process start time (Unix timestamp)
    pub start_time: u64,
    /// Memory usage in bytes (RSS)
    pub memory_bytes: u64,
    /// Virtual memory usage in bytes
    pub virtual_memory_bytes: u64,
    /// CPU usage percentage
    pub cpu_percent: f32,
    /// Number of handles (Windows) or file descriptors (Unix)
    pub handle_count: u32,
    /// Number of threads
    pub thread_count: u32,
    /// Is the binary digitally signed
    pub is_signed: bool,
    /// Signer name (if signed)
    pub signer: Option<String>,
    /// Is the process running with elevated privileges
    pub is_elevated: bool,
    /// Process status (Running, Sleeping, etc.)
    pub status: String,
    /// Working directory
    pub working_directory: Option<String>,
    /// Environment variables (security-relevant subset)
    pub environment: Option<HashMap<String, String>>,
    /// Network connections owned by this process
    pub network_connections: Vec<NetworkConnectionInfo>,
}

/// Network connection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnectionInfo {
    /// Protocol (TCP/UDP)
    pub protocol: String,
    /// Local address
    pub local_address: String,
    /// Local port
    pub local_port: u16,
    /// Remote address
    pub remote_address: String,
    /// Remote port
    pub remote_port: u16,
    /// Connection state (for TCP)
    pub state: String,
}

/// Process tree node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTreeNode {
    /// Process details
    pub process: ProcessDetails,
    /// Child processes
    pub children: Vec<ProcessTreeNode>,
}

/// Get the full process tree
pub async fn get_process_tree() -> Result<Vec<ProcessTreeNode>> {
    let processes = get_all_processes().await?;
    let tree = build_process_tree(&processes);
    Ok(tree)
}

/// Get all processes with details
pub async fn get_all_processes() -> Result<Vec<ProcessDetails>> {
    let mut system = System::new();
    system.refresh_processes_specifics(ProcessRefreshKind::everything());

    let mut processes = Vec::new();

    for (pid, process) in system.processes() {
        let pid_u32 = pid.as_u32();

        let details = collect_process_details(pid_u32, process, &system).await;
        processes.push(details);
    }

    Ok(processes)
}

/// Get detailed information about a specific process
pub async fn get_process_details(pid: u32) -> Result<ProcessDetails> {
    let mut system = System::new();
    system.refresh_processes_specifics(ProcessRefreshKind::everything());

    let sysinfo_pid = Pid::from_u32(pid);
    let process = system
        .process(sysinfo_pid)
        .ok_or(ProcessManagerError::ProcessNotFound(pid))?;

    Ok(collect_process_details(pid, process, &system).await)
}

/// Collect all details for a process
async fn collect_process_details(pid: u32, process: &Process, _system: &System) -> ProcessDetails {
    let name = process.name().to_string();
    let path = process.exe().map(|p| p.to_string_lossy().to_string());
    let cmdline = process.cmd().to_vec();
    let user = process.user_id().map(|u| get_username_from_uid(u));
    let start_time = process.start_time();
    let memory_bytes = process.memory();
    let virtual_memory_bytes = process.virtual_memory();
    let cpu_percent = process.cpu_usage();
    let status = format!("{:?}", process.status());
    let ppid = process.parent().map(|p| p.as_u32());
    let working_directory = process.cwd().map(|p| p.to_string_lossy().to_string());

    // Get platform-specific details
    let (handle_count, thread_count) = get_handle_and_thread_count(pid);
    let (is_signed, signer) = get_signature_info(path.as_deref());
    let is_elevated = check_is_elevated(pid);
    let network_connections = get_process_network_connections(pid);
    let environment = get_security_environment(pid);

    ProcessDetails {
        pid,
        ppid,
        name,
        path,
        cmdline,
        user,
        start_time,
        memory_bytes,
        virtual_memory_bytes,
        cpu_percent,
        handle_count,
        thread_count,
        is_signed,
        signer,
        is_elevated,
        status,
        working_directory,
        environment,
        network_connections,
    }
}

/// Build hierarchical process tree from flat list
fn build_process_tree(processes: &[ProcessDetails]) -> Vec<ProcessTreeNode> {
    let mut pid_to_idx: HashMap<u32, usize> = HashMap::new();
    for (idx, proc) in processes.iter().enumerate() {
        pid_to_idx.insert(proc.pid, idx);
    }

    // Find root processes (no parent or parent not in list)
    let mut roots = Vec::new();
    let mut nodes: HashMap<u32, ProcessTreeNode> = HashMap::new();

    // Create nodes for all processes
    for proc in processes {
        nodes.insert(
            proc.pid,
            ProcessTreeNode {
                process: proc.clone(),
                children: Vec::new(),
            },
        );
    }

    // Identify roots and attach children
    for proc in processes {
        let is_root = match proc.ppid {
            None => true,
            Some(ppid) => !pid_to_idx.contains_key(&ppid),
        };

        if is_root {
            if let Some(node) = nodes.remove(&proc.pid) {
                roots.push(node);
            }
        }
    }

    // Recursively attach children
    fn attach_children(
        node: &mut ProcessTreeNode,
        all_processes: &[ProcessDetails],
        nodes: &mut HashMap<u32, ProcessTreeNode>,
    ) {
        let parent_pid = node.process.pid;
        for proc in all_processes {
            if proc.ppid == Some(parent_pid) {
                if let Some(mut child) = nodes.remove(&proc.pid) {
                    attach_children(&mut child, all_processes, nodes);
                    node.children.push(child);
                }
            }
        }
        // Sort children by PID for consistent ordering
        node.children.sort_by_key(|c| c.process.pid);
    }

    for root in &mut roots {
        attach_children(root, processes, &mut nodes);
    }

    // Sort roots by PID
    roots.sort_by_key(|r| r.process.pid);
    roots
}

/// Get username from UID
fn get_username_from_uid(uid: &sysinfo::Uid) -> String {
    uid.to_string()
}

/// Get handle and thread count
fn get_handle_and_thread_count(pid: u32) -> (u32, u32) {
    #[cfg(target_os = "windows")]
    {
        get_handle_and_thread_count_windows(pid)
    }

    #[cfg(target_os = "linux")]
    {
        get_handle_and_thread_count_linux(pid)
    }

    #[cfg(target_os = "macos")]
    {
        get_handle_and_thread_count_macos(pid)
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        (0, 0)
    }
}

#[cfg(target_os = "windows")]
fn get_handle_and_thread_count_windows(pid: u32) -> (u32, u32) {
    let mut handle_count = 0u32;
    let mut thread_count = 0u32;

    unsafe {
        // Get handle count
        if let Ok(handle) = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) {
            let mut count = 0u32;
            if GetProcessHandleCount(handle, &mut count).is_ok() {
                handle_count = count;
            }
            let _ = CloseHandle(handle);
        }

        // Get thread count using toolhelp
        if let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
            let mut entry = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..Default::default()
            };

            if Thread32First(snapshot, &mut entry).is_ok() {
                loop {
                    if entry.th32OwnerProcessID == pid {
                        thread_count += 1;
                    }
                    if Thread32Next(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snapshot);
        }
    }

    (handle_count, thread_count)
}

#[cfg(target_os = "linux")]
fn get_handle_and_thread_count_linux(pid: u32) -> (u32, u32) {
    let mut handle_count = 0u32;
    let mut thread_count = 0u32;

    // Count file descriptors
    let fd_path = format!("/proc/{}/fd", pid);
    if let Ok(entries) = std::fs::read_dir(&fd_path) {
        handle_count = entries.count() as u32;
    }

    // Count threads from /proc/{pid}/task
    let task_path = format!("/proc/{}/task", pid);
    if let Ok(entries) = std::fs::read_dir(&task_path) {
        thread_count = entries.count() as u32;
    }

    (handle_count, thread_count)
}

#[cfg(target_os = "macos")]
fn get_handle_and_thread_count_macos(pid: u32) -> (u32, u32) {
    // macOS requires different APIs (proc_pidinfo)
    // For now return 0s - full implementation would use libproc
    (0, 0)
}

/// Get signature information for a binary
fn get_signature_info(path: Option<&str>) -> (bool, Option<String>) {
    let Some(path) = path else {
        return (false, None);
    };

    #[cfg(target_os = "windows")]
    {
        get_signature_info_windows(path)
    }

    #[cfg(target_os = "linux")]
    {
        get_signature_info_linux(path)
    }

    #[cfg(target_os = "macos")]
    {
        get_signature_info_macos(path)
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        (false, None)
    }
}

#[cfg(target_os = "windows")]
fn get_signature_info_windows(path: &str) -> (bool, Option<String>) {
    use std::ptr::null_mut;
    use windows::core::GUID;
    use windows::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_WHOLECHAIN,
        WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };

    // WINTRUST_ACTION_GENERIC_VERIFY_V2 GUID
    let action_guid = GUID::from_u128(0x00AAC56B_CD44_11d0_8CC2_00C04FC295EE);

    let wide_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: windows::core::PCWSTR(wide_path.as_ptr()),
            hFile: windows::Win32::Foundation::HANDLE::default(),
            pgKnownSubject: null_mut(),
        };

        let mut trust_data = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: std::mem::zeroed(),
            dwStateAction: WTD_STATEACTION_VERIFY,
            ..std::mem::zeroed()
        };
        trust_data.Anonymous.pFile = &mut file_info;

        let mut action_guid = action_guid;
        let result = WinVerifyTrust(
            windows::Win32::Foundation::HWND::default(),
            &mut action_guid,
            &mut trust_data as *mut _ as *mut std::ffi::c_void,
        );

        // 0 = signed and trusted
        let is_signed = result == 0;

        // For signer, we'd need to extract from the certificate
        // This is a simplified implementation
        (is_signed, None)
    }
}

#[cfg(target_os = "linux")]
fn get_signature_info_linux(path: &str) -> (bool, Option<String>) {
    // Linux doesn't have native code signing like Windows
    // Check for ELF signature section or package manager verification
    // For now, return false
    let _ = path;
    (false, None)
}

#[cfg(target_os = "macos")]
fn get_signature_info_macos(path: &str) -> (bool, Option<String>) {
    // Use codesign -dv to check signature
    use std::process::Command;

    let output = Command::new("codesign")
        .args(["-dv", "--verbose=2", path])
        .output();

    match output {
        Ok(result) => {
            let stderr = String::from_utf8_lossy(&result.stderr);
            if result.status.success() || stderr.contains("Authority=") {
                // Extract authority (signer) from output
                let signer = stderr
                    .lines()
                    .find(|l| l.starts_with("Authority="))
                    .map(|l| l.trim_start_matches("Authority=").to_string());
                (true, signer)
            } else {
                (false, None)
            }
        }
        Err(_) => (false, None),
    }
}

/// Check if process is elevated
fn check_is_elevated(pid: u32) -> bool {
    #[cfg(target_os = "windows")]
    {
        check_is_elevated_windows(pid)
    }

    #[cfg(target_os = "linux")]
    {
        // Check if effective UID is 0
        if let Ok(status) = std::fs::read_to_string(format!("/proc/{}/status", pid)) {
            for line in status.lines() {
                if line.starts_with("Uid:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    // parts[2] is effective UID
                    if let Some(euid) = parts.get(2) {
                        return euid == &"0";
                    }
                }
            }
        }
        false
    }

    #[cfg(target_os = "macos")]
    {
        // Check using ps
        use std::process::Command;
        if let Ok(output) = Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "uid="])
            .output()
        {
            let uid = String::from_utf8_lossy(&output.stdout).trim().to_string();
            return uid == "0";
        }
        false
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    false
}

#[cfg(target_os = "windows")]
fn check_is_elevated_windows(pid: u32) -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION};

    unsafe {
        let process_handle = match OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let mut token_handle = windows::Win32::Foundation::HANDLE::default();
        let result = windows::Win32::System::Threading::OpenProcessToken(
            process_handle,
            TOKEN_QUERY,
            &mut token_handle,
        );

        let _ = CloseHandle(process_handle);

        if result.is_err() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut return_length = 0u32;

        let result = GetTokenInformation(
            token_handle,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut std::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );

        let _ = CloseHandle(token_handle);

        if result.is_ok() {
            elevation.TokenIsElevated != 0
        } else {
            false
        }
    }
}

/// Get network connections for a specific process
fn get_process_network_connections(pid: u32) -> Vec<NetworkConnectionInfo> {
    #[cfg(target_os = "windows")]
    {
        get_connections_windows(pid)
    }

    #[cfg(target_os = "linux")]
    {
        get_connections_linux(pid)
    }

    #[cfg(target_os = "macos")]
    {
        get_connections_macos(pid)
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        Vec::new()
    }
}

#[cfg(target_os = "windows")]
fn get_connections_windows(pid: u32) -> Vec<NetworkConnectionInfo> {
    let mut connections = Vec::new();

    // Implementation would use GetExtendedTcpTable and GetExtendedUdpTable
    // This is a placeholder - full implementation requires careful Windows API usage

    connections
}

#[cfg(target_os = "linux")]
fn get_connections_linux(pid: u32) -> Vec<NetworkConnectionInfo> {
    let mut connections = Vec::new();

    // Read /proc/{pid}/fd and check for socket links
    // Then correlate with /proc/net/tcp and /proc/net/udp

    // Get inode numbers for this process's sockets
    let fd_path = format!("/proc/{}/fd", pid);
    let mut socket_inodes: Vec<u64> = Vec::new();

    if let Ok(entries) = std::fs::read_dir(&fd_path) {
        for entry in entries.flatten() {
            if let Ok(link) = std::fs::read_link(entry.path()) {
                let link_str = link.to_string_lossy();
                if link_str.starts_with("socket:[") {
                    if let Some(inode_str) = link_str
                        .strip_prefix("socket:[")
                        .and_then(|s| s.strip_suffix("]"))
                    {
                        if let Ok(inode) = inode_str.parse::<u64>() {
                            socket_inodes.push(inode);
                        }
                    }
                }
            }
        }
    }

    // Parse /proc/net/tcp
    if let Ok(tcp_content) = std::fs::read_to_string("/proc/net/tcp") {
        for line in tcp_content.lines().skip(1) {
            if let Some(conn) = parse_proc_net_line(line, "TCP", &socket_inodes) {
                connections.push(conn);
            }
        }
    }

    // Parse /proc/net/tcp6
    if let Ok(tcp6_content) = std::fs::read_to_string("/proc/net/tcp6") {
        for line in tcp6_content.lines().skip(1) {
            if let Some(conn) = parse_proc_net_line(line, "TCP6", &socket_inodes) {
                connections.push(conn);
            }
        }
    }

    // Parse /proc/net/udp
    if let Ok(udp_content) = std::fs::read_to_string("/proc/net/udp") {
        for line in udp_content.lines().skip(1) {
            if let Some(conn) = parse_proc_net_line(line, "UDP", &socket_inodes) {
                connections.push(conn);
            }
        }
    }

    connections
}

#[cfg(target_os = "linux")]
fn parse_proc_net_line(
    line: &str,
    protocol: &str,
    socket_inodes: &[u64],
) -> Option<NetworkConnectionInfo> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 10 {
        return None;
    }

    // Format: sl local_address remote_address st tx_queue:rx_queue ... inode
    let inode: u64 = parts.get(9)?.parse().ok()?;

    if !socket_inodes.contains(&inode) {
        return None;
    }

    let (local_addr, local_port) = parse_hex_address(parts.get(1)?)?;
    let (remote_addr, remote_port) = parse_hex_address(parts.get(2)?)?;
    let state_hex = parts.get(3)?;
    let state = tcp_state_from_hex(state_hex);

    Some(NetworkConnectionInfo {
        protocol: protocol.to_string(),
        local_address: local_addr,
        local_port,
        remote_address: remote_addr,
        remote_port,
        state,
    })
}

#[cfg(target_os = "linux")]
fn parse_hex_address(s: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return None;
    }

    let addr_hex = parts[0];
    let port_hex = parts[1];

    // Parse port
    let port = u16::from_str_radix(port_hex, 16).ok()?;

    // Parse address (little-endian for IPv4)
    let addr = if addr_hex.len() == 8 {
        // IPv4
        let bytes = u32::from_str_radix(addr_hex, 16).ok()?;
        format!(
            "{}.{}.{}.{}",
            bytes & 0xFF,
            (bytes >> 8) & 0xFF,
            (bytes >> 16) & 0xFF,
            (bytes >> 24) & 0xFF
        )
    } else {
        // IPv6 - simplified
        addr_hex.to_string()
    };

    Some((addr, port))
}

#[cfg(target_os = "linux")]
fn tcp_state_from_hex(hex: &str) -> String {
    match hex {
        "01" => "ESTABLISHED".to_string(),
        "02" => "SYN_SENT".to_string(),
        "03" => "SYN_RECV".to_string(),
        "04" => "FIN_WAIT1".to_string(),
        "05" => "FIN_WAIT2".to_string(),
        "06" => "TIME_WAIT".to_string(),
        "07" => "CLOSE".to_string(),
        "08" => "CLOSE_WAIT".to_string(),
        "09" => "LAST_ACK".to_string(),
        "0A" => "LISTEN".to_string(),
        "0B" => "CLOSING".to_string(),
        _ => "UNKNOWN".to_string(),
    }
}

#[cfg(target_os = "macos")]
fn get_connections_macos(pid: u32) -> Vec<NetworkConnectionInfo> {
    let mut connections = Vec::new();

    // Use lsof to get network connections
    use std::process::Command;

    if let Ok(output) = Command::new("lsof")
        .args(["-i", "-n", "-P", "-a", "-p", &pid.to_string()])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().skip(1) {
            if let Some(conn) = parse_lsof_line(line) {
                connections.push(conn);
            }
        }
    }

    connections
}

#[cfg(target_os = "macos")]
fn parse_lsof_line(line: &str) -> Option<NetworkConnectionInfo> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 9 {
        return None;
    }

    // lsof format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
    let type_field = parts.get(4)?;
    let name_field = parts.get(8)?;

    let protocol = if type_field.contains("TCP") {
        "TCP"
    } else if type_field.contains("UDP") {
        "UDP"
    } else {
        return None;
    };

    // Parse name field like "192.168.1.1:443->10.0.0.1:12345 (ESTABLISHED)"
    let name = *name_field;
    let (local, remote, state) = if let Some(arrow_pos) = name.find("->") {
        let local = &name[..arrow_pos];
        let rest = &name[arrow_pos + 2..];
        let (remote, state) = if let Some(paren_pos) = rest.find('(') {
            let remote = &rest[..paren_pos - 1];
            let state = rest[paren_pos + 1..].trim_end_matches(')');
            (remote, state)
        } else {
            (rest, "")
        };
        (local, remote, state)
    } else {
        (name, "*:*", "LISTEN")
    };

    let (local_addr, local_port) = parse_addr_port(local)?;
    let (remote_addr, remote_port) = parse_addr_port(remote)?;

    Some(NetworkConnectionInfo {
        protocol: protocol.to_string(),
        local_address: local_addr,
        local_port,
        remote_address: remote_addr,
        remote_port,
        state: state.to_string(),
    })
}

#[cfg(target_os = "macos")]
fn parse_addr_port(s: &str) -> Option<(String, u16)> {
    let last_colon = s.rfind(':')?;
    let addr = &s[..last_colon];
    let port_str = &s[last_colon + 1..];
    let port = if port_str == "*" {
        0
    } else {
        port_str.parse().ok()?
    };
    let addr = if addr == "*" {
        "0.0.0.0".to_string()
    } else {
        addr.to_string()
    };
    Some((addr, port))
}

/// Get security-relevant environment variables
fn get_security_environment(pid: u32) -> Option<HashMap<String, String>> {
    #[cfg(target_os = "linux")]
    {
        let environ_path = format!("/proc/{}/environ", pid);
        let data = std::fs::read(&environ_path).ok()?;

        let security_vars = [
            "PATH",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "HOME",
            "USER",
            "SHELL",
            "DISPLAY",
            "SSH_AUTH_SOCK",
            "TMPDIR",
            "TEMP",
        ];

        let mut env_map = HashMap::new();
        for entry in data.split(|&b| b == 0) {
            if let Ok(s) = std::str::from_utf8(entry) {
                if let Some((key, value)) = s.split_once('=') {
                    if security_vars.iter().any(|&v| v == key) {
                        env_map.insert(key.to_string(), value.to_string());
                    }
                }
            }
        }

        if env_map.is_empty() {
            None
        } else {
            Some(env_map)
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_process_tree() {
        let tree = get_process_tree().await;
        assert!(tree.is_ok());
        let tree = tree.unwrap();
        // Should have at least one root process
        assert!(!tree.is_empty());
    }

    #[tokio::test]
    async fn test_get_current_process_details() {
        let pid = std::process::id();
        let details = get_process_details(pid).await;
        assert!(details.is_ok());
        let details = details.unwrap();
        assert_eq!(details.pid, pid);
        assert!(!details.name.is_empty());
    }

    #[tokio::test]
    async fn test_build_process_tree() {
        let processes = vec![
            ProcessDetails {
                pid: 1,
                ppid: None,
                name: "init".to_string(),
                path: None,
                cmdline: vec![],
                user: None,
                start_time: 0,
                memory_bytes: 0,
                virtual_memory_bytes: 0,
                cpu_percent: 0.0,
                handle_count: 0,
                thread_count: 1,
                is_signed: false,
                signer: None,
                is_elevated: true,
                status: "Running".to_string(),
                working_directory: None,
                environment: None,
                network_connections: vec![],
            },
            ProcessDetails {
                pid: 100,
                ppid: Some(1),
                name: "child".to_string(),
                path: None,
                cmdline: vec![],
                user: None,
                start_time: 0,
                memory_bytes: 0,
                virtual_memory_bytes: 0,
                cpu_percent: 0.0,
                handle_count: 0,
                thread_count: 1,
                is_signed: false,
                signer: None,
                is_elevated: false,
                status: "Running".to_string(),
                working_directory: None,
                environment: None,
                network_connections: vec![],
            },
        ];

        let tree = build_process_tree(&processes);
        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0].process.pid, 1);
        assert_eq!(tree[0].children.len(), 1);
        assert_eq!(tree[0].children[0].process.pid, 100);
    }
}
