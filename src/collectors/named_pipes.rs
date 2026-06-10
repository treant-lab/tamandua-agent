//! Named Pipes monitoring collector
//!
//! Monitors named pipe creation, connections, and suspicious patterns.
//! Named pipes are heavily used for C2 communication and lateral movement.
//!
//! Windows:
//! - Enumerates existing pipes via FindFirstFile on \\.\pipe\*
//! - Uses NtQueryInformationFile for pipe owner info
//! - Monitors pipe creation and connections via polling
//! - Tracks cross-process pipe communication
//!
//! Linux:
//! - Monitors /tmp, /var/run, /dev/shm for UNIX sockets
//! - Tracks socket creation with inotify + /proc scanning
//! - Monitors mkfifo operations
//! - Detects suspicious socket patterns
//!
//! MITRE ATT&CK Mappings:
//! - T1570: Lateral Tool Transfer
//! - T1071: Application Layer Protocol
//! - T1021.002: Remote Services: SMB/Windows Admin Shares
//! - T1559.001: Inter-Process Communication: Component Object Model
//! - T1559.002: Inter-Process Communication: Dynamic Data Exchange

// Detector for named-pipe-based C2 and lateral movement. Several fields and
// helper parameters are intentionally retained for cross-platform symmetry and
// future stage-2 detections that are scaffolded but not yet wired up.
#![allow(dead_code, unused_variables)]

use super::{Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent};
use crate::config::AgentConfig;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Named pipe event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedPipeEvent {
    /// Full pipe path (e.g., \\.\pipe\name or /tmp/socket)
    pub pipe_path: String,

    /// Pipe name without prefix
    pub pipe_name: String,

    /// Operation type: create, connect, disconnect, delete
    pub operation: String,

    /// Process ID that created/connected to the pipe
    pub pid: u32,

    /// Process name
    pub process_name: String,

    /// Process path
    pub process_path: String,

    /// Process command line
    pub process_cmdline: Option<String>,

    /// Server or client mode
    pub mode: String,

    /// Remote process info (for cross-process communication)
    pub remote_pid: Option<u32>,
    pub remote_process_name: Option<String>,
    pub remote_process_path: Option<String>,

    /// Pipe security descriptor (Windows - SDDL format)
    pub security_descriptor: Option<String>,

    /// Pipe instance count (Windows)
    pub instance_count: Option<u32>,

    /// Pipe max instances allowed (Windows)
    pub max_instances: Option<u32>,

    /// Pipe read/write mode
    pub pipe_mode: Option<String>,

    /// Detection reason if suspicious
    pub detection_reason: Option<String>,
}

/// Known malicious pipe patterns
struct MaliciousPipePatterns {
    /// Exact match pipe names (IOCs)
    exact_matches: HashSet<String>,

    /// Regex patterns for C2 detection
    regex_patterns: Vec<(Regex, &'static str, &'static str, f32)>, // (pattern, tool_name, description, confidence)

    /// Random name detection threshold (entropy-based)
    random_name_threshold: f32,
}

impl Default for MaliciousPipePatterns {
    fn default() -> Self {
        let mut exact_matches = HashSet::new();

        // Cobalt Strike default pipes
        exact_matches.insert("msagent_fedac123".to_string());
        exact_matches.insert("mojo.5688.8052.183894939787088877".to_string());
        exact_matches.insert("mojo.5688.8052.35780273329370473".to_string());
        exact_matches.insert("win_crash_svc".to_string());
        exact_matches.insert("wkssvc".to_string());
        exact_matches.insert("ntsvcs".to_string());
        exact_matches.insert("demoagent_11".to_string());

        // Metasploit pipes
        exact_matches.insert("meterpreter".to_string());
        exact_matches.insert("metsvc".to_string());
        exact_matches.insert("metsvc-server".to_string());

        // PsExec and variants
        exact_matches.insert("PSEXESVC".to_string());
        exact_matches.insert("psexec".to_string());
        exact_matches.insert("RemCom_communicaton".to_string());

        // Mimikatz
        exact_matches.insert("mimikatz".to_string());
        exact_matches.insert("mimidrv".to_string());

        // Empire
        exact_matches.insert("empire".to_string());
        exact_matches.insert("empyre".to_string());

        // Covenant
        exact_matches.insert("grunt".to_string());
        exact_matches.insert("covenant".to_string());

        // Sliver C2
        exact_matches.insert("sliver".to_string());

        // Common C2 frameworks
        exact_matches.insert("beacon".to_string());
        exact_matches.insert("pivot".to_string());
        exact_matches.insert("shell".to_string());
        exact_matches.insert("cmd".to_string());
        exact_matches.insert("exec".to_string());
        exact_matches.insert("backdoor".to_string());
        exact_matches.insert("implant".to_string());
        exact_matches.insert("agent".to_string());

        // Build regex patterns
        let regex_patterns = vec![
            // Cobalt Strike patterns
            (
                Regex::new(r"(?i)^msagent_[0-9a-f]+$").unwrap(),
                "Cobalt Strike",
                "MSAgent pipe pattern",
                0.95,
            ),
            (
                Regex::new(r"(?i)^MSSE-[0-9]+-server$").unwrap(),
                "Cobalt Strike",
                "MSSE server pipe",
                0.95,
            ),
            (
                Regex::new(r"(?i)^postex_[0-9a-f]+$").unwrap(),
                "Cobalt Strike",
                "Post-exploitation pipe",
                0.95,
            ),
            (
                Regex::new(r"(?i)^postex_ssh_[0-9a-f]+$").unwrap(),
                "Cobalt Strike",
                "SSH post-ex pipe",
                0.95,
            ),
            (
                Regex::new(r"(?i)^status_[0-9a-f]+$").unwrap(),
                "Cobalt Strike",
                "Status pipe",
                0.90,
            ),
            (
                Regex::new(r"(?i)^msf_[0-9a-f]+$").unwrap(),
                "Cobalt Strike/MSF",
                "MSF compatibility pipe",
                0.90,
            ),
            (
                Regex::new(r"(?i)^DserNamePipe[0-9]+$").unwrap(),
                "Cobalt Strike",
                "Default pipe naming",
                0.90,
            ),
            (
                Regex::new(r"(?i)^[a-f0-9]{32}$").unwrap(),
                "Cobalt Strike",
                "SMB beacon pipe (MD5)",
                0.85,
            ),
            (
                Regex::new(r"(?i)^\\\\\.\\pipe\\[a-f0-9]{32}$").unwrap(),
                "Cobalt Strike",
                "Full SMB beacon path",
                0.90,
            ),
            (
                Regex::new(r"(?i)^win_crash_svc_[0-9]+$").unwrap(),
                "Cobalt Strike",
                "Crash service pipe",
                0.90,
            ),
            (
                Regex::new(r"(?i)^wkssvc[0-9]+$").unwrap(),
                "Cobalt Strike",
                "Workstation service pipe",
                0.85,
            ),
            (
                Regex::new(r"(?i)^ntsvcs[0-9]+$").unwrap(),
                "Cobalt Strike",
                "NT services pipe",
                0.85,
            ),
            // Metasploit patterns
            (
                Regex::new(r"(?i)^meterpreter_").unwrap(),
                "Metasploit",
                "Meterpreter pipe prefix",
                0.95,
            ),
            (
                Regex::new(r"(?i)^msf_").unwrap(),
                "Metasploit",
                "Metasploit pipe prefix",
                0.90,
            ),
            (
                Regex::new(r"(?i)^metsvc").unwrap(),
                "Metasploit",
                "Metsvc service",
                0.95,
            ),
            // PsExec variants
            (
                Regex::new(r"(?i)^PSEXE[A-Z]+").unwrap(),
                "PsExec",
                "PsExec pipe variant",
                0.90,
            ),
            (
                Regex::new(r"(?i)^csexec").unwrap(),
                "CsExec",
                "CsExec lateral movement",
                0.90,
            ),
            (
                Regex::new(r"(?i)^paexec").unwrap(),
                "PaExec",
                "PaExec lateral movement",
                0.90,
            ),
            (
                Regex::new(r"(?i)^remcom").unwrap(),
                "RemCom",
                "RemCom lateral movement",
                0.90,
            ),
            (
                Regex::new(r"(?i)^RemCom_[0-9]+").unwrap(),
                "RemCom",
                "RemCom session pipe",
                0.95,
            ),
            // WMI lateral movement
            (
                Regex::new(r"(?i)^wmi[0-9]+").unwrap(),
                "WMI",
                "WMI lateral movement pipe",
                0.75,
            ),
            // SMB relay/lateral movement - lower confidence as these are legitimate services
            (
                Regex::new(r"(?i)^ntsvcs$").unwrap(),
                "SMB",
                "NTSVCS pipe (may be legitimate)",
                0.5,
            ),
            (
                Regex::new(r"(?i)^scerpc$").unwrap(),
                "SMB",
                "SCERPC pipe",
                0.5,
            ),
            (Regex::new(r"(?i)^samr$").unwrap(), "SMB", "SAMR pipe", 0.5),
            (
                Regex::new(r"(?i)^lsarpc$").unwrap(),
                "SMB",
                "LSARPC pipe",
                0.5,
            ),
            (
                Regex::new(r"(?i)^netlogon$").unwrap(),
                "SMB",
                "Netlogon pipe",
                0.5,
            ),
            // Generic suspicious patterns
            (
                Regex::new(r"(?i)^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")
                    .unwrap(),
                "UUID Pipe",
                "GUID-based pipe name (common in C2)",
                0.70,
            ),
            (
                Regex::new(r"^[a-zA-Z0-9]{25,}$").unwrap(),
                "Random Pipe",
                "Very long random pipe name",
                0.65,
            ),
            (
                Regex::new(r"(?i)^[a-z]{3,6}_[a-f0-9]{8,}$").unwrap(),
                "C2 Pattern",
                "Prefix with hex suffix pattern",
                0.75,
            ),
            // Sliver C2
            (
                Regex::new(r"(?i)^sliver").unwrap(),
                "Sliver",
                "Sliver C2 pipe",
                0.95,
            ),
            // Brute Ratel
            (
                Regex::new(r"(?i)^brc4").unwrap(),
                "Brute Ratel",
                "Brute Ratel C4",
                0.95,
            ),
            (
                Regex::new(r"(?i)^badger").unwrap(),
                "Brute Ratel",
                "Brute Ratel badger",
                0.90,
            ),
            // Havoc C2
            (
                Regex::new(r"(?i)^havoc").unwrap(),
                "Havoc",
                "Havoc C2 pipe",
                0.95,
            ),
            (
                Regex::new(r"(?i)^demon").unwrap(),
                "Havoc",
                "Havoc demon pipe",
                0.85,
            ),
            // Generic backdoor patterns
            (
                Regex::new(r"(?i)backdoor").unwrap(),
                "Backdoor",
                "Backdoor pipe pattern",
                0.90,
            ),
            (
                Regex::new(r"(?i)rootkit").unwrap(),
                "Rootkit",
                "Rootkit pipe pattern",
                0.95,
            ),
            (
                Regex::new(r"(?i)trojan").unwrap(),
                "Trojan",
                "Trojan pipe pattern",
                0.90,
            ),
            (
                Regex::new(r"(?i)rat$|^rat_").unwrap(),
                "RAT",
                "Remote Access Trojan pipe",
                0.90,
            ),
            (
                Regex::new(r"(?i)c2$|^c2_|_c2_").unwrap(),
                "C2",
                "C2 communication pipe",
                0.90,
            ),
            (
                Regex::new(r"(?i)reverse.*shell").unwrap(),
                "Reverse Shell",
                "Reverse shell pipe",
                0.95,
            ),
            (
                Regex::new(r"(?i)bind.*shell").unwrap(),
                "Bind Shell",
                "Bind shell pipe",
                0.95,
            ),
        ];

        Self {
            exact_matches,
            regex_patterns,
            random_name_threshold: 4.0, // Entropy threshold for random-looking names
        }
    }
}

impl MaliciousPipePatterns {
    /// Check if a pipe name matches known malicious patterns
    fn check_pipe(&self, pipe_name: &str) -> Option<(String, String, f32)> {
        let pipe_name_lower = pipe_name.to_lowercase();

        // Check exact matches first (highest confidence)
        if self.exact_matches.contains(&pipe_name_lower) {
            return Some((
                "Known Malicious Pipe".to_string(),
                format!("Exact match for known malicious pipe: {}", pipe_name),
                1.0,
            ));
        }

        // Check regex patterns
        for (pattern, tool_name, description, confidence) in &self.regex_patterns {
            if pattern.is_match(pipe_name) {
                return Some((
                    format!("{} C2 Pipe", tool_name),
                    description.to_string(),
                    *confidence,
                ));
            }
        }

        // Check for random-looking names (high entropy)
        let entropy = Self::calculate_name_entropy(pipe_name);
        if entropy > self.random_name_threshold && pipe_name.len() > 10 {
            // Additional checks for truly suspicious random names
            let is_hex_like = pipe_name
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == '_' || c == '-');
            let confidence = if is_hex_like && pipe_name.len() > 16 {
                0.75 // Higher confidence for long hex strings
            } else {
                0.55
            };

            return Some((
                "Suspicious Random Pipe".to_string(),
                format!("High entropy pipe name (entropy: {:.2})", entropy),
                confidence,
            ));
        }

        None
    }

    /// Calculate Shannon entropy of a string
    fn calculate_name_entropy(s: &str) -> f32 {
        if s.is_empty() {
            return 0.0;
        }

        let mut freq = HashMap::new();
        for c in s.chars() {
            *freq.entry(c).or_insert(0) += 1;
        }

        let len = s.len() as f32;
        freq.values()
            .map(|&count| {
                let p = count as f32 / len;
                -p * p.log2()
            })
            .sum()
    }
}

/// Cross-process pipe connection tracking
#[derive(Debug, Clone)]
struct PipeConnection {
    server_pid: u32,
    server_process: String,
    client_pid: u32,
    client_process: String,
    pipe_name: String,
    timestamp: u64,
}

/// Helper struct for parsing extended handle information (Windows)
#[cfg(target_os = "windows")]
#[repr(C)]
struct SystemExtendedHandleInfoHeader {
    number_of_handles: usize,
    reserved: usize,
}

/// Helper struct for parsing extended handle entries (Windows)
#[cfg(target_os = "windows")]
#[repr(C)]
struct SystemExtendedHandleEntry {
    object: *mut std::ffi::c_void,
    unique_process_id: usize,
    handle_value: usize,
    granted_access: u32,
    creator_back_trace_index: u16,
    object_type_index: u16,
    handle_attributes: u32,
    reserved: u32,
}

/// Helper struct for parsing UNICODE_STRING from NtQueryObject (Windows)
#[cfg(target_os = "windows")]
#[repr(C)]
struct UnicodeStringHeader {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

/// Named pipes collector
pub struct NamedPipeCollector {
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    patterns: MaliciousPipePatterns,
}

impl NamedPipeCollector {
    /// Create a new named pipe collector
    pub fn new(config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(1000);
        let patterns = MaliciousPipePatterns::default();

        // Start monitoring in background
        let config_clone = config.clone();
        tokio::spawn(async move {
            Self::monitor_loop(tx, config_clone).await;
        });

        Self {
            config: config.clone(),
            event_rx: rx,
            patterns,
        }
    }

    async fn monitor_loop(tx: mpsc::Sender<TelemetryEvent>, config: AgentConfig) {
        let patterns = MaliciousPipePatterns::default();
        let mut known_pipes: HashMap<String, PipeInfo> = HashMap::new();
        let mut pipe_connections: HashMap<String, Vec<PipeConnection>> = HashMap::new();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(2));

        // Initial scan
        let current_pipes = Self::enumerate_pipes().await;
        for (path, info) in &current_pipes {
            known_pipes.insert(path.clone(), info.clone());
        }

        info!(
            count = known_pipes.len(),
            "Named pipe collector initialized"
        );

        loop {
            interval.tick().await;

            let current_pipes = Self::enumerate_pipes().await;

            // Check for new pipes
            for (path, info) in &current_pipes {
                if !known_pipes.contains_key(path) {
                    // New pipe detected
                    if let Some(event) = Self::create_pipe_event(
                        path, info, "create", None, // No old info for new pipes
                        &patterns, &config,
                    )
                    .await
                    {
                        if tx.send(event).await.is_err() {
                            warn!("Event channel closed");
                            return;
                        }
                    }

                    known_pipes.insert(path.clone(), info.clone());
                } else if let Some(old_info) = known_pipes.get(path) {
                    // Check for changes in existing pipe (new connections, instance count changes)
                    if info.instance_count != old_info.instance_count
                        || info.connected_pids != old_info.connected_pids
                    {
                        // Connection change detected
                        if let Some(event) = Self::create_pipe_event(
                            path,
                            info,
                            "connect",
                            Some(old_info),
                            &patterns,
                            &config,
                        )
                        .await
                        {
                            if tx.send(event).await.is_err() {
                                warn!("Event channel closed");
                                return;
                            }
                        }

                        // Track cross-process communication
                        Self::track_cross_process_communication(
                            path,
                            info,
                            old_info,
                            &mut pipe_connections,
                        );

                        known_pipes.insert(path.clone(), info.clone());
                    }
                }
            }

            // Check for removed pipes
            let current_paths: HashSet<_> = current_pipes.keys().cloned().collect();
            let removed: Vec<_> = known_pipes
                .keys()
                .filter(|k| !current_paths.contains(*k))
                .cloned()
                .collect();

            for path in removed {
                if let Some(info) = known_pipes.remove(&path) {
                    // Pipe was closed/deleted - only log if it was suspicious
                    if patterns.check_pipe(&info.name).is_some() {
                        if let Some(event) = Self::create_pipe_event(
                            &path, &info, "delete", None, &patterns, &config,
                        )
                        .await
                        {
                            let _ = tx.send(event).await;
                        }
                    }

                    // Clean up connection tracking
                    pipe_connections.remove(&path);
                }
            }

            // Monitor for high-frequency pipe operations and cross-process anomalies
            Self::check_behavioral_anomalies(
                &current_pipes,
                &pipe_connections,
                &patterns,
                &tx,
                &config,
            )
            .await;
        }
    }

    fn track_cross_process_communication(
        pipe_path: &str,
        new_info: &PipeInfo,
        old_info: &PipeInfo,
        connections: &mut HashMap<String, Vec<PipeConnection>>,
    ) {
        // Find new connections
        for &new_pid in &new_info.connected_pids {
            if !old_info.connected_pids.contains(&new_pid) && new_pid != new_info.pid {
                // New cross-process connection
                let connection = PipeConnection {
                    server_pid: new_info.pid,
                    server_process: new_info.process_name.clone(),
                    client_pid: new_pid,
                    client_process: Self::get_process_name(new_pid),
                    pipe_name: new_info.name.clone(),
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                };

                connections
                    .entry(pipe_path.to_string())
                    .or_default()
                    .push(connection);
            }
        }
    }

    fn get_process_name(pid: u32) -> String {
        #[cfg(target_os = "windows")]
        {
            Self::get_process_name_windows(pid)
        }

        #[cfg(target_os = "linux")]
        {
            std::fs::read_to_string(format!("/proc/{}/comm", pid))
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| format!("pid:{}", pid))
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            format!("pid:{}", pid)
        }
    }

    #[cfg(target_os = "windows")]
    fn get_process_name_windows(pid: u32) -> String {
        use windows::Win32::Foundation::{CloseHandle, HMODULE};
        use windows::Win32::System::ProcessStatus::GetModuleBaseNameW;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(h) => h,
                Err(_) => return format!("pid:{}", pid),
            };

            let mut name_buf = [0u16; 256];
            let len = GetModuleBaseNameW(handle, HMODULE::default(), &mut name_buf);
            let _ = CloseHandle(handle);

            if len > 0 {
                String::from_utf16_lossy(&name_buf[..len as usize])
            } else {
                format!("pid:{}", pid)
            }
        }
    }

    /// Enumerate current named pipes
    async fn enumerate_pipes() -> HashMap<String, PipeInfo> {
        #[cfg(target_os = "windows")]
        return Self::enumerate_pipes_windows().await;

        #[cfg(target_os = "linux")]
        return Self::enumerate_pipes_linux().await;

        #[cfg(target_os = "macos")]
        return Self::enumerate_pipes_macos().await;

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        return HashMap::new();
    }

    #[cfg(target_os = "windows")]
    async fn enumerate_pipes_windows() -> HashMap<String, PipeInfo> {
        use windows::core::PCWSTR;
        use windows::Win32::Storage::FileSystem::{
            FindClose, FindFirstFileW, FindNextFileW, WIN32_FIND_DATAW,
        };

        let mut pipes = HashMap::new();

        // Enumerate pipes using FindFirstFile on \\.\pipe\*
        let search_path: Vec<u16> = "\\\\.\\pipe\\*"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            let mut find_data = WIN32_FIND_DATAW::default();
            let handle =
                match FindFirstFileW(PCWSTR::from_raw(search_path.as_ptr()), &mut find_data) {
                    Ok(h) => h,
                    Err(_) => return pipes,
                };

            loop {
                // Extract pipe name
                let name_len = find_data
                    .cFileName
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(find_data.cFileName.len());
                let name = String::from_utf16_lossy(&find_data.cFileName[..name_len]);

                if !name.is_empty() && name != "." && name != ".." {
                    let full_path = format!("\\\\.\\pipe\\{}", name);

                    // Get detailed pipe info using native APIs
                    let info = Self::get_pipe_info_windows(&full_path, &name);
                    pipes.insert(full_path, info);
                }

                if FindNextFileW(handle, &mut find_data).is_err() {
                    break;
                }
            }

            let _ = FindClose(handle);
        }

        debug!(count = pipes.len(), "Enumerated Windows named pipes");
        pipes
    }

    #[cfg(target_os = "windows")]
    fn get_pipe_info_windows(pipe_path: &str, pipe_name: &str) -> PipeInfo {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE};
        use windows::Win32::Storage::FileSystem::{
            CreateFileW, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        };
        use windows::Win32::System::Pipes::{
            GetNamedPipeClientProcessId, GetNamedPipeInfo, GetNamedPipeServerProcessId,
            NAMED_PIPE_MODE, PIPE_SERVER_END, PIPE_TYPE_MESSAGE,
        };

        let mut info = PipeInfo {
            path: pipe_path.to_string(),
            name: pipe_name.to_string(),
            pid: 0,
            process_name: String::new(),
            process_path: String::new(),
            process_cmdline: None,
            mode: "unknown".to_string(),
            security_descriptor: None,
            instance_count: None,
            max_instances: None,
            pipe_mode: None,
            connected_pids: HashSet::new(),
        };

        // Try to open the pipe and get information
        let pipe_path_wide: Vec<u16> = pipe_path.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            // Try to open the pipe with read access to get detailed info
            // Some pipes may deny access, so we handle errors gracefully
            let pipe_handle = CreateFileW(
                PCWSTR::from_raw(pipe_path_wide.as_ptr()),
                GENERIC_READ.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                HANDLE::default(),
            );

            if let Ok(handle) = pipe_handle {
                // Get pipe info using GetNamedPipeInfo
                let mut flags: NAMED_PIPE_MODE = NAMED_PIPE_MODE::default();
                let mut out_buffer_size: u32 = 0;
                let mut in_buffer_size: u32 = 0;
                let mut max_instances: u32 = 0;

                if GetNamedPipeInfo(
                    handle,
                    Some(&mut flags as *mut NAMED_PIPE_MODE),
                    Some(&mut out_buffer_size),
                    Some(&mut in_buffer_size),
                    Some(&mut max_instances),
                )
                .is_ok()
                {
                    info.max_instances = if max_instances == 255 {
                        None // PIPE_UNLIMITED_INSTANCES
                    } else {
                        Some(max_instances)
                    };

                    // Determine pipe mode from flags
                    info.pipe_mode = Some(if flags.0 & PIPE_TYPE_MESSAGE.0 != 0 {
                        "message".to_string()
                    } else {
                        "byte".to_string()
                    });

                    // Determine if server or client based on PIPE_SERVER_END flag
                    info.mode = if flags.0 & PIPE_SERVER_END.0 != 0 {
                        "server".to_string()
                    } else {
                        "client".to_string()
                    };
                }

                // Get server process ID using GetNamedPipeServerProcessId
                let mut server_pid: u32 = 0;
                if GetNamedPipeServerProcessId(handle, &mut server_pid).is_ok() && server_pid > 0 {
                    info.pid = server_pid;
                    info.connected_pids.insert(server_pid);

                    // Get process details for the server
                    let (name, path) = Self::get_process_details_windows(server_pid);
                    info.process_name = name;
                    info.process_path = path;
                }

                // Get client process ID using GetNamedPipeClientProcessId
                let mut client_pid: u32 = 0;
                if GetNamedPipeClientProcessId(handle, &mut client_pid).is_ok() && client_pid > 0 {
                    info.connected_pids.insert(client_pid);

                    // If we didn't get a server PID, use client as primary
                    if info.pid == 0 {
                        info.pid = client_pid;
                        let (name, path) = Self::get_process_details_windows(client_pid);
                        info.process_name = name;
                        info.process_path = path;
                    }
                }

                let _ = CloseHandle(handle);
            }

            // If we couldn't get PIDs from the pipe APIs, try handle enumeration
            if info.pid == 0 {
                let (owner_pid, owner_name, owner_path, connected_pids) =
                    Self::find_pipe_owner_via_native_handle_enum(pipe_name);

                info.pid = owner_pid;
                if !owner_name.is_empty() {
                    info.process_name = owner_name;
                }
                if !owner_path.is_empty() {
                    info.process_path = owner_path;
                }
                for pid in connected_pids {
                    info.connected_pids.insert(pid);
                }
            }

            // Get command line for the owner process
            if info.pid > 0 && info.process_cmdline.is_none() {
                info.process_cmdline = Self::get_process_cmdline_windows(info.pid);
            }
        }

        info
    }

    /// Get process name and path for a given PID
    #[cfg(target_os = "windows")]
    fn get_process_details_windows(pid: u32) -> (String, String) {
        use windows::Win32::Foundation::{CloseHandle, HMODULE};
        use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

        if pid == 0 || pid == 4 {
            return (String::new(), String::new());
        }

        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(h) => h,
                Err(_) => return (format!("pid:{}", pid), String::new()),
            };

            let mut path_buf = [0u16; 512];
            let len = GetModuleFileNameExW(handle, HMODULE::default(), &mut path_buf);
            let _ = CloseHandle(handle);

            if len > 0 {
                let path = String::from_utf16_lossy(&path_buf[..len as usize]);
                let name = std::path::Path::new(&path)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                (name, path)
            } else {
                (format!("pid:{}", pid), String::new())
            }
        }
    }

    /// Find pipe owner using native NtQuerySystemInformation handle enumeration
    /// This is the proper way to find pipe owners without external tools
    #[cfg(target_os = "windows")]
    fn find_pipe_owner_via_native_handle_enum(
        pipe_name: &str,
    ) -> (u32, String, String, HashSet<u32>) {
        use crate::collectors::win_compat::ntapi::{
            get_nt_api, DUPLICATE_SAME_ACCESS, OBJECT_NAME_INFORMATION,
            STATUS_INFO_LENGTH_MISMATCH, STATUS_SUCCESS, SYSTEM_EXTENDED_HANDLE_INFORMATION,
            SYSTEM_HANDLE_INFORMATION,
        };
        use std::ffi::c_void;
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::System::Threading::{
            GetCurrentProcess, OpenProcess, PROCESS_DUP_HANDLE,
        };

        let mut owner_pid = 0u32;
        let mut owner_name = String::new();
        let mut owner_path = String::new();
        let mut connected_pids = HashSet::new();

        // Handle enumeration via NtQuerySystemInformation requires elevation.
        // Without it, NtDuplicateObject can crash inside ntdll.dll.
        if !super::win_compat::is_elevated() {
            return (owner_pid, owner_name, owner_path, connected_pids);
        }

        let api = match get_nt_api() {
            Some(api) => api,
            None => {
                debug!("NT API not available for handle enumeration");
                return (owner_pid, owner_name, owner_path, connected_pids);
            }
        };

        let dup_fn = match api.nt_duplicate_object {
            Some(f) => f,
            None => {
                debug!("NtDuplicateObject not available");
                return (owner_pid, owner_name, owner_path, connected_pids);
            }
        };

        let query_obj_fn = match api.nt_query_object {
            Some(f) => f,
            None => {
                debug!("NtQueryObject not available");
                return (owner_pid, owner_name, owner_path, connected_pids);
            }
        };

        // Normalize pipe name for comparison
        let pipe_name_lower = pipe_name.to_lowercase();
        let pipe_search_pattern = format!("\\device\\namedpipe\\{}", pipe_name_lower);

        unsafe {
            // Try extended handle information first (Win8+), fall back to legacy
            let mut buffer_size: u32 = 0x100000; // Start with 1MB
            let mut buffer: Vec<u8>;
            let mut return_length: u32 = 0;

            // Query system handle information
            loop {
                buffer = vec![0u8; buffer_size as usize];
                let status = (api.nt_query_system_information)(
                    SYSTEM_EXTENDED_HANDLE_INFORMATION,
                    buffer.as_mut_ptr() as *mut c_void,
                    buffer_size,
                    &mut return_length,
                );

                if status == STATUS_SUCCESS {
                    break;
                } else if status == STATUS_INFO_LENGTH_MISMATCH {
                    // Buffer too small, increase and retry
                    buffer_size = return_length + 0x10000;
                    if buffer_size > 0x10000000 {
                        // 256MB limit
                        debug!("Handle information buffer too large, aborting");
                        return (owner_pid, owner_name, owner_path, connected_pids);
                    }
                    continue;
                } else {
                    // Try legacy SYSTEM_HANDLE_INFORMATION for older Windows
                    buffer_size = 0x100000;
                    loop {
                        buffer = vec![0u8; buffer_size as usize];
                        let status = (api.nt_query_system_information)(
                            SYSTEM_HANDLE_INFORMATION,
                            buffer.as_mut_ptr() as *mut c_void,
                            buffer_size,
                            &mut return_length,
                        );

                        if status == STATUS_SUCCESS {
                            break;
                        } else if status == STATUS_INFO_LENGTH_MISMATCH {
                            buffer_size = return_length + 0x10000;
                            if buffer_size > 0x10000000 {
                                return (owner_pid, owner_name, owner_path, connected_pids);
                            }
                            continue;
                        } else {
                            debug!(status = status, "NtQuerySystemInformation failed");
                            return (owner_pid, owner_name, owner_path, connected_pids);
                        }
                    }
                    break;
                }
            }

            // Parse the handle information
            // We need to handle both extended and legacy formats
            let handle_info = buffer.as_ptr() as *const SystemExtendedHandleInfoHeader;
            let num_handles = (*handle_info).number_of_handles;

            // Get current process handle for duplication
            let current_process = GetCurrentProcess();

            // Cache of opened process handles
            let mut process_handles: HashMap<usize, HANDLE> = HashMap::new();

            // Iterate through all handles looking for named pipes
            let handles_offset = std::mem::size_of::<SystemExtendedHandleInfoHeader>();
            let handles_ptr =
                (buffer.as_ptr() as usize + handles_offset) as *const SystemExtendedHandleEntry;

            // Cap iteration at buffer bounds to prevent out-of-bounds reads
            let entry_size = std::mem::size_of::<SystemExtendedHandleEntry>();
            let max_entries = if entry_size > 0 && buffer.len() > handles_offset {
                (buffer.len() - handles_offset) / entry_size
            } else {
                0
            };
            let safe_count = num_handles.min(max_entries).min(1_000_000);

            for i in 0..safe_count {
                let entry = &*handles_ptr.add(i);
                let pid = entry.unique_process_id as u32;

                // Skip system process and idle process
                if pid == 0 || pid == 4 {
                    continue;
                }

                // Object type index 28-31 is typically File on modern Windows
                // But we need to check the object name to confirm it's a pipe
                // Skip non-file types to improve performance
                let object_type = entry.object_type_index;
                if object_type < 25 || object_type > 45 {
                    continue;
                }

                // Get or open process handle
                let process_handle = process_handles.entry(pid as usize).or_insert_with(|| {
                    match OpenProcess(PROCESS_DUP_HANDLE, false, pid) {
                        Ok(h) => h,
                        Err(_) => HANDLE::default(),
                    }
                });

                if process_handle.is_invalid() {
                    continue;
                }

                // Duplicate the handle to our process
                let mut dup_handle: *mut c_void = std::ptr::null_mut();
                let status = dup_fn(
                    process_handle.0 as *mut c_void,
                    entry.handle_value as *mut c_void,
                    current_process.0 as *mut c_void,
                    &mut dup_handle,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                );

                if status != STATUS_SUCCESS || dup_handle.is_null() {
                    continue;
                }

                // Query the object name
                let mut name_buffer: Vec<u8> = vec![0u8; 1024];
                let mut name_return_length: u32 = 0;
                let name_status = query_obj_fn(
                    dup_handle,
                    OBJECT_NAME_INFORMATION,
                    name_buffer.as_mut_ptr() as *mut c_void,
                    name_buffer.len() as u32,
                    &mut name_return_length,
                );

                // Close the duplicated handle
                if let Some(close_fn) = api.nt_close {
                    close_fn(dup_handle);
                }

                if name_status != STATUS_SUCCESS {
                    continue;
                }

                // Parse the UNICODE_STRING from the buffer
                let unicode_str = &*(name_buffer.as_ptr() as *const UnicodeStringHeader);
                if unicode_str.length == 0 || unicode_str.buffer.is_null() {
                    continue;
                }

                let name_slice = std::slice::from_raw_parts(
                    unicode_str.buffer,
                    (unicode_str.length / 2) as usize,
                );
                let object_name = String::from_utf16_lossy(name_slice).to_lowercase();

                // Check if this is our pipe
                if object_name.contains(&pipe_search_pattern)
                    || object_name.ends_with(&format!("\\{}", pipe_name_lower))
                {
                    connected_pids.insert(pid);

                    if owner_pid == 0 {
                        owner_pid = pid;
                        let (name, path) = Self::get_process_details_windows(pid);
                        owner_name = name;
                        owner_path = path;
                    }
                }
            }

            // Clean up cached process handles
            for (_, handle) in process_handles {
                if !handle.is_invalid() {
                    let _ = CloseHandle(handle);
                }
            }
        }

        (owner_pid, owner_name, owner_path, connected_pids)
    }

    /// Get process command line using native NT API
    #[cfg(target_os = "windows")]
    fn get_process_cmdline_windows(pid: u32) -> Option<String> {
        use crate::collectors::win_compat::ntapi::{
            get_nt_api, PROCESS_COMMAND_LINE_INFORMATION, STATUS_BUFFER_TOO_SMALL,
            STATUS_INFO_LENGTH_MISMATCH, STATUS_SUCCESS,
        };
        use std::ffi::c_void;
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

        if pid == 0 || pid == 4 {
            return None;
        }

        let api = get_nt_api()?;

        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;

            // First call to get required buffer size
            let mut return_length: u32 = 0;
            let status = (api.nt_query_information_process)(
                handle.0 as *mut c_void,
                PROCESS_COMMAND_LINE_INFORMATION,
                std::ptr::null_mut(),
                0,
                &mut return_length,
            );

            if status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL {
                let _ = CloseHandle(handle);
                return None;
            }

            // Allocate buffer and query again
            let mut buffer: Vec<u8> = vec![0u8; return_length as usize + 256];
            let status = (api.nt_query_information_process)(
                handle.0 as *mut c_void,
                PROCESS_COMMAND_LINE_INFORMATION,
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len() as u32,
                &mut return_length,
            );

            let _ = CloseHandle(handle);

            if status != STATUS_SUCCESS {
                return None;
            }

            // Parse UNICODE_STRING structure from buffer
            let unicode_str = &*(buffer.as_ptr() as *const UnicodeStringHeader);
            if unicode_str.length == 0 || unicode_str.buffer.is_null() {
                return None;
            }

            let cmdline_slice =
                std::slice::from_raw_parts(unicode_str.buffer, (unicode_str.length / 2) as usize);
            let cmdline = String::from_utf16_lossy(cmdline_slice);

            if cmdline.is_empty() {
                None
            } else {
                Some(cmdline)
            }
        }
    }

    #[cfg(target_os = "linux")]
    async fn enumerate_pipes_linux() -> HashMap<String, PipeInfo> {
        use std::fs;
        use std::os::unix::fs::FileTypeExt;

        let mut pipes = HashMap::new();

        // Directories to scan for UNIX sockets and FIFOs
        let socket_dirs = [
            "/tmp",
            "/var/run",
            "/run",
            "/dev/shm",
            "/var/tmp",
            "/run/user",
        ];

        for dir in &socket_dirs {
            Self::scan_directory_for_sockets(dir, &mut pipes);
        }

        // Also check /proc/net/unix for abstract sockets
        if let Ok(content) = fs::read_to_string("/proc/net/unix") {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 8 {
                    let path = parts.last().unwrap_or(&"");
                    if !path.is_empty() && *path != "@" {
                        let name = path.trim_start_matches('@').to_string();
                        let path_str = path.to_string();

                        // Skip known system sockets
                        if Self::is_system_socket(&name) {
                            continue;
                        }

                        // Parse inode to find owner
                        let inode = parts.get(6).and_then(|s| s.parse::<u64>().ok());

                        let (pid, process_name, process_path, cmdline) =
                            Self::find_socket_owner_linux_detailed(&path_str, inode);

                        let connected_pids = Self::find_connected_processes_linux(&path_str, inode);

                        pipes.insert(
                            path_str.clone(),
                            PipeInfo {
                                path: path_str,
                                name,
                                pid,
                                process_name,
                                process_path,
                                process_cmdline: cmdline,
                                mode: "abstract_socket".to_string(),
                                security_descriptor: None,
                                instance_count: None,
                                max_instances: None,
                                pipe_mode: None,
                                connected_pids,
                            },
                        );
                    }
                }
            }
        }

        debug!(count = pipes.len(), "Enumerated Linux UNIX sockets");
        pipes
    }

    #[cfg(target_os = "linux")]
    fn scan_directory_for_sockets(dir: &str, pipes: &mut HashMap<String, PipeInfo>) {
        use std::fs;
        use std::os::unix::fs::FileTypeExt;

        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();

            if let Ok(metadata) = fs::metadata(&path) {
                let file_type = metadata.file_type();

                // Check for sockets and FIFOs (named pipes)
                if file_type.is_socket() || file_type.is_fifo() {
                    let path_str = path.to_string_lossy().to_string();
                    let name = path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();

                    // Skip system sockets
                    if Self::is_system_socket(&name) {
                        continue;
                    }

                    let (pid, process_name, process_path, cmdline) =
                        Self::find_socket_owner_linux_detailed(&path_str, None);

                    let connected_pids = Self::find_connected_processes_linux(&path_str, None);

                    let mode = if file_type.is_socket() {
                        "socket"
                    } else {
                        "fifo"
                    };

                    pipes.insert(
                        path_str.clone(),
                        PipeInfo {
                            path: path_str,
                            name,
                            pid,
                            process_name,
                            process_path,
                            process_cmdline: cmdline,
                            mode: mode.to_string(),
                            security_descriptor: None,
                            instance_count: None,
                            max_instances: None,
                            pipe_mode: None,
                            connected_pids,
                        },
                    );
                }
            }

            // Recurse into subdirectories (one level)
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                let subdir = entry.path().to_string_lossy().to_string();
                // Don't recurse into system directories
                if !subdir.contains("/proc") && !subdir.contains("/sys") {
                    // Single level recursion
                    if let Ok(sub_entries) = fs::read_dir(&subdir) {
                        for sub_entry in sub_entries.filter_map(|e| e.ok()) {
                            if let Ok(meta) = fs::metadata(sub_entry.path()) {
                                if meta.file_type().is_socket() || meta.file_type().is_fifo() {
                                    let sub_path = sub_entry.path();
                                    let path_str = sub_path.to_string_lossy().to_string();
                                    let name = sub_path
                                        .file_name()
                                        .map(|n| n.to_string_lossy().to_string())
                                        .unwrap_or_default();

                                    if Self::is_system_socket(&name) {
                                        continue;
                                    }

                                    let (pid, process_name, process_path, cmdline) =
                                        Self::find_socket_owner_linux_detailed(&path_str, None);

                                    let mode = if meta.file_type().is_socket() {
                                        "socket"
                                    } else {
                                        "fifo"
                                    };

                                    pipes.insert(
                                        path_str.clone(),
                                        PipeInfo {
                                            path: path_str,
                                            name,
                                            pid,
                                            process_name,
                                            process_path,
                                            process_cmdline: cmdline,
                                            mode: mode.to_string(),
                                            security_descriptor: None,
                                            instance_count: None,
                                            max_instances: None,
                                            pipe_mode: None,
                                            connected_pids: HashSet::new(),
                                        },
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn is_system_socket(name: &str) -> bool {
        let system_prefixes = [
            "dbus",
            "systemd",
            "snapd",
            "docker",
            "containerd",
            "X11",
            "wayland",
            "pulseaudio",
            "pipewire",
            "gdm",
            "gnome",
            "kde",
            "xfce",
            "at-spi",
            "speech-dispatcher",
            "accounts-daemon",
            "polkit",
            "colord",
            "udisks",
            "upower",
            "bluetoothd",
            "NetworkManager",
            "avahi",
            "cups",
            "sshd",
            "cron",
            "rsyslog",
            "journal",
        ];

        let name_lower = name.to_lowercase();
        system_prefixes
            .iter()
            .any(|p| name_lower.contains(&p.to_lowercase()))
    }

    #[cfg(target_os = "linux")]
    fn find_socket_owner_linux_detailed(
        socket_path: &str,
        inode: Option<u64>,
    ) -> (u32, String, String, Option<String>) {
        use std::fs;

        // First, try to find by path in /proc/*/fd
        if let Ok(proc_entries) = fs::read_dir("/proc") {
            for entry in proc_entries.filter_map(|e| e.ok()) {
                let pid_str = entry.file_name().to_string_lossy().to_string();
                let pid: u32 = match pid_str.parse() {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                let fd_dir = format!("/proc/{}/fd", pid);
                if let Ok(fd_entries) = fs::read_dir(&fd_dir) {
                    for fd_entry in fd_entries.filter_map(|e| e.ok()) {
                        if let Ok(link_target) = fs::read_link(fd_entry.path()) {
                            let target_str = link_target.to_string_lossy();

                            // Check by path or inode
                            let matches = if socket_path.starts_with('@') {
                                // Abstract socket - match by name or inode
                                target_str.contains(&socket_path[1..])
                                    || (inode.is_some()
                                        && target_str
                                            .contains(&format!("socket:[{}]", inode.unwrap())))
                            } else {
                                target_str.contains(socket_path) || target_str == socket_path
                            };

                            if matches {
                                let comm_path = format!("/proc/{}/comm", pid);
                                let exe_path = format!("/proc/{}/exe", pid);
                                let cmdline_path = format!("/proc/{}/cmdline", pid);

                                let process_name = fs::read_to_string(&comm_path)
                                    .map(|s| s.trim().to_string())
                                    .unwrap_or_default();

                                let process_path = fs::read_link(&exe_path)
                                    .map(|p| p.to_string_lossy().to_string())
                                    .unwrap_or_default();

                                let cmdline = fs::read_to_string(&cmdline_path)
                                    .map(|s| s.replace('\0', " ").trim().to_string())
                                    .ok()
                                    .filter(|s| !s.is_empty());

                                return (pid, process_name, process_path, cmdline);
                            }
                        }
                    }
                }
            }
        }

        (0, String::new(), String::new(), None)
    }

    #[cfg(target_os = "linux")]
    fn find_connected_processes_linux(socket_path: &str, inode: Option<u64>) -> HashSet<u32> {
        use std::fs;
        let mut connected = HashSet::new();

        // Scan all processes looking for this socket
        if let Ok(proc_entries) = fs::read_dir("/proc") {
            for entry in proc_entries.filter_map(|e| e.ok()) {
                let pid_str = entry.file_name().to_string_lossy().to_string();
                let pid: u32 = match pid_str.parse() {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                let fd_dir = format!("/proc/{}/fd", pid);
                if let Ok(fd_entries) = fs::read_dir(&fd_dir) {
                    for fd_entry in fd_entries.filter_map(|e| e.ok()) {
                        if let Ok(link_target) = fs::read_link(fd_entry.path()) {
                            let target_str = link_target.to_string_lossy();

                            let matches = if socket_path.starts_with('@') {
                                target_str.contains(&socket_path[1..])
                                    || (inode.is_some()
                                        && target_str
                                            .contains(&format!("socket:[{}]", inode.unwrap())))
                            } else {
                                target_str.contains(socket_path)
                            };

                            if matches {
                                connected.insert(pid);
                                break;
                            }
                        }
                    }
                }
            }
        }

        connected
    }

    #[cfg(target_os = "macos")]
    async fn enumerate_pipes_macos() -> HashMap<String, PipeInfo> {
        use std::fs;
        use std::os::unix::fs::FileTypeExt;

        let mut pipes = HashMap::new();

        // Similar to Linux, check common socket locations
        let socket_dirs = ["/tmp", "/var/run", "/private/tmp", "/private/var/run"];

        for dir in &socket_dirs {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let path = entry.path();

                    if let Ok(metadata) = fs::metadata(&path) {
                        if metadata.file_type().is_socket() {
                            let path_str = path.to_string_lossy().to_string();
                            let name = path
                                .file_name()
                                .map(|n| n.to_string_lossy().to_string())
                                .unwrap_or_default();

                            // Use lsof to find owner
                            let (pid, process_name, process_path) =
                                Self::find_socket_owner_macos(&path_str);

                            pipes.insert(
                                path_str.clone(),
                                PipeInfo {
                                    path: path_str,
                                    name,
                                    pid,
                                    process_name,
                                    process_path,
                                    process_cmdline: None,
                                    mode: "socket".to_string(),
                                    security_descriptor: None,
                                    instance_count: None,
                                    max_instances: None,
                                    pipe_mode: None,
                                    connected_pids: HashSet::new(),
                                },
                            );
                        }
                    }
                }
            }
        }

        debug!(count = pipes.len(), "Enumerated macOS UNIX sockets");
        pipes
    }

    #[cfg(target_os = "macos")]
    fn find_socket_owner_macos(socket_path: &str) -> (u32, String, String) {
        use std::process::Command;

        let output = match Command::new("lsof")
            .args(["-F", "pcn", socket_path])
            .output()
        {
            Ok(o) => o,
            Err(_) => return (0, String::new(), String::new()),
        };

        if !output.status.success() {
            return (0, String::new(), String::new());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut pid: Option<u32> = None;
        let mut process_name = String::new();

        for line in stdout.lines() {
            if line.starts_with('p') {
                pid = line[1..].parse().ok();
            } else if line.starts_with('c') {
                process_name = line[1..].to_string();
            }
        }

        let pid = pid.unwrap_or(0);
        let process_path = if pid > 0 {
            Command::new("ps")
                .args(["-p", &pid.to_string(), "-o", "comm="])
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default()
        } else {
            String::new()
        };

        (pid, process_name, process_path)
    }

    /// Create a telemetry event for a pipe operation
    async fn create_pipe_event(
        path: &str,
        info: &PipeInfo,
        operation: &str,
        old_info: Option<&PipeInfo>,
        patterns: &MaliciousPipePatterns,
        config: &AgentConfig,
    ) -> Option<TelemetryEvent> {
        // Check exclusions
        if config.excluded_paths.iter().any(|p| path.contains(p)) {
            return None;
        }

        // Check for malicious patterns
        let (detection_info, severity) =
            if let Some((rule, desc, confidence)) = patterns.check_pipe(&info.name) {
                let sev = if confidence >= 0.9 {
                    Severity::Critical
                } else if confidence >= 0.75 {
                    Severity::High
                } else if confidence >= 0.6 {
                    Severity::Medium
                } else {
                    Severity::Low
                };
                (Some((rule, desc, confidence)), sev)
            } else {
                (None, Severity::Info)
            };

        // Only create events for suspicious pipes or pipe creations/connections
        if detection_info.is_none() && operation != "create" && operation != "connect" {
            return None;
        }

        // Determine remote process info for cross-process communication
        let (remote_pid, remote_process_name, remote_process_path) = if operation == "connect" {
            if let Some(old) = old_info {
                // Find new connected PIDs
                let new_pids: Vec<_> = info
                    .connected_pids
                    .iter()
                    .filter(|p| !old.connected_pids.contains(*p) && **p != info.pid)
                    .copied()
                    .collect();

                if let Some(&remote) = new_pids.first() {
                    let name = Self::get_process_name(remote);
                    (Some(remote), Some(name.clone()), None)
                } else {
                    (None, None, None)
                }
            } else {
                (None, None, None)
            }
        } else {
            (None, None, None)
        };

        let pipe_event = NamedPipeEvent {
            pipe_path: path.to_string(),
            pipe_name: info.name.clone(),
            operation: operation.to_string(),
            pid: info.pid,
            process_name: info.process_name.clone(),
            process_path: info.process_path.clone(),
            process_cmdline: info.process_cmdline.clone(),
            mode: info.mode.clone(),
            remote_pid,
            remote_process_name,
            remote_process_path,
            security_descriptor: info.security_descriptor.clone(),
            instance_count: info.instance_count,
            max_instances: info.max_instances,
            pipe_mode: info.pipe_mode.clone(),
            detection_reason: detection_info.as_ref().map(|(_, d, _)| d.clone()),
        };

        let event_type = match operation {
            "create" => EventType::NamedPipeCreate,
            "connect" => EventType::NamedPipeConnect,
            "delete" | "close" => EventType::NamedPipeClose,
            _ => EventType::NamedPipeCreate,
        };

        let mut event = TelemetryEvent::new(
            event_type,
            severity.clone(),
            EventPayload::Custom(serde_json::to_value(&pipe_event).unwrap_or_default()),
        );

        // Add MITRE metadata
        event
            .metadata
            .insert("mitre_tactic".to_string(), "lateral-movement".to_string());
        event
            .metadata
            .insert("mitre_technique".to_string(), "T1570".to_string());

        if detection_info.is_some() {
            event
                .metadata
                .insert("mitre_technique_secondary".to_string(), "T1071".to_string());
        }

        // Cross-process communication detection
        if remote_pid.is_some() {
            event
                .metadata
                .insert("cross_process".to_string(), "true".to_string());
            event
                .metadata
                .insert("mitre_technique_ipc".to_string(), "T1559".to_string());
        }

        // Add detection if suspicious
        if let Some((rule_name, description, confidence)) = detection_info {
            event.add_detection(Detection {
                detection_type: DetectionType::Ioc,
                rule_name,
                confidence,
                description,
                mitre_tactics: vec![
                    "lateral-movement".to_string(),
                    "command-and-control".to_string(),
                ],
                mitre_techniques: vec!["T1570".to_string(), "T1071".to_string()],
            });
        }

        Some(event)
    }

    /// Check for behavioral anomalies in pipe activity
    async fn check_behavioral_anomalies(
        current_pipes: &HashMap<String, PipeInfo>,
        pipe_connections: &HashMap<String, Vec<PipeConnection>>,
        patterns: &MaliciousPipePatterns,
        tx: &mpsc::Sender<TelemetryEvent>,
        config: &AgentConfig,
    ) {
        // Group pipes by process
        let mut pipes_by_process: HashMap<u32, Vec<&PipeInfo>> = HashMap::new();

        for info in current_pipes.values() {
            if info.pid > 0 {
                pipes_by_process.entry(info.pid).or_default().push(info);
            }
        }

        // Check for processes with many pipes (potential C2 or lateral movement)
        for (pid, pipes) in &pipes_by_process {
            if pipes.len() > 10 {
                let process_name = pipes
                    .first()
                    .map(|p| p.process_name.clone())
                    .unwrap_or_default();

                // Skip known legitimate processes
                if Self::is_legitimate_pipe_heavy_process(&process_name) {
                    continue;
                }

                let pipe_event = NamedPipeEvent {
                    pipe_path: format!("multiple_pipes_pid_{}", pid),
                    pipe_name: format!("{}_pipes", pipes.len()),
                    operation: "behavioral_anomaly".to_string(),
                    pid: *pid,
                    process_name: process_name.clone(),
                    process_path: pipes
                        .first()
                        .map(|p| p.process_path.clone())
                        .unwrap_or_default(),
                    process_cmdline: pipes.first().and_then(|p| p.process_cmdline.clone()),
                    mode: "multiple".to_string(),
                    remote_pid: None,
                    remote_process_name: None,
                    remote_process_path: None,
                    security_descriptor: None,
                    instance_count: Some(pipes.len() as u32),
                    max_instances: None,
                    pipe_mode: None,
                    detection_reason: Some(format!(
                        "Process {} ({}) has {} named pipes - potential C2 activity",
                        process_name,
                        pid,
                        pipes.len()
                    )),
                };

                let mut event = TelemetryEvent::new(
                    EventType::NamedPipeCreate,
                    Severity::Medium,
                    EventPayload::Custom(serde_json::to_value(&pipe_event).unwrap_or_default()),
                );

                event.add_detection(Detection {
                    detection_type: DetectionType::Behavioral,
                    rule_name: "high_pipe_count".to_string(),
                    confidence: 0.6,
                    description: format!(
                        "Process has unusual number of named pipes: {}",
                        pipes.len()
                    ),
                    mitre_tactics: vec!["command-and-control".to_string()],
                    mitre_techniques: vec!["T1071".to_string()],
                });

                let _ = tx.send(event).await;
            }
        }

        // Check for suspicious cross-process communication patterns
        for (pipe_path, connections) in pipe_connections {
            if connections.len() > 5 {
                // Many processes connecting to same pipe - potential C2 beacon
                let unique_clients: HashSet<_> = connections.iter().map(|c| c.client_pid).collect();

                if unique_clients.len() > 3 {
                    let first_conn = &connections[0];

                    let pipe_event = NamedPipeEvent {
                        pipe_path: pipe_path.clone(),
                        pipe_name: first_conn.pipe_name.clone(),
                        operation: "suspicious_communication".to_string(),
                        pid: first_conn.server_pid,
                        process_name: first_conn.server_process.clone(),
                        process_path: String::new(),
                        process_cmdline: None,
                        mode: "multi_client".to_string(),
                        remote_pid: None,
                        remote_process_name: None,
                        remote_process_path: None,
                        security_descriptor: None,
                        instance_count: Some(connections.len() as u32),
                        max_instances: None,
                        pipe_mode: None,
                        detection_reason: Some(format!(
                            "Pipe {} has {} client connections from {} unique processes",
                            first_conn.pipe_name,
                            connections.len(),
                            unique_clients.len()
                        )),
                    };

                    let mut event = TelemetryEvent::new(
                        EventType::NamedPipeConnect,
                        Severity::Medium,
                        EventPayload::Custom(serde_json::to_value(&pipe_event).unwrap_or_default()),
                    );

                    event.add_detection(Detection {
                        detection_type: DetectionType::Behavioral,
                        rule_name: "suspicious_pipe_communication".to_string(),
                        confidence: 0.65,
                        description: format!("Multiple processes communicating via single pipe"),
                        mitre_tactics: vec![
                            "command-and-control".to_string(),
                            "lateral-movement".to_string(),
                        ],
                        mitre_techniques: vec!["T1071".to_string(), "T1559".to_string()],
                    });

                    let _ = tx.send(event).await;
                }
            }
        }
    }

    /// Check if a process is known to legitimately use many pipes
    fn is_legitimate_pipe_heavy_process(name: &str) -> bool {
        let legitimate = [
            "svchost",
            "services",
            "lsass",
            "csrss",
            "wininit",
            "System",
            "smss",
            "spoolsv",
            "SearchIndexer",
            "docker",
            "containerd",
            "dockerd",
            "kubelet",
            "systemd",
            "dbus",
            "dbus-daemon",
            "dbus-broker",
            "Xorg",
            "gnome-shell",
            "kwin",
            "pulseaudio",
            "pipewire",
            "chrome",
            "firefox",
            "msedge",
            "brave",
            "code",
            "node",
            "python",
            "java",
            "postgres",
            "mysql",
            "mongod",
            "redis-server",
        ];

        let name_lower = name.to_lowercase();
        legitimate
            .iter()
            .any(|p| name_lower.contains(&p.to_lowercase()))
    }

    /// Get next event from collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }
}

/// Internal pipe information structure
#[derive(Clone, Debug)]
struct PipeInfo {
    path: String,
    name: String,
    pid: u32,
    process_name: String,
    process_path: String,
    process_cmdline: Option<String>,
    mode: String,
    security_descriptor: Option<String>,
    instance_count: Option<u32>,
    max_instances: Option<u32>,
    pipe_mode: Option<String>,
    connected_pids: HashSet<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_malicious_pipe_detection() {
        let patterns = MaliciousPipePatterns::default();

        // Test Cobalt Strike patterns
        assert!(patterns.check_pipe("msagent_abc123").is_some());
        assert!(patterns.check_pipe("MSSE-12345-server").is_some());
        assert!(patterns.check_pipe("postex_deadbeef").is_some());

        // Test Metasploit patterns
        assert!(patterns.check_pipe("meterpreter").is_some());
        assert!(patterns.check_pipe("meterpreter_session").is_some());

        // Test PsExec
        assert!(patterns.check_pipe("PSEXESVC").is_some());
        assert!(patterns.check_pipe("RemCom_communicaton").is_some());

        // Test GUID-based pipes
        let guid_result = patterns.check_pipe("a1b2c3d4-e5f6-7890-abcd-ef1234567890");
        assert!(guid_result.is_some());

        // Test legitimate pipes should not match with high confidence
        // Note: Some like "browser_pipe" might match low-confidence random patterns
        let chrome_pipe = patterns.check_pipe("chrome.NativeMessaging.out.1234");
        assert!(
            chrome_pipe.is_none()
                || chrome_pipe
                    .as_ref()
                    .map(|(_, _, c)| *c < 0.7)
                    .unwrap_or(true)
        );
    }

    #[test]
    fn test_entropy_calculation() {
        // High entropy (random-looking)
        let random_name = "a8f3b2c9d4e5f6a7b8c9d0e1f2a3b4c5";
        let entropy = MaliciousPipePatterns::calculate_name_entropy(random_name);
        assert!(
            entropy > 3.5,
            "Expected high entropy for random string, got {}",
            entropy
        );

        // Low entropy (repetitive)
        let simple_name = "aaaaaaaaaa";
        let entropy = MaliciousPipePatterns::calculate_name_entropy(simple_name);
        assert!(
            entropy < 1.0,
            "Expected low entropy for repetitive string, got {}",
            entropy
        );

        // Medium entropy (real word)
        let word_name = "browser_pipe";
        let entropy = MaliciousPipePatterns::calculate_name_entropy(word_name);
        assert!(
            entropy > 2.0 && entropy < 4.0,
            "Expected medium entropy for word, got {}",
            entropy
        );
    }

    #[test]
    fn test_is_system_socket() {
        #[cfg(target_os = "linux")]
        {
            assert!(NamedPipeCollector::is_system_socket("dbus-session"));
            assert!(NamedPipeCollector::is_system_socket("/run/systemd/notify"));
            assert!(NamedPipeCollector::is_system_socket("pulseaudio"));
            assert!(!NamedPipeCollector::is_system_socket("suspicious_socket"));
            assert!(!NamedPipeCollector::is_system_socket("beacon"));
        }
    }

    #[test]
    fn test_legitimate_process_detection() {
        assert!(NamedPipeCollector::is_legitimate_pipe_heavy_process(
            "svchost.exe"
        ));
        assert!(NamedPipeCollector::is_legitimate_pipe_heavy_process(
            "chrome"
        ));
        assert!(NamedPipeCollector::is_legitimate_pipe_heavy_process(
            "docker"
        ));
        assert!(!NamedPipeCollector::is_legitimate_pipe_heavy_process(
            "beacon.exe"
        ));
        assert!(!NamedPipeCollector::is_legitimate_pipe_heavy_process(
            "malware"
        ));
    }
}
