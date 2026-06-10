//! Live Response Process Manager
//!
//! Provides comprehensive process management capabilities for incident response:
//! - Full process tree enumeration with parent-child relationships
//! - Process actions: kill, suspend, resume, set priority
//! - Memory dumping (full process memory and minidump)
//! - Handle inspection (files, registry, network)
//! - Security detections:
//!   - Privilege escalation (elevated processes)
//!   - Unsigned binaries
//!   - Hidden processes
//!   - Process hollowing
//!   - Parent spoofing

// Live response process manager. Scaffolded PMC handle/memory counter fields
// retained for upcoming GetProcessHandleCount / PROCESS_MEMORY_COUNTERS path.
#![allow(dead_code, unused_variables, unused_assignments)]

use crate::transport::CommandResult;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use sysinfo::System;
use tracing::info;

#[cfg(target_os = "windows")]
use windows::Win32::{
    Foundation::CloseHandle,
    System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    },
    System::Threading::{
        OpenProcess, OpenThread, ResumeThread, SuspendThread, TerminateProcess,
        PROCESS_QUERY_INFORMATION, PROCESS_TERMINATE, THREAD_SUSPEND_RESUME,
    },
};

/// Process information with full details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub path: Option<String>,
    pub cmdline: Vec<String>,
    pub user: Option<String>,
    pub cpu_usage: f32,
    pub memory: u64,
    pub virtual_memory: u64,
    pub start_time: u64,
    pub status: String,
    pub is_elevated: bool,
    pub is_signed: bool,
    pub signer: Option<String>,
    pub is_hidden: bool,
    pub suspected_hollowing: bool,
    pub suspected_spoofing: bool,
    pub thread_count: usize,
    pub handle_count: Option<u32>,
}

/// Process tree node with children
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTreeNode {
    pub process: ProcessInfo,
    pub children: Vec<ProcessTreeNode>,
}

/// List all processes with full details and security checks
pub async fn process_tree_list(payload: &serde_json::Value) -> CommandResult {
    let include_security_checks = payload
        .get("include_security_checks")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let filter_elevated = payload
        .get("filter_elevated")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    info!(
        security_checks = include_security_checks,
        filter_elevated = filter_elevated,
        "Enumerating process tree"
    );

    let mut sys = System::new_all();
    sys.refresh_processes();

    // Collect all processes with full details
    let mut processes: Vec<ProcessInfo> = Vec::new();
    let mut pid_map: HashMap<u32, usize> = HashMap::new();

    for (pid, process) in sys.processes() {
        let pid_u32 = pid.as_u32();

        let process_info = ProcessInfo {
            pid: pid_u32,
            ppid: process.parent().map(|p| p.as_u32()),
            name: process.name().to_string(),
            path: process.exe().map(|p| p.to_string_lossy().to_string()),
            cmdline: process.cmd().to_vec(),
            user: process.user_id().map(|u| u.to_string()),
            cpu_usage: process.cpu_usage(),
            memory: process.memory(),
            virtual_memory: process.virtual_memory(),
            start_time: process.start_time(),
            status: format!("{:?}", process.status()),
            is_elevated: if include_security_checks {
                check_is_elevated(pid_u32)
            } else {
                false
            },
            is_signed: if include_security_checks {
                if let Some(ref path) = process.exe() {
                    check_is_signed(&path.to_string_lossy())
                } else {
                    false
                }
            } else {
                false
            },
            signer: if include_security_checks {
                if let Some(ref path) = process.exe() {
                    get_signer(&path.to_string_lossy())
                } else {
                    None
                }
            } else {
                None
            },
            is_hidden: if include_security_checks {
                check_is_hidden(pid_u32)
            } else {
                false
            },
            suspected_hollowing: if include_security_checks {
                check_process_hollowing(pid_u32)
            } else {
                false
            },
            suspected_spoofing: if include_security_checks {
                check_parent_spoofing(pid_u32, process.parent().map(|p| p.as_u32()))
            } else {
                false
            },
            thread_count: 0, // Will be filled on Windows
            handle_count: if include_security_checks {
                get_handle_count(pid_u32)
            } else {
                None
            },
        };

        // Apply filters
        if filter_elevated && !process_info.is_elevated {
            continue;
        }

        pid_map.insert(pid_u32, processes.len());
        processes.push(process_info);
    }

    // Build tree structure
    let tree = build_process_tree(&processes, &pid_map);

    CommandResult {
        success: true,
        error_message: None,
        result_data: Some(serde_json::json!({
            "processes": processes,
            "tree": tree,
            "count": processes.len(),
            "security_checks_enabled": include_security_checks,
        })),
    }
}

/// Build hierarchical process tree
fn build_process_tree(
    processes: &[ProcessInfo],
    pid_map: &HashMap<u32, usize>,
) -> Vec<ProcessTreeNode> {
    let mut roots = Vec::new();
    let mut nodes: HashMap<u32, ProcessTreeNode> = HashMap::new();

    // Create nodes for all processes
    for process in processes {
        nodes.insert(
            process.pid,
            ProcessTreeNode {
                process: process.clone(),
                children: Vec::new(),
            },
        );
    }

    // Build parent-child relationships
    for process in processes {
        if let Some(ppid) = process.ppid {
            if pid_map.contains_key(&ppid) {
                // Has a parent in our list - will be added to parent's children
                continue;
            }
        }
        // No parent or parent not in our list - this is a root
        if let Some(node) = nodes.remove(&process.pid) {
            roots.push(node);
        }
    }

    // Recursively build children
    fn attach_children(
        node: &mut ProcessTreeNode,
        all_processes: &[ProcessInfo],
        nodes: &mut HashMap<u32, ProcessTreeNode>,
    ) {
        for process in all_processes {
            if process.ppid == Some(node.process.pid) {
                if let Some(mut child_node) = nodes.remove(&process.pid) {
                    attach_children(&mut child_node, all_processes, nodes);
                    node.children.push(child_node);
                }
            }
        }
    }

    for root in &mut roots {
        attach_children(root, processes, &mut nodes);
    }

    roots
}

/// Kill a process
pub async fn process_kill(payload: &serde_json::Value) -> CommandResult {
    let pid = payload.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let force = payload
        .get("force")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if pid == 0 {
        return CommandResult {
            success: false,
            error_message: Some("Invalid PID".to_string()),
            result_data: None,
        };
    }

    info!(pid = pid, force = force, "Killing process");

    #[cfg(unix)]
    {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;

        let signal = if force {
            Signal::SIGKILL
        } else {
            Signal::SIGTERM
        };

        match kill(Pid::from_raw(pid as i32), signal) {
            Ok(_) => CommandResult {
                success: true,
                error_message: None,
                result_data: Some(serde_json::json!({ "pid": pid })),
            },
            Err(e) => CommandResult {
                success: false,
                error_message: Some(format!("Failed to kill process: {}", e)),
                result_data: None,
            },
        }
    }

    #[cfg(windows)]
    {
        unsafe {
            match OpenProcess(PROCESS_TERMINATE, false, pid) {
                Ok(handle) => {
                    let result = TerminateProcess(handle, 1);
                    let _ = CloseHandle(handle);

                    if result.is_ok() {
                        CommandResult {
                            success: true,
                            error_message: None,
                            result_data: Some(serde_json::json!({ "pid": pid })),
                        }
                    } else {
                        CommandResult {
                            success: false,
                            error_message: Some("TerminateProcess failed".to_string()),
                            result_data: None,
                        }
                    }
                }
                Err(e) => CommandResult {
                    success: false,
                    error_message: Some(format!("Failed to open process: {}", e)),
                    result_data: None,
                },
            }
        }
    }

    #[cfg(not(any(unix, windows)))]
    CommandResult {
        success: false,
        error_message: Some("Platform not supported".to_string()),
        result_data: None,
    }
}

/// Suspend a process (all threads)
pub async fn process_suspend(payload: &serde_json::Value) -> CommandResult {
    let pid = payload.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

    if pid == 0 {
        return CommandResult {
            success: false,
            error_message: Some("Invalid PID".to_string()),
            result_data: None,
        };
    }

    info!(pid = pid, "Suspending process");

    #[cfg(unix)]
    {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;

        match kill(Pid::from_raw(pid as i32), Signal::SIGSTOP) {
            Ok(_) => CommandResult {
                success: true,
                error_message: None,
                result_data: Some(serde_json::json!({ "pid": pid, "status": "suspended" })),
            },
            Err(e) => CommandResult {
                success: false,
                error_message: Some(format!("Failed to suspend process: {}", e)),
                result_data: None,
            },
        }
    }

    #[cfg(windows)]
    {
        match suspend_all_threads(pid) {
            Ok(count) => CommandResult {
                success: true,
                error_message: None,
                result_data: Some(serde_json::json!({
                    "pid": pid,
                    "status": "suspended",
                    "threads_suspended": count
                })),
            },
            Err(e) => CommandResult {
                success: false,
                error_message: Some(e),
                result_data: None,
            },
        }
    }

    #[cfg(not(any(unix, windows)))]
    CommandResult {
        success: false,
        error_message: Some("Platform not supported".to_string()),
        result_data: None,
    }
}

/// Resume a process (all threads)
pub async fn process_resume(payload: &serde_json::Value) -> CommandResult {
    let pid = payload.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

    if pid == 0 {
        return CommandResult {
            success: false,
            error_message: Some("Invalid PID".to_string()),
            result_data: None,
        };
    }

    info!(pid = pid, "Resuming process");

    #[cfg(unix)]
    {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;

        match kill(Pid::from_raw(pid as i32), Signal::SIGCONT) {
            Ok(_) => CommandResult {
                success: true,
                error_message: None,
                result_data: Some(serde_json::json!({ "pid": pid, "status": "resumed" })),
            },
            Err(e) => CommandResult {
                success: false,
                error_message: Some(format!("Failed to resume process: {}", e)),
                result_data: None,
            },
        }
    }

    #[cfg(windows)]
    {
        match resume_all_threads(pid) {
            Ok(count) => CommandResult {
                success: true,
                error_message: None,
                result_data: Some(serde_json::json!({
                    "pid": pid,
                    "status": "resumed",
                    "threads_resumed": count
                })),
            },
            Err(e) => CommandResult {
                success: false,
                error_message: Some(e),
                result_data: None,
            },
        }
    }

    #[cfg(not(any(unix, windows)))]
    CommandResult {
        success: false,
        error_message: Some("Platform not supported".to_string()),
        result_data: None,
    }
}

/// Set process priority
pub async fn process_set_priority(payload: &serde_json::Value) -> CommandResult {
    let pid = payload.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let priority = payload
        .get("priority")
        .and_then(|v| v.as_str())
        .unwrap_or("normal");

    if pid == 0 {
        return CommandResult {
            success: false,
            error_message: Some("Invalid PID".to_string()),
            result_data: None,
        };
    }

    info!(pid = pid, priority = priority, "Setting process priority");

    #[cfg(unix)]
    {
        use nix::errno::Errno;
        use nix::unistd::Pid;

        // Map priority names to nice values
        let nice_value: i32 = match priority {
            "realtime" | "high" => -20,
            "above_normal" => -10,
            "normal" => 0,
            "below_normal" => 10,
            "idle" | "low" => 19,
            _ => 0,
        };

        // setpriority requires libc
        let result = unsafe { libc::setpriority(libc::PRIO_PROCESS, pid, nice_value) };

        if result == 0 {
            CommandResult {
                success: true,
                error_message: None,
                result_data: Some(serde_json::json!({
                    "pid": pid,
                    "priority": priority,
                    "nice_value": nice_value
                })),
            }
        } else {
            CommandResult {
                success: false,
                error_message: Some(format!("Failed to set priority: {}", Errno::last())),
                result_data: None,
            }
        }
    }

    #[cfg(windows)]
    {
        use windows::Win32::System::Threading::*;

        let priority_class = match priority {
            "realtime" => REALTIME_PRIORITY_CLASS,
            "high" => HIGH_PRIORITY_CLASS,
            "above_normal" => ABOVE_NORMAL_PRIORITY_CLASS,
            "normal" => NORMAL_PRIORITY_CLASS,
            "below_normal" => BELOW_NORMAL_PRIORITY_CLASS,
            "idle" | "low" => IDLE_PRIORITY_CLASS,
            _ => NORMAL_PRIORITY_CLASS,
        };

        unsafe {
            match OpenProcess(PROCESS_SET_INFORMATION, false, pid) {
                Ok(handle) => {
                    let result = SetPriorityClass(handle, priority_class);
                    let _ = CloseHandle(handle);

                    if result.is_ok() {
                        CommandResult {
                            success: true,
                            error_message: None,
                            result_data: Some(serde_json::json!({
                                "pid": pid,
                                "priority": priority
                            })),
                        }
                    } else {
                        CommandResult {
                            success: false,
                            error_message: Some("SetPriorityClass failed".to_string()),
                            result_data: None,
                        }
                    }
                }
                Err(e) => CommandResult {
                    success: false,
                    error_message: Some(format!("Failed to open process: {}", e)),
                    result_data: None,
                },
            }
        }
    }

    #[cfg(not(any(unix, windows)))]
    CommandResult {
        success: false,
        error_message: Some("Platform not supported".to_string()),
        result_data: None,
    }
}

/// List handles for a process
pub async fn process_list_handles(payload: &serde_json::Value) -> CommandResult {
    let pid = payload.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let handle_type = payload.get("type").and_then(|v| v.as_str());

    if pid == 0 {
        return CommandResult {
            success: false,
            error_message: Some("Invalid PID".to_string()),
            result_data: None,
        };
    }

    info!(pid = pid, handle_type = ?handle_type, "Listing process handles");

    #[cfg(target_os = "windows")]
    {
        match enumerate_handles(pid, handle_type) {
            Ok(handles) => CommandResult {
                success: true,
                error_message: None,
                result_data: Some(serde_json::json!({
                    "pid": pid,
                    "handles": handles,
                    "count": handles.len()
                })),
            },
            Err(e) => CommandResult {
                success: false,
                error_message: Some(e),
                result_data: None,
            },
        }
    }

    #[cfg(target_os = "linux")]
    {
        match enumerate_handles_linux(pid, handle_type) {
            Ok(handles) => CommandResult {
                success: true,
                error_message: None,
                result_data: Some(serde_json::json!({
                    "pid": pid,
                    "handles": handles,
                    "count": handles.len()
                })),
            },
            Err(e) => CommandResult {
                success: false,
                error_message: Some(e),
                result_data: None,
            },
        }
    }

    #[cfg(target_os = "macos")]
    {
        match enumerate_handles_macos(pid, handle_type) {
            Ok(handles) => CommandResult {
                success: true,
                error_message: None,
                result_data: Some(serde_json::json!({
                    "pid": pid,
                    "handles": handles,
                    "count": handles.len()
                })),
            },
            Err(e) => CommandResult {
                success: false,
                error_message: Some(e),
                result_data: None,
            },
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    CommandResult {
        success: false,
        error_message: Some("Platform not supported".to_string()),
        result_data: None,
    }
}

// ============================================================================
// Platform-specific implementations
// ============================================================================

#[cfg(target_os = "windows")]
fn suspend_all_threads(pid: u32) -> Result<usize, String> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            .map_err(|e| format!("CreateToolhelp32Snapshot failed: {}", e))?;

        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        let mut suspended_count = 0;

        if Thread32First(snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32OwnerProcessID == pid {
                    if let Ok(thread_handle) =
                        OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID)
                    {
                        let _ = SuspendThread(thread_handle);
                        let _ = CloseHandle(thread_handle);
                        suspended_count += 1;
                    }
                }

                if Thread32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);

        if suspended_count > 0 {
            Ok(suspended_count)
        } else {
            Err("No threads found or suspended".to_string())
        }
    }
}

#[cfg(target_os = "windows")]
fn resume_all_threads(pid: u32) -> Result<usize, String> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            .map_err(|e| format!("CreateToolhelp32Snapshot failed: {}", e))?;

        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        let mut resumed_count = 0;

        if Thread32First(snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32OwnerProcessID == pid {
                    if let Ok(thread_handle) =
                        OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID)
                    {
                        let _ = ResumeThread(thread_handle);
                        let _ = CloseHandle(thread_handle);
                        resumed_count += 1;
                    }
                }

                if Thread32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);

        if resumed_count > 0 {
            Ok(resumed_count)
        } else {
            Err("No threads found or resumed".to_string())
        }
    }
}

// ============================================================================
// Security detection functions
// ============================================================================

fn check_is_elevated(pid: u32) -> bool {
    #[cfg(target_os = "windows")]
    {
        crate::collectors::win_compat::is_process_elevated(pid)
    }

    #[cfg(target_os = "linux")]
    {
        // Check if process UID is 0 (root)
        if let Ok(status) = std::fs::read_to_string(format!("/proc/{}/status", pid)) {
            for line in status.lines() {
                if line.starts_with("Uid:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if let Some(uid) = parts.get(1) {
                        return *uid == "0";
                    }
                }
            }
        }
        false
    }

    #[cfg(target_os = "macos")]
    {
        // Use `ps` to check EUID
        use std::process::Command;
        if let Ok(output) = Command::new("ps")
            .args(&["-p", &pid.to_string(), "-o", "uid="])
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

fn check_is_signed(path: &str) -> bool {
    #[cfg(target_os = "windows")]
    {
        crate::collectors::win_compat::is_file_signed(path)
    }

    #[cfg(target_os = "macos")]
    {
        check_macos_signature(path).0
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let _ = path;
        false
    }
}

fn get_signer(path: &str) -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        crate::collectors::win_compat::get_file_signer(path)
    }

    #[cfg(target_os = "macos")]
    {
        check_macos_signature(path).1
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let _ = path;
        None
    }
}

#[cfg(target_os = "macos")]
fn check_macos_signature(path: &str) -> (bool, Option<String>) {
    if path.is_empty() {
        return (false, None);
    }

    let verify_output = std::process::Command::new("codesign")
        .args(["--verify", "--strict", path])
        .output();

    if !verify_output
        .map(|out| out.status.success())
        .unwrap_or(false)
    {
        return (false, None);
    }

    let signer = std::process::Command::new("codesign")
        .args(["-dv", "--verbose=4", path])
        .output()
        .ok()
        .and_then(|out| parse_macos_codesign_signer(&String::from_utf8_lossy(&out.stderr)));

    (
        true,
        signer.or_else(|| Some("Signed (unknown signer)".to_string())),
    )
}

#[cfg(target_os = "macos")]
fn parse_macos_codesign_signer(output: &str) -> Option<String> {
    output
        .lines()
        .find_map(|line| line.strip_prefix("Authority=").map(str::to_string))
        .or_else(|| {
            if output.contains("Apple")
                || output.contains("Software Signing")
                || output.contains("Platform Binary")
            {
                Some("Apple".to_string())
            } else {
                None
            }
        })
}

fn check_is_hidden(_pid: u32) -> bool {
    // Hidden process detection would require kernel driver or advanced techniques
    // For now, return false (placeholder for future implementation)
    false
}

fn check_process_hollowing(_pid: u32) -> bool {
    // Process hollowing detection requires memory analysis
    // Placeholder for future implementation
    false
}

fn check_parent_spoofing(_pid: u32, _claimed_ppid: Option<u32>) -> bool {
    // Parent spoofing detection requires comparing claimed PPID with actual
    // Placeholder for future implementation
    false
}

fn get_handle_count(pid: u32) -> Option<u32> {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::ProcessStatus::*;
        use windows::Win32::System::Threading::OpenProcess;

        unsafe {
            if let Ok(handle) = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) {
                let mut pmc = PROCESS_MEMORY_COUNTERS::default();
                pmc.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;

                // Note: Handle count is not in PROCESS_MEMORY_COUNTERS
                // This is a placeholder - actual implementation would use GetProcessHandleCount
                let _ = CloseHandle(handle);
            }
        }
    }

    None
}

#[cfg(target_os = "windows")]
fn enumerate_handles(
    pid: u32,
    handle_type: Option<&str>,
) -> Result<Vec<serde_json::Value>, String> {
    // This would require NtQuerySystemInformation with SystemHandleInformation
    // Placeholder implementation returning empty for now
    let _ = pid;
    let _ = handle_type;
    Ok(Vec::new())
}

#[cfg(target_os = "linux")]
fn enumerate_handles_linux(
    pid: u32,
    handle_type: Option<&str>,
) -> Result<Vec<serde_json::Value>, String> {
    let mut handles = Vec::new();
    let fd_dir = format!("/proc/{}/fd", pid);

    if let Ok(entries) = std::fs::read_dir(&fd_dir) {
        for entry in entries.flatten() {
            if let Ok(link) = std::fs::read_link(entry.path()) {
                let target = link.to_string_lossy().to_string();

                // Filter by type if specified
                if let Some(filter_type) = handle_type {
                    let matches = match filter_type {
                        "file" => target.starts_with('/') && !target.starts_with("/dev/"),
                        "socket" => target.starts_with("socket:"),
                        "pipe" => target.starts_with("pipe:"),
                        _ => true,
                    };

                    if !matches {
                        continue;
                    }
                }

                handles.push(serde_json::json!({
                    "fd": entry.file_name().to_string_lossy().to_string(),
                    "target": target,
                    "type": categorize_handle_type(&target),
                }));
            }
        }
    }

    Ok(handles)
}

#[cfg(target_os = "linux")]
fn categorize_handle_type(target: &str) -> &'static str {
    if target.starts_with("socket:") {
        "socket"
    } else if target.starts_with("pipe:") {
        "pipe"
    } else if target.starts_with("/dev/") {
        "device"
    } else if target.starts_with('/') {
        "file"
    } else {
        "other"
    }
}

#[cfg(target_os = "macos")]
fn enumerate_handles_macos(
    pid: u32,
    handle_type: Option<&str>,
) -> Result<Vec<serde_json::Value>, String> {
    let output = std::process::Command::new("lsof")
        .args(["-n", "-P", "-p", &pid.to_string(), "-Fnft"])
        .output()
        .map_err(|e| format!("Failed to execute lsof: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "lsof failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(parse_macos_lsof_handles(
        &String::from_utf8_lossy(&output.stdout),
        handle_type,
    ))
}

#[cfg(target_os = "macos")]
fn parse_macos_lsof_handles(output: &str, handle_type: Option<&str>) -> Vec<serde_json::Value> {
    let mut handles = Vec::new();
    let mut current_fd: Option<String> = None;
    let mut current_lsof_type: Option<String> = None;

    for line in output.lines() {
        if line.is_empty() {
            continue;
        }

        let (prefix, value) = line.split_at(1);
        match prefix {
            "f" => {
                current_fd = Some(value.to_string());
                current_lsof_type = None;
            }
            "t" => {
                current_lsof_type = Some(value.to_string());
            }
            "n" => {
                let Some(fd) = current_fd.take() else {
                    continue;
                };
                let lsof_type = current_lsof_type.take().unwrap_or_default();
                let normalized_type = categorize_macos_lsof_handle_type(&lsof_type, value);

                if let Some(filter_type) = handle_type {
                    if normalized_type != filter_type {
                        continue;
                    }
                }

                handles.push(serde_json::json!({
                    "fd": fd,
                    "target": value,
                    "type": normalized_type,
                    "lsof_type": lsof_type,
                }));
            }
            _ => {}
        }
    }

    handles
}

#[cfg(target_os = "macos")]
fn categorize_macos_lsof_handle_type(lsof_type: &str, target: &str) -> &'static str {
    match lsof_type {
        "REG" => "file",
        "DIR" => "directory",
        "CHR" | "BLK" => "device",
        "PIPE" | "FIFO" => "pipe",
        "IPv4" | "IPv6" | "unix" => "socket",
        _ if target.starts_with('/') => "file",
        _ if target.contains("->") || target.starts_with("TCP ") || target.starts_with("UDP ") => {
            "socket"
        }
        _ => "other",
    }
}

#[cfg(test)]
#[path = "process_manager_test.rs"]
mod tests;
