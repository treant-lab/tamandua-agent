//! LSASS (Local Security Authority Subsystem Service) Protection Monitor
//!
//! Detects credential theft attempts targeting LSASS:
//! - Mimikatz and similar tools
//! - LSASS memory dumps
//! - Suspicious process access to LSASS
//! - Debug privilege usage against LSASS
//!
//! Uses undocumented NT APIs for deep visibility:
//! - NtQuerySystemInformation with SystemHandleInformation for handle enumeration
//! - NtQueryInformationProcess for command line and protection status
//!
//! MITRE ATT&CK:
//! - T1003.001 (OS Credential Dumping: LSASS Memory)
//! - T1003.002 (Security Account Manager)
//! - T1003.003 (NTDS)

#![cfg(target_os = "windows")]
// LSASS credential theft detector. Scaffolded handle/info fields retained.
#![allow(dead_code, unused_variables)]

use super::{
    win_compat::{
        get_windows_version,
        ntapi::{
            self, get_nt_api, get_process_command_line, is_process_protected,
            ProcessBasicInformation, PsProtection, SystemHandleTableEntryInfo,
            SystemHandleTableEntryInfoEx, PROCESS_BASIC_INFORMATION, STATUS_INFO_LENGTH_MISMATCH,
            STATUS_SUCCESS, SYSTEM_EXTENDED_HANDLE_INFORMATION, SYSTEM_HANDLE_INFORMATION,
        },
    },
    Detection, DetectionType, EventPayload, EventType, ProcessEvent, Severity, TelemetryEvent,
};
use crate::config::AgentConfig;
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
use windows::Win32::Security::{
    GetTokenInformation, LookupPrivilegeValueW, TokenPrivileges, SE_PRIVILEGE_ENABLED,
    TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::ProcessStatus::K32GetProcessImageFileNameW;
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_DUP_HANDLE,
    PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};

/// LSASS access patterns that indicate credential theft
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LsassAccessType {
    /// Full memory read access (common for Mimikatz)
    MemoryRead,
    /// Memory dump creation
    MemoryDump,
    /// Debug privilege access
    DebugAccess,
    /// Duplicate handle access
    HandleDuplicate,
    /// Process hollowing attempt
    ProcessHollowing,
    /// Unknown/suspicious
    Unknown,
}

impl LsassAccessType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MemoryRead => "memory_read",
            Self::MemoryDump => "memory_dump",
            Self::DebugAccess => "debug_access",
            Self::HandleDuplicate => "handle_duplicate",
            Self::ProcessHollowing => "process_hollowing",
            Self::Unknown => "unknown",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Self::MemoryRead | Self::MemoryDump => Severity::Critical,
            Self::DebugAccess | Self::HandleDuplicate => Severity::High,
            _ => Severity::Medium,
        }
    }
}

/// Information about LSASS process
#[derive(Debug, Clone)]
struct LsassInfo {
    pid: u32,
    path: String,
    is_protected: bool,
    protection_level: Option<PsProtection>,
}

/// Handle access information from NtQuerySystemInformation
#[derive(Debug, Clone)]
struct HandleAccess {
    accessor_pid: u32,
    handle_value: usize,
    granted_access: u32,
    object_type_index: u8,
}

/// LSASS Protection Monitor
pub struct LsassMonitor {
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    lsass_info: Option<LsassInfo>,
}

impl LsassMonitor {
    /// Create a new LSASS monitor
    pub fn new(config: &AgentConfig) -> Result<Self> {
        let (tx, rx) = mpsc::channel(500);

        info!("Initializing LSASS protection monitor with NT API support");

        // Check for NT API availability
        if get_nt_api().is_some() {
            info!("NtQuerySystemInformation available for handle enumeration");
        } else {
            warn!("NT API not available, using fallback monitoring");
        }

        // Find LSASS process with protection info
        let lsass_info = Self::find_lsass();
        if let Some(ref info) = lsass_info {
            info!(
                pid = info.pid,
                path = %info.path,
                protected = info.is_protected,
                "Found LSASS process"
            );
            if let Some(ref prot) = info.protection_level {
                debug!(
                    protection_type = prot.protection_type(),
                    protection_signer = prot.protection_signer(),
                    "LSASS protection details"
                );
            }
        } else {
            warn!("Could not find LSASS process");
        }

        // Start monitoring
        let config_clone = config.clone();
        let tx_clone = tx.clone();
        let lsass_info_clone = lsass_info.clone();

        tokio::spawn(async move {
            Self::monitor_loop(tx_clone, config_clone, lsass_info_clone).await;
        });

        Ok(Self {
            config: config.clone(),
            event_rx: rx,
            lsass_info,
        })
    }

    /// Find LSASS process with protection status
    fn find_lsass() -> Option<LsassInfo> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;

            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            if Process32FirstW(snapshot, &mut entry).is_err() {
                let _ = CloseHandle(snapshot);
                return None;
            }

            loop {
                let name = String::from_utf16_lossy(
                    &entry.szExeFile[..entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0)],
                );

                if name.to_lowercase() == "lsass.exe" {
                    let _ = CloseHandle(snapshot);

                    let pid = entry.th32ProcessID;
                    let path = Self::get_process_path(pid);

                    // Try to get protection info
                    let (is_protected, protection_level) = Self::get_protection_info(pid);

                    return Some(LsassInfo {
                        pid,
                        path,
                        is_protected,
                        protection_level,
                    });
                }

                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }

            let _ = CloseHandle(snapshot);
            None
        }
    }

    /// Get LSASS protection info using NtQueryInformationProcess
    fn get_protection_info(pid: u32) -> (bool, Option<PsProtection>) {
        unsafe {
            // Use limited query access (works even for protected processes)
            let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(h) => h,
                Err(_) => return (false, None),
            };

            let protection = is_process_protected(std::mem::transmute::<_, *mut c_void>(handle));
            let _ = CloseHandle(handle);

            match protection {
                Some(prot) => (prot.is_protected(), Some(prot)),
                None => (false, None),
            }
        }
    }

    /// Get process path
    fn get_process_path(pid: u32) -> String {
        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(h) => h,
                Err(_) => return String::new(),
            };

            let mut path_buf = [0u16; 260];
            let len = K32GetProcessImageFileNameW(handle, &mut path_buf);
            let _ = CloseHandle(handle);

            if len > 0 {
                String::from_utf16_lossy(&path_buf[..len as usize])
            } else {
                String::new()
            }
        }
    }

    /// Main monitoring loop
    async fn monitor_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        _config: AgentConfig,
        lsass_info: Option<LsassInfo>,
    ) {
        info!("Starting LSASS monitoring loop");

        let lsass_pid = match &lsass_info {
            Some(info) => info.pid,
            None => {
                warn!("No LSASS PID, monitoring disabled");
                return;
            }
        };

        // Track known good processes that legitimately access LSASS
        let legitimate_accessors: HashSet<&str> = [
            "csrss.exe",
            "services.exe",
            "svchost.exe",
            "wininit.exe",
            "winlogon.exe",
            "smss.exe",
            "MsMpEng.exe", // Windows Defender
            "MsSense.exe", // Windows Defender ATP
            "SenseIR.exe", // Windows Defender ATP
            "SecurityHealthService.exe",
            "System",
            "NisSrv.exe",      // Windows Defender Network Inspection
            "MpCmdRun.exe",    // Windows Defender CLI
            "audiodg.exe",     // Audio Device Graph
            "dwm.exe",         // Desktop Window Manager
            "fontdrvhost.exe", // Font Driver Host
        ]
        .iter()
        .copied()
        .collect();

        // Known Mimikatz signatures/patterns
        let mimikatz_signatures = [
            "mimikatz",
            "sekurlsa",
            "logonpasswords",
            "lsadump",
            "kerberos::ptt",
            "kerberos::golden",
            "privilege::debug",
            "wdigest",
            "livessp",
            "tspkg",
            "credman",
            "dpapi::chrome",
        ];

        // Known credential dumping tools
        let known_tools = [
            "procdump",
            "comsvcs.dll",
            "rundll32",
            "minidump",
            "lazagne",
            "pypykatz",
            "gosecretsdump",
            "crackmapexec",
            "impacket",
        ];

        // Track processes that have accessed LSASS
        let mut lsass_accessors: HashMap<u32, (String, u64)> = HashMap::new();

        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(500));

        loop {
            interval.tick().await;

            // Method 1: Enumerate handles to LSASS using NtQuerySystemInformation
            if let Some(accessors) = Self::enumerate_lsass_handles(lsass_pid) {
                for access in accessors {
                    // Skip self
                    if access.accessor_pid == std::process::id() {
                        continue;
                    }

                    // Skip system processes
                    if access.accessor_pid == 0 || access.accessor_pid == 4 {
                        continue;
                    }

                    // Get accessor info
                    let accessor_name = Self::get_process_name(access.accessor_pid);

                    // Check if legitimate
                    if legitimate_accessors
                        .iter()
                        .any(|&l| accessor_name.to_lowercase() == l.to_lowercase())
                    {
                        continue;
                    }

                    // Check if already reported recently
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    if let Some((_, last_seen)) = lsass_accessors.get(&access.accessor_pid) {
                        if now - last_seen < 60 {
                            continue; // Skip if seen in last minute
                        }
                    }

                    let accessor_path = Self::get_process_path(access.accessor_pid);
                    lsass_accessors.insert(access.accessor_pid, (accessor_name.clone(), now));

                    // Determine access type based on granted access
                    let access_type = Self::classify_access(access.granted_access);

                    // Get command line using NT API
                    let cmdline = Self::get_process_cmdline_nt(access.accessor_pid);

                    // Check for Mimikatz patterns
                    let cmdline_lower = cmdline.to_lowercase();
                    let name_lower = accessor_name.to_lowercase();
                    let path_lower = accessor_path.to_lowercase();

                    let is_mimikatz = mimikatz_signatures
                        .iter()
                        .any(|sig| cmdline_lower.contains(sig) || name_lower.contains(sig));

                    let is_known_tool = known_tools
                        .iter()
                        .any(|tool| cmdline_lower.contains(tool) || name_lower.contains(tool));

                    // Additional suspicious indicators
                    let suspicious_location = path_lower.contains("\\temp\\")
                        || path_lower.contains("\\appdata\\local\\temp")
                        || path_lower.contains("\\downloads\\")
                        || path_lower.contains("\\public\\")
                        || path_lower.contains("c:\\users\\public");

                    // Suspicious access mask (full access or memory read)
                    let suspicious_access = (access.granted_access & 0x1F0FFF) == 0x1F0FFF  // PROCESS_ALL_ACCESS
                        || (access.granted_access & 0x0010) != 0; // PROCESS_VM_READ

                    // Skip if not suspicious enough
                    if !is_mimikatz && !is_known_tool && !suspicious_location && !suspicious_access
                    {
                        continue;
                    }

                    // Create alert
                    let event = Self::create_lsass_alert(
                        access.accessor_pid,
                        &accessor_name,
                        &accessor_path,
                        &cmdline,
                        lsass_pid,
                        access_type,
                        is_mimikatz,
                        is_known_tool,
                        access.granted_access,
                    );

                    if tx.send(event).await.is_err() {
                        warn!("Event channel closed");
                        return;
                    }
                }
            }

            // Method 2: Check for debug privilege usage
            if let Some(debug_processes) = Self::get_processes_with_debug_privilege() {
                for (pid, name) in debug_processes {
                    // Skip known legitimate processes
                    if legitimate_accessors
                        .iter()
                        .any(|&l| name.to_lowercase() == l.to_lowercase())
                    {
                        continue;
                    }

                    // Skip self
                    if pid == std::process::id() {
                        continue;
                    }

                    let path = Self::get_process_path(pid);
                    let cmdline = Self::get_process_cmdline_nt(pid);

                    let cmdline_lower = cmdline.to_lowercase();
                    let path_lower = path.to_lowercase();

                    // Check for suspicious indicators
                    let is_suspicious = path_lower.contains("\\temp\\")
                        || path_lower.contains("\\appdata\\")
                        || path_lower.contains("\\downloads\\")
                        || cmdline_lower.contains("privilege::debug")
                        || mimikatz_signatures
                            .iter()
                            .any(|sig| cmdline_lower.contains(sig));

                    if is_suspicious {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();

                        if let Some((_, last_seen)) = lsass_accessors.get(&pid) {
                            if now - last_seen < 60 {
                                continue;
                            }
                        }

                        lsass_accessors.insert(pid, (name.clone(), now));

                        let event = Self::create_debug_privilege_alert(pid, &name, &path, &cmdline);
                        if tx.send(event).await.is_err() {
                            warn!("Event channel closed");
                            return;
                        }
                    }
                }
            }

            // Cleanup old entries
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            lsass_accessors.retain(|_, (_, timestamp)| now - *timestamp < 300);
        }
    }

    /// Enumerate handles to LSASS using NtQuerySystemInformation
    /// This is the key function that uses undocumented NT APIs
    fn enumerate_lsass_handles(lsass_pid: u32) -> Option<Vec<HandleAccess>> {
        // NtQuerySystemInformation with SYSTEM_EXTENDED_HANDLE_INFORMATION
        // requires elevation. Without it, the data may be incomplete/corrupted
        // and NtDuplicateObject can crash inside ntdll.dll.
        if !super::win_compat::is_elevated() {
            return None;
        }

        let api = get_nt_api()?;

        // Try extended handle information first (Win8+)
        if get_windows_version().is_win8_or_later() {
            if let Some(handles) = Self::enumerate_handles_ex(api, lsass_pid) {
                return Some(handles);
            }
        }

        // Fallback to legacy handle information
        Self::enumerate_handles_legacy(api, lsass_pid)
    }

    /// Enumerate handles using SYSTEM_EXTENDED_HANDLE_INFORMATION (Win8+)
    fn enumerate_handles_ex(api: &ntapi::NtApi, lsass_pid: u32) -> Option<Vec<HandleAccess>> {
        unsafe {
            // Start with 64KB buffer and grow
            let mut buffer_size: u32 = 64 * 1024;
            let mut buffer: Vec<u8>;
            let mut return_length: u32 = 0;
            let mut status: i32;

            // Keep growing buffer until we have enough space
            loop {
                buffer = vec![0u8; buffer_size as usize];

                status = (api.nt_query_system_information)(
                    SYSTEM_EXTENDED_HANDLE_INFORMATION,
                    buffer.as_mut_ptr() as *mut c_void,
                    buffer_size,
                    &mut return_length,
                );

                if status == STATUS_INFO_LENGTH_MISMATCH as i32 {
                    // Need bigger buffer
                    buffer_size = return_length + 0x10000;
                    if buffer_size > 256 * 1024 * 1024 {
                        // Safety limit: 256MB
                        debug!("Handle buffer too large, skipping");
                        return None;
                    }
                    continue;
                }

                break;
            }

            if status != STATUS_SUCCESS {
                debug!(
                    status = status,
                    "NtQuerySystemInformation (extended) failed"
                );
                return None;
            }

            // Parse the extended handle information
            let handle_info = &*(buffer.as_ptr() as *const ntapi::SystemExtendedHandleInformation);
            let handle_count = handle_info.number_of_handles;

            let mut accessors = Vec::new();

            // Get the handle entries array
            let handles_offset =
                std::mem::offset_of!(ntapi::SystemExtendedHandleInformation, handles);
            let handles_ptr =
                (buffer.as_ptr() as usize + handles_offset) as *const SystemHandleTableEntryInfoEx;

            // Cap iteration at buffer bounds to prevent out-of-bounds reads
            let entry_size = std::mem::size_of::<SystemHandleTableEntryInfoEx>();
            let max_entries = if entry_size > 0 && buffer.len() > handles_offset {
                (buffer.len() - handles_offset) / entry_size
            } else {
                0
            };
            let safe_count = handle_count.min(max_entries);

            for i in 0..safe_count {
                let entry = &*handles_ptr.add(i);

                // We're looking for handles TO the LSASS process
                // The object would be the LSASS process object
                // Skip handles owned by LSASS itself
                if entry.unique_process_id == lsass_pid as usize {
                    continue;
                }

                // Only check process handles (type index 7)
                // The access mask filter was too broad and matched non-process handles,
                // causing crashes when NtQueryInformationProcess was called on them.
                if entry.object_type_index == 7 {
                    // Check if this handle points to LSASS by trying to duplicate and verify
                    if Self::verify_handle_target_is_lsass(
                        entry.unique_process_id as u32,
                        entry.handle_value,
                        lsass_pid,
                    ) {
                        accessors.push(HandleAccess {
                            accessor_pid: entry.unique_process_id as u32,
                            handle_value: entry.handle_value,
                            granted_access: entry.granted_access,
                            object_type_index: entry.object_type_index as u8,
                        });
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

    /// Enumerate handles using SYSTEM_HANDLE_INFORMATION (Win7+)
    fn enumerate_handles_legacy(api: &ntapi::NtApi, lsass_pid: u32) -> Option<Vec<HandleAccess>> {
        unsafe {
            let mut buffer_size: u32 = 64 * 1024;
            let mut buffer: Vec<u8>;
            let mut return_length: u32 = 0;
            let mut status: i32;

            loop {
                buffer = vec![0u8; buffer_size as usize];

                status = (api.nt_query_system_information)(
                    SYSTEM_HANDLE_INFORMATION,
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
                debug!(status = status, "NtQuerySystemInformation (legacy) failed");
                return None;
            }

            // Parse legacy handle information
            let handle_info = &*(buffer.as_ptr() as *const ntapi::SystemHandleInformation);
            let handle_count = handle_info.number_of_handles;

            let mut accessors = Vec::new();

            let handles_offset = std::mem::offset_of!(ntapi::SystemHandleInformation, handles);
            let handles_ptr =
                (buffer.as_ptr() as usize + handles_offset) as *const SystemHandleTableEntryInfo;

            // Cap iteration at buffer bounds
            let entry_size = std::mem::size_of::<SystemHandleTableEntryInfo>();
            let max_entries = if entry_size > 0 && buffer.len() > handles_offset {
                (buffer.len() - handles_offset) / entry_size
            } else {
                0
            };
            let safe_count = (handle_count as usize).min(max_entries);

            for i in 0..safe_count {
                let entry = &*handles_ptr.add(i);

                if entry.process_id as u32 == lsass_pid {
                    continue;
                }

                // Only check process handles (type index 7)
                if entry.object_type_index == 7 {
                    if Self::verify_handle_target_is_lsass(
                        entry.process_id as u32,
                        entry.handle_value as usize,
                        lsass_pid,
                    ) {
                        accessors.push(HandleAccess {
                            accessor_pid: entry.process_id as u32,
                            handle_value: entry.handle_value as usize,
                            granted_access: entry.granted_access,
                            object_type_index: entry.object_type_index,
                        });
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

    /// Verify if a handle in another process points to LSASS
    fn verify_handle_target_is_lsass(owner_pid: u32, handle_value: usize, lsass_pid: u32) -> bool {
        let api = match get_nt_api() {
            Some(api) => api,
            None => return false,
        };

        let dup_fn = match api.nt_duplicate_object {
            Some(f) => f,
            None => return false,
        };

        let close_fn = match api.nt_close {
            Some(f) => f,
            None => return false,
        };

        unsafe {
            // Open the process that owns the handle
            let owner_handle = match OpenProcess(PROCESS_DUP_HANDLE, false, owner_pid) {
                Ok(h) => h,
                Err(_) => return false,
            };

            // Try to duplicate the handle to our process
            let mut duplicated_handle: *mut c_void = std::ptr::null_mut();
            let current_process = GetCurrentProcess();

            let status = dup_fn(
                std::mem::transmute::<_, *mut c_void>(owner_handle),
                handle_value as *mut c_void,
                std::mem::transmute::<_, *mut c_void>(current_process),
                &mut duplicated_handle,
                PROCESS_QUERY_LIMITED_INFORMATION.0,
                0,
                0,
            );

            let _ = CloseHandle(owner_handle);

            // Check for failure, null, AND INVALID_HANDLE_VALUE (-1)
            let invalid_handle = -1isize as *mut c_void;
            if status != STATUS_SUCCESS
                || duplicated_handle.is_null()
                || duplicated_handle == invalid_handle
            {
                if !duplicated_handle.is_null() && duplicated_handle != invalid_handle {
                    let _ = close_fn(duplicated_handle);
                }
                return false;
            }

            // Now check if this duplicated handle points to LSASS
            // We do this by querying the process ID of the target
            let mut pbi: ProcessBasicInformation = std::mem::zeroed();
            let mut return_length: u32 = 0;

            let query_status = (api.nt_query_information_process)(
                duplicated_handle,
                PROCESS_BASIC_INFORMATION,
                &mut pbi as *mut _ as *mut c_void,
                std::mem::size_of::<ProcessBasicInformation>() as u32,
                &mut return_length,
            );

            let is_lsass =
                query_status == STATUS_SUCCESS && pbi.unique_process_id as u32 == lsass_pid;

            // Close our duplicated handle
            let _ = close_fn(duplicated_handle);

            is_lsass
        }
    }

    /// Get processes with SeDebugPrivilege enabled
    fn get_processes_with_debug_privilege() -> Option<Vec<(u32, String)>> {
        let mut debug_processes = Vec::new();

        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;

            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    let pid = entry.th32ProcessID;

                    if pid > 4 {
                        if let Ok(handle) =
                            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
                        {
                            let mut token_handle = HANDLE::default();
                            if OpenProcessToken(handle, TOKEN_QUERY, &mut token_handle).is_ok() {
                                if Self::has_debug_privilege(token_handle) {
                                    let name = String::from_utf16_lossy(
                                        &entry.szExeFile[..entry
                                            .szExeFile
                                            .iter()
                                            .position(|&c| c == 0)
                                            .unwrap_or(0)],
                                    );
                                    debug_processes.push((pid, name));
                                }
                                let _ = CloseHandle(token_handle);
                            }
                            let _ = CloseHandle(handle);
                        }
                    }

                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
        }

        if debug_processes.is_empty() {
            None
        } else {
            Some(debug_processes)
        }
    }

    /// Check if token has SeDebugPrivilege enabled
    fn has_debug_privilege(token: HANDLE) -> bool {
        unsafe {
            let debug_name: Vec<u16> = "SeDebugPrivilege\0".encode_utf16().collect();
            let mut debug_luid = LUID::default();

            if LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(debug_name.as_ptr()), &mut debug_luid)
                .is_err()
            {
                return false;
            }

            let mut needed = 0u32;
            let _ = GetTokenInformation(token, TokenPrivileges, None, 0, &mut needed);

            if needed == 0 {
                return false;
            }

            let mut buffer = vec![0u8; needed as usize];
            if GetTokenInformation(
                token,
                TokenPrivileges,
                Some(buffer.as_mut_ptr() as *mut _),
                needed,
                &mut needed,
            )
            .is_err()
            {
                return false;
            }

            let privs = &*(buffer.as_ptr() as *const TOKEN_PRIVILEGES);
            let privileges = std::slice::from_raw_parts(
                privs.Privileges.as_ptr(),
                privs.PrivilegeCount as usize,
            );

            for priv_info in privileges {
                if priv_info.Luid.LowPart == debug_luid.LowPart
                    && priv_info.Luid.HighPart == debug_luid.HighPart
                {
                    return (priv_info.Attributes.0 & SE_PRIVILEGE_ENABLED.0) != 0;
                }
            }

            false
        }
    }

    /// Classify access type based on access mask
    fn classify_access(access_mask: u32) -> LsassAccessType {
        // PROCESS_VM_READ = 0x0010
        // PROCESS_VM_WRITE = 0x0020
        // PROCESS_VM_OPERATION = 0x0008
        // PROCESS_DUP_HANDLE = 0x0040
        // PROCESS_ALL_ACCESS = 0x1F0FFF

        if access_mask & 0x1F0FFF == 0x1F0FFF {
            LsassAccessType::MemoryDump // Full access usually means dump
        } else if access_mask & 0x0040 != 0 {
            LsassAccessType::HandleDuplicate
        } else if access_mask & 0x0018 != 0 {
            // VM_READ or VM_OPERATION
            LsassAccessType::MemoryRead
        } else if access_mask & 0x0020 != 0 {
            LsassAccessType::ProcessHollowing // Write access
        } else {
            LsassAccessType::Unknown
        }
    }

    /// Get process name
    fn get_process_name(pid: u32) -> String {
        unsafe {
            let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(h) => h,
                Err(_) => return String::new(),
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
            String::new()
        }
    }

    /// Get process command line using NT API
    fn get_process_cmdline_nt(pid: u32) -> String {
        unsafe {
            // Try with limited access first
            let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(h) => h,
                Err(_) => {
                    // Fall back to full query
                    match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
                        Ok(h) => h,
                        Err(_) => return String::new(),
                    }
                }
            };

            let cmdline = get_process_command_line(std::mem::transmute::<_, *mut c_void>(handle))
                .unwrap_or_default();
            let _ = CloseHandle(handle);

            cmdline
        }
    }

    /// Create LSASS access alert
    fn create_lsass_alert(
        accessor_pid: u32,
        accessor_name: &str,
        accessor_path: &str,
        cmdline: &str,
        lsass_pid: u32,
        access_type: LsassAccessType,
        is_mimikatz: bool,
        is_known_tool: bool,
        access_mask: u32,
    ) -> TelemetryEvent {
        let severity = if is_mimikatz {
            Severity::Critical
        } else if is_known_tool {
            Severity::Critical
        } else {
            access_type.severity()
        };

        let mut event = TelemetryEvent::new(
            EventType::ProcessCreate,
            severity,
            EventPayload::Process(ProcessEvent {
                pid: accessor_pid,
                ppid: 0,
                name: accessor_name.to_string(),
                path: accessor_path.to_string(),
                cmdline: cmdline.to_string(),
                user: String::new(),
                sha256: Vec::new(),
                entropy: 0.0,
                is_elevated: true,
                parent_name: None,
                parent_path: None,
                is_signed: false,
                signer: None,
                start_time: 0,
                cpu_usage: 0.0,
                memory_bytes: 0,
                company_name: None,
                file_description: None,
                product_name: None,
                file_version: None,
                environment: None,
            }),
        );

        let rule_name = if is_mimikatz {
            "Mimikatz_LSASS_Access"
        } else if is_known_tool {
            "Credential_Dump_Tool_LSASS_Access"
        } else {
            "LSASS_Memory_Access"
        };

        let confidence = if is_mimikatz {
            0.99
        } else if is_known_tool {
            0.95
        } else {
            0.85
        };

        event.add_detection(Detection {
            detection_type: DetectionType::Behavioral,
            rule_name: rule_name.to_string(),
            confidence,
            description: format!(
                "Potential credential theft: {} (PID: {}) accessed LSASS (PID: {}), Access type: {}, Mask: 0x{:08X}",
                accessor_name, accessor_pid, lsass_pid, access_type.as_str(), access_mask
            ),
            mitre_tactics: vec!["Credential Access".to_string()],
            mitre_techniques: vec!["T1003.001".to_string()],
        });

        event
            .metadata
            .insert("lsass_pid".to_string(), lsass_pid.to_string());
        event
            .metadata
            .insert("access_type".to_string(), access_type.as_str().to_string());
        event
            .metadata
            .insert("access_mask".to_string(), format!("0x{:08X}", access_mask));

        if is_mimikatz {
            event
                .metadata
                .insert("mimikatz_detected".to_string(), "true".to_string());
        }
        if is_known_tool {
            event
                .metadata
                .insert("known_tool_detected".to_string(), "true".to_string());
        }

        event
    }

    /// Create debug privilege alert
    fn create_debug_privilege_alert(
        pid: u32,
        name: &str,
        path: &str,
        cmdline: &str,
    ) -> TelemetryEvent {
        let mut event = TelemetryEvent::new(
            EventType::ProcessCreate,
            Severity::High,
            EventPayload::Process(ProcessEvent {
                pid,
                ppid: 0,
                name: name.to_string(),
                path: path.to_string(),
                cmdline: cmdline.to_string(),
                user: String::new(),
                sha256: Vec::new(),
                entropy: 0.0,
                is_elevated: true,
                parent_name: None,
                parent_path: None,
                is_signed: false,
                signer: None,
                start_time: 0,
                cpu_usage: 0.0,
                memory_bytes: 0,
                company_name: None,
                file_description: None,
                product_name: None,
                file_version: None,
                environment: None,
            }),
        );

        event.add_detection(Detection {
            detection_type: DetectionType::Behavioral,
            rule_name: "Suspicious_Debug_Privilege".to_string(),
            confidence: 0.75,
            description: format!(
                "Suspicious process with SeDebugPrivilege: {} (PID: {}) from {}",
                name, pid, path
            ),
            mitre_tactics: vec![
                "Credential Access".to_string(),
                "Privilege Escalation".to_string(),
            ],
            mitre_techniques: vec!["T1003.001".to_string(), "T1134".to_string()],
        });

        event
            .metadata
            .insert("debug_privilege".to_string(), "enabled".to_string());

        event
    }

    /// Get next event from monitor
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }
}
