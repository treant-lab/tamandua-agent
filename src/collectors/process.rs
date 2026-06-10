//! Process event collector
//!
//! Monitors process creation, termination, and injection events.
//! Uses NT APIs for deep visibility on Windows.
//!
//! Maintains a process info cache for parent resolution and a signature
//! cache to avoid redundant Authenticode / package-manager checks.
//!
//! ## Command Line Spoofing Detection (T1564.010)
//!
//! Detects when a process modifies its command line after creation by:
//! 1. Recording the original command line at process creation (via ETW or CreateProcess hook)
//! 2. Later reading the current command line from PEB->ProcessParameters->CommandLine
//! 3. Comparing: if different, flagging as spoofed
//!
//! This detects techniques like Cobalt Strike's argue command and similar evasion methods.

// Process collector. Helper functions and SECURITY_MANDATORY_* constants are
// retained for upcoming Linux/Windows feature parity expansions.
#![allow(dead_code, unused_variables, unused_assignments)]

use super::governor_aware_interval::GovernorAwareInterval;
use super::{
    Detection, DetectionType, EventPayload, EventType, ProcessEvent, Severity, TelemetryEvent,
};
use crate::analyzers;
use crate::config::AgentConfig;
use crate::resource_governor::GovernorHandle;
use std::collections::{HashMap, HashSet};
use sysinfo::{Pid, Process, ProcessRefreshKind, System, UpdateKind, Users};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

#[cfg(target_os = "windows")]
use super::win_compat::ntapi::{get_process_command_line, get_real_parent_pid};

// ---------------------------------------------------------------------------
// Environment variable capture for process events
// ---------------------------------------------------------------------------

/// Environment variables worth capturing for security analysis.
/// Only security-relevant variables are collected, not the full environment.
const SECURITY_ENV_VARS: &[&str] = &[
    "PATH",
    "COMSPEC",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "HOME",
    "APPDATA",
    "LOCALAPPDATA",
    "SYSTEMROOT",
    "WINDIR",
    "PROCESSOR_ARCHITECTURE",
    "USERNAME",
    "USER",
    "COMPUTERNAME",
    "HOSTNAME",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "LD_PRELOAD",            // Linux: DLL injection equivalent
    "LD_LIBRARY_PATH",       // Linux: library path manipulation
    "DYLD_INSERT_LIBRARIES", // macOS: library injection
    "PSModulePath",          // PowerShell module path
    "_",                     // Last executed command (Linux)
];

/// Capture security-relevant environment variables for a process.
///
/// On Windows, reads from the current process environment for self, or returns
/// None for remote processes (reading remote PEB requires elevated access and
/// the kernel driver handles this more reliably).
///
/// On Linux, reads /proc/{pid}/environ which is available for same-user
/// processes or with appropriate capabilities.
///
/// On macOS, reads from the current process environment for self, or returns
/// None for remote processes (requires elevated access).
#[cfg(target_os = "windows")]
fn capture_process_environment(pid: u32) -> Option<HashMap<String, String>> {
    if pid == std::process::id() {
        let mut env_map = HashMap::new();
        for var_name in SECURITY_ENV_VARS {
            if let Ok(val) = std::env::var(var_name) {
                env_map.insert(var_name.to_string(), val);
            }
        }
        if !env_map.is_empty() {
            Some(env_map)
        } else {
            None
        }
    } else {
        // For remote processes, attempt to read via Windows API.
        // Reading remote process environment requires:
        // 1. NtQueryInformationProcess to get PEB address
        // 2. Read PEB to get ProcessParameters
        // 3. Read RTL_USER_PROCESS_PARAMETERS.Environment
        // 4. Parse the environment block (null-separated KEY=VALUE pairs)
        //
        // This is complex and error-prone -- the kernel driver captures
        // this info more reliably at process creation time.
        // For now, return None for remote processes.
        None
    }
}

#[cfg(target_os = "linux")]
fn capture_process_environment(pid: u32) -> Option<HashMap<String, String>> {
    // On Linux, read /proc/{pid}/environ (null-separated KEY=VALUE pairs)
    let environ_path = format!("/proc/{}/environ", pid);
    let data = std::fs::read(&environ_path).ok()?;

    let mut env_map = HashMap::new();
    for entry in data.split(|&b| b == 0) {
        if let Ok(s) = std::str::from_utf8(entry) {
            if let Some((key, value)) = s.split_once('=') {
                if SECURITY_ENV_VARS
                    .iter()
                    .any(|&v| v.eq_ignore_ascii_case(key))
                {
                    env_map.insert(key.to_string(), value.to_string());
                }
            }
        }
    }

    if !env_map.is_empty() {
        Some(env_map)
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn capture_process_environment(pid: u32) -> Option<HashMap<String, String>> {
    // On macOS, use sysctl KERN_PROCARGS2 to get process arguments and environment.
    // This requires appropriate permissions.  For the current process we can
    // just read std::env; for remote processes elevated access is needed.
    if pid == std::process::id() {
        let mut env_map = HashMap::new();
        for var_name in SECURITY_ENV_VARS {
            if let Ok(val) = std::env::var(var_name) {
                env_map.insert(var_name.to_string(), val);
            }
        }
        if !env_map.is_empty() {
            Some(env_map)
        } else {
            None
        }
    } else {
        None // Requires elevated access on macOS
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn capture_process_environment(_pid: u32) -> Option<HashMap<String, String>> {
    None
}

#[cfg(target_os = "linux")]
fn read_proc_cmdline(pid: u32) -> Option<String> {
    let path = format!("/proc/{}/cmdline", pid);
    let data = std::fs::read(path).ok()?;
    let parts: Vec<String> = data
        .split(|b| *b == 0)
        .filter_map(|part| {
            if part.is_empty() {
                return None;
            }
            std::str::from_utf8(part).ok().map(|s| s.to_string())
        })
        .collect();
    let cmdline = parts.join(" ");
    if cmdline.trim().is_empty() {
        None
    } else {
        Some(cmdline)
    }
}

#[cfg(target_os = "linux")]
fn read_proc_pids() -> HashSet<u32> {
    let mut pids = HashSet::new();

    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if let Ok(pid) = name.parse::<u32>() {
                    if read_proc_tgid(pid).unwrap_or(pid) == pid {
                        pids.insert(pid);
                    }
                }
            }
        }
    }

    pids
}

#[cfg(target_os = "linux")]
fn read_proc_tgid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    status.lines().find_map(|line| {
        line.strip_prefix("Tgid:")
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|tgid| tgid.parse::<u32>().ok())
    })
}

#[cfg(target_os = "linux")]
fn read_proc_comm(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{}/comm", pid))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(target_os = "linux")]
fn name_from_proc(pid: u32) -> String {
    read_proc_comm(pid).unwrap_or_else(|| format!("Process_{}", pid))
}

#[cfg(target_os = "linux")]
fn linux_retry_due(
    pid: u32,
    name: &str,
    cmdline: &str,
    retry_cache: &mut HashMap<u32, (String, u8, std::time::Instant)>,
) -> bool {
    let lower_name = name.to_ascii_lowercase();
    let lower_cmdline = cmdline.to_ascii_lowercase();
    let interesting = matches!(
        lower_name.as_str(),
        "sh" | "bash"
            | "dash"
            | "zsh"
            | "fish"
            | "python"
            | "python3"
            | "perl"
            | "ruby"
            | "node"
            | "php"
            | "curl"
            | "wget"
            | "nc"
            | "ncat"
            | "socat"
    ) || lower_cmdline.contains(" -c ")
        || lower_cmdline.contains("tamandua-semantic-rewrite");

    if !interesting {
        retry_cache.remove(&pid);
        return false;
    }

    const MAX_RETRIES: u8 = 3;
    const RETRY_INTERVAL_SECS: u64 = 15;

    let now = std::time::Instant::now();
    match retry_cache.get_mut(&pid) {
        Some((cached_cmdline, count, last_emit)) if cached_cmdline == cmdline => {
            if *count >= MAX_RETRIES {
                return false;
            }

            if now.duration_since(*last_emit).as_secs() < RETRY_INTERVAL_SECS {
                return false;
            }

            *count = count.saturating_add(1);
            *last_emit = now;
            true
        }
        _ => {
            retry_cache.insert(pid, (cmdline.to_string(), 0, now));
            false
        }
    }
}

#[cfg(target_os = "linux")]
fn read_proc_exe(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{}/exe", pid))
        .ok()
        .map(|path| path.to_string_lossy().to_string())
        .map(|value| value.trim_end_matches(" (deleted)").to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(target_os = "linux")]
fn read_proc_ppid(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    let close_paren = stat.rfind(") ")?;
    let after_name = &stat[close_paren + 2..];
    let mut fields = after_name.split_whitespace();
    fields.next()?; // state
    fields.next()?.parse::<u32>().ok()
}

#[cfg(target_os = "linux")]
fn read_proc_uid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    status.lines().find_map(|line| {
        line.strip_prefix("Uid:")
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|uid| uid.parse::<u32>().ok())
    })
}

#[cfg(target_os = "linux")]
fn linux_username_from_uid(uid: u32) -> String {
    unsafe {
        let pwd = libc::getpwuid(uid);
        if !pwd.is_null() {
            let name_ptr = (*pwd).pw_name;
            if !name_ptr.is_null() {
                if let Ok(name) = std::ffi::CStr::from_ptr(name_ptr).to_str() {
                    return name.to_string();
                }
            }
        }
    }

    uid.to_string()
}

#[cfg(not(target_os = "linux"))]
fn read_proc_cmdline(_pid: u32) -> Option<String> {
    None
}

// ---------------------------------------------------------------------------
// Command Line Spoofing Detection (MITRE T1564.010)
// ---------------------------------------------------------------------------

/// Alert generated when command line spoofing is detected.
///
/// This occurs when a process modifies its PEB->ProcessParameters->CommandLine
/// after creation, a technique used by malware like Cobalt Strike to evade
/// detection by command-line based rules.
#[derive(Debug, Clone)]
pub struct SpoofingAlert {
    /// Process ID where spoofing was detected
    pub pid: u32,
    /// Original command line captured at process creation
    pub original_cmdline: String,
    /// Current command line read from PEB
    pub current_cmdline: String,
    /// Timestamp when spoofing was detected
    pub detected_at: std::time::Instant,
}

/// Detects command line spoofing by comparing original vs current command lines.
///
/// # Detection Method
///
/// 1. **Recording Phase**: When a process is created, the original command line
///    is captured (from ETW, sysinfo, or direct API call) and stored.
///
/// 2. **Verification Phase**: Periodically (or on-demand), the current command
///    line is read directly from the process's PEB (Process Environment Block)
///    using NtQueryInformationProcess with ProcessCommandLineInformation.
///
/// 3. **Comparison**: If the current command line differs significantly from
///    the original, a spoofing alert is generated.
///
/// # Why This Works
///
/// Command line spoofing tools (Cobalt Strike argue, custom implants) modify
/// the PEB after process creation to hide suspicious arguments. However:
/// - EDR tools often capture the original at creation time
/// - The PEB can be read at any time to detect modifications
/// - Significant differences indicate tampering
///
/// # False Positive Mitigation
///
/// - Whitespace normalization before comparison
/// - Threshold-based similarity checking (not exact match)
/// - Exclusion of known-benign processes that legitimately modify cmdline
#[derive(Debug)]
pub struct CommandLineSpoofingDetector {
    /// Original command lines captured at process creation: PID -> cmdline
    original_cmdlines: HashMap<u32, String>,
    /// Timestamp when each entry was added (for cache eviction)
    entry_timestamps: HashMap<u32, std::time::Instant>,
    /// Maximum cache size before LRU eviction
    max_cache_size: usize,
    /// Processes known to legitimately modify their command line
    excluded_processes: HashSet<String>,
}

impl Default for CommandLineSpoofingDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandLineSpoofingDetector {
    /// Create a new command line spoofing detector with default settings.
    pub fn new() -> Self {
        Self::with_capacity(10000)
    }

    /// Create a detector with a specific cache capacity.
    pub fn with_capacity(max_cache_size: usize) -> Self {
        // Processes known to legitimately modify their command line
        let mut excluded = HashSet::new();
        // Some Java applications modify their command line
        excluded.insert("java.exe".to_string());
        excluded.insert("javaw.exe".to_string());
        // Some .NET applications do as well
        excluded.insert("dotnet.exe".to_string());

        Self {
            original_cmdlines: HashMap::with_capacity(max_cache_size / 2),
            entry_timestamps: HashMap::with_capacity(max_cache_size / 2),
            max_cache_size,
            excluded_processes: excluded,
        }
    }

    /// Record the original command line at process creation.
    ///
    /// This should be called as early as possible when a new process is detected,
    /// ideally from ETW ProcessStart events or CreateProcess hooks.
    pub fn record_creation(&mut self, pid: u32, cmdline: String) {
        // Evict oldest entries if cache is full
        if self.original_cmdlines.len() >= self.max_cache_size {
            self.evict_oldest(self.max_cache_size / 10); // Evict 10%
        }

        let now = std::time::Instant::now();
        self.original_cmdlines.insert(pid, cmdline);
        self.entry_timestamps.insert(pid, now);
    }

    /// Record creation with process name for exclusion checking.
    pub fn record_creation_with_name(&mut self, pid: u32, cmdline: String, process_name: &str) {
        // Skip excluded processes
        let name_lower = process_name.to_lowercase();
        if self
            .excluded_processes
            .iter()
            .any(|e| name_lower.contains(e))
        {
            return;
        }
        self.record_creation(pid, cmdline);
    }

    /// Check if a process has spoofed its command line.
    ///
    /// Compares the original command line (recorded at creation) with the
    /// current command line read from the process's PEB.
    ///
    /// Returns `Some(SpoofingAlert)` if spoofing is detected, `None` otherwise.
    pub fn check_for_spoofing(&self, pid: u32, current_cmdline: &str) -> Option<SpoofingAlert> {
        let original = self.original_cmdlines.get(&pid)?;

        // Normalize both command lines for comparison
        let original_normalized = Self::normalize_cmdline(original);
        let current_normalized = Self::normalize_cmdline(current_cmdline);

        // If they're identical after normalization, no spoofing
        if original_normalized == current_normalized {
            return None;
        }

        // Calculate similarity - if very different, it's likely spoofed
        let similarity = Self::calculate_similarity(&original_normalized, &current_normalized);

        // Threshold: if less than 70% similar, consider it spoofed
        // This accounts for minor variations while catching significant changes
        if similarity < 0.70 {
            debug!(
                pid,
                original = %original,
                current = %current_cmdline,
                similarity = %similarity,
                "Command line spoofing detected"
            );

            return Some(SpoofingAlert {
                pid,
                original_cmdline: original.clone(),
                current_cmdline: current_cmdline.to_string(),
                detected_at: std::time::Instant::now(),
            });
        }

        None
    }

    /// Check for spoofing by reading the current command line from PEB.
    ///
    /// This is the primary detection method on Windows - it opens the process,
    /// reads the command line from PEB, and compares with the recorded original.
    #[cfg(target_os = "windows")]
    pub fn check_process(&self, pid: u32) -> Option<SpoofingAlert> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

        // Skip if we don't have an original to compare
        if !self.original_cmdlines.contains_key(&pid) {
            return None;
        }

        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(h) => h,
                Err(_) => return None,
            };

            let current_cmdline = get_process_command_line(std::mem::transmute(handle));
            let _ = CloseHandle(handle);

            if let Some(current) = current_cmdline {
                self.check_for_spoofing(pid, &current)
            } else {
                None
            }
        }
    }

    /// Check for spoofing (non-Windows stub).
    #[cfg(not(target_os = "windows"))]
    pub fn check_process(&self, _pid: u32) -> Option<SpoofingAlert> {
        // Command line spoofing detection is currently Windows-only
        // as it relies on PEB manipulation which is a Windows-specific technique
        None
    }

    /// Remove a process from tracking (e.g., when it terminates).
    pub fn remove_process(&mut self, pid: u32) {
        self.original_cmdlines.remove(&pid);
        self.entry_timestamps.remove(&pid);
    }

    /// Get the number of processes being tracked.
    pub fn tracked_count(&self) -> usize {
        self.original_cmdlines.len()
    }

    /// Normalize a command line for comparison.
    ///
    /// - Trims whitespace
    /// - Normalizes multiple spaces to single space
    /// - Converts to lowercase for case-insensitive comparison
    fn normalize_cmdline(cmdline: &str) -> String {
        cmdline
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase()
    }

    /// Calculate similarity between two strings using Levenshtein-like ratio.
    ///
    /// Returns a value between 0.0 (completely different) and 1.0 (identical).
    fn calculate_similarity(s1: &str, s2: &str) -> f64 {
        if s1 == s2 {
            return 1.0;
        }
        if s1.is_empty() || s2.is_empty() {
            return 0.0;
        }

        // Use a simpler metric: longest common substring ratio
        let shorter = if s1.len() < s2.len() { s1 } else { s2 };
        let longer = if s1.len() >= s2.len() { s1 } else { s2 };

        // Count matching characters in order
        let mut matches = 0;
        let mut longer_chars = longer.chars().peekable();

        for c in shorter.chars() {
            while let Some(&lc) = longer_chars.peek() {
                longer_chars.next();
                if lc == c {
                    matches += 1;
                    break;
                }
            }
        }

        matches as f64 / longer.len() as f64
    }

    /// Evict the oldest entries from the cache.
    fn evict_oldest(&mut self, count: usize) {
        let mut entries: Vec<(u32, std::time::Instant)> = self
            .entry_timestamps
            .iter()
            .map(|(&pid, &ts)| (pid, ts))
            .collect();

        entries.sort_by_key(|(_, ts)| *ts);

        for (pid, _) in entries.into_iter().take(count) {
            self.original_cmdlines.remove(&pid);
            self.entry_timestamps.remove(&pid);
        }
    }

    /// Garbage collect entries for processes that no longer exist.
    pub fn gc_dead_processes(&mut self, live_pids: &HashSet<u32>) {
        let dead_pids: Vec<u32> = self
            .original_cmdlines
            .keys()
            .filter(|pid| !live_pids.contains(pid))
            .copied()
            .collect();

        for pid in dead_pids {
            self.remove_process(pid);
        }
    }

    /// Get an iterator over tracked PIDs.
    /// Used for periodic spoofing checks.
    pub fn tracked_pids(&self) -> impl Iterator<Item = u32> + '_ {
        self.original_cmdlines.keys().copied()
    }
}

// ---------------------------------------------------------------------------
// Cached information about a process (used for parent resolution)
// ---------------------------------------------------------------------------

/// Lightweight snapshot of a process kept in our cache so we can resolve
/// parent name/path even after the parent has exited.
#[derive(Debug, Clone)]
struct CachedProcessInfo {
    name: String,
    path: String,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
struct WindowsToolhelpProcess {
    pid: u32,
    ppid: u32,
    name: String,
}

// ---------------------------------------------------------------------------
// Signature cache entry
// ---------------------------------------------------------------------------

/// Result of a signature check, cached by file path.
#[derive(Debug, Clone)]
struct SignatureCacheEntry {
    is_signed: bool,
    signer: Option<String>,
    last_accessed: std::time::Instant,
}

// ---------------------------------------------------------------------------
// PE version info cache entry
// ---------------------------------------------------------------------------

/// Cached PE version info fields (CompanyName, FileDescription, etc.)
#[derive(Debug, Clone)]
struct PeVersionInfoEntry {
    company_name: Option<String>,
    file_description: Option<String>,
    product_name: Option<String>,
    file_version: Option<String>,
    last_accessed: std::time::Instant,
}

impl Default for PeVersionInfoEntry {
    fn default() -> Self {
        Self {
            company_name: None,
            file_description: None,
            product_name: None,
            file_version: None,
            last_accessed: std::time::Instant::now(),
        }
    }
}

/// Detailed signature information including thumbprint and validity (Windows only)
#[cfg(target_os = "windows")]
#[allow(dead_code)]
pub struct SignatureInfo {
    pub signer_name: String,
    pub thumbprint: String,
    pub is_valid: bool,
    pub is_trusted: bool,
    pub not_before: i64,
    pub not_after: i64,
}

/// Process collector
pub struct ProcessCollector {
    event_rx: mpsc::Receiver<TelemetryEvent>,
}

impl ProcessCollector {
    /// Create a new process collector
    ///
    /// `governor_handle`: Optional handle to resource governor for pressure-aware interval scaling
    pub fn new(config: &AgentConfig) -> Self {
        Self::with_governor(config, None)
    }

    /// Create a process collector with resource governor pressure handling
    pub fn with_governor(config: &AgentConfig, governor_handle: Option<GovernorHandle>) -> Self {
        let (tx, rx) = mpsc::channel(1000);

        // Start monitoring in background
        let config = config.clone();
        tokio::spawn(async move {
            Self::monitor_loop(tx, config, governor_handle).await;
        });

        Self { event_rx: rx }
    }

    async fn monitor_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        config: AgentConfig,
        _governor_handle: Option<GovernorHandle>,
    ) {
        let mut system = System::new(); // Start empty instead of new_all()
        let mut users = Users::new_with_refreshed_list();
        let mut known_pids: HashSet<u32> = HashSet::new();
        #[cfg(target_os = "linux")]
        let mut linux_observed_cmdlines: HashMap<u32, String> = HashMap::new();
        #[cfg(target_os = "linux")]
        let mut linux_retry_cmdline_snapshots: HashMap<
            u32,
            (String, u8, std::time::Instant),
        > = HashMap::new();

        // Process info cache: PID -> (name, path).
        // Persists across collection cycles so we can resolve parent info
        // even after the parent has exited.
        let mut process_cache: HashMap<u32, CachedProcessInfo> = HashMap::new();

        // Signature verification cache: file path -> (is_signed, signer).
        // Avoids re-running WinVerifyTrust / PowerShell / dpkg / codesign
        // for the same binary multiple times.
        let mut signature_cache: HashMap<String, SignatureCacheEntry> = HashMap::new();

        // PE version info cache: file path -> version info fields.
        // Avoids redundant GetFileVersionInfoW calls for the same binary.
        let mut version_info_cache: HashMap<String, PeVersionInfoEntry> = HashMap::new();

        // Command line spoofing detector (MITRE T1564.010)
        // Records original command lines at process creation and periodically
        // checks for modifications indicating spoofing attempts.
        let mut cmdline_spoofing_detector = CommandLineSpoofingDetector::new();

        // Get our own PID to exclude self-detection
        let self_pid = std::process::id();

        let skip_expensive = config.collector_tuning.skip_expensive_analysis;

        // Initial scan — enumerate ALL running processes and emit events so the
        // process tree is fully populated from the start.  create_process_event()
        // already respects skip_expensive_analysis for SHA256/entropy/YARA, and
        // signature + PE version info are cached per-path, so the cost is bounded.
        {
            system.refresh_processes_specifics(ProcessRefreshKind::everything());
            info!(
                count = system.processes().len(),
                "Initial process enumeration starting"
            );

            // Pre-populate the process cache from the initial snapshot so that
            // parent lookups during this very first pass can succeed.
            // Use the same path-fallback chain as create_process_event.
            for (pid, process) in system.processes() {
                let pid_u32 = pid.as_u32();
                let name = {
                    let n = process.name().to_string();
                    if n.is_empty() {
                        format!("Process_{}", pid_u32)
                    } else {
                        n
                    }
                };
                let mut path = process
                    .exe()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();

                #[cfg(target_os = "windows")]
                if path.is_empty() {
                    if let Some(img_path) = Self::get_process_image_path(pid_u32) {
                        path = img_path;
                    } else {
                        let args = process.cmd();
                        if !args.is_empty() {
                            let first = args[0].trim_matches('"').trim_matches('\'').to_string();
                            if !first.is_empty() && first.contains('\\') {
                                path = first;
                            }
                        }
                    }
                }

                process_cache.insert(pid_u32, CachedProcessInfo { name, path });
            }

            #[cfg(target_os = "linux")]
            {
                for pid in system.processes().keys() {
                    let pid_u32 = pid.as_u32();
                    if read_proc_tgid(pid_u32).unwrap_or(pid_u32) == pid_u32 {
                        known_pids.insert(pid_u32);
                    }
                }

                for pid in read_proc_pids() {
                    known_pids.insert(pid);
                    if let Some(cmdline) = read_proc_cmdline(pid) {
                        linux_observed_cmdlines.insert(pid, cmdline);
                    }
                }

                info!(
                    process_count = known_pids.len(),
                    process_cache_size = process_cache.len(),
                    signature_cache_size = signature_cache.len(),
                    version_info_cache_size = version_info_cache.len(),
                    "Initial Linux process snapshot cached as baseline"
                );
            }

            #[cfg(not(target_os = "linux"))]
            {
                for (pid, process) in system.processes() {
                    let pid_u32 = pid.as_u32();
                    known_pids.insert(pid_u32);

                    // Skip our own process to avoid self-detection
                    if pid_u32 == self_pid {
                        continue;
                    }

                    if let Some(event) = Self::create_process_event(
                        process,
                        &system,
                        &users,
                        &config,
                        &process_cache,
                        &mut signature_cache,
                        &mut version_info_cache,
                    )
                    .await
                    {
                        if tx.send(event).await.is_err() {
                            warn!("Event channel closed during initial enumeration");
                            return;
                        }
                    }
                }
            }

            #[cfg(not(target_os = "linux"))]
            info!(
                process_count = known_pids.len(),
                process_cache_size = process_cache.len(),
                signature_cache_size = signature_cache.len(),
                version_info_cache_size = version_info_cache.len(),
                "Initial process enumeration complete — all processes emitted"
            );
        }

        // Use configurable process scan interval from collector_tuning.
        // Controlled by the performance profile (aggressive=3s, balanced=5s, lightweight=15s).
        // Can be scaled by resource governor pressure (2x-16x when system is under load).
        let configured_process_interval_ms =
            config.collector_tuning.process_scan_interval_secs * 1000;
        let process_interval_ms = configured_process_interval_ms.clamp(500, 1000);
        if configured_process_interval_ms > process_interval_ms {
            info!(
                configured_interval_ms = configured_process_interval_ms,
                effective_interval_ms = process_interval_ms,
                "Process collector interval capped for near-real-time process creation telemetry"
            );
        }
        // Process creation telemetry is latency-critical for EDR detection and
        // benchmark evidence. Expensive enrichment is controlled separately via
        // skip_expensive_analysis, so the polling cadence should not stretch to
        // multi-second windows under generic collector pressure.
        let mut interval = GovernorAwareInterval::new(
            tokio::time::Duration::from_millis(process_interval_ms.max(500)),
            None,
        );
        info!(
            base_interval_ms = process_interval_ms.max(500),
            governor_enabled = false,
            "Process collector started (pressure-aware interval scaling)"
        );

        let mut user_refresh_counter = 0u32;
        let mut cache_gc_counter = 0u32;
        // Counter for command line spoofing checks (every 10 iterations = 5 seconds at default interval)
        let mut spoofing_check_counter = 0u32;

        // Choose the refresh kind for the ongoing loop.  We only need to
        // enumerate PIDs (detect new/terminated processes).  Refreshing CPU,
        // memory, disk, environ, etc. for ALL processes every tick is extremely
        // expensive and unnecessary — we only read those attributes for NEW
        // processes inside create_process_event().
        //
        // OnlyIfNotSet ensures new processes get their exe path populated
        // while existing processes keep their cached values without re-querying
        // the OS every tick.
        let tick_refresh_kind = if skip_expensive {
            // Lightweight: bare minimum — just PID list
            ProcessRefreshKind::new()
        } else {
            // Balanced/Aggressive: populate exe+cmd for new processes only
            ProcessRefreshKind::new()
                .with_exe(UpdateKind::OnlyIfNotSet)
                .with_cmd(UpdateKind::OnlyIfNotSet)
                .with_memory()
        };

        loop {
            interval.tick().await;

            system.refresh_processes_specifics(tick_refresh_kind);

            // Refresh users list every 60 iterations (30 seconds)
            user_refresh_counter += 1;
            if user_refresh_counter >= 60 {
                users.refresh_list();
                user_refresh_counter = 0;
            }

            let mut current_pids: HashSet<u32> = {
                #[cfg(target_os = "linux")]
                let mut pids: HashSet<u32> = system
                    .processes()
                    .keys()
                    .map(|p| p.as_u32())
                    .filter(|pid| read_proc_tgid(*pid).unwrap_or(*pid) == *pid)
                    .collect();

                #[cfg(not(target_os = "linux"))]
                let pids: HashSet<u32> = system.processes().keys().map(|p| p.as_u32()).collect();

                #[cfg(target_os = "linux")]
                {
                    pids.extend(read_proc_pids());
                }

                pids
            };

            #[cfg(target_os = "windows")]
            let windows_toolhelp_snapshot = Self::windows_toolhelp_process_snapshot();

            #[cfg(target_os = "windows")]
            {
                current_pids.extend(windows_toolhelp_snapshot.iter().map(|entry| entry.pid));
            }

            // Update process cache with any new/refreshed process info
            for (pid, process) in system.processes() {
                let pid_u32 = pid.as_u32();
                if !process_cache.contains_key(&pid_u32) {
                    let name = {
                        let n = process.name().to_string();
                        if n.is_empty() {
                            format!("Process_{}", pid_u32)
                        } else {
                            n
                        }
                    };
                    let mut path = process
                        .exe()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_default();

                    #[cfg(target_os = "windows")]
                    if path.is_empty() {
                        if let Some(img_path) = Self::get_process_image_path(pid_u32) {
                            path = img_path;
                        } else {
                            let args = process.cmd();
                            if !args.is_empty() {
                                let first =
                                    args[0].trim_matches('"').trim_matches('\'').to_string();
                                if !first.is_empty() && first.contains('\\') {
                                    path = first;
                                }
                            }
                        }
                    }

                    process_cache.insert(pid_u32, CachedProcessInfo { name, path });
                }
            }

            // Check for new processes
            for pid in current_pids.difference(&known_pids) {
                // Skip our own process. Children spawned by the agent are still
                // emitted below with explicit metadata for response/audit clarity.
                if *pid == self_pid {
                    continue;
                }

                let mut agent_spawned_child = false;
                if let Some(process) = system.process(Pid::from_u32(*pid)) {
                    // Do not drop child processes spawned by the agent. Live Response,
                    // response actions, and benchmark probes must be auditable as real
                    // process telemetry. Mark them explicitly so detectors/UI can
                    // distinguish operator/agent activity from ambient endpoint activity.
                    if let Some(ppid) = process.parent() {
                        if ppid.as_u32() == self_pid {
                            agent_spawned_child = true;
                        }
                    }
                    if let Some(mut event) = Self::create_process_event(
                        process,
                        &system,
                        &users,
                        &config,
                        &process_cache,
                        &mut signature_cache,
                        &mut version_info_cache,
                    )
                    .await
                    {
                        if agent_spawned_child {
                            event
                                .metadata
                                .insert("agent_spawned".to_string(), "true".to_string());
                            event.metadata.insert(
                                "source".to_string(),
                                "endpoint_process_agent_child".to_string(),
                            );
                            event.metadata.insert(
                                "agent_spawned_reason".to_string(),
                                "direct_child_of_agent".to_string(),
                            );
                        }

                        // Record original command line for spoofing detection (T1564.010)
                        // This captures the cmdline at process creation time
                        if let EventPayload::Process(ref proc_event) = event.payload {
                            let proc_name = process.name().to_string();
                            #[cfg(target_os = "linux")]
                            linux_observed_cmdlines.insert(*pid, proc_event.cmdline.clone());
                            cmdline_spoofing_detector.record_creation_with_name(
                                *pid,
                                proc_event.cmdline.clone(),
                                &proc_name,
                            );
                        }

                        if tx.send(event).await.is_err() {
                            warn!("Event channel closed");
                            return;
                        }
                    }
                } else {
                    #[cfg(target_os = "linux")]
                    {
                        if let Some(event) =
                            Self::create_linux_proc_process_event(*pid, &config, &process_cache)
                                .await
                        {
                            if let EventPayload::Process(ref proc_event) = event.payload {
                                linux_observed_cmdlines.insert(*pid, proc_event.cmdline.clone());
                                cmdline_spoofing_detector.record_creation_with_name(
                                    *pid,
                                    proc_event.cmdline.clone(),
                                    &proc_event.name,
                                );
                            }

                            if tx.send(event).await.is_err() {
                                warn!("Event channel closed");
                                return;
                            }
                        }
                    }

                    #[cfg(target_os = "windows")]
                    {
                        if let Some(entry) = windows_toolhelp_snapshot
                            .iter()
                            .find(|entry| entry.pid == *pid)
                            .cloned()
                        {
                            if let Some(mut event) = Self::create_windows_toolhelp_process_event(
                                &entry,
                                &config,
                                &process_cache,
                            )
                            .await
                            {
                                if entry.ppid == self_pid {
                                    event
                                        .metadata
                                        .insert("agent_spawned".to_string(), "true".to_string());
                                    event.metadata.insert(
                                        "agent_spawned_reason".to_string(),
                                        "direct_child_of_agent_toolhelp".to_string(),
                                    );
                                }

                                if let EventPayload::Process(ref proc_event) = event.payload {
                                    cmdline_spoofing_detector.record_creation_with_name(
                                        *pid,
                                        proc_event.cmdline.clone(),
                                        &proc_event.name,
                                    );
                                }

                                if tx.send(event).await.is_err() {
                                    warn!("Event channel closed during Windows Toolhelp snapshot");
                                    return;
                                }
                            }
                        }
                    }
                }
            }

            #[cfg(target_os = "linux")]
            {
                // Linux polling can miss short or sysinfo-invisible process starts when
                // /proc and sysinfo snapshots race. Keep a lightweight cmdline cache as
                // a second source of truth so long-lived shells and benchmark probes are
                // still observable with their original command line.
                let mut snapshot_emitted = 0usize;
                let mut snapshot_first: Option<(u32, String)> = None;
                let mut pids_by_recency: Vec<u32> = current_pids.iter().copied().collect();
                pids_by_recency.sort_unstable_by(|left, right| right.cmp(left));

                for pid in pids_by_recency {
                    if pid == self_pid {
                        continue;
                    }

                    let Some(cmdline) = read_proc_cmdline(pid) else {
                        linux_observed_cmdlines.remove(&pid);
                        continue;
                    };

                    if cmdline.trim().is_empty() {
                        continue;
                    }

                    let observed_cmdline = linux_observed_cmdlines.get(&pid) == Some(&cmdline);
                    let retry_due = linux_retry_due(
                        pid,
                        &name_from_proc(pid),
                        &cmdline,
                        &mut linux_retry_cmdline_snapshots,
                    );

                    if observed_cmdline && !retry_due {
                        continue;
                    }

                    if let Some(mut event) =
                        Self::create_linux_proc_process_event(pid, &config, &process_cache).await
                    {
                        event.metadata.insert(
                            "linux_proc_cmdline_snapshot".to_string(),
                            "true".to_string(),
                        );
                        if retry_due {
                            event
                                .metadata
                                .insert("linux_proc_cmdline_retry".to_string(), "true".to_string());
                        }

                        if let EventPayload::Process(ref proc_event) = event.payload {
                            cmdline_spoofing_detector.record_creation_with_name(
                                pid,
                                proc_event.cmdline.clone(),
                                &proc_event.name,
                            );
                        }

                        if tx.send(event).await.is_err() {
                            warn!("Event channel closed during Linux cmdline snapshot");
                            return;
                        }
                        if snapshot_first.is_none() {
                            snapshot_first = Some((pid, cmdline.chars().take(160).collect()));
                        }
                        snapshot_emitted += 1;
                    }

                    linux_observed_cmdlines.insert(pid, cmdline);

                    // Bound per-tick work. Prioritizing high PIDs keeps recently-created
                    // probe processes ahead of long-lived system services.
                    if snapshot_emitted >= 512 {
                        break;
                    }
                }

                if snapshot_emitted > 0 {
                    if let Some((pid, cmdline)) = snapshot_first {
                        info!(
                            emitted = snapshot_emitted,
                            sample_pid = pid,
                            sample_cmdline = %cmdline,
                            "Linux /proc cmdline snapshot emitted process events"
                        );
                    }
                }

                linux_observed_cmdlines.retain(|pid, _| current_pids.contains(pid));
                linux_retry_cmdline_snapshots.retain(|pid, _| current_pids.contains(pid));
            }

            // Command line spoofing detection check (MITRE T1564.010)
            // Periodically compare original cmdlines with current PEB values
            // to detect post-creation modifications (e.g., Cobalt Strike argue)
            #[cfg(target_os = "windows")]
            {
                spoofing_check_counter += 1;
                // Check every 10 iterations (approx 5 seconds at default interval)
                if spoofing_check_counter >= 10 && !skip_expensive {
                    spoofing_check_counter = 0;

                    // Check a sample of tracked processes for spoofing
                    // Limit to 50 processes per cycle to avoid performance impact
                    let mut checked = 0;
                    let tracked: Vec<u32> = cmdline_spoofing_detector.tracked_pids().collect();
                    for pid in tracked {
                        if checked >= 50 {
                            break;
                        }
                        if !current_pids.contains(&pid) {
                            continue; // Process exited
                        }

                        if let Some(alert) = cmdline_spoofing_detector.check_process(pid) {
                            // Get process info for the alert event
                            let (proc_name, proc_path) =
                                if let Some(cached) = process_cache.get(&pid) {
                                    (cached.name.clone(), cached.path.clone())
                                } else {
                                    (format!("Process_{}", pid), String::new())
                                };

                            warn!(
                                pid,
                                original = %alert.original_cmdline,
                                current = %alert.current_cmdline,
                                "Command line spoofing detected (T1564.010)"
                            );

                            // Create a DefenseEvasion event for the spoofing detection
                            let mut spoof_event = TelemetryEvent::new(
                                EventType::DefenseEvasion,
                                Severity::High,
                                EventPayload::DefenseEvasion(super::DefenseEvasionEvent {
                                    evasion_type: super::EvasionType::CommandLineSpoofing,
                                    pid,
                                    process_name: proc_name.clone(),
                                    process_path: proc_path,
                                    cmdline: alert.current_cmdline.clone(),
                                    user: String::new(),
                                    target: format!("Process {} (PID {})", proc_name, pid),
                                    details: format!(
                                        "Command Line Spoofing (T1564.010): Process modified its command line after creation. Original: '{}', Current: '{}'",
                                        alert.original_cmdline, alert.current_cmdline
                                    ),
                                    original_value: Some(alert.original_cmdline.clone()),
                                    new_value: Some(alert.current_cmdline.clone()),
                                }),
                            );

                            spoof_event.add_detection(Detection {
                                detection_type: DetectionType::CommandLineSpoofing,
                                rule_name: "cmdline_spoofing_detected".to_string(),
                                confidence: 0.95,
                                description: format!(
                                    "Command line changed from '{}' to '{}'",
                                    alert.original_cmdline, alert.current_cmdline
                                ),
                                mitre_tactics: vec!["defense-evasion".to_string()],
                                mitre_techniques: vec!["T1564.010".to_string()],
                            });

                            if tx.send(spoof_event).await.is_err() {
                                warn!("Event channel closed during spoofing alert");
                                return;
                            }
                        }
                        checked += 1;
                    }
                }
            }

            // Suppress unused variable warning on non-Windows
            #[cfg(not(target_os = "windows"))]
            let _ = spoofing_check_counter;

            // Garbage-collect stale entries from the process cache every
            // 120 iterations (60 seconds). We keep entries for PIDs that
            // are still alive, plus a grace window for recently-exited
            // parents. To keep things simple we just purge PIDs that are
            // no longer running and weren't a parent of any current process.
            cache_gc_counter += 1;
            if cache_gc_counter >= 120 {
                cache_gc_counter = 0;
                // Collect parent PIDs that are still referenced
                let referenced_ppids: HashSet<u32> = system
                    .processes()
                    .values()
                    .filter_map(|p| p.parent().map(|pp| pp.as_u32()))
                    .collect();
                // Keep entries that are either alive or referenced as parents
                let before = process_cache.len();
                process_cache
                    .retain(|pid, _| current_pids.contains(pid) || referenced_ppids.contains(pid));
                let removed = before - process_cache.len();
                if removed > 0 {
                    debug!(removed, remaining = process_cache.len(), "Process cache GC");
                }

                // Evict oldest 20% of signature cache when it exceeds 1000 entries
                const SIG_CACHE_MAX: usize = 1000;
                if signature_cache.len() > SIG_CACHE_MAX {
                    let evict_count = signature_cache.len() / 5; // 20%
                    let mut entries: Vec<(String, std::time::Instant)> = signature_cache
                        .iter()
                        .map(|(k, v)| (k.clone(), v.last_accessed))
                        .collect();
                    entries.sort_by_key(|(_, t)| *t);
                    for (key, _) in entries.into_iter().take(evict_count) {
                        signature_cache.remove(&key);
                    }
                    debug!(
                        evicted = evict_count,
                        remaining = signature_cache.len(),
                        "Signature cache LRU eviction"
                    );
                }

                // Evict oldest 20% of version info cache when it exceeds 500 entries
                const VER_CACHE_MAX: usize = 500;
                if version_info_cache.len() > VER_CACHE_MAX {
                    let evict_count = version_info_cache.len() / 5; // 20%
                    let mut entries: Vec<(String, std::time::Instant)> = version_info_cache
                        .iter()
                        .map(|(k, v)| (k.clone(), v.last_accessed))
                        .collect();
                    entries.sort_by_key(|(_, t)| *t);
                    for (key, _) in entries.into_iter().take(evict_count) {
                        version_info_cache.remove(&key);
                    }
                    debug!(
                        evicted = evict_count,
                        remaining = version_info_cache.len(),
                        "Version info cache LRU eviction"
                    );
                }

                // GC cmdline spoofing detector entries for dead processes
                let before_spoofing = cmdline_spoofing_detector.tracked_count();
                cmdline_spoofing_detector.gc_dead_processes(&current_pids);
                let removed_spoofing = before_spoofing - cmdline_spoofing_detector.tracked_count();
                if removed_spoofing > 0 {
                    debug!(
                        removed = removed_spoofing,
                        remaining = cmdline_spoofing_detector.tracked_count(),
                        "Cmdline spoofing detector GC"
                    );
                }
            }

            known_pids = current_pids;
        }
    }

    #[cfg(target_os = "linux")]
    async fn create_linux_proc_process_event(
        pid: u32,
        config: &AgentConfig,
        process_cache: &HashMap<u32, CachedProcessInfo>,
    ) -> Option<TelemetryEvent> {
        if pid == std::process::id() {
            return None;
        }

        if read_proc_tgid(pid).unwrap_or(pid) != pid {
            return None;
        }

        let name = read_proc_comm(pid).unwrap_or_else(|| format!("Process_{}", pid));
        if config.excluded_processes.iter().any(|p| name.contains(p)) {
            return None;
        }

        let path = read_proc_exe(pid).unwrap_or_default();
        if config.excluded_paths.iter().any(|p| path.contains(p)) {
            return None;
        }

        let ppid = read_proc_ppid(pid).unwrap_or(0);
        let cmdline = read_proc_cmdline(pid).filter(|value| !value.trim().is_empty())?;
        let uid = read_proc_uid(pid).unwrap_or(0);
        let user = linux_username_from_uid(uid);
        let is_elevated = uid == 0;

        let (parent_name, parent_path) = if ppid != 0 {
            if let Some(cached) = process_cache.get(&ppid) {
                (
                    Some(cached.name.clone()),
                    if cached.path.is_empty() {
                        None
                    } else {
                        Some(cached.path.clone())
                    },
                )
            } else {
                Self::resolve_parent_fallback(ppid)
            }
        } else {
            (None, None)
        };

        let start_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0);

        let mut event = TelemetryEvent::new(
            EventType::ProcessCreate,
            Severity::Info,
            EventPayload::Process(ProcessEvent {
                pid,
                ppid,
                name,
                path,
                cmdline,
                user,
                sha256: Vec::new(),
                entropy: 0.0,
                is_elevated,
                parent_name,
                parent_path,
                is_signed: false,
                signer: None,
                start_time,
                cpu_usage: 0.0,
                memory_bytes: 0,
                company_name: None,
                file_description: None,
                product_name: None,
                file_version: None,
                environment: None,
            }),
        );

        event
            .metadata
            .insert("linux_proc_fallback".to_string(), "true".to_string());

        Some(event)
    }

    #[cfg(target_os = "windows")]
    async fn create_windows_toolhelp_process_event(
        entry: &WindowsToolhelpProcess,
        config: &AgentConfig,
        process_cache: &HashMap<u32, CachedProcessInfo>,
    ) -> Option<TelemetryEvent> {
        if entry.pid == std::process::id() {
            return None;
        }

        if config
            .excluded_processes
            .iter()
            .any(|pattern| entry.name.contains(pattern))
        {
            return None;
        }

        let path = Self::get_process_image_path(entry.pid).unwrap_or_default();
        if config
            .excluded_paths
            .iter()
            .any(|pattern| path.contains(pattern))
        {
            return None;
        }

        let cmdline = Self::get_cmdline_nt(entry.pid)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| {
                if path.is_empty() {
                    entry.name.clone()
                } else {
                    path.clone()
                }
            });

        let (parent_name, parent_path) = if entry.ppid != 0 {
            if let Some(cached) = process_cache.get(&entry.ppid) {
                (
                    Some(cached.name.clone()),
                    if cached.path.is_empty() {
                        None
                    } else {
                        Some(cached.path.clone())
                    },
                )
            } else {
                Self::resolve_parent_via_toolhelp(entry.ppid)
            }
        } else {
            (None, None)
        };

        let start_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0);

        let mut event = TelemetryEvent::new(
            EventType::ProcessCreate,
            Severity::Info,
            EventPayload::Process(ProcessEvent {
                pid: entry.pid,
                ppid: entry.ppid,
                name: entry.name.clone(),
                path,
                cmdline,
                user: "unknown".to_string(),
                sha256: Vec::new(),
                entropy: 0.0,
                is_elevated: false,
                parent_name,
                parent_path,
                is_signed: false,
                signer: None,
                start_time,
                cpu_usage: 0.0,
                memory_bytes: 0,
                company_name: None,
                file_description: None,
                product_name: None,
                file_version: None,
                environment: None,
            }),
        );

        event.metadata.insert(
            "source".to_string(),
            "endpoint_process_toolhelp_snapshot".to_string(),
        );
        event
            .metadata
            .insert("windows_toolhelp_snapshot".to_string(), "true".to_string());
        event
            .metadata
            .insert("provider".to_string(), "windows_toolhelp".to_string());

        Some(event)
    }

    async fn create_process_event(
        process: &Process,
        system: &System,
        users: &Users,
        config: &AgentConfig,
        process_cache: &HashMap<u32, CachedProcessInfo>,
        signature_cache: &mut HashMap<String, SignatureCacheEntry>,
        version_info_cache: &mut HashMap<String, PeVersionInfoEntry>,
    ) -> Option<TelemetryEvent> {
        // Get process name - handle empty names
        let name = {
            let proc_name = process.name().to_string();
            if proc_name.is_empty() {
                format!("Process_{}", process.pid().as_u32())
            } else {
                proc_name
            }
        };

        // Check exclusions
        if config.excluded_processes.iter().any(|p| name.contains(p)) {
            return None;
        }

        // -----------------------------------------------------------------
        // Resolve process executable path with fallback chain:
        // 1. sysinfo Process::exe()  (fast, works for most own-user procs)
        // 2. QueryFullProcessImageNameW (works for cross-user procs)
        // 3. First argument of cmdline (last resort, strip quotes)
        // -----------------------------------------------------------------
        let mut path = process
            .exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        #[cfg(target_os = "windows")]
        if path.is_empty() {
            // Fallback: QueryFullProcessImageNameW — works for processes
            // that sysinfo can't query (different session, restricted access)
            if let Some(img_path) = Self::get_process_image_path(process.pid().as_u32()) {
                path = img_path;
            } else {
                // Last resort: extract from cmdline first argument
                let args = process.cmd();
                if !args.is_empty() {
                    let first = args[0].trim_matches('"').trim_matches('\'').to_string();
                    if !first.is_empty() && first.contains('\\') {
                        path = first;
                    }
                }
            }
        }

        // Check path exclusions
        if config.excluded_paths.iter().any(|p| path.contains(p)) {
            return None;
        }

        // Get command line - join arguments with spaces
        // Use NT API fallback on Windows for protected processes
        let cmdline = {
            let args = process.cmd();
            let from_sysinfo = if args.is_empty() {
                None
            } else {
                Some(
                    args.iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                        .join(" "),
                )
            };

            if let Some(cmd) = from_sysinfo.filter(|cmd| !cmd.trim().is_empty()) {
                cmd
            } else {
                let pid = process.pid().as_u32();
                #[cfg(target_os = "windows")]
                {
                    Self::get_cmdline_nt(pid).unwrap_or_else(|| path.clone())
                }
                #[cfg(not(target_os = "windows"))]
                {
                    read_proc_cmdline(pid).unwrap_or_else(|| path.clone())
                }
            }
        };

        // Resolve username from user_id
        let user = Self::resolve_username(process, users);

        // Calculate hash if file exists.
        // In lightweight mode (skip_expensive_analysis), skip SHA256 + entropy
        // computation — each call reads the entire executable from disk and is
        // one of the heaviest per-process operations.
        let skip_expensive = config.collector_tuning.skip_expensive_analysis;
        let (sha256, entropy) = if skip_expensive {
            (Vec::new(), 0.0)
        } else if !path.is_empty() && std::path::Path::new(&path).exists() {
            match analyzers::hash_file(&path).await {
                Ok((hash, ent)) => (hash, ent),
                Err(_) => (Vec::new(), 0.0),
            }
        } else {
            (Vec::new(), 0.0)
        };

        // -----------------------------------------------------------------
        // Resolve parent process info.
        //
        // 1. Try the live sysinfo snapshot (parent still running).
        // 2. Fall back to our process_cache (parent may have already exited).
        // 3. On Windows, additionally try CreateToolhelp32Snapshot for ppid
        //    resolution if sysinfo didn't provide a parent PID.
        // -----------------------------------------------------------------
        let ppid_raw = process.parent().map(|p| p.as_u32()).unwrap_or(0);

        let (parent_name, parent_path) = if ppid_raw != 0 {
            // First try the live system snapshot
            if let Some(p) = system.process(Pid::from_u32(ppid_raw)) {
                (
                    Some(p.name().to_string()),
                    p.exe().map(|e| e.to_string_lossy().to_string()),
                )
            } else if let Some(cached) = process_cache.get(&ppid_raw) {
                // Parent exited but we have cached info
                (
                    Some(cached.name.clone()),
                    if cached.path.is_empty() {
                        None
                    } else {
                        Some(cached.path.clone())
                    },
                )
            } else {
                // Last resort on Windows: query the Toolhelp snapshot for the
                // parent PID, then try to resolve name/path from the snapshot.
                #[cfg(target_os = "windows")]
                {
                    Self::resolve_parent_via_toolhelp(ppid_raw)
                }
                #[cfg(not(target_os = "windows"))]
                {
                    Self::resolve_parent_fallback(ppid_raw)
                }
            }
        } else {
            (None, None)
        };

        // Get process start time - sysinfo returns seconds since epoch
        // Convert to milliseconds and handle 0 (unknown) by using current time
        let start_time_secs = process.start_time();
        let start_time = if start_time_secs > 0 {
            start_time_secs * 1000
        } else {
            // Use current time as fallback for processes where start time is unavailable
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0)
        };

        let is_elevated = Self::check_elevation(process.pid().as_u32(), skip_expensive);

        // -----------------------------------------------------------------
        // Signature check with caching.
        // The underlying check is expensive on first call (WinVerifyTrust
        // on Windows, dpkg/rpm/codesign on Unix/macOS), but results are
        // cached by file path so subsequent checks for the same binary are
        // a cheap HashMap lookup.  Because of this caching, signature
        // checking is NOT gated by skip_expensive_analysis — the amortised
        // cost is negligible and signature status is critical for the
        // process tree UI (unsigned processes are flagged).
        // -----------------------------------------------------------------
        let (is_signed, signer) = if skip_expensive {
            (false, None)
        } else if path.is_empty() {
            (false, None)
        } else if let Some(cached) = signature_cache.get_mut(&path) {
            cached.last_accessed = std::time::Instant::now();
            (cached.is_signed, cached.signer.clone())
        } else {
            let result = Self::check_signature(&path);
            signature_cache.insert(
                path.clone(),
                SignatureCacheEntry {
                    is_signed: result.0,
                    signer: result.1.clone(),
                    last_accessed: std::time::Instant::now(),
                },
            );
            result
        };

        // -----------------------------------------------------------------
        // CPU and memory usage from sysinfo.
        // Note: cpu_usage() requires at least two refresh cycles to return
        // accurate values; the first call typically returns 0. Since the
        // agent polls every 500ms this is fine for ongoing monitoring.
        // -----------------------------------------------------------------
        let cpu_usage = process.cpu_usage();
        let memory_bytes = process.memory();

        // -----------------------------------------------------------------
        // PE version info with caching.
        // On Windows, reads CompanyName, FileDescription, ProductName,
        // FileVersion from the PE VersionInfo resource.  Cached by path
        // to avoid repeated GetFileVersionInfoW calls for the same binary.
        // On non-Windows platforms all fields remain None.
        // Like signature checking, this is NOT gated by skip_expensive
        // because results are cached per-path and the UI needs company
        // name / file description for the process tree display.
        // -----------------------------------------------------------------
        let version_info = if skip_expensive {
            PeVersionInfoEntry::default()
        } else if path.is_empty() {
            PeVersionInfoEntry::default()
        } else if let Some(cached) = version_info_cache.get_mut(&path) {
            cached.last_accessed = std::time::Instant::now();
            cached.clone()
        } else {
            let mut info = Self::get_pe_version_info(&path);
            info.last_accessed = std::time::Instant::now();
            version_info_cache.insert(path.clone(), info.clone());
            info
        };

        // -----------------------------------------------------------------
        // Capture security-relevant environment variables.
        // On Linux reads /proc/{pid}/environ; on Windows/macOS only for the
        // current process (remote process env requires elevated access).
        // Skipped when skip_expensive_analysis is set since reading
        // /proc/*/environ involves filesystem I/O for every process.
        // -----------------------------------------------------------------
        let environment = if skip_expensive {
            None
        } else {
            capture_process_environment(process.pid().as_u32())
        };

        let mut event = TelemetryEvent::new(
            EventType::ProcessCreate,
            Severity::Info,
            EventPayload::Process(ProcessEvent {
                pid: process.pid().as_u32(),
                ppid: process.parent().map(|p| p.as_u32()).unwrap_or(0),
                name,
                path: path.clone(),
                cmdline,
                user,
                sha256,
                entropy,
                is_elevated,
                parent_name,
                parent_path,
                is_signed,
                signer,
                start_time,
                cpu_usage,
                memory_bytes,
                company_name: version_info.company_name,
                file_description: version_info.file_description,
                product_name: version_info.product_name,
                file_version: version_info.file_version,
                environment,
            }),
        );

        // Run YARA analysis if enabled (skip in lightweight mode)
        #[cfg(feature = "yara")]
        if !skip_expensive && config.yara_enabled && !path.is_empty() {
            if let Ok(matches) = analyzers::yara::scan_file(&path).await {
                for match_name in matches {
                    event.add_detection(Detection {
                        detection_type: DetectionType::Yara,
                        rule_name: match_name.clone(),
                        confidence: 1.0,
                        description: format!("YARA rule matched: {}", match_name),
                        mitre_tactics: Vec::new(),
                        mitre_techniques: Vec::new(),
                    });
                }
            }
        }

        // Check entropy (skip in lightweight mode — entropy not computed)
        if !skip_expensive && config.entropy_check_enabled && entropy > config.entropy_threshold {
            event.add_detection(Detection {
                detection_type: DetectionType::Entropy,
                rule_name: "high_entropy".to_string(),
                confidence: 0.7,
                description: format!("High entropy detected: {:.2}", entropy),
                mitre_tactics: vec!["defense-evasion".to_string()],
                mitre_techniques: vec!["T1027".to_string()],
            });
        }

        // Elevate severity if detections found
        if !event.detections.is_empty() {
            event.severity = Severity::High;
        }

        Some(event)
    }

    /// Get next event from collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }

    /// Drain one already-buffered event without waiting.
    pub fn try_next_event(&mut self) -> Option<TelemetryEvent> {
        match self.event_rx.try_recv() {
            Ok(event) => Some(event),
            Err(_) => None,
        }
    }

    // =====================================================================
    // Parent process resolution fallbacks
    // =====================================================================

    #[cfg(target_os = "windows")]
    fn windows_toolhelp_process_snapshot() -> Vec<WindowsToolhelpProcess> {
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        unsafe {
            let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(h) => h,
                Err(_) => return Vec::new(),
            };

            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..std::mem::zeroed()
            };

            if Process32FirstW(snapshot, &mut entry).is_err() {
                let _ = windows::Win32::Foundation::CloseHandle(snapshot);
                return Vec::new();
            }

            let mut processes = Vec::new();
            loop {
                let name_len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..name_len]);
                if !name.is_empty() {
                    processes.push(WindowsToolhelpProcess {
                        pid: entry.th32ProcessID,
                        ppid: entry.th32ParentProcessID,
                        name,
                    });
                }

                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }

            let _ = windows::Win32::Foundation::CloseHandle(snapshot);
            processes
        }
    }

    /// Windows: Use CreateToolhelp32Snapshot to enumerate all processes and
    /// find the parent by PID.  This works even when sysinfo and our cache
    /// both missed the parent (e.g. very short-lived processes).
    #[cfg(target_os = "windows")]
    fn resolve_parent_via_toolhelp(ppid: u32) -> (Option<String>, Option<String>) {
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        unsafe {
            let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(h) => h,
                Err(_) => return (None, None),
            };

            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..std::mem::zeroed()
            };

            if Process32FirstW(snapshot, &mut entry).is_err() {
                let _ = windows::Win32::Foundation::CloseHandle(snapshot);
                return (None, None);
            }

            loop {
                if entry.th32ProcessID == ppid {
                    let name_len = entry
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len());
                    let parent_name = String::from_utf16_lossy(&entry.szExeFile[..name_len]);

                    // Toolhelp only gives us the executable name, not the
                    // full path.  Try to resolve the full path via
                    // QueryFullProcessImageNameW.
                    let parent_path = Self::get_process_image_path(ppid);

                    let _ = windows::Win32::Foundation::CloseHandle(snapshot);
                    return (Some(parent_name), parent_path);
                }

                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }

            let _ = windows::Win32::Foundation::CloseHandle(snapshot);
            (None, None)
        }
    }

    /// Windows: Get full image path for a PID using QueryFullProcessImageNameW.
    #[cfg(target_os = "windows")]
    fn get_process_image_path(pid: u32) -> Option<String> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
            PROCESS_QUERY_LIMITED_INFORMATION,
        };

        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(h) => h,
                Err(_) => return None,
            };

            let mut buf = [0u16; 1024];
            let mut size = buf.len() as u32;

            let ok = QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_WIN32,
                windows::core::PWSTR(buf.as_mut_ptr()),
                &mut size,
            );
            let _ = CloseHandle(handle);

            if ok.is_ok() && size > 0 {
                // QueryFullProcessImageNameW returns the character count excluding
                // the null terminator, but strip any trailing nulls defensively.
                let end = size as usize;
                let trimmed = match buf[..end].iter().rposition(|&c| c != 0) {
                    Some(pos) => &buf[..=pos],
                    None => return None,
                };
                Some(String::from_utf16_lossy(trimmed))
            } else {
                None
            }
        }
    }

    /// Linux / macOS fallback: read /proc/<ppid> on Linux or use `ps` on macOS.
    #[cfg(not(target_os = "windows"))]
    fn resolve_parent_fallback(ppid: u32) -> (Option<String>, Option<String>) {
        #[cfg(target_os = "linux")]
        {
            // Try /proc/<ppid>/comm for the name
            let comm_path = format!("/proc/{}/comm", ppid);
            let name = std::fs::read_to_string(&comm_path)
                .ok()
                .map(|s| s.trim().to_string());

            // Try /proc/<ppid>/exe for the path (symlink to binary)
            let exe_path = format!("/proc/{}/exe", ppid);
            let path = std::fs::read_link(&exe_path)
                .ok()
                .map(|p| p.to_string_lossy().to_string())
                // Deleted executables show as "/path/to/bin (deleted)"
                .map(|s| s.trim_end_matches(" (deleted)").to_string());

            (name, path)
        }
        #[cfg(target_os = "macos")]
        {
            use std::process::Command;

            let pid_str = ppid.to_string();

            // Get name via ps
            let name = Command::new("ps")
                .args(["-o", "comm=", "-p", &pid_str])
                .output()
                .ok()
                .and_then(|out| {
                    if out.status.success() {
                        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                        if s.is_empty() {
                            None
                        } else {
                            Some(s)
                        }
                    } else {
                        None
                    }
                });

            // Path is the same as comm on macOS (ps -o comm gives full path)
            let path = name.clone();

            (
                name.map(|n| {
                    // Extract just the binary name from the path
                    std::path::Path::new(&n)
                        .file_name()
                        .map(|f| f.to_string_lossy().to_string())
                        .unwrap_or(n)
                }),
                path,
            )
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = ppid;
            (None, None)
        }
    }

    /// Resolve username from process user_id using the Users cache
    fn resolve_username(process: &Process, users: &Users) -> String {
        let pid = process.pid().as_u32();

        // First try to get the user from the sysinfo Users cache
        if let Some(uid) = process.user_id() {
            // Try to find the user in our cached users list
            for user in users.list() {
                if user.id() == uid {
                    return user.name().to_string();
                }
            }

            // If not found in cache, try platform-specific resolution
            #[cfg(target_os = "windows")]
            {
                // Try SID-based resolution first
                if let Some(name) = Self::resolve_windows_username(uid) {
                    return name;
                }
                // Try token-based resolution as fallback
                if let Some(name) = Self::get_username_from_token(pid) {
                    return name;
                }
            }

            #[cfg(target_os = "linux")]
            {
                if let Some(name) = Self::resolve_linux_username(uid) {
                    return name;
                }
            }

            // Fallback to UID string representation
            uid.to_string()
        } else {
            // No UID from sysinfo, try direct token access on Windows
            #[cfg(target_os = "windows")]
            {
                if let Some(name) = Self::get_username_from_token(pid) {
                    return name;
                }
            }
            "SYSTEM".to_string()
        }
    }

    /// Resolve username from SID on Windows using LookupAccountSidW
    #[cfg(target_os = "windows")]
    fn resolve_windows_username(uid: &sysinfo::Uid) -> Option<String> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{LocalFree, HLOCAL, PSID};
        use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
        use windows::Win32::Security::{LookupAccountSidW, SID_NAME_USE};

        let sid_str = uid.to_string();

        // Convert SID string to SID structure
        let sid_wide: Vec<u16> = sid_str.encode_utf16().chain(std::iter::once(0)).collect();
        let mut psid = PSID::default();

        unsafe {
            if ConvertStringSidToSidW(PCWSTR(sid_wide.as_ptr()), &mut psid).is_err() {
                return None;
            }

            let mut name_buf = vec![0u16; 256];
            let mut domain_buf = vec![0u16; 256];
            let mut name_len = name_buf.len() as u32;
            let mut domain_len = domain_buf.len() as u32;
            let mut sid_type = SID_NAME_USE::default();

            let result = LookupAccountSidW(
                PCWSTR::null(),
                psid,
                windows::core::PWSTR(name_buf.as_mut_ptr()),
                &mut name_len,
                windows::core::PWSTR(domain_buf.as_mut_ptr()),
                &mut domain_len,
                &mut sid_type,
            );

            let _ = LocalFree(HLOCAL(psid.0));

            if result.is_ok() {
                let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                let domain = String::from_utf16_lossy(&domain_buf[..domain_len as usize]);

                if domain.is_empty() {
                    Some(name)
                } else {
                    Some(format!("{}\\{}", domain, name))
                }
            } else {
                None
            }
        }
    }

    /// Resolve username from UID on Linux
    #[cfg(target_os = "linux")]
    fn resolve_linux_username(uid: &sysinfo::Uid) -> Option<String> {
        use std::ffi::CStr;

        // Parse the UID from the sysinfo Uid type
        let uid_str = uid.to_string();
        if let Ok(uid_num) = uid_str.parse::<u32>() {
            unsafe {
                let pwd = libc::getpwuid(uid_num);
                if !pwd.is_null() {
                    let name_ptr = (*pwd).pw_name;
                    if !name_ptr.is_null() {
                        if let Ok(name) = CStr::from_ptr(name_ptr).to_str() {
                            return Some(name.to_string());
                        }
                    }
                }
            }
        }
        None
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    fn resolve_linux_username(_uid: &sysinfo::Uid) -> Option<String> {
        None
    }

    #[cfg(not(target_os = "windows"))]
    fn resolve_windows_username(_uid: &sysinfo::Uid) -> Option<String> {
        None
    }

    /// Check if a process is running with elevated privileges
    /// Uses multiple methods: TOKEN_ELEVATION, TokenIntegrityLevel, and SID check
    #[cfg(target_os = "windows")]
    fn check_elevation(pid: u32, skip_expensive: bool) -> bool {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::Security::{
            GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TokenElevation,
            TokenIntegrityLevel, TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

        // Windows security RIDs not exported by windows crate
        const SECURITY_MANDATORY_HIGH_RID: u32 = 0x00003000;
        const SECURITY_MANDATORY_SYSTEM_RID: u32 = 0x00004000;

        if skip_expensive {
            return false;
        }

        unsafe {
            // Open process
            let process_handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(h) => h,
                Err(e) => {
                    tracing::trace!(pid, error = %e, "Failed to open process for elevation check");
                    // Try alternative method: check if it's a system process (PID < 10 or special)
                    return pid < 10; // System processes like System (4), smss.exe (approx)
                }
            };

            // Open process token
            let mut token_handle = windows::Win32::Foundation::HANDLE::default();
            let result = windows::Win32::System::Threading::OpenProcessToken(
                process_handle,
                TOKEN_QUERY,
                &mut token_handle,
            );

            let _ = CloseHandle(process_handle);

            if result.is_err() {
                tracing::trace!(
                    pid,
                    "Failed to open process token, trying integrity level check"
                );
                if skip_expensive {
                    return false;
                }
                // Can't open token - this happens for protected processes
                // Protected processes (like antimalware) are typically elevated
                return Self::check_elevation_via_sid(pid);
            }

            // Method 1: Try TOKEN_ELEVATION (most reliable for normal processes)
            let mut elevation = TOKEN_ELEVATION::default();
            let mut return_length = 0u32;

            let result = GetTokenInformation(
                token_handle,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut return_length,
            );

            if result.is_ok() && elevation.TokenIsElevated != 0 {
                let _ = CloseHandle(token_handle);
                return true;
            }

            // Method 2: Check Token Integrity Level (works for UAC-elevated and SYSTEM)
            // First get the required buffer size
            let mut required_size = 0u32;
            let _ = GetTokenInformation(
                token_handle,
                TokenIntegrityLevel,
                None,
                0,
                &mut required_size,
            );

            if required_size > 0 {
                let mut buffer = vec![0u8; required_size as usize];
                let result = GetTokenInformation(
                    token_handle,
                    TokenIntegrityLevel,
                    Some(buffer.as_mut_ptr() as *mut _),
                    required_size,
                    &mut required_size,
                );

                if result.is_ok() {
                    let label = buffer.as_ptr() as *const TOKEN_MANDATORY_LABEL;
                    let sid = (*label).Label.Sid;
                    if !sid.is_invalid() {
                        let sub_auth_count = *GetSidSubAuthorityCount(sid);
                        if sub_auth_count > 0 {
                            let integrity_level =
                                *GetSidSubAuthority(sid, (sub_auth_count - 1) as u32);
                            // High integrity (0x3000) or System integrity (0x4000) = elevated
                            if integrity_level >= SECURITY_MANDATORY_HIGH_RID as u32 {
                                let _ = CloseHandle(token_handle);
                                return true;
                            }
                        }
                    }
                }
            }

            let _ = CloseHandle(token_handle);
            false
        }
    }

    /// Fallback elevation check using SID comparison
    #[cfg(target_os = "windows")]
    fn check_elevation_via_sid(pid: u32) -> bool {
        use std::process::Command;

        // Use tasklist to check if process is running as SYSTEM or Administrator
        let output = Command::new("tasklist")
            .args(["/FI", &format!("PID eq {}", pid), "/FO", "CSV", "/V"])
            .output();

        match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                // Check if running as SYSTEM or Administrator
                stdout.contains("SYSTEM") || stdout.contains("Administrator")
            }
            Err(_) => false,
        }
    }

    #[cfg(target_os = "linux")]
    fn check_elevation(pid: u32, _skip_expensive: bool) -> bool {
        // Check if process is running as root or has elevated capabilities
        let status_path = format!("/proc/{}/status", pid);

        if let Ok(content) = std::fs::read_to_string(&status_path) {
            for line in content.lines() {
                // Check for UID 0 (root)
                if line.starts_with("Uid:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        // Real UID is second field
                        if parts[1] == "0" {
                            return true;
                        }
                        // Effective UID is third field
                        if parts.len() >= 3 && parts[2] == "0" {
                            return true;
                        }
                    }
                }

                // Check for elevated capabilities
                if line.starts_with("CapEff:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        // CAP_SYS_ADMIN is bit 21
                        if let Ok(caps) = u64::from_str_radix(parts[1].trim_start_matches("0x"), 16)
                        {
                            // Check for CAP_SYS_ADMIN (1 << 21) or full caps
                            if caps & (1 << 21) != 0 || caps == 0xffffffffffffffff {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        false
    }

    #[cfg(target_os = "macos")]
    fn check_elevation(pid: u32, skip_expensive: bool) -> bool {
        if skip_expensive {
            return false;
        }
        use std::process::Command;

        let pid_str = pid.to_string();

        // 1. Check if process is running as root
        let output = Command::new("ps")
            .args(["-o", "user=", "-p", &pid_str])
            .output();

        let user = match &output {
            Ok(out) => String::from_utf8_lossy(&out.stdout).trim().to_string(),
            Err(_) => return false,
        };

        if user == "root" {
            return true;
        }

        // 2. Check admin group membership via `id -Gn <user>`
        //    A user in "admin" or "wheel" groups has elevated privileges on macOS
        if !user.is_empty() {
            if let Ok(groups_output) = Command::new("id").args(["-Gn", &user]).output() {
                let groups = String::from_utf8_lossy(&groups_output.stdout);
                let group_list: Vec<&str> = groups.split_whitespace().collect();
                if group_list.iter().any(|g| *g == "admin" || *g == "wheel") {
                    return true;
                }
            }
        }

        // 3. Check if the process binary has elevated entitlements via codesign
        //    Look for entitlements like com.apple.security.get-task-allow,
        //    com.apple.private.*, or com.apple.rootless.* which grant special privileges
        let proc_path_output = Command::new("ps")
            .args(["-o", "comm=", "-p", &pid_str])
            .output();

        if let Ok(path_out) = proc_path_output {
            let proc_path = String::from_utf8_lossy(&path_out.stdout).trim().to_string();
            if !proc_path.is_empty() {
                if let Ok(entitlements_output) = Command::new("codesign")
                    .args(["--display", "--entitlements", "-", &proc_path])
                    .output()
                {
                    let entitlements = String::from_utf8_lossy(&entitlements_output.stdout);
                    let elevated_entitlements = [
                        "com.apple.security.get-task-allow",
                        "com.apple.private.",
                        "com.apple.rootless.",
                        "com.apple.security.cs.allow-unsigned-executable-memory",
                        "com.apple.security.cs.disable-library-validation",
                    ];
                    for ent in &elevated_entitlements {
                        if entitlements.contains(ent) {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    fn check_elevation(_pid: u32, _skip_expensive: bool) -> bool {
        false
    }

    /// Check if a file is digitally signed.
    /// Tries embedded signature first (WinVerifyTrust), then falls back to
    /// catalog signature verification (CryptCATAdmin) for Windows system files.
    #[cfg(target_os = "windows")]
    fn check_signature(path: &str) -> (bool, Option<String>) {
        if path.is_empty() {
            return (false, None);
        }

        // Try embedded signature first
        if let Some(result) = Self::check_embedded_signature(path) {
            return result;
        }

        // Fallback: check catalog signature (Windows system files like cmd.exe, wmic.exe)
        if let Some(result) = Self::check_catalog_signature(path) {
            return result;
        }

        (false, None)
    }

    /// Check for embedded Authenticode signature using WinVerifyTrust
    #[cfg(target_os = "windows")]
    fn check_embedded_signature(path: &str) -> Option<(bool, Option<String>)> {
        use windows::core::{GUID, PWSTR};
        use windows::Win32::Security::WinTrust::{
            WinVerifyTrust, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_DATA_PROVIDER_FLAGS,
            WINTRUST_DATA_UICONTEXT, WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_NONE,
            WTD_STATEACTION_VERIFY, WTD_UI_NONE,
        };

        let path_wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            let mut file_info = WINTRUST_FILE_INFO {
                cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
                pcwszFilePath: windows::core::PCWSTR::from_raw(path_wide.as_ptr()),
                hFile: windows::Win32::Foundation::HANDLE::default(),
                pgKnownSubject: std::ptr::null_mut(),
            };

            let mut trust_data = WINTRUST_DATA {
                cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
                pPolicyCallbackData: std::ptr::null_mut(),
                pSIPClientData: std::ptr::null_mut(),
                dwUIChoice: WTD_UI_NONE,
                fdwRevocationChecks: WTD_REVOKE_NONE,
                dwUnionChoice: WTD_CHOICE_FILE,
                Anonymous: WINTRUST_DATA_0 {
                    pFile: &mut file_info,
                },
                dwStateAction: WTD_STATEACTION_VERIFY,
                hWVTStateData: windows::Win32::Foundation::HANDLE::default(),
                pwszURLReference: PWSTR::null(),
                dwProvFlags: WINTRUST_DATA_PROVIDER_FLAGS(0),
                dwUIContext: WINTRUST_DATA_UICONTEXT(0),
                pSignatureSettings: std::ptr::null_mut(),
            };

            // WINTRUST_ACTION_GENERIC_VERIFY_V2 GUID
            let mut action_guid = GUID::from_values(
                0xaac56b_u32,
                0xcd44,
                0x11d0,
                [0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
            );

            let result = WinVerifyTrust(
                windows::Win32::Foundation::HWND::default(),
                &mut action_guid as *mut _,
                &mut trust_data as *mut _ as *mut _,
            );

            let ret = if result == 0 {
                // Embedded signature is valid - extract signer using native APIs
                let signer = Self::get_signer_name_native(path);
                Some((true, signer))
            } else {
                // Not embedded-signed, try catalog next
                None
            };

            // Must close WinVerifyTrust state to avoid resource leak
            trust_data.dwStateAction = windows::Win32::Security::WinTrust::WTD_STATEACTION_CLOSE;
            let _ = WinVerifyTrust(
                windows::Win32::Foundation::HWND::default(),
                &mut action_guid as *mut _,
                &mut trust_data as *mut _ as *mut _,
            );

            ret
        }
    }

    /// Check for catalog signature using CryptCATAdmin API.
    /// Most Windows system files (cmd.exe, wmic.exe, etc.) are catalog-signed,
    /// not embedded-signed. This method checks the Windows security catalog.
    #[cfg(target_os = "windows")]
    fn check_catalog_signature(path: &str) -> Option<(bool, Option<String>)> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE};
        use windows::Win32::Security::Cryptography::Catalog::{
            CryptCATAdminAcquireContext, CryptCATAdminCalcHashFromFileHandle,
            CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
            CryptCATAdminReleaseContext,
        };
        use windows::Win32::Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING,
        };

        let path_wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            // Acquire catalog admin context
            let mut cat_admin = isize::default();
            if CryptCATAdminAcquireContext(&mut cat_admin, None, 0).is_err() {
                return None;
            }

            // Open the file
            let file_handle = match CreateFileW(
                PCWSTR::from_raw(path_wide.as_ptr()),
                GENERIC_READ.0,
                FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                HANDLE::default(),
            ) {
                Ok(h) => h,
                Err(_) => {
                    CryptCATAdminReleaseContext(cat_admin, 0);
                    return None;
                }
            };

            // Calculate the hash of the file
            let mut hash_size = 0u32;
            // First call to get required size
            let _ = CryptCATAdminCalcHashFromFileHandle(file_handle, &mut hash_size, None, 0);

            if hash_size == 0 {
                let _ = CloseHandle(file_handle);
                CryptCATAdminReleaseContext(cat_admin, 0);
                return None;
            }

            let mut hash_buf = vec![0u8; hash_size as usize];
            let hash_ok = CryptCATAdminCalcHashFromFileHandle(
                file_handle,
                &mut hash_size,
                Some(hash_buf.as_mut_ptr()),
                0,
            );

            let _ = CloseHandle(file_handle);

            if !hash_ok.as_bool() {
                CryptCATAdminReleaseContext(cat_admin, 0);
                return None;
            }

            // Search for the hash in the catalog database
            let cat_info = CryptCATAdminEnumCatalogFromHash(cat_admin, &hash_buf, 0, None);

            let found = cat_info != isize::default();

            if found {
                CryptCATAdminReleaseCatalogContext(cat_admin, cat_info, 0);
            }
            CryptCATAdminReleaseContext(cat_admin, 0);

            if found {
                // File is catalog-signed — it's a verified Windows system file
                let signer = Self::infer_signer_from_path(path);
                Some((true, signer))
            } else {
                None
            }
        }
    }

    /// Infer signer from known Windows system paths when catalog verification succeeds
    /// but we can't easily extract the signer name from the catalog.
    #[cfg(target_os = "windows")]
    fn infer_signer_from_path(path: &str) -> Option<String> {
        // First try to extract signer using native Windows APIs
        if let Some(signer) = Self::get_signer_name_native(path) {
            return Some(signer);
        }

        // Fallback to path-based inference for catalog-signed files
        let lower = path.to_lowercase();
        if lower.starts_with("c:\\windows\\") || lower.starts_with("c:\\program files\\windows") {
            Some("Microsoft Windows".to_string())
        } else if lower.contains("microsoft") {
            Some("Microsoft Corporation".to_string())
        } else {
            Some("Catalog-signed".to_string())
        }
    }

    /// Extract signer name from a PE file using native Windows Crypto APIs.
    /// Uses CryptQueryObject to get the certificate from the embedded signature
    /// and CertGetNameStringW to extract the subject name.
    #[cfg(target_os = "windows")]
    fn get_signer_name_native(path: &str) -> Option<String> {
        use windows::core::PCWSTR;
        use windows::Win32::Security::Cryptography::{
            CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext,
            CertGetNameStringW, CryptMsgClose, CryptMsgGetParam, CryptQueryObject,
            CERT_FIND_SUBJECT_CERT, CERT_INFO, CERT_NAME_SIMPLE_DISPLAY_TYPE,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_CONTENT_TYPE,
            CERT_QUERY_ENCODING_TYPE, CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_FORMAT_TYPE,
            CERT_QUERY_OBJECT_FILE, CMSG_SIGNER_INFO, CMSG_SIGNER_INFO_PARAM, HCERTSTORE,
            PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
        };

        let path_wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            let mut encoding_type = CERT_QUERY_ENCODING_TYPE::default();
            let mut content_type = CERT_QUERY_CONTENT_TYPE::default();
            let mut format_type = CERT_QUERY_FORMAT_TYPE::default();
            let mut cert_store: HCERTSTORE = HCERTSTORE::default();
            let mut crypt_msg: *mut std::ffi::c_void = std::ptr::null_mut();

            // Query the object to get the certificate store and message
            let result = CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                PCWSTR::from_raw(path_wide.as_ptr()).as_ptr() as *const _,
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                CERT_QUERY_FORMAT_FLAG_BINARY,
                0,
                Some(&mut encoding_type as *mut _),
                Some(&mut content_type as *mut _),
                Some(&mut format_type as *mut _),
                Some(&mut cert_store),
                Some(&mut crypt_msg),
                None,
            );

            if result.is_err() {
                return None;
            }

            // Get the signer info size first
            let mut signer_info_size: u32 = 0;
            let get_size_result = CryptMsgGetParam(
                crypt_msg,
                CMSG_SIGNER_INFO_PARAM,
                0,
                None,
                &mut signer_info_size,
            );

            if get_size_result.is_err() || signer_info_size == 0 {
                if !cert_store.is_invalid() {
                    let _ = CertCloseStore(cert_store, 0);
                }
                if !crypt_msg.is_null() {
                    let _ = CryptMsgClose(Some(crypt_msg));
                }
                return None;
            }

            // Allocate buffer and get signer info
            let mut signer_info_buf: Vec<u8> = vec![0; signer_info_size as usize];
            let get_info_result = CryptMsgGetParam(
                crypt_msg,
                CMSG_SIGNER_INFO_PARAM,
                0,
                Some(signer_info_buf.as_mut_ptr() as *mut _),
                &mut signer_info_size,
            );

            if get_info_result.is_err() {
                if !cert_store.is_invalid() {
                    let _ = CertCloseStore(cert_store, 0);
                }
                if !crypt_msg.is_null() {
                    let _ = CryptMsgClose(Some(crypt_msg));
                }
                return None;
            }

            // The signer info contains the issuer and serial number we need
            let signer_info = &*(signer_info_buf.as_ptr() as *const CMSG_SIGNER_INFO);

            // Build a CERT_INFO structure to find the certificate
            let mut cert_info: CERT_INFO = std::mem::zeroed();
            cert_info.Issuer = signer_info.Issuer;
            cert_info.SerialNumber = signer_info.SerialNumber;

            // Find the certificate in the store
            let cert_context = CertFindCertificateInStore(
                cert_store,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0,
                CERT_FIND_SUBJECT_CERT,
                Some(&cert_info as *const _ as *const _),
                None,
            );

            let signer_name = if !cert_context.is_null() {
                // Get the size of the name string first
                let name_size =
                    CertGetNameStringW(cert_context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None);

                if name_size > 1 {
                    let mut name_buf: Vec<u16> = vec![0; name_size as usize];
                    let chars_copied = CertGetNameStringW(
                        cert_context,
                        CERT_NAME_SIMPLE_DISPLAY_TYPE,
                        0,
                        None,
                        Some(&mut name_buf),
                    );

                    if chars_copied > 1 {
                        // Convert to string, removing null terminator
                        let name = String::from_utf16_lossy(&name_buf[..chars_copied as usize - 1]);
                        if !name.is_empty() {
                            Some(name)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

            // Cleanup
            if !cert_context.is_null() {
                let _ = CertFreeCertificateContext(Some(cert_context));
            }
            if !cert_store.is_invalid() {
                let _ = CertCloseStore(cert_store, 0);
            }
            if !crypt_msg.is_null() {
                let _ = CryptMsgClose(Some(crypt_msg));
            }

            signer_name
        }
    }

    /// Get detailed signature information from a PE file using native Windows APIs.
    /// Returns signer name, certificate thumbprint, validity dates, and trust status.
    #[cfg(target_os = "windows")]
    #[allow(dead_code)]
    fn get_signature_info(path: &str) -> Option<SignatureInfo> {
        use windows::core::{GUID, PCWSTR, PWSTR};
        use windows::Win32::Security::Cryptography::{
            CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext,
            CertGetNameStringW, CryptHashCertificate, CryptMsgClose, CryptMsgGetParam,
            CryptQueryObject, CALG_SHA1, CERT_FIND_SUBJECT_CERT, CERT_INFO,
            CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_CONTENT_TYPE, CERT_QUERY_ENCODING_TYPE, CERT_QUERY_FORMAT_FLAG_BINARY,
            CERT_QUERY_FORMAT_TYPE, CERT_QUERY_OBJECT_FILE, CMSG_SIGNER_INFO,
            CMSG_SIGNER_INFO_PARAM, HCERTSTORE, HCRYPTPROV_LEGACY, PKCS_7_ASN_ENCODING,
            X509_ASN_ENCODING,
        };
        use windows::Win32::Security::WinTrust::{
            WinVerifyTrust, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_DATA_PROVIDER_FLAGS,
            WINTRUST_DATA_UICONTEXT, WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_WHOLECHAIN,
            WTD_STATEACTION_VERIFY, WTD_UI_NONE,
        };

        let path_wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            // First verify the signature with revocation checking
            let mut file_info = WINTRUST_FILE_INFO {
                cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
                pcwszFilePath: PCWSTR::from_raw(path_wide.as_ptr()),
                hFile: windows::Win32::Foundation::HANDLE::default(),
                pgKnownSubject: std::ptr::null_mut(),
            };

            let mut trust_data = WINTRUST_DATA {
                cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
                pPolicyCallbackData: std::ptr::null_mut(),
                pSIPClientData: std::ptr::null_mut(),
                dwUIChoice: WTD_UI_NONE,
                fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
                dwUnionChoice: WTD_CHOICE_FILE,
                Anonymous: WINTRUST_DATA_0 {
                    pFile: &mut file_info,
                },
                dwStateAction: WTD_STATEACTION_VERIFY,
                hWVTStateData: windows::Win32::Foundation::HANDLE::default(),
                pwszURLReference: PWSTR::null(),
                dwProvFlags: WINTRUST_DATA_PROVIDER_FLAGS(0),
                dwUIContext: WINTRUST_DATA_UICONTEXT(0),
                pSignatureSettings: std::ptr::null_mut(),
            };

            let mut action_guid = GUID::from_values(
                0xaac56b_u32,
                0xcd44,
                0x11d0,
                [0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
            );

            let trust_result = WinVerifyTrust(
                windows::Win32::Foundation::HWND::default(),
                &mut action_guid as *mut _,
                &mut trust_data as *mut _ as *mut _,
            );

            let is_trusted = trust_result == 0;

            // Close WinVerifyTrust state to avoid resource leak
            trust_data.dwStateAction = windows::Win32::Security::WinTrust::WTD_STATEACTION_CLOSE;
            let _ = WinVerifyTrust(
                windows::Win32::Foundation::HWND::default(),
                &mut action_guid as *mut _,
                &mut trust_data as *mut _ as *mut _,
            );
            // Reset for the rest of the function
            trust_data.dwStateAction = WTD_STATEACTION_VERIFY;

            // Now get certificate details
            let mut encoding_type = CERT_QUERY_ENCODING_TYPE::default();
            let mut content_type = CERT_QUERY_CONTENT_TYPE::default();
            let mut format_type = CERT_QUERY_FORMAT_TYPE::default();
            let mut cert_store: HCERTSTORE = HCERTSTORE::default();
            let mut crypt_msg: *mut std::ffi::c_void = std::ptr::null_mut();

            let result = CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                PCWSTR::from_raw(path_wide.as_ptr()).as_ptr() as *const _,
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                CERT_QUERY_FORMAT_FLAG_BINARY,
                0,
                Some(&mut encoding_type as *mut _),
                Some(&mut content_type as *mut _),
                Some(&mut format_type as *mut _),
                Some(&mut cert_store),
                Some(&mut crypt_msg),
                None,
            );

            if result.is_err() {
                return None;
            }

            // Get signer info
            let mut signer_info_size: u32 = 0;
            if CryptMsgGetParam(
                crypt_msg,
                CMSG_SIGNER_INFO_PARAM,
                0,
                None,
                &mut signer_info_size,
            )
            .is_err()
            {
                let _ = CertCloseStore(cert_store, 0);
                let _ = CryptMsgClose(Some(crypt_msg));
                return None;
            }

            let mut signer_info_buf: Vec<u8> = vec![0; signer_info_size as usize];
            if CryptMsgGetParam(
                crypt_msg,
                CMSG_SIGNER_INFO_PARAM,
                0,
                Some(signer_info_buf.as_mut_ptr() as *mut _),
                &mut signer_info_size,
            )
            .is_err()
            {
                let _ = CertCloseStore(cert_store, 0);
                let _ = CryptMsgClose(Some(crypt_msg));
                return None;
            }

            let signer_info = &*(signer_info_buf.as_ptr() as *const CMSG_SIGNER_INFO);

            let mut cert_info: CERT_INFO = std::mem::zeroed();
            cert_info.Issuer = signer_info.Issuer;
            cert_info.SerialNumber = signer_info.SerialNumber;

            let cert_context = CertFindCertificateInStore(
                cert_store,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0,
                CERT_FIND_SUBJECT_CERT,
                Some(&cert_info as *const _ as *const _),
                None,
            );

            if cert_context.is_null() {
                let _ = CertCloseStore(cert_store, 0);
                let _ = CryptMsgClose(Some(crypt_msg));
                return None;
            }

            // Get signer name
            let name_size =
                CertGetNameStringW(cert_context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None);
            let signer_name = if name_size > 1 {
                let mut name_buf: Vec<u16> = vec![0; name_size as usize];
                CertGetNameStringW(
                    cert_context,
                    CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    0,
                    None,
                    Some(&mut name_buf),
                );
                String::from_utf16_lossy(&name_buf[..name_size as usize - 1])
            } else {
                String::from("Unknown")
            };

            // Get certificate thumbprint (SHA1 hash of the certificate)
            let cert = &*cert_context;
            let mut hash_size: u32 = 20; // SHA1 is 20 bytes
            let mut hash_buf: [u8; 20] = [0; 20];

            let thumbprint = if CryptHashCertificate(
                HCRYPTPROV_LEGACY::default(),
                CALG_SHA1,
                0,
                std::slice::from_raw_parts(cert.pbCertEncoded, cert.cbCertEncoded as usize),
                Some(hash_buf.as_mut_ptr()),
                &mut hash_size,
            )
            .is_ok()
            {
                hash_buf
                    .iter()
                    .map(|b| format!("{:02X}", b))
                    .collect::<Vec<_>>()
                    .join("")
            } else {
                String::new()
            };

            // Get validity dates
            let cert_info_ptr = cert.pCertInfo;
            let not_before = if !cert_info_ptr.is_null() {
                let ft = (*cert_info_ptr).NotBefore;
                ((ft.dwHighDateTime as i64) << 32) | (ft.dwLowDateTime as i64)
            } else {
                0
            };
            let not_after = if !cert_info_ptr.is_null() {
                let ft = (*cert_info_ptr).NotAfter;
                ((ft.dwHighDateTime as i64) << 32) | (ft.dwLowDateTime as i64)
            } else {
                0
            };

            // Check if certificate is currently valid (not expired)
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);

            // Convert FILETIME to Unix timestamp (FILETIME is 100-nanosecond intervals since 1601)
            let filetime_to_unix = |ft: i64| -> i64 { (ft - 116444736000000000) / 10000000 };

            let not_before_unix = filetime_to_unix(not_before);
            let not_after_unix = filetime_to_unix(not_after);
            let is_valid = now >= not_before_unix && now <= not_after_unix;

            // Cleanup
            let _ = CertFreeCertificateContext(Some(cert_context));
            let _ = CertCloseStore(cert_store, 0);
            let _ = CryptMsgClose(Some(crypt_msg));

            Some(SignatureInfo {
                signer_name,
                thumbprint,
                is_valid,
                is_trusted,
                not_before: not_before_unix,
                not_after: not_after_unix,
            })
        }
    }

    /// Legacy PowerShell-based signer extraction (kept as last-resort fallback)
    #[cfg(target_os = "windows")]
    #[allow(dead_code)]
    fn get_signer_name_powershell(path: &str) -> Option<String> {
        use std::process::Command;

        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "(Get-AuthenticodeSignature '{}').SignerCertificate.Subject",
                    path.replace("'", "''")
                ),
            ])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                let subject = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if subject.is_empty() {
                    None
                } else {
                    // Extract CN from subject
                    subject
                        .split(',')
                        .find(|part| part.trim().starts_with("CN="))
                        .map(|cn| cn.trim().trim_start_matches("CN=").to_string())
                }
            }
            _ => None,
        }
    }

    #[cfg(target_os = "linux")]
    fn check_signature(path: &str) -> (bool, Option<String>) {
        if path.is_empty() {
            return (false, None);
        }

        // Check for ELF signature using package managers or GPG
        // Also check if binary is from a signed package

        use std::process::Command;

        // Try dpkg for Debian-based systems
        let dpkg_output = Command::new("dpkg").args(["-S", path]).output();

        if let Ok(out) = dpkg_output {
            if out.status.success() {
                let package = String::from_utf8_lossy(&out.stdout);
                let package_name = package.split(':').next().unwrap_or("").trim();

                if !package_name.is_empty() {
                    // Verify package integrity using debsums if available
                    let debsums_check = Command::new("debsums")
                        .args(["--changed", package_name])
                        .output();

                    // If debsums exists and reports no changes, package is verified
                    let verified = debsums_check
                        .map(|o| o.status.success() && o.stdout.is_empty())
                        .unwrap_or(true);

                    if verified {
                        return (true, Some(format!("Package: {}", package_name)));
                    }
                }
            }
        }

        // Try rpm for RedHat-based systems
        let rpm_output = Command::new("rpm").args(["-qf", path]).output();

        if let Ok(out) = rpm_output {
            if out.status.success() {
                let package = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !package.is_empty() && !package.contains("not owned") {
                    // Verify file hasn't been modified
                    let verify = Command::new("rpm").args(["-Vf", path]).output();

                    // If verification passes or only shows expected differences
                    if let Ok(v) = verify {
                        let stdout = String::from_utf8_lossy(&v.stdout);
                        // If no output or only config file changes, consider it verified
                        if stdout.is_empty() || !stdout.contains("..5") {
                            // 5 means MD5 mismatch
                            // Get GPG key info for the package
                            let key_output = Command::new("rpm").args(["-qi", &package]).output();

                            let signer = if let Ok(ki) = key_output {
                                let info = String::from_utf8_lossy(&ki.stdout);
                                info.lines()
                                    .find(|l| l.starts_with("Signature"))
                                    .map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string())
                                    .filter(|s| !s.is_empty())
                                    .unwrap_or_else(|| format!("RPM: {}", package))
                            } else {
                                format!("RPM: {}", package)
                            };

                            return (true, Some(signer));
                        }
                    }
                }
            }
        }

        // Try pacman for Arch-based systems
        let pacman_output = Command::new("pacman").args(["-Qo", path]).output();

        if let Ok(out) = pacman_output {
            if out.status.success() {
                let stdout = String::from_utf8_lossy(&out.stdout);
                // Parse "path is owned by package version"
                if let Some(pkg) = stdout.split(" is owned by ").nth(1) {
                    let package_name = pkg.split_whitespace().next().unwrap_or("").trim();
                    if !package_name.is_empty() {
                        return (true, Some(format!("Package: {}", package_name)));
                    }
                }
            }
        }

        // Check for GPG signature in ELF binary (some projects embed signatures)
        let gpg_check = Command::new("gpg")
            .args(["--verify", &format!("{}.sig", path), path])
            .output();

        if let Ok(out) = gpg_check {
            if out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr);
                // Extract signer from GPG output
                let signer = stderr
                    .lines()
                    .find(|l| l.contains("Good signature from"))
                    .map(|l| l.to_string());

                if let Some(s) = signer {
                    return (true, Some(s));
                }
            }
        }

        // Check if binary is from known trusted system path and hasn't been modified
        let trusted_paths = [
            "/usr/bin/",
            "/bin/",
            "/usr/sbin/",
            "/sbin/",
            "/usr/lib/",
            "/lib/",
        ];
        if trusted_paths.iter().any(|p| path.starts_with(p)) {
            // Check file attributes (immutable flag)
            let lsattr_output = Command::new("lsattr").args([path]).output();

            if let Ok(out) = lsattr_output {
                let stdout = String::from_utf8_lossy(&out.stdout);
                if stdout.contains('i') {
                    return (true, Some("System binary (immutable)".to_string()));
                }
            }
        }

        (false, None)
    }

    #[cfg(target_os = "macos")]
    fn check_signature(path: &str) -> (bool, Option<String>) {
        if path.is_empty() {
            return (false, None);
        }

        use std::process::Command;

        // First verify the signature is valid
        let verify_output = Command::new("codesign")
            .args(["--verify", "--deep", "--strict", path])
            .output();

        let is_valid = match verify_output {
            Ok(out) => out.status.success(),
            Err(_) => false,
        };

        if !is_valid {
            return (false, None);
        }

        // Then get signer information
        let output = Command::new("codesign")
            .args(["-dv", "--verbose=4", path])
            .output();

        match output {
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);

                // Extract signer identity (Authority line contains the signing identity)
                let signer = stderr
                    .lines()
                    .find(|line| line.starts_with("Authority="))
                    .map(|line| line.trim_start_matches("Authority=").to_string());

                // Also check for Apple-signed binaries
                let is_apple = stderr.contains("Apple") || stderr.contains("Software Signing");

                if let Some(ref s) = signer {
                    (true, Some(s.clone()))
                } else if is_apple {
                    (true, Some("Apple".to_string()))
                } else {
                    (true, Some("Signed (unknown signer)".to_string()))
                }
            }
            Err(_) => (true, None), // Signature verified but couldn't get signer info
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    fn check_signature(_path: &str) -> (bool, Option<String>) {
        (false, None)
    }

    /// Get command line using NT API (Windows only)
    /// This can retrieve cmdline even for some protected processes
    #[cfg(target_os = "windows")]
    fn get_cmdline_nt(pid: u32) -> Option<String> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
            PROCESS_VM_READ,
        };

        unsafe {
            // Try limited access first (works for more processes)
            let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(h) => h,
                Err(_) => {
                    // Try full access
                    match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
                        Ok(h) => h,
                        Err(_) => return None,
                    }
                }
            };

            let cmdline = get_process_command_line(std::mem::transmute(handle));
            let _ = CloseHandle(handle);

            cmdline
        }
    }

    /// Get the real parent PID using NT API (detects PPID spoofing)
    #[cfg(target_os = "windows")]
    fn get_real_ppid(pid: u32) -> Option<u32> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(h) => h,
                Err(_) => return None,
            };

            let ppid = get_real_parent_pid(std::mem::transmute(handle));
            let _ = CloseHandle(handle);

            ppid
        }
    }

    /// Get username from process token (alternative method)
    #[cfg(target_os = "windows")]
    fn get_username_from_token(pid: u32) -> Option<String> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::Security::{
            GetTokenInformation, LookupAccountSidW, TokenUser, SID_NAME_USE, TOKEN_QUERY,
            TOKEN_USER,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        unsafe {
            let process_handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(h) => h,
                Err(_) => return None,
            };

            let mut token_handle = HANDLE::default();
            if OpenProcessToken(process_handle, TOKEN_QUERY, &mut token_handle).is_err() {
                let _ = CloseHandle(process_handle);
                return None;
            }

            let _ = CloseHandle(process_handle);

            // Get token user info
            let mut needed = 0u32;
            let _ = GetTokenInformation(token_handle, TokenUser, None, 0, &mut needed);

            if needed == 0 {
                let _ = CloseHandle(token_handle);
                return None;
            }

            let mut buffer = vec![0u8; needed as usize];
            if GetTokenInformation(
                token_handle,
                TokenUser,
                Some(buffer.as_mut_ptr() as *mut _),
                needed,
                &mut needed,
            )
            .is_err()
            {
                let _ = CloseHandle(token_handle);
                return None;
            }

            let _ = CloseHandle(token_handle);

            let token_user = &*(buffer.as_ptr() as *const TOKEN_USER);
            let sid = token_user.User.Sid;

            // Lookup account from SID
            let mut name_buf = vec![0u16; 256];
            let mut domain_buf = vec![0u16; 256];
            let mut name_len = name_buf.len() as u32;
            let mut domain_len = domain_buf.len() as u32;
            let mut sid_type = SID_NAME_USE::default();

            if LookupAccountSidW(
                PCWSTR::null(),
                sid,
                windows::core::PWSTR(name_buf.as_mut_ptr()),
                &mut name_len,
                windows::core::PWSTR(domain_buf.as_mut_ptr()),
                &mut domain_len,
                &mut sid_type,
            )
            .is_ok()
            {
                let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                let domain = String::from_utf16_lossy(&domain_buf[..domain_len as usize]);

                if domain.is_empty() {
                    Some(name)
                } else {
                    Some(format!("{}\\{}", domain, name))
                }
            } else {
                None
            }
        }
    }

    // =====================================================================
    // PE version info extraction
    // =====================================================================

    /// Extract PE VersionInfo fields (CompanyName, FileDescription,
    /// ProductName, FileVersion) from a Windows PE file using the
    /// GetFileVersionInfoW / VerQueryValueW APIs.
    ///
    /// Results are cached by the caller to avoid redundant I/O.
    #[cfg(target_os = "windows")]
    fn get_pe_version_info(path: &str) -> PeVersionInfoEntry {
        use windows::core::PCWSTR;
        use windows::Win32::Storage::FileSystem::{
            GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
        };

        if path.is_empty() {
            return PeVersionInfoEntry::default();
        }

        let path_wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            // Determine the size of the version-info block
            let mut dummy_handle: u32 = 0;
            let size = GetFileVersionInfoSizeW(
                PCWSTR::from_raw(path_wide.as_ptr()),
                Some(&mut dummy_handle),
            );
            if size == 0 {
                return PeVersionInfoEntry::default();
            }

            // Allocate a buffer and read the version-info resource
            let mut buffer: Vec<u8> = vec![0u8; size as usize];
            let ok = GetFileVersionInfoW(
                PCWSTR::from_raw(path_wide.as_ptr()),
                0,
                size,
                buffer.as_mut_ptr() as *mut _,
            );
            if ok.is_err() {
                return PeVersionInfoEntry::default();
            }

            // Helper closure: query a single StringFileInfo value.
            // We try the common "040904B0" (US English, Unicode) translation
            // first, then fall back to "040904E4" (US English, Multilingual)
            // and "000004B0" (Language-neutral, Unicode).
            let query_string = |key: &str| -> Option<String> {
                let translations: &[&str] = &["040904B0", "040904E4", "000004B0"];
                for &translation in translations {
                    let sub_block = format!("\\StringFileInfo\\{}\\{}\0", translation, key);
                    let sub_block_wide: Vec<u16> = sub_block.encode_utf16().collect();

                    let mut ptr: *mut std::ffi::c_void = std::ptr::null_mut();
                    let mut len: u32 = 0;

                    let found = VerQueryValueW(
                        buffer.as_ptr() as *const _,
                        PCWSTR::from_raw(sub_block_wide.as_ptr()),
                        &mut ptr,
                        &mut len,
                    );

                    if found.as_bool() && !ptr.is_null() && len > 0 {
                        // len is in WCHARs (including trailing null)
                        let slice = std::slice::from_raw_parts(ptr as *const u16, len as usize);
                        // Trim trailing nulls
                        let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
                        let value = String::from_utf16_lossy(&slice[..end]);
                        if !value.is_empty() {
                            return Some(value);
                        }
                    }
                }
                None
            };

            PeVersionInfoEntry {
                company_name: query_string("CompanyName"),
                file_description: query_string("FileDescription"),
                product_name: query_string("ProductName"),
                file_version: query_string("FileVersion"),
                last_accessed: std::time::Instant::now(),
            }
        }
    }

    /// Non-Windows stub: PE version info is not available.
    #[cfg(not(target_os = "windows"))]
    fn get_pe_version_info(_path: &str) -> PeVersionInfoEntry {
        PeVersionInfoEntry::default()
    }
}

// ============================================================================
// macOS Native Process APIs
// ============================================================================

/// macOS-specific process monitoring using native APIs
/// Provides deeper visibility than sysinfo through libproc and sysctl
#[cfg(target_os = "macos")]
pub mod macos_process {
    use std::ffi::{CStr, CString};
    use std::mem::MaybeUninit;
    use tracing::{debug, trace, warn};

    // libproc constants
    const PROC_PIDPATHINFO_MAXSIZE: u32 = 4096;
    const PROC_ALL_PIDS: u32 = 1;
    const PROC_PIDTBSDINFO: i32 = 3;
    const PROC_PIDTASKALLINFO: i32 = 2;
    const PROC_PIDVNODEPATHINFO: i32 = 9;

    // sysctl identifiers
    const CTL_KERN: libc::c_int = 1;
    const KERN_PROC: libc::c_int = 14;
    const KERN_PROC_ALL: libc::c_int = 0;
    const KERN_PROC_PID: libc::c_int = 1;
    const KERN_ARGMAX: libc::c_int = 8;
    const KERN_PROCARGS2: libc::c_int = 49;

    /// Process BSD info structure
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct ProcBsdInfo {
        pub pbi_flags: u32,
        pub pbi_status: u32,
        pub pbi_xstatus: u32,
        pub pbi_pid: u32,
        pub pbi_ppid: u32,
        pub pbi_uid: libc::uid_t,
        pub pbi_gid: libc::gid_t,
        pub pbi_ruid: libc::uid_t,
        pub pbi_rgid: libc::gid_t,
        pub pbi_svuid: libc::uid_t,
        pub pbi_svgid: libc::gid_t,
        pub rfu_1: u32,
        pub pbi_comm: [libc::c_char; 16],
        pub pbi_name: [libc::c_char; 32],
        pub pbi_nfiles: u32,
        pub pbi_pgid: u32,
        pub pbi_pjobc: u32,
        pub e_tdev: u32,
        pub e_tpgid: u32,
        pub pbi_nice: i32,
        pub pbi_start_tvsec: u64,
        pub pbi_start_tvusec: u64,
    }

    /// Process task info structure
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct ProcTaskInfo {
        pub pti_virtual_size: u64,
        pub pti_resident_size: u64,
        pub pti_total_user: u64,
        pub pti_total_system: u64,
        pub pti_threads_user: u64,
        pub pti_threads_system: u64,
        pub pti_policy: i32,
        pub pti_faults: i32,
        pub pti_pageins: i32,
        pub pti_cow_faults: i32,
        pub pti_messages_sent: i32,
        pub pti_messages_received: i32,
        pub pti_syscalls_mach: i32,
        pub pti_syscalls_unix: i32,
        pub pti_csw: i32,
        pub pti_threadnum: i32,
        pub pti_numrunning: i32,
        pub pti_priority: i32,
    }

    /// Process task all info (combines BSD and task info)
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct ProcTaskAllInfo {
        pub pbsd: ProcBsdInfo,
        pub ptinfo: ProcTaskInfo,
    }

    /// kinfo_proc structure for sysctl
    #[repr(C)]
    pub struct KinfoProc {
        pub kp_proc: ExternProc,
        pub kp_eproc: Eproc,
    }

    #[repr(C)]
    pub struct ExternProc {
        pub p_un: [u8; 16],
        pub p_vmspace: u64,
        pub p_sigacts: u64,
        pub p_flag: i32,
        pub p_stat: i8,
        pub p_pid: i32,
        pub p_oppid: i32,
        pub p_dupfd: i32,
        pub user_stack: u64,
        pub exit_thread: u64,
        pub p_debugger: i32,
        pub sigwait: i32,
        pub p_estcpu: u32,
        pub p_cpticks: i32,
        pub p_pctcpu: u32,
        pub p_wchan: u64,
        pub p_wmesg: u64,
        pub p_swtime: u32,
        pub p_slptime: u32,
        pub p_realtimer: [u8; 32],
        pub p_rtime: [u8; 16],
        pub p_uticks: u64,
        pub p_sticks: u64,
        pub p_iticks: u64,
        pub p_traceflag: i32,
        pub p_tracep: u64,
        pub p_siglist: i32,
        pub p_textvp: u64,
        pub p_holdcnt: i32,
        pub p_sigmask: u32,
        pub p_sigignore: u32,
        pub p_sigcatch: u32,
        pub p_priority: u8,
        pub p_usrpri: u8,
        pub p_nice: i8,
        pub p_comm: [libc::c_char; 17],
        pub p_pgrp: u64,
        pub p_addr: u64,
        pub p_xstat: u16,
        pub p_acflag: u16,
        pub p_ru: u64,
    }

    #[repr(C)]
    pub struct Eproc {
        pub e_paddr: u64,
        pub e_sess: u64,
        pub e_pcred: Pcred,
        pub e_ucred: Ucred,
        pub e_vm: [u8; 160],
        pub e_ppid: i32,
        pub e_pgid: i32,
        pub e_jobc: i16,
        pub e_tdev: i32,
        pub e_tpgid: i32,
        pub e_tsess: u64,
        pub e_wmesg: [libc::c_char; 8],
        pub e_xsize: i32,
        pub e_xrssize: i16,
        pub e_xccount: i16,
        pub e_xswrss: i16,
        pub e_flag: i32,
        pub e_login: [libc::c_char; 12],
        pub e_spare: [i32; 4],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Pcred {
        pub pc_lock: [u8; 72],
        pub pc_ucred: u64,
        pub p_ruid: libc::uid_t,
        pub p_svuid: libc::uid_t,
        pub p_rgid: libc::gid_t,
        pub p_svgid: libc::gid_t,
        pub p_refcnt: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Ucred {
        pub cr_ref: i32,
        pub cr_uid: libc::uid_t,
        pub cr_ngroups: i16,
        pub cr_groups: [libc::gid_t; 16],
    }

    // libproc function declarations
    extern "C" {
        fn proc_listpids(
            type_: u32,
            typeinfo: u32,
            buffer: *mut libc::c_void,
            buffersize: i32,
        ) -> i32;

        fn proc_pidpath(pid: i32, buffer: *mut libc::c_void, buffersize: u32) -> i32;

        fn proc_pidinfo(
            pid: i32,
            flavor: i32,
            arg: u64,
            buffer: *mut libc::c_void,
            buffersize: i32,
        ) -> i32;

        fn proc_name(pid: i32, buffer: *mut libc::c_void, buffersize: u32) -> i32;
    }

    /// Get all process IDs on the system
    pub fn get_all_pids() -> Vec<i32> {
        // First call to get buffer size
        let buffer_size = unsafe { proc_listpids(PROC_ALL_PIDS, 0, std::ptr::null_mut(), 0) };
        if buffer_size <= 0 {
            return Vec::new();
        }

        let num_pids = buffer_size as usize / std::mem::size_of::<i32>();
        let mut pids = vec![0i32; num_pids];

        let result = unsafe {
            proc_listpids(
                PROC_ALL_PIDS,
                0,
                pids.as_mut_ptr() as *mut libc::c_void,
                buffer_size,
            )
        };

        if result <= 0 {
            return Vec::new();
        }

        let actual_count = result as usize / std::mem::size_of::<i32>();
        pids.truncate(actual_count);
        pids.retain(|&pid| pid > 0);
        pids
    }

    /// Get executable path for a process using libproc
    pub fn get_process_path(pid: i32) -> Option<String> {
        let mut buffer = [0u8; PROC_PIDPATHINFO_MAXSIZE as usize];

        let result = unsafe {
            proc_pidpath(
                pid,
                buffer.as_mut_ptr() as *mut libc::c_void,
                PROC_PIDPATHINFO_MAXSIZE,
            )
        };

        if result <= 0 {
            return None;
        }

        let path = unsafe { CStr::from_ptr(buffer.as_ptr() as *const libc::c_char) };
        Some(path.to_string_lossy().to_string())
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

    /// Get BSD info for a process
    pub fn get_process_bsd_info(pid: i32) -> Option<ProcBsdInfo> {
        let mut info = MaybeUninit::<ProcBsdInfo>::uninit();

        let result = unsafe {
            proc_pidinfo(
                pid,
                PROC_PIDTBSDINFO,
                0,
                info.as_mut_ptr() as *mut libc::c_void,
                std::mem::size_of::<ProcBsdInfo>() as i32,
            )
        };

        if result <= 0 {
            return None;
        }

        Some(unsafe { info.assume_init() })
    }

    /// Get all info for a process (BSD + task info)
    pub fn get_process_all_info(pid: i32) -> Option<ProcTaskAllInfo> {
        let mut info = MaybeUninit::<ProcTaskAllInfo>::uninit();

        let result = unsafe {
            proc_pidinfo(
                pid,
                PROC_PIDTASKALLINFO,
                0,
                info.as_mut_ptr() as *mut libc::c_void,
                std::mem::size_of::<ProcTaskAllInfo>() as i32,
            )
        };

        if result <= 0 {
            return None;
        }

        Some(unsafe { info.assume_init() })
    }

    /// Get command line arguments for a process using sysctl
    pub fn get_process_args(pid: i32) -> Option<String> {
        // Get the maximum argument size
        let mut argmax: libc::c_int = 0;
        let mut size = std::mem::size_of::<libc::c_int>();
        let mut mib = [CTL_KERN, KERN_ARGMAX];

        unsafe {
            if libc::sysctl(
                mib.as_mut_ptr(),
                2,
                &mut argmax as *mut _ as *mut libc::c_void,
                &mut size,
                std::ptr::null_mut(),
                0,
            ) != 0
            {
                return None;
            }
        }

        // Get the process arguments
        let mut buffer = vec![0u8; argmax as usize];
        let mut mib = [CTL_KERN, KERN_PROCARGS2, pid];

        unsafe {
            let mut size = argmax as usize;
            if libc::sysctl(
                mib.as_mut_ptr(),
                3,
                buffer.as_mut_ptr() as *mut libc::c_void,
                &mut size,
                std::ptr::null_mut(),
                0,
            ) != 0
            {
                return None;
            }

            // Parse the buffer
            // First 4 bytes are argc
            if size < 4 {
                return None;
            }

            let argc = i32::from_ne_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;

            // Find the start of the arguments (skip executable path and null bytes)
            let mut pos = 4;

            // Skip executable path
            while pos < size && buffer[pos] != 0 {
                pos += 1;
            }

            // Skip null bytes
            while pos < size && buffer[pos] == 0 {
                pos += 1;
            }

            // Collect arguments
            let mut args = Vec::new();
            for _ in 0..argc {
                if pos >= size {
                    break;
                }
                let start = pos;
                while pos < size && buffer[pos] != 0 {
                    pos += 1;
                }
                if start < pos {
                    if let Ok(arg) = std::str::from_utf8(&buffer[start..pos]) {
                        args.push(arg.to_string());
                    }
                }
                pos += 1; // Skip null terminator
            }

            if args.is_empty() {
                None
            } else {
                Some(args.join(" "))
            }
        }
    }

    /// Get username from UID
    pub fn get_username(uid: libc::uid_t) -> Option<String> {
        unsafe {
            let pwd = libc::getpwuid(uid);
            if pwd.is_null() {
                return None;
            }
            let name = CStr::from_ptr((*pwd).pw_name);
            Some(name.to_string_lossy().to_string())
        }
    }

    /// Check if process is running as root
    pub fn is_process_root(pid: i32) -> bool {
        if let Some(info) = get_process_bsd_info(pid) {
            info.pbi_uid == 0 || info.pbi_ruid == 0
        } else {
            false
        }
    }

    /// Get process start time as milliseconds since epoch
    pub fn get_process_start_time(pid: i32) -> Option<u64> {
        if let Some(info) = get_process_bsd_info(pid) {
            Some(info.pbi_start_tvsec * 1000 + info.pbi_start_tvusec / 1000)
        } else {
            None
        }
    }

    /// Detailed process information structure
    #[derive(Debug, Clone)]
    pub struct MacOsProcessInfo {
        pub pid: u32,
        pub ppid: u32,
        pub name: String,
        pub path: String,
        pub cmdline: String,
        pub uid: u32,
        pub username: String,
        pub start_time: u64,
        pub is_elevated: bool,
        pub is_signed: bool,
        pub signer: Option<String>,
    }

    /// Get comprehensive process information
    pub fn get_process_info(pid: i32) -> Option<MacOsProcessInfo> {
        let info = get_process_bsd_info(pid)?;

        let path = get_process_path(pid).unwrap_or_default();
        let name = get_process_name(pid).unwrap_or_else(|| {
            std::path::Path::new(&path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default()
        });

        let cmdline = get_process_args(pid).unwrap_or_else(|| path.clone());
        let username =
            get_username(info.pbi_uid).unwrap_or_else(|| format!("uid:{}", info.pbi_uid));

        // Check code signature
        let (is_signed, signer) = check_codesign(&path);

        Some(MacOsProcessInfo {
            pid: info.pbi_pid,
            ppid: info.pbi_ppid,
            name,
            path,
            cmdline,
            uid: info.pbi_uid,
            username,
            start_time: info.pbi_start_tvsec * 1000 + info.pbi_start_tvusec / 1000,
            is_elevated: info.pbi_uid == 0 || info.pbi_ruid == 0,
            is_signed,
            signer,
        })
    }

    /// Check code signature using codesign command
    fn check_codesign(path: &str) -> (bool, Option<String>) {
        if path.is_empty() {
            return (false, None);
        }

        use std::process::Command;

        // Verify signature
        let verify = Command::new("codesign")
            .args(["--verify", "--deep", "--strict", path])
            .output();

        let is_valid = match verify {
            Ok(out) => out.status.success(),
            Err(_) => return (false, None),
        };

        if !is_valid {
            return (false, None);
        }

        // Get signer info
        let output = Command::new("codesign")
            .args(["-dv", "--verbose=2", path])
            .output();

        match output {
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);

                // Extract Authority line
                let signer = stderr
                    .lines()
                    .find(|line| line.starts_with("Authority="))
                    .map(|line| line.trim_start_matches("Authority=").to_string());

                if signer.is_some() {
                    (true, signer)
                } else if stderr.contains("Apple") {
                    (true, Some("Apple".to_string()))
                } else {
                    (true, Some("Signed".to_string()))
                }
            }
            Err(_) => (true, None),
        }
    }

    /// Enumerate all processes with their info
    pub fn enumerate_processes() -> Vec<MacOsProcessInfo> {
        let pids = get_all_pids();
        let mut processes = Vec::with_capacity(pids.len());

        for pid in pids {
            if let Some(info) = get_process_info(pid) {
                processes.push(info);
            }
        }

        processes
    }
}

// ============================================================================
// macOS kqueue Process Event Monitoring
// ============================================================================

/// kqueue-based process event monitoring for macOS
/// Provides real-time notifications of process fork/exec/exit
#[cfg(target_os = "macos")]
pub mod macos_kqueue {
    use super::macos_process;
    use std::collections::HashSet;
    use tracing::{debug, error, info, warn};

    // kqueue event filter constants
    const EVFILT_PROC: i16 = -5;

    // kqueue event flags
    const EV_ADD: u16 = 0x0001;
    const EV_ENABLE: u16 = 0x0004;
    const EV_CLEAR: u16 = 0x0020;
    const EV_EOF: u16 = 0x8000;

    // Process filter flags
    const NOTE_EXIT: u32 = 0x80000000;
    const NOTE_FORK: u32 = 0x40000000;
    const NOTE_EXEC: u32 = 0x20000000;
    const NOTE_TRACK: u32 = 0x00000001;
    const NOTE_CHILD: u32 = 0x00000004;
    const NOTE_TRACKERR: u32 = 0x00000002;

    /// kevent structure for process monitoring
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Kevent {
        pub ident: usize,
        pub filter: i16,
        pub flags: u16,
        pub fflags: u32,
        pub data: isize,
        pub udata: *mut libc::c_void,
    }

    extern "C" {
        fn kqueue() -> libc::c_int;
        fn kevent(
            kq: libc::c_int,
            changelist: *const Kevent,
            nchanges: libc::c_int,
            eventlist: *mut Kevent,
            nevents: libc::c_int,
            timeout: *const libc::timespec,
        ) -> libc::c_int;
    }

    /// Process event type
    #[derive(Debug, Clone, Copy, PartialEq)]
    pub enum ProcessEventType {
        Fork,
        Exec,
        Exit,
    }

    /// Process event notification
    #[derive(Debug, Clone)]
    pub struct ProcessKqueueEvent {
        pub event_type: ProcessEventType,
        pub pid: u32,
        pub child_pid: Option<u32>,
    }

    /// kqueue-based process monitor
    pub struct ProcessMonitor {
        kq: libc::c_int,
        tracked_pids: HashSet<u32>,
    }

    impl ProcessMonitor {
        /// Create a new process monitor
        pub fn new() -> Result<Self, String> {
            let kq = unsafe { kqueue() };
            if kq < 0 {
                return Err("Failed to create kqueue".to_string());
            }

            info!("Created kqueue process monitor");

            Ok(Self {
                kq,
                tracked_pids: HashSet::new(),
            })
        }

        /// Start tracking a process
        pub fn track_process(&mut self, pid: u32) -> Result<(), String> {
            if self.tracked_pids.contains(&pid) {
                return Ok(());
            }

            let event = Kevent {
                ident: pid as usize,
                filter: EVFILT_PROC,
                flags: EV_ADD | EV_ENABLE | EV_CLEAR,
                fflags: NOTE_EXIT | NOTE_FORK | NOTE_EXEC | NOTE_TRACK,
                data: 0,
                udata: std::ptr::null_mut(),
            };

            let result = unsafe {
                kevent(
                    self.kq,
                    &event as *const Kevent,
                    1,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null(),
                )
            };

            if result < 0 {
                return Err(format!(
                    "Failed to register process {}: {}",
                    pid,
                    std::io::Error::last_os_error()
                ));
            }

            self.tracked_pids.insert(pid);
            debug!(pid = pid, "Started tracking process");

            Ok(())
        }

        /// Track all current processes
        pub fn track_all_processes(&mut self) {
            let pids = macos_process::get_all_pids();
            for pid in pids {
                let _ = self.track_process(pid as u32);
            }
            info!(count = self.tracked_pids.len(), "Tracking all processes");
        }

        /// Wait for and return the next process event
        pub fn next_event(&mut self, timeout_ms: u64) -> Option<ProcessKqueueEvent> {
            let timeout = libc::timespec {
                tv_sec: (timeout_ms / 1000) as libc::time_t,
                tv_nsec: ((timeout_ms % 1000) * 1_000_000) as libc::c_long,
            };

            let mut event = Kevent {
                ident: 0,
                filter: 0,
                flags: 0,
                fflags: 0,
                data: 0,
                udata: std::ptr::null_mut(),
            };

            let result = unsafe {
                kevent(
                    self.kq,
                    std::ptr::null(),
                    0,
                    &mut event as *mut Kevent,
                    1,
                    &timeout as *const libc::timespec,
                )
            };

            if result <= 0 {
                return None;
            }

            let pid = event.ident as u32;

            // Determine event type
            if event.fflags & NOTE_EXIT != 0 {
                self.tracked_pids.remove(&pid);
                return Some(ProcessKqueueEvent {
                    event_type: ProcessEventType::Exit,
                    pid,
                    child_pid: None,
                });
            }

            if event.fflags & NOTE_FORK != 0 {
                // Try to track the child process
                if event.fflags & NOTE_CHILD != 0 {
                    let child_pid = event.data as u32;
                    let _ = self.track_process(child_pid);
                    return Some(ProcessKqueueEvent {
                        event_type: ProcessEventType::Fork,
                        pid,
                        child_pid: Some(child_pid),
                    });
                }
                return Some(ProcessKqueueEvent {
                    event_type: ProcessEventType::Fork,
                    pid,
                    child_pid: None,
                });
            }

            if event.fflags & NOTE_EXEC != 0 {
                return Some(ProcessKqueueEvent {
                    event_type: ProcessEventType::Exec,
                    pid,
                    child_pid: None,
                });
            }

            None
        }
    }

    impl Drop for ProcessMonitor {
        fn drop(&mut self) {
            if self.kq >= 0 {
                unsafe { libc::close(self.kq) };
            }
        }
    }
}
