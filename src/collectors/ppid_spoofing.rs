//! PPID Spoofing Detection Collector
//!
//! Detects Parent Process ID (PPID) spoofing attacks where adversaries manipulate
//! the apparent parent process of a newly spawned process to evade detection.
//!
//! Detection Methods:
//! 1. ETW process creation events with real creator PID comparison
//! 2. NtQueryInformationProcess to get InheritedFromUniqueProcessId
//! 3. Handle enumeration to correlate process creation handles
//! 4. STARTUPINFOEX/UpdateProcThreadAttribute pattern detection via ETW API tracing
//! 5. Thread creation context analysis for PROC_THREAD_ATTRIBUTE_PARENT_PROCESS usage
//! 6. **Timeline validation** - Verify claimed parent was running when child started
//! 7. **Orphan process detection** - Detect processes with terminated/suspicious parents
//! 8. **Handle inheritance anomalies** - Detect unusual handle inheritance patterns
//! 9. **Process tree anomaly detection** - Identify impossible parent-child relationships
//!
//! MITRE ATT&CK: T1134.004 - Access Token Manipulation: Parent PID Spoofing
//!
//! References:
//! - https://attack.mitre.org/techniques/T1134/004/
//! - https://blog.didierstevens.com/2009/11/22/quickpost-selectmyparent-or-playing-with-the-windows-process-tree/
//! - https://blog.f-secure.com/detecting-parent-pid-spoofing/
//! - https://www.ired.team/offensive-security/defense-evasion/parent-pid-spoofing

// PPID spoofing detector. Scaffolded fields and helper params retained.
#![allow(dead_code, unused_variables)]

use super::{Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent};
use crate::config::AgentConfig;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

#[cfg(target_os = "windows")]
use std::ffi::c_void;

/// Information about a process creation event used for spoofing detection
#[derive(Debug, Clone)]
pub struct ProcessCreationInfo {
    /// Process ID of the created process
    pub pid: u32,
    /// Declared parent PID (from process structure/token)
    pub declared_ppid: u32,
    /// Actual creator PID (the process that called CreateProcess)
    pub actual_creator_pid: u32,
    /// Process name
    pub process_name: String,
    /// Process path
    pub process_path: String,
    /// Command line
    pub cmdline: String,
    /// User account
    pub user: String,
    /// Timestamp (Unix ms)
    pub timestamp: u64,
    /// Whether STARTUPINFOEX was used (detected via ETW or API monitoring)
    pub used_startupinfoex: bool,
    /// Whether PROC_THREAD_ATTRIBUTE_PARENT_PROCESS was used
    pub used_parent_process_attribute: bool,
    /// Process creation time from kernel (used for timeline validation)
    pub kernel_create_time: Option<u64>,
    /// Session ID of the process
    pub session_id: Option<u32>,
    /// Integrity level (if available)
    pub integrity_level: Option<String>,
}

// ============================================================================
// Timeline-based detection structures
// ============================================================================

/// Process timeline entry for historical tracking
#[derive(Debug, Clone)]
pub struct ProcessTimelineEntry {
    /// Process ID
    pub pid: u32,
    /// Process name
    pub name: String,
    /// Full path
    pub path: String,
    /// Creation time (Unix ms from kernel)
    pub create_time: u64,
    /// Termination time (Unix ms, 0 if still running)
    pub exit_time: u64,
    /// Parent PID at creation
    pub ppid: u32,
    /// Session ID
    pub session_id: u32,
    /// Whether this process is known to be a system process
    pub is_system_process: bool,
    /// When this entry was last validated
    pub last_validated: Instant,
}

impl ProcessTimelineEntry {
    /// Check if this process was running at a given time
    pub fn was_running_at(&self, timestamp_ms: u64) -> bool {
        if timestamp_ms < self.create_time {
            return false;
        }
        if self.exit_time == 0 {
            return true; // Still running
        }
        timestamp_ms <= self.exit_time
    }

    /// Check if this process is currently running
    pub fn is_running(&self) -> bool {
        self.exit_time == 0
    }
}

/// Timeline-based process tracker for validating parent-child relationships
#[derive(Debug)]
pub struct ProcessTimelineTracker {
    /// Map of PID -> Timeline entries (multiple entries possible for PID reuse)
    timeline: HashMap<u32, VecDeque<ProcessTimelineEntry>>,
    /// Maximum entries per PID (for PID reuse tracking)
    max_entries_per_pid: usize,
    /// Maximum total entries
    max_total_entries: usize,
    /// Current total entries
    total_entries: usize,
    /// Known terminated PIDs for orphan detection
    terminated_pids: HashSet<u32>,
    /// Last cleanup time
    last_cleanup: Instant,
    /// Cleanup interval
    cleanup_interval: Duration,
}

impl Default for ProcessTimelineTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessTimelineTracker {
    /// Create a new timeline tracker
    pub fn new() -> Self {
        Self {
            timeline: HashMap::with_capacity(5000),
            max_entries_per_pid: 5,
            max_total_entries: 50000,
            total_entries: 0,
            terminated_pids: HashSet::with_capacity(1000),
            last_cleanup: Instant::now(),
            cleanup_interval: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Record a process start
    pub fn record_start(&mut self, entry: ProcessTimelineEntry) {
        self.maybe_cleanup();

        let pid = entry.pid;
        self.terminated_pids.remove(&pid);

        let entries = self.timeline.entry(pid).or_insert_with(VecDeque::new);

        // Evict old entries if needed
        while entries.len() >= self.max_entries_per_pid {
            entries.pop_front();
            self.total_entries = self.total_entries.saturating_sub(1);
        }

        entries.push_back(entry);
        self.total_entries += 1;
    }

    /// Record a process termination
    pub fn record_exit(&mut self, pid: u32, exit_time: u64) {
        if let Some(entries) = self.timeline.get_mut(&pid) {
            if let Some(entry) = entries.back_mut() {
                if entry.exit_time == 0 {
                    entry.exit_time = exit_time;
                }
            }
        }
        self.terminated_pids.insert(pid);
    }

    /// Validate that a claimed parent was running when the child was created
    ///
    /// Returns Ok(()) if valid, Err(reason) if invalid
    pub fn validate_parent_timeline(
        &self,
        child_pid: u32,
        child_create_time: u64,
        claimed_ppid: u32,
    ) -> Result<(), TimelineValidationError> {
        // System processes (PID 0, 4) are always valid parents
        if claimed_ppid == 0 || claimed_ppid == 4 {
            return Ok(());
        }

        // Check if claimed parent exists in timeline
        let entries = self
            .timeline
            .get(&claimed_ppid)
            .ok_or(TimelineValidationError::ParentNotInTimeline)?;

        // Find the entry that was active at child_create_time
        for entry in entries.iter().rev() {
            if entry.was_running_at(child_create_time) {
                return Ok(());
            }
        }

        // Check if parent terminated before child was created
        if let Some(last_entry) = entries.back() {
            if last_entry.exit_time > 0 && last_entry.exit_time < child_create_time {
                return Err(TimelineValidationError::ParentTerminatedBeforeChild {
                    parent_exit_time: last_entry.exit_time,
                    child_create_time,
                });
            }
            if last_entry.create_time > child_create_time {
                return Err(TimelineValidationError::ParentCreatedAfterChild {
                    parent_create_time: last_entry.create_time,
                    child_create_time,
                });
            }
        }

        Err(TimelineValidationError::ParentNotRunningAtTime)
    }

    /// Check if a PID is known to be terminated
    pub fn is_terminated(&self, pid: u32) -> bool {
        self.terminated_pids.contains(&pid)
    }

    /// Get the current entry for a PID (if running)
    pub fn get_current(&self, pid: u32) -> Option<&ProcessTimelineEntry> {
        self.timeline
            .get(&pid)
            .and_then(|entries| entries.back())
            .filter(|e| e.is_running())
    }

    /// Get the most recent entry for a PID
    pub fn get_latest(&self, pid: u32) -> Option<&ProcessTimelineEntry> {
        self.timeline.get(&pid).and_then(|entries| entries.back())
    }

    /// Clean up old entries
    fn maybe_cleanup(&mut self) {
        if self.last_cleanup.elapsed() < self.cleanup_interval {
            return;
        }

        self.last_cleanup = Instant::now();
        let cutoff = Instant::now() - Duration::from_secs(3600); // 1 hour

        // Remove very old terminated entries
        self.timeline.retain(|_, entries| {
            entries.retain(|e| {
                if e.exit_time > 0 {
                    // Keep terminated entries for 1 hour
                    e.last_validated > cutoff
                } else {
                    true // Keep running entries
                }
            });
            !entries.is_empty()
        });

        // Clean up terminated PID set
        self.terminated_pids
            .retain(|pid| self.timeline.contains_key(pid));

        // Recount entries
        self.total_entries = self.timeline.values().map(|v| v.len()).sum();

        debug!(
            total_entries = self.total_entries,
            tracked_pids = self.timeline.len(),
            terminated_pids = self.terminated_pids.len(),
            "Process timeline cleanup completed"
        );
    }
}

/// Timeline validation errors
#[derive(Debug, Clone)]
pub enum TimelineValidationError {
    /// Parent process not found in timeline
    ParentNotInTimeline,
    /// Parent terminated before child was created
    ParentTerminatedBeforeChild {
        parent_exit_time: u64,
        child_create_time: u64,
    },
    /// Parent was created after child (impossible without spoofing or PID reuse)
    ParentCreatedAfterChild {
        parent_create_time: u64,
        child_create_time: u64,
    },
    /// Parent was not running at the time child was created
    ParentNotRunningAtTime,
}

impl std::fmt::Display for TimelineValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParentNotInTimeline => {
                write!(
                    f,
                    "Parent process not found in timeline (may indicate spoofing)"
                )
            }
            Self::ParentTerminatedBeforeChild {
                parent_exit_time,
                child_create_time,
            } => {
                write!(
                    f,
                    "Parent terminated ({}) before child was created ({})",
                    parent_exit_time, child_create_time
                )
            }
            Self::ParentCreatedAfterChild {
                parent_create_time,
                child_create_time,
            } => {
                write!(
                    f,
                    "Parent created ({}) after child ({})",
                    parent_create_time, child_create_time
                )
            }
            Self::ParentNotRunningAtTime => {
                write!(f, "Parent was not running when child was created")
            }
        }
    }
}

// ============================================================================
// Handle inheritance anomaly detection
// ============================================================================

/// Tracks handle inheritance patterns for anomaly detection
#[derive(Debug)]
pub struct HandleInheritanceTracker {
    /// Recent process creations with handle counts: PID -> (handle_count, timestamp)
    recent_creations: HashMap<u32, (u32, Instant)>,
    /// Cross-process handle operations: (source_pid, target_pid) -> count
    cross_process_handles: HashMap<(u32, u32), u32>,
    /// Maximum entries
    max_entries: usize,
}

impl Default for HandleInheritanceTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl HandleInheritanceTracker {
    pub fn new() -> Self {
        Self {
            recent_creations: HashMap::with_capacity(2000),
            cross_process_handles: HashMap::with_capacity(5000),
            max_entries: 10000,
        }
    }

    /// Record a handle duplication to a target process
    pub fn record_handle_dup(&mut self, source_pid: u32, target_pid: u32) {
        // Cleanup if needed
        if self.cross_process_handles.len() >= self.max_entries {
            let cutoff = Instant::now() - Duration::from_secs(60);
            self.recent_creations.retain(|_, (_, ts)| *ts > cutoff);
            self.cross_process_handles.clear();
        }

        *self
            .cross_process_handles
            .entry((source_pid, target_pid))
            .or_insert(0) += 1;
    }

    /// Record process creation with initial handle count
    pub fn record_creation(&mut self, pid: u32, handle_count: u32) {
        self.recent_creations
            .insert(pid, (handle_count, Instant::now()));
    }

    /// Check for handle inheritance anomalies
    ///
    /// Returns Some(anomaly_description) if anomalies detected
    pub fn check_anomalies(
        &self,
        child_pid: u32,
        declared_ppid: u32,
        actual_creator: u32,
    ) -> Option<String> {
        let mut anomalies = Vec::new();

        // Check if there were recent cross-process handle operations
        // from actual_creator to declared_ppid (setting up spoofing)
        if let Some(&count) = self
            .cross_process_handles
            .get(&(actual_creator, declared_ppid))
        {
            if count > 0 {
                anomalies.push(format!(
                    "Cross-process handle from actual creator {} to declared parent {}",
                    actual_creator, declared_ppid
                ));
            }
        }

        // Check if declared parent has unusually many handles to child
        // (would indicate the parent handle was duplicated for spoofing)
        let handle_key = (declared_ppid, child_pid);
        if let Some(&count) = self.cross_process_handles.get(&handle_key) {
            if count > 2 {
                anomalies.push(format!(
                    "Unusual number of handles ({}) from declared parent {} to child {}",
                    count, declared_ppid, child_pid
                ));
            }
        }

        if anomalies.is_empty() {
            None
        } else {
            Some(anomalies.join("; "))
        }
    }
}

/// Detection method used to identify PPID spoofing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpoofingDetectionMethod {
    /// NtQueryInformationProcess - InheritedFromUniqueProcessId comparison
    NtQueryInformationProcess,
    /// ETW process creation event correlation
    EtwProcessCreation,
    /// STARTUPINFOEX / UpdateProcThreadAttribute API usage detection
    StartupInfoExUsage,
    /// Handle table enumeration showing cross-process handle to parent
    HandleEnumeration,
    /// Thread creation attribute analysis
    ThreadAttributeAnalysis,
}

impl std::fmt::Display for SpoofingDetectionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NtQueryInformationProcess => write!(f, "NtQueryInformationProcess"),
            Self::EtwProcessCreation => write!(f, "ETW_ProcessCreation"),
            Self::StartupInfoExUsage => write!(f, "STARTUPINFOEX_Usage"),
            Self::HandleEnumeration => write!(f, "HandleEnumeration"),
            Self::ThreadAttributeAnalysis => write!(f, "ThreadAttributeAnalysis"),
        }
    }
}

/// Tracks STARTUPINFOEX usage patterns for detection
#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
pub struct StartupInfoExTracker {
    /// Map of PID -> timestamp when UpdateProcThreadAttribute was called
    api_calls: HashMap<u32, Vec<ApiCallRecord>>,
    /// Maximum entries before cleanup
    max_entries: usize,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
struct ApiCallRecord {
    timestamp: Instant,
    attribute_type: u32,
    target_pid: Option<u32>,
}

#[cfg(target_os = "windows")]
impl Default for StartupInfoExTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "windows")]
impl StartupInfoExTracker {
    /// PROC_THREAD_ATTRIBUTE_PARENT_PROCESS value
    const PROC_THREAD_ATTRIBUTE_PARENT_PROCESS: u32 = 0x00020000;

    pub fn new() -> Self {
        Self {
            api_calls: HashMap::new(),
            max_entries: 5000,
        }
    }

    /// Record an UpdateProcThreadAttribute call
    pub fn record_attribute_update(
        &mut self,
        caller_pid: u32,
        attribute: u32,
        target_pid: Option<u32>,
    ) {
        // Cleanup old entries
        if self.api_calls.len() >= self.max_entries {
            let cutoff = Instant::now() - Duration::from_secs(60);
            self.api_calls.retain(|_, records| {
                records.retain(|r| r.timestamp > cutoff);
                !records.is_empty()
            });
        }

        let record = ApiCallRecord {
            timestamp: Instant::now(),
            attribute_type: attribute,
            target_pid,
        };

        self.api_calls.entry(caller_pid).or_default().push(record);

        if attribute == Self::PROC_THREAD_ATTRIBUTE_PARENT_PROCESS {
            trace!(
                caller_pid = caller_pid,
                target_pid = ?target_pid,
                "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS usage detected"
            );
        }
    }

    /// Check if a process recently used PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
    pub fn check_parent_process_attribute(&self, pid: u32) -> Option<u32> {
        let records = self.api_calls.get(&pid)?;
        let cutoff = Instant::now() - Duration::from_secs(5);

        for record in records.iter().rev() {
            if record.timestamp > cutoff
                && record.attribute_type == Self::PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
            {
                return record.target_pid;
            }
        }
        None
    }

    /// Check if a process used STARTUPINFOEX recently
    pub fn was_startupinfoex_used(&self, pid: u32) -> bool {
        self.api_calls.get(&pid).map_or(false, |records| {
            let cutoff = Instant::now() - Duration::from_secs(5);
            records.iter().any(|r| r.timestamp > cutoff)
        })
    }
}

/// PPID spoofing detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PpidSpoofingEvent {
    /// Process ID of the spoofed process
    pub pid: u32,
    /// Declared parent PID (the spoofed PPID)
    pub declared_ppid: u32,
    /// Actual creator PID (true parent)
    pub actual_creator_pid: u32,
    /// Name of the created process
    pub process_name: String,
    /// Path of the created process
    pub process_path: String,
    /// Command line of the created process
    pub cmdline: String,
    /// Name of the declared (spoofed) parent
    pub declared_parent_name: Option<String>,
    /// Name of the actual creator process
    pub actual_creator_name: Option<String>,
    /// User context
    pub user: String,
    /// Spoofing confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// Detection method used
    pub detection_method: String,
    /// Additional context/details
    pub details: String,
    /// Whether STARTUPINFOEX was detected
    pub startupinfoex_detected: bool,
    /// Whether PROC_THREAD_ATTRIBUTE_PARENT_PROCESS was used
    pub parent_process_attribute_used: bool,
    /// MITRE ATT&CK technique ID
    pub mitre_technique: String,
    /// Path of the declared parent process (if available)
    pub declared_parent_path: Option<String>,
    /// Path of the actual creator process (if available)
    pub actual_creator_path: Option<String>,
}

/// PPID Spoofing detector state
pub struct PpidSpoofingDetector {
    /// Map of PID -> ProcessCreationInfo for tracking
    process_creation_map: Arc<RwLock<HashMap<u32, ProcessCreationInfo>>>,
    /// Known legitimate parent-child relationships (whitelist)
    /// Format: (parent_name_lowercase, child_name_lowercase)
    legitimate_relationships: Vec<(String, String)>,
    /// Maximum entries in the process map (LRU eviction)
    max_entries: usize,
    /// Tracks STARTUPINFOEX/UpdateProcThreadAttribute usage (Windows only)
    #[cfg(target_os = "windows")]
    startupinfoex_tracker: Arc<RwLock<StartupInfoExTracker>>,
    /// Known LOLBins that are commonly spoofed into
    high_value_parents: Vec<String>,
    /// Suspicious child processes often created via PPID spoofing
    suspicious_children: Vec<String>,
    /// Timeline tracker for validating parent existence at child creation time
    timeline_tracker: Arc<RwLock<ProcessTimelineTracker>>,
    /// Handle inheritance anomaly tracker
    handle_tracker: Arc<RwLock<HandleInheritanceTracker>>,
    /// Impossible parent-child relationships (process tree anomalies)
    impossible_parents: Vec<(String, String)>,
    /// Known system process PIDs (populated at startup)
    system_process_pids: Arc<RwLock<HashMap<String, u32>>>,
}

impl Default for PpidSpoofingDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PpidSpoofingDetector {
    /// Create a new PPID spoofing detector
    pub fn new() -> Self {
        Self {
            process_creation_map: Arc::new(RwLock::new(HashMap::new())),
            legitimate_relationships: Self::build_legitimate_relationships(),
            max_entries: 10000,
            #[cfg(target_os = "windows")]
            startupinfoex_tracker: Arc::new(RwLock::new(StartupInfoExTracker::new())),
            high_value_parents: Self::build_high_value_parents(),
            suspicious_children: Self::build_suspicious_children(),
            timeline_tracker: Arc::new(RwLock::new(ProcessTimelineTracker::new())),
            handle_tracker: Arc::new(RwLock::new(HandleInheritanceTracker::new())),
            impossible_parents: Self::build_impossible_parents(),
            system_process_pids: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Build list of impossible parent-child relationships
    /// These relationships are impossible in a normal Windows system
    fn build_impossible_parents() -> Vec<(String, String)> {
        vec![
            // No process can have lsass as parent except wininit
            ("lsass.exe".to_string(), "cmd.exe".to_string()),
            ("lsass.exe".to_string(), "powershell.exe".to_string()),
            ("lsass.exe".to_string(), "pwsh.exe".to_string()),
            // csrss.exe cannot spawn user processes
            ("csrss.exe".to_string(), "cmd.exe".to_string()),
            ("csrss.exe".to_string(), "powershell.exe".to_string()),
            // smss.exe only creates csrss, wininit, winlogon
            ("smss.exe".to_string(), "cmd.exe".to_string()),
            ("smss.exe".to_string(), "powershell.exe".to_string()),
            ("smss.exe".to_string(), "explorer.exe".to_string()),
            // System (PID 4) cannot spawn user-mode processes
            ("system".to_string(), "cmd.exe".to_string()),
            ("system".to_string(), "powershell.exe".to_string()),
            ("system".to_string(), "explorer.exe".to_string()),
            // SearchIndexer should not spawn shells
            ("searchindexer.exe".to_string(), "cmd.exe".to_string()),
            (
                "searchindexer.exe".to_string(),
                "powershell.exe".to_string(),
            ),
            // Spooler service should not spawn shells directly
            ("spoolsv.exe".to_string(), "cmd.exe".to_string()),
            ("spoolsv.exe".to_string(), "powershell.exe".to_string()),
        ]
    }

    /// Check if a parent-child relationship is impossible
    pub fn is_impossible_relationship(&self, parent_name: &str, child_name: &str) -> bool {
        let parent_lower = parent_name.to_lowercase();
        let child_lower = child_name.to_lowercase();

        self.impossible_parents
            .iter()
            .any(|(p, c)| parent_lower.ends_with(p) && child_lower.ends_with(c))
    }

    /// Record a process in the timeline tracker
    pub fn record_timeline_entry(&self, entry: ProcessTimelineEntry) {
        if let Ok(mut tracker) = self.timeline_tracker.write() {
            tracker.record_start(entry);
        }
    }

    /// Record a process termination in the timeline
    pub fn record_process_exit(&self, pid: u32) {
        let exit_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        if let Ok(mut tracker) = self.timeline_tracker.write() {
            tracker.record_exit(pid, exit_time);
        }
    }

    /// Record a handle duplication event
    pub fn record_handle_dup(&self, source_pid: u32, target_pid: u32) {
        if let Ok(mut tracker) = self.handle_tracker.write() {
            tracker.record_handle_dup(source_pid, target_pid);
        }
    }

    /// Validate parent timeline - checks if claimed parent was running when child started
    pub fn validate_parent_timeline(
        &self,
        child_pid: u32,
        child_create_time: u64,
        claimed_ppid: u32,
    ) -> Result<(), TimelineValidationError> {
        if let Ok(tracker) = self.timeline_tracker.read() {
            tracker.validate_parent_timeline(child_pid, child_create_time, claimed_ppid)
        } else {
            Err(TimelineValidationError::ParentNotInTimeline)
        }
    }

    /// Check for handle inheritance anomalies
    pub fn check_handle_anomalies(
        &self,
        child_pid: u32,
        declared_ppid: u32,
        actual_creator: u32,
    ) -> Option<String> {
        if let Ok(tracker) = self.handle_tracker.read() {
            tracker.check_anomalies(child_pid, declared_ppid, actual_creator)
        } else {
            None
        }
    }

    /// Check if claimed parent is a terminated process (orphan detection)
    pub fn is_orphan_process(&self, claimed_ppid: u32) -> bool {
        if let Ok(tracker) = self.timeline_tracker.read() {
            tracker.is_terminated(claimed_ppid)
        } else {
            false
        }
    }

    /// Update system process PID cache
    #[cfg(target_os = "windows")]
    pub fn update_system_process_pids(&self) {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        let system_processes = [
            "System",
            "smss.exe",
            "csrss.exe",
            "wininit.exe",
            "services.exe",
            "lsass.exe",
            "winlogon.exe",
            "explorer.exe",
            "svchost.exe",
        ];

        if let Ok(mut pids) = self.system_process_pids.write() {
            pids.clear();

            unsafe {
                let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                    Ok(h) => h,
                    Err(_) => return,
                };

                let mut entry = PROCESSENTRY32W {
                    dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                    ..std::mem::zeroed()
                };

                if Process32FirstW(snapshot, &mut entry).is_ok() {
                    loop {
                        let name_len = entry
                            .szExeFile
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(entry.szExeFile.len());
                        let name = String::from_utf16_lossy(&entry.szExeFile[..name_len]);

                        if system_processes
                            .iter()
                            .any(|&sp| name.eq_ignore_ascii_case(sp))
                        {
                            pids.insert(name.to_lowercase(), entry.th32ProcessID);
                        }

                        if Process32NextW(snapshot, &mut entry).is_err() {
                            break;
                        }
                    }
                }

                let _ = CloseHandle(snapshot);
            }
        }
    }

    /// Check if a PID is a known system process
    pub fn is_system_process_pid(&self, pid: u32) -> bool {
        if pid == 0 || pid == 4 {
            return true;
        }
        if let Ok(pids) = self.system_process_pids.read() {
            pids.values().any(|&p| p == pid)
        } else {
            false
        }
    }

    /// Build list of known legitimate parent-child relationships
    /// These are processes that commonly spawn other processes legitimately
    fn build_legitimate_relationships() -> Vec<(String, String)> {
        vec![
            // Windows system processes
            ("services.exe".to_string(), "svchost.exe".to_string()),
            ("services.exe".to_string(), "msiexec.exe".to_string()),
            ("smss.exe".to_string(), "csrss.exe".to_string()),
            ("smss.exe".to_string(), "wininit.exe".to_string()),
            ("smss.exe".to_string(), "winlogon.exe".to_string()),
            ("wininit.exe".to_string(), "services.exe".to_string()),
            ("wininit.exe".to_string(), "lsass.exe".to_string()),
            ("winlogon.exe".to_string(), "userinit.exe".to_string()),
            ("userinit.exe".to_string(), "explorer.exe".to_string()),
            // Task Scheduler
            ("svchost.exe".to_string(), "taskhostw.exe".to_string()),
            ("svchost.exe".to_string(), "taskeng.exe".to_string()),
            // WMI
            ("wmiprvse.exe".to_string(), "cmd.exe".to_string()),
            ("wmiprvse.exe".to_string(), "powershell.exe".to_string()),
            ("wmiprvse.exe".to_string(), "pwsh.exe".to_string()),
            // Common admin tools
            ("explorer.exe".to_string(), "cmd.exe".to_string()),
            ("explorer.exe".to_string(), "powershell.exe".to_string()),
            ("explorer.exe".to_string(), "pwsh.exe".to_string()),
            // Windows Terminal
            ("windowsterminal.exe".to_string(), "cmd.exe".to_string()),
            (
                "windowsterminal.exe".to_string(),
                "powershell.exe".to_string(),
            ),
            ("windowsterminal.exe".to_string(), "pwsh.exe".to_string()),
            // VSCode
            ("code.exe".to_string(), "cmd.exe".to_string()),
            ("code.exe".to_string(), "powershell.exe".to_string()),
        ]
    }

    /// Build list of high-value parent processes commonly spoofed into
    fn build_high_value_parents() -> Vec<String> {
        vec![
            "svchost.exe".to_string(),
            "services.exe".to_string(),
            "lsass.exe".to_string(),
            "explorer.exe".to_string(),
            "winlogon.exe".to_string(),
            "csrss.exe".to_string(),
            "wininit.exe".to_string(),
            "smss.exe".to_string(),
            "RuntimeBroker.exe".to_string(),
            "sihost.exe".to_string(),
            "taskhostw.exe".to_string(),
            "dllhost.exe".to_string(),
            "conhost.exe".to_string(),
            "searchindexer.exe".to_string(),
            "spoolsv.exe".to_string(),
        ]
    }

    /// Build list of suspicious child processes often spawned via PPID spoofing
    fn build_suspicious_children() -> Vec<String> {
        vec![
            "cmd.exe".to_string(),
            "powershell.exe".to_string(),
            "pwsh.exe".to_string(),
            "wscript.exe".to_string(),
            "cscript.exe".to_string(),
            "mshta.exe".to_string(),
            "rundll32.exe".to_string(),
            "regsvr32.exe".to_string(),
            "certutil.exe".to_string(),
            "bitsadmin.exe".to_string(),
            "msbuild.exe".to_string(),
            "installutil.exe".to_string(),
            "regasm.exe".to_string(),
            "regsvcs.exe".to_string(),
            "cmstp.exe".to_string(),
            "msiexec.exe".to_string(),
            "control.exe".to_string(),
            "wmic.exe".to_string(),
            "net.exe".to_string(),
            "net1.exe".to_string(),
        ]
    }

    /// Check if a process name is a high-value spoofing target
    fn is_high_value_parent(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();
        self.high_value_parents
            .iter()
            .any(|p| name_lower.ends_with(p))
    }

    /// Check if a process name is a suspicious child
    fn is_suspicious_child(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();
        self.suspicious_children
            .iter()
            .any(|c| name_lower.ends_with(c))
    }

    /// Record a STARTUPINFOEX/UpdateProcThreadAttribute API call (Windows only)
    #[cfg(target_os = "windows")]
    pub fn record_attribute_update(
        &self,
        caller_pid: u32,
        attribute: u32,
        target_pid: Option<u32>,
    ) {
        if let Ok(mut tracker) = self.startupinfoex_tracker.write() {
            tracker.record_attribute_update(caller_pid, attribute, target_pid);
        }
    }

    /// Check if a process used STARTUPINFOEX recently (Windows only)
    #[cfg(target_os = "windows")]
    pub fn check_startupinfoex_usage(&self, pid: u32) -> (bool, Option<u32>) {
        if let Ok(tracker) = self.startupinfoex_tracker.read() {
            let used = tracker.was_startupinfoex_used(pid);
            let target = tracker.check_parent_process_attribute(pid);
            (used, target)
        } else {
            (false, None)
        }
    }

    /// Check if the declared PPID differs from the actual creator PID
    /// Returns true if spoofing is detected
    pub fn check_ppid_mismatch(&self, pid: u32, declared_ppid: u32, actual_creator: u32) -> bool {
        // If declared PPID matches actual creator, no spoofing
        if declared_ppid == actual_creator {
            return false;
        }

        // If declared PPID is 0 (System), could be legitimate for some processes
        if declared_ppid == 0 || declared_ppid == 4 {
            return false;
        }

        // If actual creator is the same process (self-spawn edge case), no spoofing
        if actual_creator == pid {
            return false;
        }

        // PPID mismatch detected
        true
    }

    /// Record a process creation event
    pub fn record_creation(&self, info: ProcessCreationInfo) {
        if let Ok(mut map) = self.process_creation_map.write() {
            // LRU eviction if map is too large
            if map.len() >= self.max_entries {
                // Remove oldest 10% of entries
                let to_remove: Vec<u32> = map
                    .iter()
                    .take(self.max_entries / 10)
                    .map(|(k, _)| *k)
                    .collect();
                for pid in to_remove {
                    map.remove(&pid);
                }
            }
            map.insert(info.pid, info);
        }
    }

    /// Get cached process info by PID
    pub fn get_process_info(&self, pid: u32) -> Option<ProcessCreationInfo> {
        if let Ok(map) = self.process_creation_map.read() {
            map.get(&pid).cloned()
        } else {
            None
        }
    }

    /// Check if a parent-child relationship is known to be legitimate
    fn is_legitimate_relationship(&self, parent_name: &str, child_name: &str) -> bool {
        let parent_lower = parent_name.to_lowercase();
        let child_lower = child_name.to_lowercase();

        self.legitimate_relationships
            .iter()
            .any(|(p, c)| parent_lower.ends_with(p) && child_lower.ends_with(c))
    }

    /// Analyze a process creation for PPID spoofing
    /// Returns Some(PpidSpoofingEvent) if spoofing is detected
    pub fn analyze(
        &self,
        pid: u32,
        declared_ppid: u32,
        actual_creator_pid: u32,
        process_name: &str,
        process_path: &str,
        cmdline: &str,
        user: &str,
        declared_parent_name: Option<&str>,
        actual_creator_name: Option<&str>,
    ) -> Option<PpidSpoofingEvent> {
        // Check for mismatch
        if !self.check_ppid_mismatch(pid, declared_ppid, actual_creator_pid) {
            return None;
        }

        // Calculate confidence based on various factors
        let mut confidence: f32 = 0.8; // Base confidence for any mismatch
        let mut details = Vec::new();

        // High-value targets being spoofed into increase confidence
        if let Some(parent) = declared_parent_name {
            let parent_lower = parent.to_lowercase();
            if parent_lower.contains("svchost")
                || parent_lower.contains("services")
                || parent_lower.contains("explorer")
                || parent_lower.contains("lsass")
                || parent_lower.contains("winlogon")
            {
                confidence += 0.1;
                details.push(format!("Spoofed into privileged parent: {}", parent));
            }
        }

        // Suspicious child processes increase confidence
        let process_lower = process_name.to_lowercase();
        if process_lower.contains("cmd.exe")
            || process_lower.contains("powershell")
            || process_lower.contains("pwsh")
            || process_lower.contains("wscript")
            || process_lower.contains("cscript")
            || process_lower.contains("mshta")
            || process_lower.contains("rundll32")
            || process_lower.contains("regsvr32")
        {
            confidence += 0.05;
            details.push(format!("Suspicious child process: {}", process_name));
        }

        // Check for known legitimate relationships (reduce confidence)
        if let (Some(declared), Some(_actual)) = (declared_parent_name, actual_creator_name) {
            if self.is_legitimate_relationship(declared, process_name) {
                confidence -= 0.3;
                details.push("Matches legitimate parent-child pattern".to_string());
            }
        }

        // Command line indicators
        let cmdline_lower = cmdline.to_lowercase();
        if cmdline_lower.contains("-enc")
            || cmdline_lower.contains("-encodedcommand")
            || cmdline_lower.contains("frombase64")
            || cmdline_lower.contains("iex")
            || cmdline_lower.contains("invoke-expression")
            || cmdline_lower.contains("downloadstring")
        {
            confidence += 0.05;
            details.push("Suspicious command line patterns".to_string());
        }

        // Cap confidence at 1.0
        confidence = confidence.min(1.0).max(0.0);

        // Only report if confidence is above threshold
        if confidence < 0.5 {
            debug!(
                pid = pid,
                declared_ppid = declared_ppid,
                actual_creator = actual_creator_pid,
                confidence = confidence,
                "PPID mismatch below confidence threshold, not reporting"
            );
            return None;
        }

        let detail_str = if details.is_empty() {
            format!(
                "PPID spoofing detected: declared parent {} (PID {}) differs from actual creator PID {}",
                declared_parent_name.unwrap_or("unknown"),
                declared_ppid,
                actual_creator_pid
            )
        } else {
            details.join("; ")
        };

        Some(PpidSpoofingEvent {
            pid,
            declared_ppid,
            actual_creator_pid,
            process_name: process_name.to_string(),
            process_path: process_path.to_string(),
            cmdline: cmdline.to_string(),
            declared_parent_name: declared_parent_name.map(String::from),
            actual_creator_name: actual_creator_name.map(String::from),
            user: user.to_string(),
            confidence,
            detection_method: SpoofingDetectionMethod::NtQueryInformationProcess.to_string(),
            details: detail_str,
            startupinfoex_detected: false,
            parent_process_attribute_used: false,
            mitre_technique: "T1134.004".to_string(),
            declared_parent_path: None,
            actual_creator_path: None,
        })
    }

    /// Enhanced analysis with STARTUPINFOEX detection (Windows only)
    /// Returns Some(PpidSpoofingEvent) if spoofing is detected
    #[cfg(target_os = "windows")]
    pub fn analyze_with_api_tracking(
        &self,
        pid: u32,
        declared_ppid: u32,
        actual_creator_pid: u32,
        process_name: &str,
        process_path: &str,
        cmdline: &str,
        user: &str,
        declared_parent_name: Option<&str>,
        actual_creator_name: Option<&str>,
        declared_parent_path: Option<&str>,
        actual_creator_path: Option<&str>,
    ) -> Option<PpidSpoofingEvent> {
        // Check for mismatch
        if !self.check_ppid_mismatch(pid, declared_ppid, actual_creator_pid) {
            return None;
        }

        // Check for STARTUPINFOEX usage
        let (startupinfoex_used, parent_attrib_target) =
            self.check_startupinfoex_usage(actual_creator_pid);

        // Calculate confidence based on various factors
        let mut confidence: f32 = 0.8; // Base confidence for any mismatch
        let mut details = Vec::new();
        let mut detection_method = SpoofingDetectionMethod::NtQueryInformationProcess;

        // STARTUPINFOEX usage significantly increases confidence
        if startupinfoex_used {
            confidence += 0.15;
            detection_method = SpoofingDetectionMethod::StartupInfoExUsage;
            details.push("STARTUPINFOEX usage detected".to_string());
        }

        // PROC_THREAD_ATTRIBUTE_PARENT_PROCESS is a strong indicator
        let parent_attrib_used = parent_attrib_target.is_some();
        if parent_attrib_used {
            confidence += 0.1;
            detection_method = SpoofingDetectionMethod::StartupInfoExUsage;
            if let Some(target) = parent_attrib_target {
                details.push(format!(
                    "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS used (target PID: {})",
                    target
                ));
            }
        }

        // High-value targets being spoofed into increase confidence
        if let Some(parent) = declared_parent_name {
            if self.is_high_value_parent(parent) {
                confidence += 0.1;
                details.push(format!("Spoofed into high-value parent: {}", parent));
            }
        }

        // Suspicious child processes increase confidence
        if self.is_suspicious_child(process_name) {
            confidence += 0.05;
            details.push(format!("Suspicious child process: {}", process_name));
        }

        // Check for known legitimate relationships (reduce confidence)
        if let (Some(declared), Some(_actual)) = (declared_parent_name, actual_creator_name) {
            if self.is_legitimate_relationship(declared, process_name) {
                confidence -= 0.3;
                details.push("Matches legitimate parent-child pattern".to_string());
            }
        }

        // Command line indicators
        let cmdline_lower = cmdline.to_lowercase();
        if cmdline_lower.contains("-enc")
            || cmdline_lower.contains("-encodedcommand")
            || cmdline_lower.contains("frombase64")
            || cmdline_lower.contains("iex")
            || cmdline_lower.contains("invoke-expression")
            || cmdline_lower.contains("downloadstring")
            || cmdline_lower.contains("-windowstyle hidden")
            || cmdline_lower.contains("-nop")
            || cmdline_lower.contains("-ep bypass")
        {
            confidence += 0.05;
            details.push("Suspicious command line patterns".to_string());
        }

        // Cap confidence at 1.0
        confidence = confidence.min(1.0).max(0.0);

        // Only report if confidence is above threshold
        if confidence < 0.5 {
            debug!(
                pid = pid,
                declared_ppid = declared_ppid,
                actual_creator = actual_creator_pid,
                confidence = confidence,
                startupinfoex_used = startupinfoex_used,
                "PPID mismatch below confidence threshold, not reporting"
            );
            return None;
        }

        let detail_str = if details.is_empty() {
            format!(
                "PPID spoofing detected: declared parent {} (PID {}) differs from actual creator PID {}",
                declared_parent_name.unwrap_or("unknown"),
                declared_ppid,
                actual_creator_pid
            )
        } else {
            details.join("; ")
        };

        Some(PpidSpoofingEvent {
            pid,
            declared_ppid,
            actual_creator_pid,
            process_name: process_name.to_string(),
            process_path: process_path.to_string(),
            cmdline: cmdline.to_string(),
            declared_parent_name: declared_parent_name.map(String::from),
            actual_creator_name: actual_creator_name.map(String::from),
            user: user.to_string(),
            confidence,
            detection_method: detection_method.to_string(),
            details: detail_str,
            startupinfoex_detected: startupinfoex_used,
            parent_process_attribute_used: parent_attrib_used,
            mitre_technique: "T1134.004".to_string(),
            declared_parent_path: declared_parent_path.map(String::from),
            actual_creator_path: actual_creator_path.map(String::from),
        })
    }

    /// Comprehensive PPID spoofing analysis with all detection mechanisms
    ///
    /// This method combines multiple detection techniques:
    /// 1. PID mismatch detection (NtQueryInformationProcess)
    /// 2. STARTUPINFOEX/UpdateProcThreadAttribute tracking
    /// 3. Timeline validation (was parent running when child started?)
    /// 4. Handle inheritance anomaly detection
    /// 5. Impossible relationship detection (process tree anomalies)
    /// 6. Orphan process detection
    ///
    /// Returns Some(PpidSpoofingEvent) if spoofing is detected with confidence >= 0.5
    #[cfg(target_os = "windows")]
    pub fn analyze_comprehensive(
        &self,
        pid: u32,
        declared_ppid: u32,
        actual_creator_pid: u32,
        process_name: &str,
        process_path: &str,
        cmdline: &str,
        user: &str,
        declared_parent_name: Option<&str>,
        actual_creator_name: Option<&str>,
        declared_parent_path: Option<&str>,
        actual_creator_path: Option<&str>,
        child_create_time: Option<u64>,
    ) -> Option<PpidSpoofingEvent> {
        let mut confidence: f32 = 0.0;
        let mut details = Vec::new();
        let mut detection_method = SpoofingDetectionMethod::NtQueryInformationProcess;
        let mut startupinfoex_used = false;
        let mut parent_attrib_used = false;

        // =================================================================
        // 1. Basic PID mismatch detection
        // =================================================================
        let ppid_mismatch = self.check_ppid_mismatch(pid, declared_ppid, actual_creator_pid);
        if ppid_mismatch {
            confidence += 0.7;
            details.push(format!(
                "PPID mismatch: declared {} vs actual creator {}",
                declared_ppid, actual_creator_pid
            ));
        }

        // =================================================================
        // 2. STARTUPINFOEX / PROC_THREAD_ATTRIBUTE_PARENT_PROCESS detection
        // =================================================================
        let (si_used, parent_attrib_target) = self.check_startupinfoex_usage(actual_creator_pid);
        if si_used {
            confidence += 0.2;
            startupinfoex_used = true;
            detection_method = SpoofingDetectionMethod::StartupInfoExUsage;
            details.push("STARTUPINFOEX usage detected".to_string());
        }
        if let Some(target) = parent_attrib_target {
            confidence += 0.15;
            parent_attrib_used = true;
            details.push(format!(
                "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS used targeting PID {}",
                target
            ));
        }

        // =================================================================
        // 3. Timeline validation - was claimed parent running at child creation?
        // =================================================================
        if let Some(create_time) = child_create_time {
            match self.validate_parent_timeline(pid, create_time, declared_ppid) {
                Ok(()) => {
                    // Parent was running at child creation - slightly reduces suspicion
                    // (but doesn't eliminate it - spoofing can use running processes)
                }
                Err(TimelineValidationError::ParentTerminatedBeforeChild { .. }) => {
                    confidence += 0.3;
                    details.push(
                        "Timeline anomaly: declared parent terminated before child was created"
                            .to_string(),
                    );
                }
                Err(TimelineValidationError::ParentCreatedAfterChild { .. }) => {
                    confidence += 0.4;
                    details.push(
                        "Timeline anomaly: declared parent was created AFTER child (impossible)"
                            .to_string(),
                    );
                }
                Err(TimelineValidationError::ParentNotInTimeline) => {
                    // Not in timeline could mean we started tracking after the parent
                    // Less confident but still suspicious if combined with other indicators
                    if ppid_mismatch {
                        confidence += 0.1;
                        details.push("Parent not in timeline tracking".to_string());
                    }
                }
                Err(TimelineValidationError::ParentNotRunningAtTime) => {
                    confidence += 0.25;
                    details.push("Parent was not running when child was created".to_string());
                }
            }
        }

        // =================================================================
        // 4. Handle inheritance anomaly detection
        // =================================================================
        if let Some(handle_anomaly) =
            self.check_handle_anomalies(pid, declared_ppid, actual_creator_pid)
        {
            confidence += 0.15;
            detection_method = SpoofingDetectionMethod::HandleEnumeration;
            details.push(format!("Handle anomaly: {}", handle_anomaly));
        }

        // =================================================================
        // 5. Impossible parent-child relationship detection
        // =================================================================
        if let Some(parent_name) = declared_parent_name {
            if self.is_impossible_relationship(parent_name, process_name) {
                confidence += 0.35;
                details.push(format!(
                    "Impossible relationship: {} cannot spawn {}",
                    parent_name, process_name
                ));
            }
        }

        // =================================================================
        // 6. Orphan process detection (parent is terminated)
        // =================================================================
        if self.is_orphan_process(declared_ppid) && ppid_mismatch {
            confidence += 0.2;
            details.push("Orphan process: declared parent has terminated".to_string());
        }

        // =================================================================
        // 7. High-value target and suspicious child analysis
        // =================================================================
        if let Some(parent) = declared_parent_name {
            if self.is_high_value_parent(parent) {
                confidence += 0.1;
                details.push(format!("Spoofed into high-value parent: {}", parent));
            }
        }

        if self.is_suspicious_child(process_name) {
            confidence += 0.05;
            details.push(format!("Suspicious child process: {}", process_name));
        }

        // =================================================================
        // 8. Known legitimate relationship check (reduces confidence)
        // =================================================================
        if let (Some(declared), Some(_actual)) = (declared_parent_name, actual_creator_name) {
            if self.is_legitimate_relationship(declared, process_name) {
                confidence -= 0.25;
                details.push("Matches known legitimate parent-child pattern".to_string());
            }
        }

        // =================================================================
        // 9. Command line analysis for additional indicators
        // =================================================================
        let cmdline_lower = cmdline.to_lowercase();
        let suspicious_patterns = [
            ("-enc", "Encoded command"),
            ("-encodedcommand", "Encoded command"),
            ("frombase64", "Base64 decoding"),
            ("iex", "Invoke-Expression"),
            ("invoke-expression", "Invoke-Expression"),
            ("downloadstring", "Download execution"),
            ("-windowstyle hidden", "Hidden window"),
            ("-nop", "No profile"),
            ("-ep bypass", "ExecutionPolicy bypass"),
            ("-w hidden", "Hidden window shorthand"),
            ("bypass", "Bypass indicator"),
        ];

        for (pattern, desc) in suspicious_patterns.iter() {
            if cmdline_lower.contains(pattern) {
                confidence += 0.02;
                details.push(format!("Suspicious cmdline: {}", desc));
                break; // Only count once
            }
        }

        // Cap confidence
        confidence = confidence.clamp(0.0, 1.0);

        // =================================================================
        // Decision: Report if confidence is high enough OR if specific
        // high-confidence indicators are present
        // =================================================================
        let should_report =
            confidence >= 0.5 || parent_attrib_used || (ppid_mismatch && startupinfoex_used);

        if !should_report {
            trace!(
                pid = pid,
                declared_ppid = declared_ppid,
                actual_creator = actual_creator_pid,
                confidence = confidence,
                "PPID analysis below reporting threshold"
            );
            return None;
        }

        let detail_str = if details.is_empty() {
            format!(
                "PPID spoofing detected: declared parent {} (PID {}) differs from actual creator PID {}",
                declared_parent_name.unwrap_or("unknown"),
                declared_ppid,
                actual_creator_pid
            )
        } else {
            details.join("; ")
        };

        info!(
            pid = pid,
            declared_ppid = declared_ppid,
            actual_creator = actual_creator_pid,
            confidence = confidence,
            detection_method = %detection_method,
            startupinfoex = startupinfoex_used,
            parent_attrib = parent_attrib_used,
            "Comprehensive PPID spoofing analysis: detection triggered"
        );

        Some(PpidSpoofingEvent {
            pid,
            declared_ppid,
            actual_creator_pid,
            process_name: process_name.to_string(),
            process_path: process_path.to_string(),
            cmdline: cmdline.to_string(),
            declared_parent_name: declared_parent_name.map(String::from),
            actual_creator_name: actual_creator_name.map(String::from),
            user: user.to_string(),
            confidence,
            detection_method: detection_method.to_string(),
            details: detail_str,
            startupinfoex_detected: startupinfoex_used,
            parent_process_attribute_used: parent_attrib_used,
            mitre_technique: "T1134.004".to_string(),
            declared_parent_path: declared_parent_path.map(String::from),
            actual_creator_path: actual_creator_path.map(String::from),
        })
    }

    /// Get process creation time from kernel (Windows)
    #[cfg(target_os = "windows")]
    pub fn get_process_create_time(pid: u32) -> Option<u64> {
        use windows::Win32::Foundation::{CloseHandle, FILETIME};
        use windows::Win32::System::Threading::{
            GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;

            let mut creation_time: FILETIME = std::mem::zeroed();
            let mut exit_time: FILETIME = std::mem::zeroed();
            let mut kernel_time: FILETIME = std::mem::zeroed();
            let mut user_time: FILETIME = std::mem::zeroed();

            let result = GetProcessTimes(
                handle,
                &mut creation_time,
                &mut exit_time,
                &mut kernel_time,
                &mut user_time,
            );

            let _ = CloseHandle(handle);

            if result.is_ok() {
                // Convert FILETIME to Unix milliseconds
                // FILETIME is 100-nanosecond intervals since January 1, 1601
                // Unix epoch is January 1, 1970
                let ft_value = ((creation_time.dwHighDateTime as u64) << 32)
                    | (creation_time.dwLowDateTime as u64);
                // Difference between 1601 and 1970 in 100-nanosecond intervals
                const EPOCH_DIFF: u64 = 116444736000000000;
                if ft_value >= EPOCH_DIFF {
                    let unix_100ns = ft_value - EPOCH_DIFF;
                    Some(unix_100ns / 10000) // Convert to milliseconds
                } else {
                    None
                }
            } else {
                None
            }
        }
    }

    /// Generate an alert from a PPID spoofing event
    pub fn generate_alert(&self, event: &PpidSpoofingEvent) -> TelemetryEvent {
        let mut telemetry_event = TelemetryEvent::new(
            EventType::DefenseEvasion,
            if event.confidence >= 0.9 {
                Severity::Critical
            } else if event.confidence >= 0.7 {
                Severity::High
            } else {
                Severity::Medium
            },
            EventPayload::Generic(serde_json::json!({
                "event_type": "ppid_spoofing",
                "pid": event.pid,
                "declared_ppid": event.declared_ppid,
                "actual_creator_pid": event.actual_creator_pid,
                "process_name": event.process_name,
                "process_path": event.process_path,
                "cmdline": event.cmdline,
                "declared_parent_name": event.declared_parent_name,
                "actual_creator_name": event.actual_creator_name,
                "declared_parent_path": event.declared_parent_path,
                "actual_creator_path": event.actual_creator_path,
                "user": event.user,
                "confidence": event.confidence,
                "detection_method": event.detection_method,
                "details": event.details,
                "startupinfoex_detected": event.startupinfoex_detected,
                "parent_process_attribute_used": event.parent_process_attribute_used,
                "mitre_technique": event.mitre_technique,
            })),
        );

        // Add detection metadata
        telemetry_event.add_detection(Detection {
            detection_type: DetectionType::Behavioral,
            rule_name: "ppid_spoofing_t1134_004".to_string(),
            confidence: event.confidence,
            description: format!(
                "PPID Spoofing: {} (PID {}) claims parent {} (PID {}) but was created by {} (PID {})",
                event.process_name,
                event.pid,
                event.declared_parent_name.as_deref().unwrap_or("unknown"),
                event.declared_ppid,
                event.actual_creator_name.as_deref().unwrap_or("unknown"),
                event.actual_creator_pid
            ),
            mitre_tactics: vec![
                "defense-evasion".to_string(),
                "privilege-escalation".to_string(),
            ],
            mitre_techniques: vec!["T1134.004".to_string()],
        });

        // Add STARTUPINFOEX detection if applicable
        if event.startupinfoex_detected {
            telemetry_event.add_detection(Detection {
                detection_type: DetectionType::Behavioral,
                rule_name: "startupinfoex_ppid_spoofing".to_string(),
                confidence: event.confidence,
                description: "STARTUPINFOEX with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS detected"
                    .to_string(),
                mitre_tactics: vec!["defense-evasion".to_string()],
                mitre_techniques: vec!["T1134.004".to_string()],
            });
        }

        telemetry_event
    }
}

/// PPID Spoofing collector that integrates with the telemetry pipeline
pub struct PpidSpoofingCollector {
    event_rx: mpsc::Receiver<TelemetryEvent>,
    detector: Arc<PpidSpoofingDetector>,
}

impl PpidSpoofingCollector {
    /// Create a new PPID spoofing collector
    pub fn new(_config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(500);
        let detector = Arc::new(PpidSpoofingDetector::new());

        // Start the monitoring loop
        let detector_clone = Arc::clone(&detector);
        tokio::spawn(async move {
            Self::monitor_loop(tx, detector_clone).await;
        });

        Self {
            event_rx: rx,
            detector,
        }
    }

    /// Get a reference to the detector for external use
    pub fn detector(&self) -> Arc<PpidSpoofingDetector> {
        Arc::clone(&self.detector)
    }

    #[cfg(target_os = "windows")]
    async fn monitor_loop(tx: mpsc::Sender<TelemetryEvent>, detector: Arc<PpidSpoofingDetector>) {
        info!("PPID spoofing detector started (Windows) with comprehensive detection");

        // Initialize system process PID cache
        detector.update_system_process_pids();

        // Poll interval for checking new processes
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(2));

        // Track known PIDs to detect new processes
        let mut known_pids: std::collections::HashSet<u32> = std::collections::HashSet::new();

        // Counter for periodic maintenance
        let mut maintenance_counter: u32 = 0;

        loop {
            interval.tick().await;
            maintenance_counter += 1;

            // Use toolhelp32 to enumerate processes
            let current_pids = Self::enumerate_processes_windows();

            // Detect terminated processes and record their exit
            let terminated: Vec<u32> = known_pids
                .iter()
                .filter(|pid| !current_pids.contains(pid))
                .copied()
                .collect();

            for pid in terminated {
                detector.record_process_exit(pid);
                known_pids.remove(&pid);
            }

            // Check new processes
            for pid in current_pids.iter() {
                // Skip if we already know this process
                if known_pids.contains(pid) {
                    continue;
                }
                known_pids.insert(*pid);

                // Skip system processes
                if *pid == 0 || *pid == 4 {
                    continue;
                }

                // Open the process and check for PPID spoofing
                if let Some(event) = Self::check_process_windows(*pid, &detector) {
                    if tx.send(event).await.is_err() {
                        warn!("PPID spoofing event channel closed");
                        return;
                    }
                }
            }

            // Periodic maintenance: refresh system process PIDs every 5 minutes (150 * 2 seconds)
            if maintenance_counter >= 150 {
                maintenance_counter = 0;
                detector.update_system_process_pids();
                debug!("PPID spoofing detector: refreshed system process PID cache");
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn enumerate_processes_windows() -> std::collections::HashSet<u32> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        let mut pids = std::collections::HashSet::new();

        unsafe {
            let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(h) => h,
                Err(_) => return pids,
            };

            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..std::mem::zeroed()
            };

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    pids.insert(entry.th32ProcessID);
                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
        }

        pids
    }

    #[cfg(target_os = "windows")]
    fn check_process_windows(pid: u32, detector: &PpidSpoofingDetector) -> Option<TelemetryEvent> {
        use super::win_compat::ntapi::get_real_parent_pid;
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

        unsafe {
            // Open the target process
            let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(h) => h,
                Err(_) => return None,
            };

            // Get the real parent PID (InheritedFromUniqueProcessId)
            let real_ppid = get_real_parent_pid(handle.0 as *mut c_void);
            let _ = CloseHandle(handle);

            let real_ppid = match real_ppid {
                Some(ppid) => ppid,
                None => return None,
            };

            // Get the declared PPID from toolhelp
            let (declared_ppid, process_name, _) = Self::get_process_info_toolhelp(pid)?;

            // Get additional process info
            let declared_parent_info = Self::get_process_info_toolhelp(declared_ppid);
            let declared_parent_name = declared_parent_info
                .as_ref()
                .map(|(_, name, _)| name.as_str());
            let actual_creator_info = Self::get_process_info_toolhelp(real_ppid);
            let actual_creator_name = actual_creator_info
                .as_ref()
                .map(|(_, name, _)| name.as_str())
                .unwrap_or("unknown");

            // Get process paths
            let process_path = Self::get_process_path(pid).unwrap_or_default();
            let cmdline = Self::get_process_cmdline(pid).unwrap_or_else(|| process_path.clone());
            let declared_parent_path = Self::get_process_path(declared_ppid);
            let actual_creator_path = Self::get_process_path(real_ppid);

            // Get process creation time for timeline validation
            let child_create_time = PpidSpoofingDetector::get_process_create_time(pid);

            // Record this process in timeline tracker for future validations
            if let Some(create_time) = child_create_time {
                let timeline_entry = ProcessTimelineEntry {
                    pid,
                    name: process_name.clone(),
                    path: process_path.clone(),
                    create_time,
                    exit_time: 0, // Still running
                    ppid: declared_ppid,
                    session_id: 0, // Could be retrieved but not critical
                    is_system_process: detector.is_system_process_pid(pid),
                    last_validated: Instant::now(),
                };
                detector.record_timeline_entry(timeline_entry);
            }

            // Use comprehensive analysis with all detection mechanisms
            let spoofing_event = detector.analyze_comprehensive(
                pid,
                declared_ppid,
                real_ppid,
                &process_name,
                &process_path,
                &cmdline,
                "UNKNOWN", // User resolution is expensive, done elsewhere
                declared_parent_name,
                Some(actual_creator_name),
                declared_parent_path.as_deref(),
                actual_creator_path.as_deref(),
                child_create_time,
            )?;

            // Use the detector's generate_alert method for consistent alert creation
            Some(detector.generate_alert(&spoofing_event))
        }
    }

    #[cfg(target_os = "windows")]
    fn get_process_info_toolhelp(pid: u32) -> Option<(u32, String, String)> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;

            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..std::mem::zeroed()
            };

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    if entry.th32ProcessID == pid {
                        let name_len = entry
                            .szExeFile
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(entry.szExeFile.len());
                        let name = String::from_utf16_lossy(&entry.szExeFile[..name_len]);
                        let ppid = entry.th32ParentProcessID;

                        let _ = CloseHandle(snapshot);
                        return Some((ppid, name, String::new()));
                    }

                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
            None
        }
    }

    #[cfg(target_os = "windows")]
    fn get_process_path(pid: u32) -> Option<String> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
            PROCESS_QUERY_LIMITED_INFORMATION,
        };

        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;

            let mut buf = [0u16; 1024];
            let mut size = buf.len() as u32;

            let result = QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_WIN32,
                windows::core::PWSTR(buf.as_mut_ptr()),
                &mut size,
            );
            let _ = CloseHandle(handle);

            if result.is_ok() && size > 0 {
                Some(String::from_utf16_lossy(&buf[..size as usize]))
            } else {
                None
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn get_process_cmdline(pid: u32) -> Option<String> {
        use super::win_compat::ntapi::get_process_command_line;
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
            let cmdline = get_process_command_line(handle.0 as *mut c_void);
            let _ = CloseHandle(handle);
            cmdline
        }
    }

    #[cfg(not(target_os = "windows"))]
    async fn monitor_loop(_tx: mpsc::Sender<TelemetryEvent>, _detector: Arc<PpidSpoofingDetector>) {
        // PPID spoofing is primarily a Windows technique
        // On Linux/macOS, similar techniques exist but use different mechanisms
        info!("PPID spoofing detector not implemented for this platform");

        // Just wait forever to keep the task alive
        std::future::pending::<()>().await;
    }

    /// Get next event from the collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ppid_mismatch_detection() {
        let detector = PpidSpoofingDetector::new();

        // No mismatch when PIDs match
        assert!(!detector.check_ppid_mismatch(100, 50, 50));

        // Mismatch when PIDs differ
        assert!(detector.check_ppid_mismatch(100, 50, 60));

        // No mismatch for System (PID 0 or 4) as parent
        assert!(!detector.check_ppid_mismatch(100, 0, 60));
        assert!(!detector.check_ppid_mismatch(100, 4, 60));
    }

    #[test]
    fn test_legitimate_relationships() {
        let detector = PpidSpoofingDetector::new();

        // Known legitimate relationships should be recognized
        assert!(detector.is_legitimate_relationship("services.exe", "svchost.exe"));
        assert!(detector.is_legitimate_relationship("explorer.exe", "cmd.exe"));
        assert!(detector
            .is_legitimate_relationship("C:\\Windows\\System32\\services.exe", "svchost.exe"));

        // Unknown relationships should not match
        assert!(!detector.is_legitimate_relationship("notepad.exe", "cmd.exe"));
        assert!(!detector.is_legitimate_relationship("random.exe", "powershell.exe"));
    }

    #[test]
    fn test_confidence_calculation() {
        let detector = PpidSpoofingDetector::new();

        // High-value target spoofing should have high confidence
        let result = detector.analyze(
            100,
            50, // declared ppid (spoofed into svchost)
            60, // actual creator
            "cmd.exe",
            "C:\\Windows\\System32\\cmd.exe",
            "cmd.exe /c whoami",
            "SYSTEM",
            Some("svchost.exe"),
            Some("malware.exe"),
        );

        assert!(result.is_some());
        let event = result.unwrap();
        assert!(event.confidence >= 0.8);
        assert_eq!(event.mitre_technique, "T1134.004");
    }

    #[test]
    fn test_high_value_parent_detection() {
        let detector = PpidSpoofingDetector::new();

        // High-value parents should be recognized
        assert!(detector.is_high_value_parent("svchost.exe"));
        assert!(detector.is_high_value_parent("C:\\Windows\\System32\\svchost.exe"));
        assert!(detector.is_high_value_parent("lsass.exe"));
        assert!(detector.is_high_value_parent("explorer.exe"));

        // Regular processes should not match
        assert!(!detector.is_high_value_parent("notepad.exe"));
        assert!(!detector.is_high_value_parent("chrome.exe"));
    }

    #[test]
    fn test_suspicious_child_detection() {
        let detector = PpidSpoofingDetector::new();

        // Suspicious children should be recognized
        assert!(detector.is_suspicious_child("cmd.exe"));
        assert!(detector.is_suspicious_child("powershell.exe"));
        assert!(detector.is_suspicious_child("mshta.exe"));
        assert!(detector.is_suspicious_child("rundll32.exe"));

        // Regular processes should not match
        assert!(!detector.is_suspicious_child("notepad.exe"));
        assert!(!detector.is_suspicious_child("calc.exe"));
    }

    #[test]
    fn test_detection_method_display() {
        assert_eq!(
            SpoofingDetectionMethod::NtQueryInformationProcess.to_string(),
            "NtQueryInformationProcess"
        );
        assert_eq!(
            SpoofingDetectionMethod::StartupInfoExUsage.to_string(),
            "STARTUPINFOEX_Usage"
        );
        assert_eq!(
            SpoofingDetectionMethod::EtwProcessCreation.to_string(),
            "ETW_ProcessCreation"
        );
    }

    #[test]
    fn test_alert_generation() {
        let detector = PpidSpoofingDetector::new();

        let spoofing_event = PpidSpoofingEvent {
            pid: 1234,
            declared_ppid: 5678,
            actual_creator_pid: 9012,
            process_name: "cmd.exe".to_string(),
            process_path: "C:\\Windows\\System32\\cmd.exe".to_string(),
            cmdline: "cmd.exe /c whoami".to_string(),
            declared_parent_name: Some("svchost.exe".to_string()),
            actual_creator_name: Some("malware.exe".to_string()),
            user: "SYSTEM".to_string(),
            confidence: 0.95,
            detection_method: "NtQueryInformationProcess".to_string(),
            details: "PPID spoofing detected".to_string(),
            startupinfoex_detected: true,
            parent_process_attribute_used: true,
            mitre_technique: "T1134.004".to_string(),
            declared_parent_path: Some("C:\\Windows\\System32\\svchost.exe".to_string()),
            actual_creator_path: Some("C:\\Users\\victim\\malware.exe".to_string()),
        };

        let alert = detector.generate_alert(&spoofing_event);

        // Should be Critical severity for high confidence
        assert_eq!(alert.severity, Severity::Critical);
        assert_eq!(alert.event_type, EventType::DefenseEvasion);

        // Should have detections
        assert!(!alert.detections.is_empty());
        assert!(alert
            .detections
            .iter()
            .any(|d| d.rule_name == "ppid_spoofing_t1134_004"));
        assert!(alert
            .detections
            .iter()
            .any(|d| d.mitre_techniques.contains(&"T1134.004".to_string())));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_startupinfoex_tracker() {
        let mut tracker = StartupInfoExTracker::new();

        // Record a PROC_THREAD_ATTRIBUTE_PARENT_PROCESS usage
        tracker.record_attribute_update(
            1234, // caller PID
            StartupInfoExTracker::PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            Some(5678), // target PID
        );

        // Should detect the usage
        assert!(tracker.was_startupinfoex_used(1234));
        assert_eq!(tracker.check_parent_process_attribute(1234), Some(5678));

        // Unknown PID should return None
        assert!(!tracker.was_startupinfoex_used(9999));
        assert_eq!(tracker.check_parent_process_attribute(9999), None);
    }

    // =========================================================================
    // Timeline validation tests
    // =========================================================================

    #[test]
    fn test_process_timeline_tracker() {
        let mut tracker = ProcessTimelineTracker::new();

        // Record a process start
        let entry = ProcessTimelineEntry {
            pid: 1000,
            name: "explorer.exe".to_string(),
            path: "C:\\Windows\\explorer.exe".to_string(),
            create_time: 1000000,
            exit_time: 0,
            ppid: 500,
            session_id: 1,
            is_system_process: false,
            last_validated: Instant::now(),
        };
        tracker.record_start(entry);

        // Should be able to retrieve it
        assert!(tracker.get_current(1000).is_some());
        assert!(tracker.get_latest(1000).is_some());

        // Validate timeline - process was running at creation time
        let result = tracker.validate_parent_timeline(2000, 1500000, 1000);
        assert!(result.is_ok());

        // Record termination
        tracker.record_exit(1000, 2000000);
        assert!(tracker.is_terminated(1000));

        // Child created after parent terminated should fail validation
        let result = tracker.validate_parent_timeline(3000, 2500000, 1000);
        assert!(matches!(
            result,
            Err(TimelineValidationError::ParentTerminatedBeforeChild { .. })
        ));
    }

    #[test]
    fn test_timeline_parent_not_found() {
        let tracker = ProcessTimelineTracker::new();

        // Parent not in timeline should fail
        let result = tracker.validate_parent_timeline(1000, 1000000, 9999);
        assert!(matches!(
            result,
            Err(TimelineValidationError::ParentNotInTimeline)
        ));
    }

    #[test]
    fn test_timeline_system_processes_always_valid() {
        let tracker = ProcessTimelineTracker::new();

        // System (PID 0) should always be valid
        let result = tracker.validate_parent_timeline(1000, 1000000, 0);
        assert!(result.is_ok());

        // System (PID 4) should always be valid
        let result = tracker.validate_parent_timeline(1000, 1000000, 4);
        assert!(result.is_ok());
    }

    // =========================================================================
    // Handle inheritance anomaly tests
    // =========================================================================

    #[test]
    fn test_handle_inheritance_tracker() {
        let mut tracker = HandleInheritanceTracker::new();

        // Record cross-process handle operations
        tracker.record_handle_dup(100, 200); // actual_creator -> declared_ppid
        tracker.record_handle_dup(100, 200);
        tracker.record_handle_dup(100, 200);

        // Should detect anomaly
        let anomaly = tracker.check_anomalies(300, 200, 100);
        assert!(anomaly.is_some());
    }

    // =========================================================================
    // Impossible relationship tests
    // =========================================================================

    #[test]
    fn test_impossible_relationships() {
        let detector = PpidSpoofingDetector::new();

        // lsass.exe spawning cmd.exe is impossible
        assert!(detector.is_impossible_relationship("lsass.exe", "cmd.exe"));
        assert!(detector.is_impossible_relationship("C:\\Windows\\System32\\lsass.exe", "cmd.exe"));

        // csrss.exe spawning powershell.exe is impossible
        assert!(detector.is_impossible_relationship("csrss.exe", "powershell.exe"));

        // smss.exe spawning explorer.exe is impossible
        assert!(detector.is_impossible_relationship("smss.exe", "explorer.exe"));

        // Legitimate relationships should not be flagged as impossible
        assert!(!detector.is_impossible_relationship("explorer.exe", "cmd.exe"));
        assert!(!detector.is_impossible_relationship("services.exe", "svchost.exe"));
    }

    // =========================================================================
    // Orphan process detection tests
    // =========================================================================

    #[test]
    fn test_orphan_process_detection() {
        let detector = PpidSpoofingDetector::new();

        // Record a process start
        let entry = ProcessTimelineEntry {
            pid: 1000,
            name: "parent.exe".to_string(),
            path: "C:\\parent.exe".to_string(),
            create_time: 1000000,
            exit_time: 0,
            ppid: 500,
            session_id: 1,
            is_system_process: false,
            last_validated: Instant::now(),
        };
        detector.record_timeline_entry(entry);

        // Not an orphan yet
        assert!(!detector.is_orphan_process(1000));

        // Terminate the process
        detector.record_process_exit(1000);

        // Now it's an orphan
        assert!(detector.is_orphan_process(1000));
    }

    // =========================================================================
    // Timeline validation error display tests
    // =========================================================================

    #[test]
    fn test_timeline_validation_error_display() {
        let err1 = TimelineValidationError::ParentNotInTimeline;
        assert!(err1.to_string().contains("not found"));

        let err2 = TimelineValidationError::ParentTerminatedBeforeChild {
            parent_exit_time: 1000,
            child_create_time: 2000,
        };
        assert!(err2.to_string().contains("terminated"));

        let err3 = TimelineValidationError::ParentCreatedAfterChild {
            parent_create_time: 2000,
            child_create_time: 1000,
        };
        assert!(err3.to_string().contains("after"));

        let err4 = TimelineValidationError::ParentNotRunningAtTime;
        assert!(err4.to_string().contains("not running"));
    }

    // =========================================================================
    // Process timeline entry tests
    // =========================================================================

    #[test]
    fn test_process_timeline_entry_was_running_at() {
        let entry = ProcessTimelineEntry {
            pid: 1000,
            name: "test.exe".to_string(),
            path: "C:\\test.exe".to_string(),
            create_time: 1000,
            exit_time: 2000,
            ppid: 500,
            session_id: 1,
            is_system_process: false,
            last_validated: Instant::now(),
        };

        // Before creation
        assert!(!entry.was_running_at(500));

        // During lifetime
        assert!(entry.was_running_at(1000)); // Exact creation time
        assert!(entry.was_running_at(1500)); // Middle
        assert!(entry.was_running_at(2000)); // Exact exit time

        // After termination
        assert!(!entry.was_running_at(2500));
    }

    #[test]
    fn test_process_timeline_entry_still_running() {
        let entry = ProcessTimelineEntry {
            pid: 1000,
            name: "test.exe".to_string(),
            path: "C:\\test.exe".to_string(),
            create_time: 1000,
            exit_time: 0, // Still running
            ppid: 500,
            session_id: 1,
            is_system_process: false,
            last_validated: Instant::now(),
        };

        assert!(entry.is_running());
        assert!(entry.was_running_at(999999999)); // Far future
    }
}
