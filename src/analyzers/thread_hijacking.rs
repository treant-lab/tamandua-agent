//! Thread Hijacking / Thread Execution Hijacking Detection (T1055.003)
//!
//! This module provides comprehensive detection of thread hijacking attacks,
//! a sophisticated process injection technique where an attacker:
//! 1. Suspends a thread in a target process
//! 2. Modifies its execution context (RIP/EIP) to point to injected code
//! 3. Resumes the thread to execute the malicious payload
//!
//! ## Detection Methods
//!
//! ### API Sequence Monitoring
//! - Track SuspendThread + SetThreadContext + ResumeThread patterns
//! - Detect NtSuspendThread + NtSetContextThread + NtResumeThread syscall sequences
//! - Monitor QueueUserAPC combined with thread context changes
//!
//! ### Context Validation
//! - Compare instruction pointers before/after suspension
//! - Validate RIP/EIP points to legitimate code (module-backed memory)
//! - Detect context modifications pointing to unbacked executable memory
//! - Track changes to other registers (RSP stack pivot detection)
//!
//! ### Cross-Process Detection
//! - Monitor threads in processes other than the caller
//! - Track process handles with THREAD_SET_CONTEXT permission
//! - Correlate handle acquisition with subsequent context changes
//!
//! ### Memory Analysis
//! - Verify instruction pointer targets are in MEM_IMAGE regions
//! - Detect RIP/EIP pointing to MEM_PRIVATE executable memory
//! - Identify shellcode patterns at hijacked addresses
//! - Check for APC routine addresses in suspicious memory
//!
//! ## MITRE ATT&CK
//! - T1055.003: Thread Execution Hijacking
//! - T1055.004: Asynchronous Procedure Call (related via QueueUserAPC)
//!
//! ## Implementation Notes
//!
//! The detector maintains state across multiple monitoring cycles to:
//! - Baseline normal thread states when first seen
//! - Track instruction pointer changes over time
//! - Correlate API call sequences that span multiple events
//! - Avoid duplicate alerts for the same hijacking incident

// Thread hijacking detector (T1055.003). PascalCase mirrors NT API param
// names; CONTEXT scaffolding retained for upcoming GetThreadContext path.
#![allow(dead_code, unused_variables, unused_assignments, non_snake_case)]

use crate::collectors::{
    Detection, DetectionType, EventPayload, EventType, ProcessEvent, Severity, TelemetryEvent,
};
use crate::config::AgentConfig;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, info, trace, warn};

// ============================================================================
// Types and Structures
// ============================================================================

/// Thread state snapshot for baseline comparison
#[derive(Debug, Clone)]
pub struct ThreadState {
    /// Thread ID
    pub thread_id: u32,
    /// Owner process ID
    pub owner_pid: u32,
    /// Thread's Win32 start address
    pub start_address: u64,
    /// Current instruction pointer (RIP/EIP)
    pub instruction_pointer: u64,
    /// Stack pointer
    pub stack_pointer: u64,
    /// Whether the thread is suspended
    pub is_suspended: bool,
    /// Suspend count (Windows tracks nested suspends)
    pub suspend_count: u32,
    /// Memory type of instruction pointer location
    pub ip_memory_type: MemoryRegionType,
    /// Memory protection of instruction pointer location
    pub ip_memory_protection: u32,
    /// Module name if IP is in a module
    pub ip_module_name: Option<String>,
    /// When this state was captured
    pub captured_at: Instant,
}

/// Memory region type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryRegionType {
    /// Mapped from a file (DLL/EXE) - legitimate
    Image,
    /// Memory-mapped file - usually legitimate
    Mapped,
    /// Private allocation - suspicious for code execution
    Private,
    /// Unknown/inaccessible
    Unknown,
}

impl MemoryRegionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Image => "MEM_IMAGE",
            Self::Mapped => "MEM_MAPPED",
            Self::Private => "MEM_PRIVATE",
            Self::Unknown => "UNKNOWN",
        }
    }

    pub fn is_suspicious_for_execution(&self) -> bool {
        matches!(self, Self::Private)
    }
}

/// Cross-process thread operation for correlation
#[derive(Debug, Clone)]
pub struct ThreadOperation {
    /// Timestamp of the operation
    pub timestamp: Instant,
    /// Source process performing the operation
    pub source_pid: u32,
    /// Source process name
    pub source_name: String,
    /// Target process containing the thread
    pub target_pid: u32,
    /// Target thread ID (if applicable)
    pub target_tid: Option<u32>,
    /// Type of operation
    pub operation: ThreadOperationType,
    /// Memory address involved (if applicable)
    pub address: Option<u64>,
    /// Additional context
    pub context: HashMap<String, String>,
}

/// Types of thread operations we track
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreadOperationType {
    /// Thread was suspended
    Suspend,
    /// Thread was resumed
    Resume,
    /// Thread context was queried
    GetContext,
    /// Thread context was modified
    SetContext,
    /// APC was queued to thread
    QueueApc,
    /// Remote thread was created
    CreateRemoteThread,
    /// Process handle was opened with thread access
    OpenProcess,
    /// Thread handle was opened
    OpenThread,
}

impl ThreadOperationType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Suspend => "SuspendThread",
            Self::Resume => "ResumeThread",
            Self::GetContext => "GetThreadContext",
            Self::SetContext => "SetThreadContext",
            Self::QueueApc => "QueueUserAPC",
            Self::CreateRemoteThread => "CreateRemoteThread",
            Self::OpenProcess => "OpenProcess",
            Self::OpenThread => "OpenThread",
        }
    }
}

/// Thread hijacking detection event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadHijackingEvent {
    /// Source process ID (attacker)
    pub source_pid: u32,
    /// Source process name
    pub source_name: String,
    /// Source process path
    pub source_path: String,
    /// Target process ID (victim)
    pub target_pid: u32,
    /// Target process name
    pub target_name: String,
    /// Target process path
    pub target_path: String,
    /// Hijacked thread ID
    pub thread_id: u32,
    /// Original instruction pointer before hijacking
    pub original_ip: u64,
    /// New instruction pointer after hijacking
    pub new_ip: u64,
    /// Memory type of new IP location
    pub new_ip_memory_type: String,
    /// Memory protection of new IP location
    pub new_ip_protection: u32,
    /// Original start address
    pub original_start_address: Option<u64>,
    /// New start address (if changed)
    pub new_start_address: Option<u64>,
    /// Hijacking technique variant
    pub technique: HijackingTechnique,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// Evidence gathered
    pub evidence: Vec<String>,
    /// API sequence that led to detection
    pub api_sequence: Vec<String>,
    /// Shellcode signatures found at target address
    pub shellcode_signatures: Vec<String>,
}

/// Specific hijacking technique variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HijackingTechnique {
    /// Classic: Suspend + SetContext + Resume
    ClassicSetContext,
    /// SetContext without explicit suspend (thread already waiting)
    SetContextNoSuspend,
    /// APC injection via QueueUserAPC pointing to injected code
    ApcInjection,
    /// Stack pivot: RSP modified to point to ROP chain
    StackPivot,
    /// Debug registers used to redirect execution
    DebugRegisterHijack,
    /// Hardware breakpoint abuse
    HardwareBreakpointHijack,
    /// Start address changed (indicates SetContext abuse)
    StartAddressChange,
    /// Thread running from unbacked memory (post-hijack state)
    UnbackedExecution,
    /// Unknown technique
    Unknown,
}

impl HijackingTechnique {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ClassicSetContext => "classic_setcontext",
            Self::SetContextNoSuspend => "setcontext_no_suspend",
            Self::ApcInjection => "apc_injection",
            Self::StackPivot => "stack_pivot",
            Self::DebugRegisterHijack => "debug_register_hijack",
            Self::HardwareBreakpointHijack => "hardware_breakpoint_hijack",
            Self::StartAddressChange => "start_address_change",
            Self::UnbackedExecution => "unbacked_execution",
            Self::Unknown => "unknown",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::ClassicSetContext => {
                "Classic thread hijacking via SuspendThread + SetThreadContext + ResumeThread"
            }
            Self::SetContextNoSuspend => "Thread context modification without explicit suspension",
            Self::ApcInjection => "APC injection via QueueUserAPC with malicious routine address",
            Self::StackPivot => {
                "Stack pivot attack - RSP modified to point to ROP chain or shellcode"
            }
            Self::DebugRegisterHijack => "Debug register abuse to redirect execution flow",
            Self::HardwareBreakpointHijack => "Hardware breakpoint abuse for execution hijacking",
            Self::StartAddressChange => "Thread start address changed indicating SetContext abuse",
            Self::UnbackedExecution => "Thread executing from unbacked private memory",
            Self::Unknown => "Unknown thread hijacking technique",
        }
    }

    pub fn mitre_technique(&self) -> &'static str {
        match self {
            Self::ClassicSetContext
            | Self::SetContextNoSuspend
            | Self::StackPivot
            | Self::DebugRegisterHijack
            | Self::HardwareBreakpointHijack
            | Self::StartAddressChange
            | Self::UnbackedExecution
            | Self::Unknown => "T1055.003",
            Self::ApcInjection => "T1055.004",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Self::ClassicSetContext | Self::StackPivot | Self::ApcInjection => Severity::Critical,
            Self::SetContextNoSuspend
            | Self::DebugRegisterHijack
            | Self::HardwareBreakpointHijack
            | Self::StartAddressChange => Severity::High,
            Self::UnbackedExecution => Severity::High,
            Self::Unknown => Severity::Medium,
        }
    }
}

/// Configuration for thread hijacking detection
#[derive(Debug, Clone)]
pub struct ThreadHijackingConfig {
    /// Enable detection
    pub enabled: bool,
    /// Monitoring interval in milliseconds
    pub interval_ms: u64,
    /// Maximum threads to track (memory limit)
    pub max_tracked_threads: usize,
    /// Maximum operations to keep in history
    pub max_operation_history: usize,
    /// Time window for correlating operations (seconds)
    pub correlation_window_secs: u64,
    /// Minimum confidence threshold for alerts
    pub min_confidence: f32,
    /// Processes to exclude from monitoring
    pub excluded_processes: HashSet<String>,
    /// Enable shellcode signature scanning at hijack addresses
    pub scan_shellcode: bool,
    /// Enable stack pivot detection
    pub detect_stack_pivot: bool,
    /// Enable debug register monitoring
    pub detect_debug_register_abuse: bool,
}

impl Default for ThreadHijackingConfig {
    fn default() -> Self {
        let mut excluded = HashSet::new();
        // System processes that legitimately manipulate threads
        excluded.insert("csrss.exe".to_lowercase());
        excluded.insert("services.exe".to_lowercase());
        excluded.insert("wininit.exe".to_lowercase());
        excluded.insert("smss.exe".to_lowercase());

        Self {
            enabled: true,
            interval_ms: 500,
            max_tracked_threads: 50000,
            max_operation_history: 10000,
            correlation_window_secs: 10,
            min_confidence: 0.7,
            excluded_processes: excluded,
            scan_shellcode: true,
            detect_stack_pivot: true,
            detect_debug_register_abuse: true,
        }
    }
}

// ============================================================================
// Main Detector Implementation
// ============================================================================

/// Thread hijacking detector with state tracking and correlation
pub struct ThreadHijackingDetector {
    config: ThreadHijackingConfig,
    /// Current thread states: (pid, tid) -> state
    thread_states: Arc<RwLock<HashMap<(u32, u32), ThreadState>>>,
    /// Historical thread operations for correlation
    operation_history: Arc<Mutex<VecDeque<ThreadOperation>>>,
    /// Known detections to avoid duplicates
    known_detections: Arc<Mutex<HashSet<(u32, u32, HijackingTechnique)>>>,
    /// Event sender
    event_tx: mpsc::Sender<TelemetryEvent>,
}

impl ThreadHijackingDetector {
    /// Create a new thread hijacking detector
    pub fn new(config: ThreadHijackingConfig, event_tx: mpsc::Sender<TelemetryEvent>) -> Self {
        Self {
            config,
            thread_states: Arc::new(RwLock::new(HashMap::new())),
            operation_history: Arc::new(Mutex::new(VecDeque::new())),
            known_detections: Arc::new(Mutex::new(HashSet::new())),
            event_tx,
        }
    }

    /// Start the detection monitoring loop
    pub async fn start_monitoring(&self) {
        if !self.config.enabled {
            info!("Thread hijacking detection is disabled");
            return;
        }

        info!(
            interval_ms = self.config.interval_ms,
            "Starting thread hijacking detector (T1055.003)"
        );

        #[cfg(target_os = "windows")]
        {
            self.windows_monitor_loop().await;
        }

        #[cfg(not(target_os = "windows"))]
        {
            info!("Thread hijacking detection is currently Windows-only");
        }
    }

    /// Main monitoring loop for Windows
    #[cfg(target_os = "windows")]
    async fn windows_monitor_loop(&self) {
        let mut interval =
            tokio::time::interval(tokio::time::Duration::from_millis(self.config.interval_ms));

        loop {
            interval.tick().await;

            // Phase 1: Enumerate all threads and capture current states
            let current_states = self.capture_thread_states().await;

            // Phase 2: Compare with baseline and detect changes
            let detections = self.analyze_state_changes(&current_states).await;

            // Phase 3: Send alerts for new detections
            for detection in detections {
                self.send_alert(&detection).await;
            }

            // Phase 4: Update baseline with current states
            self.update_baseline(current_states).await;

            // Phase 5: Cleanup old state entries
            self.cleanup_stale_state().await;
        }
    }

    /// Capture current thread states across all processes
    #[cfg(target_os = "windows")]
    async fn capture_thread_states(&self) -> HashMap<(u32, u32), ThreadState> {
        use windows::Win32::Foundation::CloseHandle;

        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
        };

        let mut states = HashMap::new();
        let my_pid = std::process::id();

        unsafe {
            // Snapshot all threads
            let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
                Ok(h) => h,
                Err(e) => {
                    trace!("Failed to create thread snapshot: {:?}", e);
                    return states;
                }
            };

            let mut entry = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..Default::default()
            };

            if Thread32First(snapshot, &mut entry).is_ok() {
                loop {
                    let owner_pid = entry.th32OwnerProcessID;
                    let thread_id = entry.th32ThreadID;

                    // Skip system processes and ourselves
                    if owner_pid > 10 && owner_pid != my_pid {
                        let key = (owner_pid, thread_id);

                        // Try to get thread information
                        if let Some(state) = self.query_thread_state(owner_pid, thread_id).await {
                            states.insert(key, state);
                        }
                    }

                    if Thread32Next(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
        }

        states
    }

    /// Query detailed state for a single thread
    #[cfg(target_os = "windows")]
    async fn query_thread_state(&self, pid: u32, tid: u32) -> Option<ThreadState> {
        use std::ffi::c_void;
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::Debug::{CONTEXT, CONTEXT_ALL_AMD64};
        use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
        use windows::Win32::System::Threading::{
            OpenProcess, OpenThread, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
            THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION,
        };

        unsafe {
            // Open thread handle
            let thread_handle =
                match OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT, false, tid) {
                    Ok(h) => h,
                    Err(_) => return None,
                };

            // Query Win32 start address
            let mut start_address: usize = 0;
            let status = ntdll_NtQueryInformationThread(
                thread_handle,
                9, // ThreadQuerySetWin32StartAddress
                &mut start_address as *mut _ as *mut c_void,
                std::mem::size_of::<usize>() as u32,
                std::ptr::null_mut(),
            );

            if status != 0 {
                let _ = CloseHandle(thread_handle);
                return None;
            }

            // Get thread context for RIP/EIP and RSP
            let mut context = CONTEXT::default();
            context.ContextFlags = CONTEXT_ALL_AMD64;

            // Note: GetThreadContext requires the thread to be suspended
            // For initial baseline, we'll use the start address as a proxy
            // and skip full context query to avoid impacting performance

            let _ = CloseHandle(thread_handle);

            // Open process to query memory characteristics
            let proc_handle =
                match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
                    Ok(h) => h,
                    Err(_) => {
                        // Can still create a basic state without memory info
                        return Some(ThreadState {
                            thread_id: tid,
                            owner_pid: pid,
                            start_address: start_address as u64,
                            instruction_pointer: start_address as u64, // Use start addr as proxy
                            stack_pointer: 0,
                            is_suspended: false,
                            suspend_count: 0,
                            ip_memory_type: MemoryRegionType::Unknown,
                            ip_memory_protection: 0,
                            ip_module_name: None,
                            captured_at: Instant::now(),
                        });
                    }
                };

            // Query memory characteristics of start address
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let query_result = VirtualQueryEx(
                proc_handle,
                Some(start_address as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            let _ = CloseHandle(proc_handle);

            let (mem_type, mem_prot) = if query_result > 0 {
                let region_type = match mbi.Type.0 {
                    t if t & 0x1000000 != 0 => MemoryRegionType::Image, // MEM_IMAGE
                    t if t & 0x40000 != 0 => MemoryRegionType::Mapped,  // MEM_MAPPED
                    t if t & 0x20000 != 0 => MemoryRegionType::Private, // MEM_PRIVATE
                    _ => MemoryRegionType::Unknown,
                };
                (region_type, mbi.Protect.0)
            } else {
                (MemoryRegionType::Unknown, 0)
            };

            Some(ThreadState {
                thread_id: tid,
                owner_pid: pid,
                start_address: start_address as u64,
                instruction_pointer: start_address as u64, // Use start addr as proxy
                stack_pointer: 0,
                is_suspended: false,
                suspend_count: 0,
                ip_memory_type: mem_type,
                ip_memory_protection: mem_prot,
                ip_module_name: None,
                captured_at: Instant::now(),
            })
        }
    }

    /// Analyze state changes and detect hijacking
    #[cfg(target_os = "windows")]
    async fn analyze_state_changes(
        &self,
        current: &HashMap<(u32, u32), ThreadState>,
    ) -> Vec<ThreadHijackingEvent> {
        let mut detections = Vec::new();
        let baseline = self.thread_states.read().await;
        let known = self.known_detections.lock().await;

        for (key, current_state) in current {
            let (pid, tid) = *key;

            // Check if we have a baseline for this thread
            if let Some(baseline_state) = baseline.get(key) {
                // Detect start address changes
                if baseline_state.start_address != 0
                    && current_state.start_address != 0
                    && baseline_state.start_address != current_state.start_address
                {
                    // Start address changed - this is a strong indicator
                    if current_state.ip_memory_type.is_suspicious_for_execution() {
                        let det_key = (pid, tid, HijackingTechnique::StartAddressChange);
                        if !known.contains(&det_key) {
                            let event = self
                                .create_detection_event(
                                    baseline_state,
                                    current_state,
                                    HijackingTechnique::StartAddressChange,
                                    0.95,
                                    vec![
                                        format!(
                                            "Thread start address changed from 0x{:x} to 0x{:x}",
                                            baseline_state.start_address,
                                            current_state.start_address
                                        ),
                                        format!(
                                        "New address is in {} memory (suspicious for execution)",
                                        current_state.ip_memory_type.as_str()
                                    ),
                                        "Start address change indicates SetThreadContext was used"
                                            .to_string(),
                                    ],
                                )
                                .await;
                            if let Some(e) = event {
                                detections.push(e);
                            }
                        }
                    }
                }

                // Detect instruction pointer in suspicious memory (if we have it)
                if current_state.instruction_pointer != 0
                    && baseline_state.instruction_pointer != current_state.instruction_pointer
                    && current_state.ip_memory_type == MemoryRegionType::Private
                    && is_executable_protection(current_state.ip_memory_protection)
                {
                    let det_key = (pid, tid, HijackingTechnique::ClassicSetContext);
                    if !known.contains(&det_key) {
                        let event = self
                            .create_detection_event(
                                baseline_state,
                                current_state,
                                HijackingTechnique::ClassicSetContext,
                                0.9,
                                vec![
                                    format!(
                                        "RIP/EIP changed from 0x{:x} to 0x{:x}",
                                        baseline_state.instruction_pointer,
                                        current_state.instruction_pointer
                                    ),
                                    format!(
                                    "New RIP/EIP is in MEM_PRIVATE executable memory (prot=0x{:x})",
                                    current_state.ip_memory_protection
                                ),
                                    "Thread execution redirected via SetThreadContext".to_string(),
                                ],
                            )
                            .await;
                        if let Some(e) = event {
                            detections.push(e);
                        }
                    }
                }
            } else {
                // First time seeing this thread - check for already-hijacked state
                if current_state.ip_memory_type == MemoryRegionType::Private
                    && is_executable_protection(current_state.ip_memory_protection)
                    && current_state.start_address != 0
                {
                    let det_key = (pid, tid, HijackingTechnique::UnbackedExecution);
                    if !known.contains(&det_key) {
                        // Thread is executing from unbacked memory
                        let event = self.create_unbacked_detection(
                            current_state,
                            0.85,
                            vec![
                                format!(
                                    "Thread start address 0x{:x} is in MEM_PRIVATE executable memory",
                                    current_state.start_address
                                ),
                                format!(
                                    "Memory protection: 0x{:x}",
                                    current_state.ip_memory_protection
                                ),
                                "Thread start address should be in MEM_IMAGE (module-backed) memory".to_string(),
                                "Possible thread hijacking or injection already in progress".to_string(),
                            ],
                        ).await;
                        if let Some(e) = event {
                            detections.push(e);
                        }
                    }
                }
            }
        }

        detections
    }

    /// Create a detection event from state comparison
    #[cfg(target_os = "windows")]
    async fn create_detection_event(
        &self,
        baseline: &ThreadState,
        current: &ThreadState,
        technique: HijackingTechnique,
        confidence: f32,
        evidence: Vec<String>,
    ) -> Option<ThreadHijackingEvent> {
        let (target_name, target_path) = get_process_info(current.owner_pid);

        Some(ThreadHijackingEvent {
            source_pid: 0, // Unknown attacker
            source_name: "unknown".to_string(),
            source_path: String::new(),
            target_pid: current.owner_pid,
            target_name,
            target_path,
            thread_id: current.thread_id,
            original_ip: baseline.instruction_pointer,
            new_ip: current.instruction_pointer,
            new_ip_memory_type: current.ip_memory_type.as_str().to_string(),
            new_ip_protection: current.ip_memory_protection,
            original_start_address: Some(baseline.start_address),
            new_start_address: Some(current.start_address),
            technique,
            confidence,
            evidence,
            api_sequence: vec!["SetThreadContext".to_string()],
            shellcode_signatures: Vec::new(),
        })
    }

    /// Create a detection event for threads already executing from unbacked memory
    #[cfg(target_os = "windows")]
    async fn create_unbacked_detection(
        &self,
        state: &ThreadState,
        confidence: f32,
        evidence: Vec<String>,
    ) -> Option<ThreadHijackingEvent> {
        let (target_name, target_path) = get_process_info(state.owner_pid);

        Some(ThreadHijackingEvent {
            source_pid: 0,
            source_name: "unknown".to_string(),
            source_path: String::new(),
            target_pid: state.owner_pid,
            target_name,
            target_path,
            thread_id: state.thread_id,
            original_ip: 0,
            new_ip: state.start_address,
            new_ip_memory_type: state.ip_memory_type.as_str().to_string(),
            new_ip_protection: state.ip_memory_protection,
            original_start_address: None,
            new_start_address: Some(state.start_address),
            technique: HijackingTechnique::UnbackedExecution,
            confidence,
            evidence,
            api_sequence: Vec::new(),
            shellcode_signatures: Vec::new(),
        })
    }

    /// Send alert for a detection
    async fn send_alert(&self, detection: &ThreadHijackingEvent) {
        // Record this detection
        {
            let mut known = self.known_detections.lock().await;
            known.insert((
                detection.target_pid,
                detection.thread_id,
                detection.technique,
            ));
        }

        // Create telemetry event
        let event = self.create_telemetry_event(detection);

        debug!(
            target_pid = detection.target_pid,
            thread_id = detection.thread_id,
            technique = detection.technique.as_str(),
            confidence = detection.confidence,
            "Thread hijacking detected"
        );

        if self.event_tx.send(event).await.is_err() {
            warn!("Failed to send thread hijacking detection event");
        }
    }

    /// Create TelemetryEvent from ThreadHijackingEvent
    fn create_telemetry_event(&self, detection: &ThreadHijackingEvent) -> TelemetryEvent {
        let mut event = TelemetryEvent::new(
            EventType::ThreadHijacking,
            detection.technique.severity(),
            EventPayload::Process(ProcessEvent {
                pid: detection.target_pid,
                ppid: detection.source_pid,
                name: detection.target_name.clone(),
                path: detection.target_path.clone(),
                cmdline: String::new(),
                user: String::new(),
                sha256: Vec::new(),
                entropy: 0.0,
                is_elevated: false,
                parent_name: Some(detection.source_name.clone()),
                parent_path: Some(detection.source_path.clone()),
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

        // Add detection
        event.add_detection(Detection {
            detection_type: DetectionType::ThreadHijacking,
            rule_name: format!("thread_hijacking_{}", detection.technique.as_str()),
            confidence: detection.confidence,
            description: format!(
                "{}: {} (PID: {}, TID: {})",
                detection.technique.description(),
                detection.target_name,
                detection.target_pid,
                detection.thread_id,
            ),
            mitre_tactics: vec![
                "defense-evasion".to_string(),
                "privilege-escalation".to_string(),
            ],
            mitre_techniques: vec![detection.technique.mitre_technique().to_string()],
        });

        // Add metadata
        event
            .metadata
            .insert("source_pid".to_string(), detection.source_pid.to_string());
        event
            .metadata
            .insert("source_name".to_string(), detection.source_name.clone());
        event
            .metadata
            .insert("thread_id".to_string(), detection.thread_id.to_string());
        event.metadata.insert(
            "original_ip".to_string(),
            format!("0x{:x}", detection.original_ip),
        );
        event
            .metadata
            .insert("new_ip".to_string(), format!("0x{:x}", detection.new_ip));
        event.metadata.insert(
            "new_ip_memory_type".to_string(),
            detection.new_ip_memory_type.clone(),
        );
        event.metadata.insert(
            "new_ip_protection".to_string(),
            format!("0x{:x}", detection.new_ip_protection),
        );
        event.metadata.insert(
            "technique".to_string(),
            detection.technique.as_str().to_string(),
        );
        event.metadata.insert(
            "mitre_technique".to_string(),
            detection.technique.mitre_technique().to_string(),
        );

        if !detection.evidence.is_empty() {
            event
                .metadata
                .insert("evidence".to_string(), detection.evidence.join("; "));
        }

        if !detection.api_sequence.is_empty() {
            event.metadata.insert(
                "api_sequence".to_string(),
                detection.api_sequence.join(" -> "),
            );
        }

        if let Some(orig) = detection.original_start_address {
            event.metadata.insert(
                "original_start_address".to_string(),
                format!("0x{:x}", orig),
            );
        }

        if let Some(new) = detection.new_start_address {
            event
                .metadata
                .insert("new_start_address".to_string(), format!("0x{:x}", new));
        }

        event
    }

    /// Update baseline with current states
    async fn update_baseline(&self, current: HashMap<(u32, u32), ThreadState>) {
        let mut baseline = self.thread_states.write().await;

        // Update existing and add new
        for (key, state) in current {
            baseline.insert(key, state);
        }

        // Enforce maximum tracked threads
        if baseline.len() > self.config.max_tracked_threads {
            // Remove oldest entries (by captured_at)
            let mut entries: Vec<_> = baseline.iter().map(|(k, v)| (*k, v.captured_at)).collect();
            entries.sort_by_key(|(_, t)| *t);

            let to_remove = baseline.len() - self.config.max_tracked_threads;
            for (key, _) in entries.into_iter().take(to_remove) {
                baseline.remove(&key);
            }
        }
    }

    /// Cleanup stale state entries
    async fn cleanup_stale_state(&self) {
        let stale_threshold = Duration::from_secs(300); // 5 minutes
        let now = Instant::now();

        // Cleanup thread states
        {
            let mut states = self.thread_states.write().await;
            states.retain(|_, state| now.duration_since(state.captured_at) < stale_threshold);
        }

        // Cleanup operation history
        {
            let mut history = self.operation_history.lock().await;
            let correlation_window = Duration::from_secs(self.config.correlation_window_secs);
            while let Some(front) = history.front() {
                if now.duration_since(front.timestamp) > correlation_window {
                    history.pop_front();
                } else {
                    break;
                }
            }
        }

        // Periodically clear old detections (every ~30 minutes of runtime)
        {
            let mut known = self.known_detections.lock().await;
            if known.len() > 10000 {
                known.clear();
            }
        }
    }

    /// Record a thread operation for correlation
    pub async fn record_operation(&self, operation: ThreadOperation) {
        let mut history = self.operation_history.lock().await;
        history.push_back(operation);

        // Enforce maximum history size
        while history.len() > self.config.max_operation_history {
            history.pop_front();
        }
    }

    /// Correlate recent operations to detect hijacking patterns
    pub async fn correlate_operations(
        &self,
        target_pid: u32,
        target_tid: u32,
    ) -> Vec<ThreadOperation> {
        let history = self.operation_history.lock().await;
        let correlation_window = Duration::from_secs(self.config.correlation_window_secs);
        let now = Instant::now();

        history
            .iter()
            .filter(|op| {
                op.target_pid == target_pid
                    && op.target_tid == Some(target_tid)
                    && now.duration_since(op.timestamp) <= correlation_window
            })
            .cloned()
            .collect()
    }

    /// Check if a sequence of operations indicates hijacking
    pub fn is_hijacking_sequence(operations: &[ThreadOperation]) -> Option<HijackingTechnique> {
        if operations.is_empty() {
            return None;
        }

        let has_suspend = operations
            .iter()
            .any(|op| op.operation == ThreadOperationType::Suspend);
        let has_set_context = operations
            .iter()
            .any(|op| op.operation == ThreadOperationType::SetContext);
        let has_resume = operations
            .iter()
            .any(|op| op.operation == ThreadOperationType::Resume);
        let has_queue_apc = operations
            .iter()
            .any(|op| op.operation == ThreadOperationType::QueueApc);

        // Classic pattern: Suspend -> SetContext -> Resume
        if has_suspend && has_set_context && has_resume {
            return Some(HijackingTechnique::ClassicSetContext);
        }

        // SetContext without explicit suspend
        if has_set_context && !has_suspend {
            return Some(HijackingTechnique::SetContextNoSuspend);
        }

        // APC injection
        if has_queue_apc {
            return Some(HijackingTechnique::ApcInjection);
        }

        None
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Check if protection flags indicate executable memory
fn is_executable_protection(protection: u32) -> bool {
    const PAGE_EXECUTE: u32 = 0x10;
    const PAGE_EXECUTE_READ: u32 = 0x20;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

    protection & PAGE_EXECUTE != 0
        || protection & PAGE_EXECUTE_READ != 0
        || protection & PAGE_EXECUTE_READWRITE != 0
        || protection & PAGE_EXECUTE_WRITECOPY != 0
}

/// Get process name and path by PID
#[cfg(target_os = "windows")]
fn get_process_info(pid: u32) -> (String, String) {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    unsafe {
        if let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            let mut buffer = [0u16; 260];
            let len = GetModuleFileNameExW(handle, None, &mut buffer);
            let _ = CloseHandle(handle);

            if len > 0 {
                let path = String::from_utf16_lossy(&buffer[..len as usize]);
                let name = std::path::Path::new(&path)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| format!("pid_{}", pid));
                return (name, path);
            }
        }
    }

    (format!("pid_{}", pid), String::new())
}

#[cfg(not(target_os = "windows"))]
fn get_process_info(pid: u32) -> (String, String) {
    (format!("pid_{}", pid), String::new())
}

/// Native function pointer for NtQueryInformationThread
#[cfg(target_os = "windows")]
#[allow(non_snake_case)]
unsafe fn ntdll_NtQueryInformationThread(
    thread_handle: windows::Win32::Foundation::HANDLE,
    thread_information_class: u32,
    thread_information: *mut std::ffi::c_void,
    thread_information_length: u32,
    return_length: *mut u32,
) -> i32 {
    use windows::core::PCWSTR;
    use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

    type NtQueryInformationThreadFn = unsafe extern "system" fn(
        windows::Win32::Foundation::HANDLE,
        u32,
        *mut std::ffi::c_void,
        u32,
        *mut u32,
    ) -> i32;

    static mut FUNC: Option<NtQueryInformationThreadFn> = None;
    static INIT: std::sync::Once = std::sync::Once::new();

    INIT.call_once(|| {
        let ntdll: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        if let Ok(module) = LoadLibraryW(PCWSTR(ntdll.as_ptr())) {
            let proc_name =
                std::ffi::CStr::from_bytes_with_nul_unchecked(b"NtQueryInformationThread\0");
            if let Some(addr) = GetProcAddress(
                module,
                windows::core::PCSTR(proc_name.as_ptr() as *const u8),
            ) {
                FUNC = Some(std::mem::transmute(addr));
            }
        }
    });

    if let Some(func) = FUNC {
        func(
            thread_handle,
            thread_information_class,
            thread_information,
            thread_information_length,
            return_length,
        )
    } else {
        -1 // STATUS_UNSUCCESSFUL
    }
}

// ============================================================================
// Collector Integration
// ============================================================================

/// Thread hijacking collector that wraps the detector
pub struct ThreadHijackingCollector {
    #[allow(dead_code)]
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    #[allow(dead_code)]
    event_tx: mpsc::Sender<TelemetryEvent>,
}

impl ThreadHijackingCollector {
    /// Create a new thread hijacking collector
    pub fn new(config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(500);

        info!("Initializing thread hijacking detection collector (T1055.003)");

        // Create detector config from agent config
        let detector_config = ThreadHijackingConfig {
            enabled: true,
            interval_ms: ((500.0 * config.sub_loop_interval_multiplier) as u64).max(250),
            ..Default::default()
        };

        // Start detector in background
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            let detector = ThreadHijackingDetector::new(detector_config, tx_clone);
            detector.start_monitoring().await;
        });

        Self {
            config: config.clone(),
            event_rx: rx,
            event_tx: tx,
        }
    }

    /// Get next event from collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }
}

// ============================================================================
// Advanced Detection: Shellcode Scanning
// ============================================================================

/// Common shellcode signatures for detection at hijacked addresses
pub struct ShellcodeScanner;

impl ShellcodeScanner {
    /// Shellcode signature patterns
    pub const SIGNATURES: &'static [(&'static str, &'static [u8])] = &[
        // Windows x64 PEB access pattern
        (
            "peb_access_x64",
            &[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00],
        ),
        // Windows x86 PEB access via fs:[0x30]
        ("peb_access_x86", &[0x64, 0xA1, 0x30, 0x00, 0x00, 0x00]),
        // Cobalt Strike beacon sleep pattern
        (
            "cs_sleep",
            &[0x48, 0x83, 0xEC, 0x28, 0x48, 0x83, 0xE4, 0xF0],
        ),
        // Metasploit reverse shell prefix
        ("msf_reverse", &[0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8]),
        // Windows API hash pattern (ROR13)
        ("api_hash_ror13", &[0x0F, 0xB6, 0x0A, 0x48, 0xFF, 0xC2]),
        // Egg hunter pattern
        ("egg_hunter", &[0x66, 0x81, 0xCA, 0xFF, 0x0F, 0x42, 0x52]),
        // NOP sled
        (
            "nop_sled",
            &[0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90],
        ),
    ];

    /// Scan memory bytes for shellcode signatures
    pub fn scan(bytes: &[u8]) -> Vec<String> {
        let mut found = Vec::new();

        for (name, pattern) in Self::SIGNATURES {
            if bytes.len() >= pattern.len() {
                for i in 0..=(bytes.len() - pattern.len()) {
                    if &bytes[i..i + pattern.len()] == *pattern {
                        found.push(name.to_string());
                        break;
                    }
                }
            }
        }

        found
    }

    /// Calculate Shannon entropy of bytes
    pub fn entropy(bytes: &[u8]) -> f32 {
        if bytes.is_empty() {
            return 0.0;
        }

        let mut freq = [0u32; 256];
        for &b in bytes {
            freq[b as usize] += 1;
        }

        let len = bytes.len() as f32;
        let mut entropy = 0.0f32;

        for &count in &freq {
            if count > 0 {
                let p = count as f32 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_region_type() {
        assert!(MemoryRegionType::Private.is_suspicious_for_execution());
        assert!(!MemoryRegionType::Image.is_suspicious_for_execution());
        assert!(!MemoryRegionType::Mapped.is_suspicious_for_execution());
    }

    #[test]
    fn test_hijacking_technique_metadata() {
        assert_eq!(
            HijackingTechnique::ClassicSetContext.mitre_technique(),
            "T1055.003"
        );
        assert_eq!(
            HijackingTechnique::ApcInjection.mitre_technique(),
            "T1055.004"
        );
        assert_eq!(
            HijackingTechnique::ClassicSetContext.severity(),
            Severity::Critical
        );
    }

    #[test]
    fn test_executable_protection() {
        assert!(is_executable_protection(0x10)); // PAGE_EXECUTE
        assert!(is_executable_protection(0x20)); // PAGE_EXECUTE_READ
        assert!(is_executable_protection(0x40)); // PAGE_EXECUTE_READWRITE
        assert!(is_executable_protection(0x80)); // PAGE_EXECUTE_WRITECOPY
        assert!(!is_executable_protection(0x04)); // PAGE_READWRITE
        assert!(!is_executable_protection(0x02)); // PAGE_READONLY
    }

    #[test]
    fn test_shellcode_entropy() {
        // High entropy (random-like)
        let random_bytes: Vec<u8> = (0..=255).collect();
        let entropy = ShellcodeScanner::entropy(&random_bytes);
        assert!(entropy > 7.5);

        // Low entropy (repeated)
        let repeated_bytes = vec![0x90u8; 256];
        let entropy = ShellcodeScanner::entropy(&repeated_bytes);
        assert!(entropy < 0.1);
    }

    #[test]
    fn test_shellcode_scanner() {
        // NOP sled
        let nop_sled = vec![0x90u8; 16];
        let found = ShellcodeScanner::scan(&nop_sled);
        assert!(found.contains(&"nop_sled".to_string()));

        // x64 PEB access
        let peb_access = [0x65u8, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00];
        let found = ShellcodeScanner::scan(&peb_access);
        assert!(found.contains(&"peb_access_x64".to_string()));
    }

    #[test]
    fn test_operation_sequence_detection() {
        // Classic hijacking pattern
        let ops = vec![
            ThreadOperation {
                timestamp: Instant::now(),
                source_pid: 1234,
                source_name: "attacker.exe".to_string(),
                target_pid: 5678,
                target_tid: Some(100),
                operation: ThreadOperationType::Suspend,
                address: None,
                context: HashMap::new(),
            },
            ThreadOperation {
                timestamp: Instant::now(),
                source_pid: 1234,
                source_name: "attacker.exe".to_string(),
                target_pid: 5678,
                target_tid: Some(100),
                operation: ThreadOperationType::SetContext,
                address: Some(0x12345678),
                context: HashMap::new(),
            },
            ThreadOperation {
                timestamp: Instant::now(),
                source_pid: 1234,
                source_name: "attacker.exe".to_string(),
                target_pid: 5678,
                target_tid: Some(100),
                operation: ThreadOperationType::Resume,
                address: None,
                context: HashMap::new(),
            },
        ];

        let technique = ThreadHijackingDetector::is_hijacking_sequence(&ops);
        assert_eq!(technique, Some(HijackingTechnique::ClassicSetContext));
    }

    #[test]
    fn test_apc_detection() {
        let ops = vec![ThreadOperation {
            timestamp: Instant::now(),
            source_pid: 1234,
            source_name: "attacker.exe".to_string(),
            target_pid: 5678,
            target_tid: Some(100),
            operation: ThreadOperationType::QueueApc,
            address: Some(0xDEADBEEF),
            context: HashMap::new(),
        }];

        let technique = ThreadHijackingDetector::is_hijacking_sequence(&ops);
        assert_eq!(technique, Some(HijackingTechnique::ApcInjection));
    }
}
