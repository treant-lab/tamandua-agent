//! Early Bird APC Injection Detection
//!
//! Comprehensive detection for Early Bird injection, a sophisticated process injection
//! technique that queues an Asynchronous Procedure Call (APC) to the initial thread of
//! a process before it starts executing.
//!
//! ## Early Bird Injection Technique
//! 1. Create a process in suspended state (CREATE_SUSPENDED)
//! 2. Allocate memory in the target process (VirtualAllocEx)
//! 3. Write shellcode to the allocated memory (WriteProcessMemory)
//! 4. Queue APC to the main thread (QueueUserAPC/NtQueueApcThread)
//! 5. Resume the thread (ResumeThread)
//!
//! The shellcode executes when the thread becomes alertable (before main() runs).
//!
//! ## Detection Methods
//! - Track process creation with CREATE_SUSPENDED flag
//! - Monitor VirtualAllocEx to suspended processes
//! - Detect NtQueueApcThread/QueueUserAPC to initial threads
//! - Correlate memory allocation + APC queue + thread resume sequence
//! - Validate APC routine address (must point to unbacked/private memory)
//! - Thread state analysis (suspended initial thread with pending APCs)
//!
//! ## MITRE ATT&CK
//! - T1055.004 (Asynchronous Procedure Call)
//! - T1055.012 (Process Hollowing - related technique)
//!
//! ## References
//! - https://www.cyberbit.com/endpoint-security/new-early-bird-code-injection-technique/
//! - https://www.ired.team/offensive-security/code-injection-process-injection/early-bird-apc-queue-code-injection

#[allow(unused_imports)]
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;
#[allow(unused_imports)]
use tracing::{debug, info, trace, warn};

/// Early Bird injection detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EarlyBirdDetection {
    /// Source process ID (injector)
    pub source_pid: u32,
    /// Source process name
    pub source_name: String,
    /// Source process path
    pub source_path: String,
    /// Target process ID (victim - suspended process)
    pub target_pid: u32,
    /// Target process name
    pub target_name: String,
    /// Target process path
    pub target_path: String,
    /// Target thread ID (initial thread)
    pub target_thread_id: u32,
    /// APC routine address
    pub apc_routine_address: u64,
    /// Memory allocation address (if detected)
    pub allocation_address: Option<u64>,
    /// Memory allocation size
    pub allocation_size: Option<u64>,
    /// Memory protection flags
    pub memory_protection: Option<u32>,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// Detection stage
    pub stage: EarlyBirdStage,
    /// Evidence details
    pub evidence: Vec<String>,
    /// Timestamp of detection
    pub timestamp: u64,
    /// MITRE ATT&CK technique ID
    pub mitre_id: &'static str,
}

/// Stage of Early Bird injection detection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EarlyBirdStage {
    /// Process created suspended - initial indicator
    SuspendedProcessCreated,
    /// Memory allocated in suspended process
    MemoryAllocated,
    /// Memory written to suspended process
    MemoryWritten,
    /// APC queued to initial thread
    ApcQueued,
    /// Thread resumed with pending APC - full injection detected
    ThreadResumed,
    /// Full Early Bird sequence detected
    FullSequence,
    /// APC target points to unbacked memory
    ApcTargetUnbacked,
}

impl EarlyBirdStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SuspendedProcessCreated => "suspended_process_created",
            Self::MemoryAllocated => "memory_allocated",
            Self::MemoryWritten => "memory_written",
            Self::ApcQueued => "apc_queued",
            Self::ThreadResumed => "thread_resumed",
            Self::FullSequence => "full_sequence",
            Self::ApcTargetUnbacked => "apc_target_unbacked",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::SuspendedProcessCreated => "Process created in suspended state",
            Self::MemoryAllocated => "Memory allocated in suspended process",
            Self::MemoryWritten => "Executable memory written to suspended process",
            Self::ApcQueued => "APC queued to initial thread of suspended process",
            Self::ThreadResumed => "Thread resumed with pending APC",
            Self::FullSequence => "Complete Early Bird APC injection sequence detected",
            Self::ApcTargetUnbacked => "APC routine points to unbacked executable memory",
        }
    }

    pub fn confidence_boost(&self) -> f32 {
        match self {
            Self::SuspendedProcessCreated => 0.2,
            Self::MemoryAllocated => 0.15,
            Self::MemoryWritten => 0.2,
            Self::ApcQueued => 0.25,
            Self::ThreadResumed => 0.15,
            Self::FullSequence => 0.05,
            Self::ApcTargetUnbacked => 0.3,
        }
    }
}

/// Tracked suspended process state
#[derive(Debug, Clone)]
pub struct SuspendedProcessState {
    /// Process ID
    pub pid: u32,
    /// Process name
    pub name: String,
    /// Process path
    pub path: String,
    /// Parent process ID (potential injector)
    pub parent_pid: u32,
    /// Parent process name
    pub parent_name: String,
    /// Initial thread ID
    pub initial_thread_id: u32,
    /// Creation timestamp
    pub creation_time: u64,
    /// Memory allocations detected
    pub allocations: Vec<MemoryAllocation>,
    /// APC queued events
    pub apc_events: Vec<ApcQueueEvent>,
    /// Whether thread has been resumed
    pub resumed: bool,
    /// Resume timestamp (if resumed)
    pub resume_time: Option<u64>,
}

/// Memory allocation in suspended process
#[derive(Debug, Clone)]
pub struct MemoryAllocation {
    /// Base address
    pub address: u64,
    /// Size in bytes
    pub size: u64,
    /// Protection flags
    pub protection: u32,
    /// Source PID that performed allocation
    pub source_pid: u32,
    /// Timestamp
    pub timestamp: u64,
    /// Whether memory was subsequently written
    pub written: bool,
}

/// APC queue event
#[derive(Debug, Clone)]
pub struct ApcQueueEvent {
    /// Thread ID that received the APC
    pub thread_id: u32,
    /// APC routine address
    pub routine_address: u64,
    /// APC argument
    pub argument: u64,
    /// Source PID that queued the APC
    pub source_pid: u32,
    /// Timestamp
    pub timestamp: u64,
    /// Whether routine address is in unbacked memory
    pub routine_unbacked: bool,
}

/// Early Bird APC injection detector
pub struct EarlyBirdDetector {
    /// Tracked suspended processes
    suspended_processes: Arc<Mutex<HashMap<u32, SuspendedProcessState>>>,
    /// Known detections (to avoid duplicates)
    known_detections: Arc<Mutex<HashSet<(u32, u32, String)>>>,
    /// Configuration
    config: EarlyBirdConfig,
}

/// Configuration for Early Bird detection
#[derive(Debug, Clone)]
pub struct EarlyBirdConfig {
    /// Maximum time to track a suspended process (milliseconds)
    pub max_track_time_ms: u64,
    /// Minimum confidence to report
    pub min_confidence: f32,
    /// Enable verbose logging
    pub verbose: bool,
}

impl Default for EarlyBirdConfig {
    fn default() -> Self {
        Self {
            max_track_time_ms: 60_000, // 60 seconds
            min_confidence: 0.5,
            verbose: false,
        }
    }
}

impl EarlyBirdDetector {
    /// Create a new Early Bird detector
    pub fn new(config: EarlyBirdConfig) -> Self {
        info!("Initializing Early Bird APC injection detector");
        Self {
            suspended_processes: Arc::new(Mutex::new(HashMap::new())),
            known_detections: Arc::new(Mutex::new(HashSet::new())),
            config,
        }
    }

    /// Record a suspended process creation
    pub async fn record_suspended_process(
        &self,
        pid: u32,
        name: String,
        path: String,
        parent_pid: u32,
        parent_name: String,
        initial_thread_id: u32,
    ) -> Option<EarlyBirdDetection> {
        let now = current_timestamp();

        let state = SuspendedProcessState {
            pid,
            name: name.clone(),
            path: path.clone(),
            parent_pid,
            parent_name: parent_name.clone(),
            initial_thread_id,
            creation_time: now,
            allocations: Vec::new(),
            apc_events: Vec::new(),
            resumed: false,
            resume_time: None,
        };

        let mut processes = self.suspended_processes.lock().await;
        processes.insert(pid, state);

        debug!(
            pid = pid,
            name = %name,
            parent_pid = parent_pid,
            thread_id = initial_thread_id,
            "Tracking suspended process for Early Bird detection"
        );

        // Return initial detection (low confidence)
        Some(EarlyBirdDetection {
            source_pid: parent_pid,
            source_name: parent_name,
            source_path: get_process_path(parent_pid),
            target_pid: pid,
            target_name: name,
            target_path: path,
            target_thread_id: initial_thread_id,
            apc_routine_address: 0,
            allocation_address: None,
            allocation_size: None,
            memory_protection: None,
            confidence: 0.3,
            stage: EarlyBirdStage::SuspendedProcessCreated,
            evidence: vec![
                format!("Process {} (PID {}) created in suspended state", pid, pid),
                format!("Parent: {} (PID {})", parent_pid, parent_pid),
                format!("Initial thread: {}", initial_thread_id),
                "CREATE_SUSPENDED flag indicates potential injection target".to_string(),
            ],
            timestamp: now,
            mitre_id: "T1055.004",
        })
    }

    /// Record memory allocation in a tracked suspended process
    pub async fn record_memory_allocation(
        &self,
        target_pid: u32,
        source_pid: u32,
        address: u64,
        size: u64,
        protection: u32,
    ) -> Option<EarlyBirdDetection> {
        let now = current_timestamp();
        let mut processes = self.suspended_processes.lock().await;

        if let Some(state) = processes.get_mut(&target_pid) {
            let allocation = MemoryAllocation {
                address,
                size,
                protection,
                source_pid,
                timestamp: now,
                written: false,
            };

            state.allocations.push(allocation);

            // Check if allocation is executable
            let is_executable = is_protection_executable(protection);
            let confidence = if is_executable { 0.55 } else { 0.4 };

            debug!(
                target_pid = target_pid,
                source_pid = source_pid,
                address = format!("0x{:X}", address),
                size = size,
                protection = format!("0x{:X}", protection),
                executable = is_executable,
                "Memory allocated in suspended process"
            );

            return Some(EarlyBirdDetection {
                source_pid,
                source_name: get_process_name(source_pid),
                source_path: get_process_path(source_pid),
                target_pid,
                target_name: state.name.clone(),
                target_path: state.path.clone(),
                target_thread_id: state.initial_thread_id,
                apc_routine_address: 0,
                allocation_address: Some(address),
                allocation_size: Some(size),
                memory_protection: Some(protection),
                confidence,
                stage: EarlyBirdStage::MemoryAllocated,
                evidence: vec![
                    format!(
                        "VirtualAllocEx detected in suspended process {}",
                        target_pid
                    ),
                    format!("Address: 0x{:X}, Size: {} bytes", address, size),
                    format!(
                        "Protection: 0x{:X} ({})",
                        protection,
                        protection_to_string(protection)
                    ),
                    format!("Source process: {} (PID {})", source_pid, source_pid),
                    if is_executable {
                        "Allocation has EXECUTE permission - shellcode staging".to_string()
                    } else {
                        "Allocation may be followed by protection change".to_string()
                    },
                ],
                timestamp: now,
                mitre_id: "T1055.004",
            });
        }

        None
    }

    /// Record memory write to a tracked suspended process
    pub async fn record_memory_write(
        &self,
        target_pid: u32,
        source_pid: u32,
        address: u64,
        size: u64,
    ) -> Option<EarlyBirdDetection> {
        let now = current_timestamp();
        let mut processes = self.suspended_processes.lock().await;

        if let Some(state) = processes.get_mut(&target_pid) {
            // Find matching allocation and mark as written
            let mut allocation_found = false;
            for alloc in &mut state.allocations {
                if address >= alloc.address && address < alloc.address + alloc.size {
                    alloc.written = true;
                    allocation_found = true;
                    break;
                }
            }

            debug!(
                target_pid = target_pid,
                source_pid = source_pid,
                address = format!("0x{:X}", address),
                size = size,
                allocation_found = allocation_found,
                "Memory written to suspended process"
            );

            return Some(EarlyBirdDetection {
                source_pid,
                source_name: get_process_name(source_pid),
                source_path: get_process_path(source_pid),
                target_pid,
                target_name: state.name.clone(),
                target_path: state.path.clone(),
                target_thread_id: state.initial_thread_id,
                apc_routine_address: 0,
                allocation_address: Some(address),
                allocation_size: Some(size),
                memory_protection: None,
                confidence: 0.6,
                stage: EarlyBirdStage::MemoryWritten,
                evidence: vec![
                    format!("WriteProcessMemory to suspended process {}", target_pid),
                    format!("Address: 0x{:X}, Size: {} bytes", address, size),
                    format!("Source process: {} (PID {})", source_pid, source_pid),
                    if allocation_found {
                        "Write is to previously allocated region".to_string()
                    } else {
                        "Write is to existing memory region".to_string()
                    },
                    "Shellcode injection in progress".to_string(),
                ],
                timestamp: now,
                mitre_id: "T1055.004",
            });
        }

        None
    }

    /// Record APC queue to a thread in a tracked suspended process
    pub async fn record_apc_queue(
        &self,
        target_pid: u32,
        target_thread_id: u32,
        source_pid: u32,
        routine_address: u64,
        argument: u64,
    ) -> Option<EarlyBirdDetection> {
        let now = current_timestamp();
        let mut processes = self.suspended_processes.lock().await;

        if let Some(state) = processes.get_mut(&target_pid) {
            // Check if this is the initial thread
            let is_initial_thread = target_thread_id == state.initial_thread_id;

            // Check if routine address is in unbacked memory
            let routine_unbacked = is_address_unbacked(target_pid, routine_address);

            let apc_event = ApcQueueEvent {
                thread_id: target_thread_id,
                routine_address,
                argument,
                source_pid,
                timestamp: now,
                routine_unbacked,
            };

            state.apc_events.push(apc_event);

            // Calculate confidence based on indicators
            let mut confidence: f32 = 0.7;
            if is_initial_thread {
                confidence += 0.15; // APC to initial thread is classic Early Bird
            }
            if routine_unbacked {
                confidence += 0.1; // Routine in unbacked memory is suspicious
            }

            // Check if routine points to previously allocated memory
            let routine_in_allocation = state.allocations.iter().any(|alloc| {
                routine_address >= alloc.address && routine_address < alloc.address + alloc.size
            });
            if routine_in_allocation {
                confidence += 0.05;
            }

            debug!(
                target_pid = target_pid,
                thread_id = target_thread_id,
                source_pid = source_pid,
                routine = format!("0x{:X}", routine_address),
                is_initial_thread = is_initial_thread,
                routine_unbacked = routine_unbacked,
                "APC queued to thread in suspended process"
            );

            let mut evidence = vec![
                format!("NtQueueApcThread/QueueUserAPC detected"),
                format!(
                    "Target: {} (PID {}), Thread: {}",
                    state.name, target_pid, target_thread_id
                ),
                format!("APC routine: 0x{:X}", routine_address),
                format!("APC argument: 0x{:X}", argument),
                format!(
                    "Source: {} (PID {})",
                    get_process_name(source_pid),
                    source_pid
                ),
            ];

            if is_initial_thread {
                evidence.push(
                    "APC queued to INITIAL thread - classic Early Bird signature".to_string(),
                );
            }
            if routine_unbacked {
                evidence.push(
                    "Routine address is in unbacked (private) memory - shellcode".to_string(),
                );
            }
            if routine_in_allocation {
                evidence.push("Routine points to previously allocated memory region".to_string());
            }

            return Some(EarlyBirdDetection {
                source_pid,
                source_name: get_process_name(source_pid),
                source_path: get_process_path(source_pid),
                target_pid,
                target_name: state.name.clone(),
                target_path: state.path.clone(),
                target_thread_id,
                apc_routine_address: routine_address,
                allocation_address: state.allocations.first().map(|a| a.address),
                allocation_size: state.allocations.first().map(|a| a.size),
                memory_protection: state.allocations.first().map(|a| a.protection),
                confidence: confidence.min(1.0),
                stage: EarlyBirdStage::ApcQueued,
                evidence,
                timestamp: now,
                mitre_id: "T1055.004",
            });
        }

        None
    }

    /// Record thread resume for a tracked suspended process
    pub async fn record_thread_resume(
        &self,
        target_pid: u32,
        thread_id: u32,
        source_pid: u32,
    ) -> Option<EarlyBirdDetection> {
        let now = current_timestamp();
        let mut processes = self.suspended_processes.lock().await;

        if let Some(state) = processes.get_mut(&target_pid) {
            state.resumed = true;
            state.resume_time = Some(now);

            // Check if there are pending APCs
            let has_pending_apc = !state.apc_events.is_empty();
            let has_allocation = !state.allocations.is_empty();
            let has_written_allocation = state.allocations.iter().any(|a| a.written);

            // Calculate confidence for full sequence
            let mut confidence: f32 = 0.5;
            if has_pending_apc {
                confidence += 0.25;
            }
            if has_allocation {
                confidence += 0.1;
            }
            if has_written_allocation {
                confidence += 0.1;
            }

            // This is the full Early Bird sequence if we have APC + allocation
            let stage = if has_pending_apc && has_allocation {
                confidence = 0.95; // Very high confidence for full sequence
                EarlyBirdStage::FullSequence
            } else {
                EarlyBirdStage::ThreadResumed
            };

            debug!(
                target_pid = target_pid,
                thread_id = thread_id,
                source_pid = source_pid,
                has_pending_apc = has_pending_apc,
                has_allocation = has_allocation,
                stage = ?stage,
                "Thread resumed in tracked suspended process"
            );

            let mut evidence = vec![
                format!("ResumeThread called on suspended process {}", target_pid),
                format!("Thread: {}", thread_id),
                format!(
                    "Source: {} (PID {})",
                    get_process_name(source_pid),
                    source_pid
                ),
            ];

            if has_pending_apc {
                let apc = state.apc_events.last().unwrap();
                evidence.push(format!(
                    "Thread has pending APC (routine: 0x{:X})",
                    apc.routine_address
                ));
                evidence.push("APC will execute BEFORE main thread code".to_string());
            }

            if has_allocation {
                let alloc = state.allocations.last().unwrap();
                evidence.push(format!(
                    "Process has remote allocation at 0x{:X} ({} bytes)",
                    alloc.address, alloc.size
                ));
            }

            if stage == EarlyBirdStage::FullSequence {
                evidence.push("COMPLETE EARLY BIRD SEQUENCE DETECTED".to_string());
                evidence.push("Sequence: CREATE_SUSPENDED -> VirtualAllocEx -> WriteProcessMemory -> QueueUserAPC -> ResumeThread".to_string());
            }

            return Some(EarlyBirdDetection {
                source_pid,
                source_name: get_process_name(source_pid),
                source_path: get_process_path(source_pid),
                target_pid,
                target_name: state.name.clone(),
                target_path: state.path.clone(),
                target_thread_id: thread_id,
                apc_routine_address: state
                    .apc_events
                    .last()
                    .map(|a| a.routine_address)
                    .unwrap_or(0),
                allocation_address: state.allocations.last().map(|a| a.address),
                allocation_size: state.allocations.last().map(|a| a.size),
                memory_protection: state.allocations.last().map(|a| a.protection),
                confidence: confidence.min(1.0),
                stage,
                evidence,
                timestamp: now,
                mitre_id: "T1055.004",
            });
        }

        None
    }

    /// Analyze a thread for Early Bird indicators (standalone scan)
    #[cfg(target_os = "windows")]
    pub async fn analyze_thread_for_early_bird(
        &self,
        pid: u32,
        thread_id: u32,
    ) -> Option<EarlyBirdDetection> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::Debug::{GetThreadContext, CONTEXT};
        use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
        use windows::Win32::System::Threading::{
            OpenProcess, OpenThread, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
            THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION,
        };

        let now = current_timestamp();

        unsafe {
            // Open the thread
            let thread_handle = match OpenThread(
                THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT,
                false,
                thread_id,
            ) {
                Ok(h) => h,
                Err(_) => return None,
            };

            // Get thread context
            let mut context: CONTEXT = std::mem::zeroed();
            #[cfg(target_arch = "x86_64")]
            {
                context.ContextFlags =
                    windows::Win32::System::Diagnostics::Debug::CONTEXT_ALL_AMD64;
            }
            #[cfg(target_arch = "x86")]
            {
                context.ContextFlags = windows::Win32::System::Diagnostics::Debug::CONTEXT_ALL_X86;
            }

            if GetThreadContext(thread_handle, &mut context).is_err() {
                let _ = CloseHandle(thread_handle);
                return None;
            }

            let _ = CloseHandle(thread_handle);

            // Get instruction pointer
            #[cfg(target_arch = "x86_64")]
            let ip = context.Rip;
            #[cfg(target_arch = "x86")]
            let ip = context.Eip as u64;

            // Open the process to query memory
            let proc_handle =
                match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
                    Ok(h) => h,
                    Err(_) => return None,
                };

            // Query memory at IP
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let result = VirtualQueryEx(
                proc_handle,
                Some(ip as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            let _ = CloseHandle(proc_handle);

            if result == 0 {
                return None;
            }

            // Check if IP is in private executable memory (unbacked)
            const MEM_PRIVATE: u32 = 0x20000;
            const MEM_COMMIT: u32 = 0x1000;
            const PAGE_EXECUTE: u32 = 0x10;
            const PAGE_EXECUTE_READ: u32 = 0x20;
            const PAGE_EXECUTE_READWRITE: u32 = 0x40;
            const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

            let is_committed = (mbi.State.0 & MEM_COMMIT) != 0;
            let is_private = (mbi.Type.0 & MEM_PRIVATE) != 0;
            let is_executable = (mbi.Protect.0 & PAGE_EXECUTE) != 0
                || (mbi.Protect.0 & PAGE_EXECUTE_READ) != 0
                || (mbi.Protect.0 & PAGE_EXECUTE_READWRITE) != 0
                || (mbi.Protect.0 & PAGE_EXECUTE_WRITECOPY) != 0;

            if is_committed && is_private && is_executable {
                let process_name = get_process_name(pid);
                let process_path = get_process_path(pid);

                debug!(
                    pid = pid,
                    thread_id = thread_id,
                    ip = format!("0x{:X}", ip),
                    "Thread IP in unbacked executable memory - Early Bird indicator"
                );

                return Some(EarlyBirdDetection {
                    source_pid: 0, // Unknown
                    source_name: "unknown".to_string(),
                    source_path: String::new(),
                    target_pid: pid,
                    target_name: process_name,
                    target_path: process_path,
                    target_thread_id: thread_id,
                    apc_routine_address: ip,
                    allocation_address: Some(mbi.BaseAddress as u64),
                    allocation_size: Some(mbi.RegionSize as u64),
                    memory_protection: Some(mbi.Protect.0),
                    confidence: 0.75,
                    stage: EarlyBirdStage::ApcTargetUnbacked,
                    evidence: vec![
                        format!("Thread {} IP at 0x{:X}", thread_id, ip),
                        format!("IP is in MEM_PRIVATE executable memory"),
                        format!(
                            "Region: 0x{:X} - 0x{:X} ({} bytes)",
                            mbi.BaseAddress as u64,
                            mbi.BaseAddress as u64 + mbi.RegionSize as u64,
                            mbi.RegionSize
                        ),
                        format!("Protection: 0x{:X}", mbi.Protect.0),
                        "Legitimate threads run from MEM_IMAGE regions".to_string(),
                        "IP in unbacked memory indicates APC/injection execution".to_string(),
                    ],
                    timestamp: now,
                    mitre_id: "T1055.004",
                });
            }
        }

        None
    }

    /// Scan all processes for Early Bird indicators
    #[cfg(target_os = "windows")]
    pub async fn scan_all_processes(&self) -> Vec<EarlyBirdDetection> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
        };

        let mut detections = Vec::new();

        unsafe {
            let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
                Ok(h) => h,
                Err(_) => return detections,
            };

            let mut entry = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..Default::default()
            };

            if Thread32First(snapshot, &mut entry).is_ok() {
                loop {
                    let pid = entry.th32OwnerProcessID;
                    let thread_id = entry.th32ThreadID;

                    // Skip system processes
                    if pid > 10 && pid != std::process::id() {
                        if let Some(detection) =
                            self.analyze_thread_for_early_bird(pid, thread_id).await
                        {
                            detections.push(detection);
                        }
                    }

                    entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
                    if Thread32Next(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
        }

        detections
    }

    /// Cleanup old tracked processes
    pub async fn cleanup_old_entries(&self) {
        let now = current_timestamp();
        let max_age = self.config.max_track_time_ms;

        let mut processes = self.suspended_processes.lock().await;
        processes.retain(|_, state| now - state.creation_time < max_age);
    }

    /// Get statistics about tracked processes
    pub async fn get_stats(&self) -> EarlyBirdStats {
        let processes = self.suspended_processes.lock().await;
        let known = self.known_detections.lock().await;

        EarlyBirdStats {
            tracked_processes: processes.len(),
            total_allocations: processes.values().map(|p| p.allocations.len()).sum(),
            total_apc_events: processes.values().map(|p| p.apc_events.len()).sum(),
            known_detections: known.len(),
        }
    }
}

/// Statistics from the Early Bird detector
#[derive(Debug, Clone)]
pub struct EarlyBirdStats {
    pub tracked_processes: usize,
    pub total_allocations: usize,
    pub total_apc_events: usize,
    pub known_detections: usize,
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn get_process_name(pid: u32) -> String {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::ProcessStatus::GetModuleBaseNameW;
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        unsafe {
            if let Ok(handle) = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            {
                let mut name_buf = vec![0u16; 512];
                let len = GetModuleBaseNameW(handle, None, &mut name_buf);
                let _ = CloseHandle(handle);

                if len > 0 {
                    return String::from_utf16_lossy(&name_buf[..len as usize]);
                }
            }
        }
    }

    format!("pid_{}", pid)
}

fn get_process_path(pid: u32) -> String {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        unsafe {
            if let Ok(handle) = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            {
                let mut path_buf = vec![0u16; 1024];
                let len = GetModuleFileNameExW(handle, None, &mut path_buf);
                let _ = CloseHandle(handle);

                if len > 0 {
                    return String::from_utf16_lossy(&path_buf[..len as usize]);
                }
            }
        }
    }

    String::new()
}

fn is_protection_executable(protection: u32) -> bool {
    const PAGE_EXECUTE: u32 = 0x10;
    const PAGE_EXECUTE_READ: u32 = 0x20;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

    (protection & PAGE_EXECUTE) != 0
        || (protection & PAGE_EXECUTE_READ) != 0
        || (protection & PAGE_EXECUTE_READWRITE) != 0
        || (protection & PAGE_EXECUTE_WRITECOPY) != 0
}

fn protection_to_string(protection: u32) -> &'static str {
    const PAGE_NOACCESS: u32 = 0x01;
    const PAGE_READONLY: u32 = 0x02;
    const PAGE_READWRITE: u32 = 0x04;
    const PAGE_WRITECOPY: u32 = 0x08;
    const PAGE_EXECUTE: u32 = 0x10;
    const PAGE_EXECUTE_READ: u32 = 0x20;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

    match protection {
        PAGE_NOACCESS => "PAGE_NOACCESS",
        PAGE_READONLY => "PAGE_READONLY",
        PAGE_READWRITE => "PAGE_READWRITE",
        PAGE_WRITECOPY => "PAGE_WRITECOPY",
        PAGE_EXECUTE => "PAGE_EXECUTE",
        PAGE_EXECUTE_READ => "PAGE_EXECUTE_READ",
        PAGE_EXECUTE_READWRITE => "PAGE_EXECUTE_READWRITE",
        PAGE_EXECUTE_WRITECOPY => "PAGE_EXECUTE_WRITECOPY",
        _ => "UNKNOWN",
    }
}

/// Check if an address is in unbacked (private) memory
fn is_address_unbacked(pid: u32, address: u64) -> bool {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION};

        const MEM_PRIVATE: u32 = 0x20000;
        const MEM_COMMIT: u32 = 0x1000;

        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) {
                Ok(h) => h,
                Err(_) => return false,
            };

            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let result = VirtualQueryEx(
                handle,
                Some(address as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            let _ = CloseHandle(handle);

            if result == 0 {
                return false;
            }

            let is_committed = (mbi.State.0 & MEM_COMMIT) != 0;
            let is_private = (mbi.Type.0 & MEM_PRIVATE) != 0;

            return is_committed && is_private;
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

// =============================================================================
// COLLECTOR INTEGRATION
// =============================================================================

use crate::collectors::{
    Detection, DetectionType, EventPayload, EventType, ProcessEvent, Severity, TelemetryEvent,
};
use crate::config::AgentConfig;
use tokio::sync::mpsc;

/// Early Bird APC injection collector
pub struct EarlyBirdCollector {
    #[allow(dead_code)]
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    #[allow(dead_code)]
    event_tx: mpsc::Sender<TelemetryEvent>,
    #[allow(dead_code)]
    detector: Arc<EarlyBirdDetector>,
}

impl EarlyBirdCollector {
    /// Create a new Early Bird collector
    pub fn new(config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(500);

        let detector = Arc::new(EarlyBirdDetector::new(EarlyBirdConfig::default()));

        info!("Initializing Early Bird APC injection collector");

        #[cfg(target_os = "windows")]
        {
            let tx_clone = tx.clone();
            let detector_clone = detector.clone();
            let config_clone = config.clone();
            tokio::spawn(async move {
                Self::windows_monitor_loop(tx_clone, detector_clone, config_clone).await;
            });
        }

        Self {
            config: config.clone(),
            event_rx: rx,
            event_tx: tx,
            detector,
        }
    }

    /// Get next event from collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }

    /// Create telemetry event from Early Bird detection
    pub fn create_event(detection: &EarlyBirdDetection) -> TelemetryEvent {
        let severity = if detection.confidence >= 0.9 {
            Severity::Critical
        } else if detection.confidence >= 0.7 {
            Severity::High
        } else if detection.confidence >= 0.5 {
            Severity::Medium
        } else {
            Severity::Low
        };

        let mut event = TelemetryEvent::new(
            EventType::ProcessInject,
            severity,
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
                start_time: detection.timestamp,
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
            detection_type: DetectionType::Behavioral,
            rule_name: format!("early_bird_{}", detection.stage.as_str()),
            confidence: detection.confidence,
            description: format!(
                "Early Bird APC Injection: {} - {} (PID {}) -> {} (PID {})",
                detection.stage.description(),
                detection.source_name,
                detection.source_pid,
                detection.target_name,
                detection.target_pid,
            ),
            mitre_tactics: vec![
                "defense-evasion".to_string(),
                "privilege-escalation".to_string(),
            ],
            mitre_techniques: vec![detection.mitre_id.to_string()],
        });

        // Add metadata
        event
            .metadata
            .insert("stage".to_string(), detection.stage.as_str().to_string());
        event
            .metadata
            .insert("source_pid".to_string(), detection.source_pid.to_string());
        event
            .metadata
            .insert("target_pid".to_string(), detection.target_pid.to_string());
        event.metadata.insert(
            "target_thread_id".to_string(),
            detection.target_thread_id.to_string(),
        );
        event.metadata.insert(
            "mitre_technique".to_string(),
            detection.mitre_id.to_string(),
        );
        event
            .metadata
            .insert("confidence".to_string(), detection.confidence.to_string());

        if detection.apc_routine_address != 0 {
            event.metadata.insert(
                "apc_routine_address".to_string(),
                format!("0x{:X}", detection.apc_routine_address),
            );
        }
        if let Some(addr) = detection.allocation_address {
            event
                .metadata
                .insert("allocation_address".to_string(), format!("0x{:X}", addr));
        }
        if let Some(size) = detection.allocation_size {
            event
                .metadata
                .insert("allocation_size".to_string(), size.to_string());
        }
        if let Some(prot) = detection.memory_protection {
            event
                .metadata
                .insert("memory_protection".to_string(), format!("0x{:X}", prot));
        }

        // Add evidence
        if !detection.evidence.is_empty() {
            event
                .metadata
                .insert("evidence".to_string(), detection.evidence.join("; "));
        }

        event
    }

    #[cfg(target_os = "windows")]
    async fn windows_monitor_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        detector: Arc<EarlyBirdDetector>,
        config: AgentConfig,
    ) {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        let mul = config.sub_loop_interval_multiplier;
        info!(
            multiplier = mul,
            "Starting Early Bird APC injection monitor"
        );

        // Track known PIDs
        let mut known_pids: HashSet<u32> = HashSet::new();

        // Initial snapshot
        unsafe {
            if let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                let mut entry = PROCESSENTRY32W {
                    dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                    ..Default::default()
                };

                if Process32FirstW(snapshot, &mut entry).is_ok() {
                    loop {
                        known_pids.insert(entry.th32ProcessID);
                        if Process32NextW(snapshot, &mut entry).is_err() {
                            break;
                        }
                    }
                }
                let _ = CloseHandle(snapshot);
            }
        }

        // Monitor loop: detect new suspended processes and scan existing threads
        let process_scan_interval = ((500.0 * mul) as u64).max(500);
        let thread_scan_interval = ((5000.0 * mul) as u64).max(5000);
        let cleanup_interval = ((30000.0 * mul) as u64).max(30000);

        let mut process_interval =
            tokio::time::interval(tokio::time::Duration::from_millis(process_scan_interval));
        let mut thread_interval =
            tokio::time::interval(tokio::time::Duration::from_millis(thread_scan_interval));
        let mut cleanup_timer =
            tokio::time::interval(tokio::time::Duration::from_millis(cleanup_interval));

        loop {
            tokio::select! {
                _ = process_interval.tick() => {
                    // Detect new processes and check if they're suspended
                    unsafe {
                        if let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                            let mut entry = PROCESSENTRY32W {
                                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                                ..Default::default()
                            };

                            let mut current_pids: HashSet<u32> = HashSet::new();

                            if Process32FirstW(snapshot, &mut entry).is_ok() {
                                loop {
                                    let pid = entry.th32ProcessID;
                                    current_pids.insert(pid);

                                    // Check for new processes
                                    if !known_pids.contains(&pid) && pid > 10 {
                                        let name = String::from_utf16_lossy(
                                            &entry.szExeFile[..entry.szExeFile
                                                .iter()
                                                .position(|&c| c == 0)
                                                .unwrap_or(0)]
                                        );

                                        // Check if process is suspended by examining threads
                                        if let Some((initial_tid, is_suspended)) =
                                            check_process_suspended_state(pid)
                                        {
                                            if is_suspended {
                                                let path = get_process_path(pid);
                                                let parent_name = get_process_name(entry.th32ParentProcessID);

                                                if let Some(detection) = detector.record_suspended_process(
                                                    pid,
                                                    name.clone(),
                                                    path,
                                                    entry.th32ParentProcessID,
                                                    parent_name,
                                                    initial_tid,
                                                ).await {
                                                    let event = Self::create_event(&detection);
                                                    if tx.send(event).await.is_err() {
                                                        warn!("Event channel closed");
                                                        return;
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    if Process32NextW(snapshot, &mut entry).is_err() {
                                        break;
                                    }
                                }
                            }
                            let _ = CloseHandle(snapshot);

                            known_pids = current_pids;
                        }
                    }
                }

                _ = thread_interval.tick() => {
                    // Scan threads for Early Bird indicators
                    let detections = detector.scan_all_processes().await;
                    for detection in detections {
                        if detection.confidence >= 0.5 {
                            let event = Self::create_event(&detection);
                            if tx.send(event).await.is_err() {
                                warn!("Event channel closed");
                                return;
                            }
                        }
                    }
                }

                _ = cleanup_timer.tick() => {
                    detector.cleanup_old_entries().await;
                }
            }
        }
    }
}

/// Check if a process has a suspended initial thread
#[cfg(target_os = "windows")]
fn check_process_suspended_state(pid: u32) -> Option<(u32, bool)> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows::Win32::System::Threading::{OpenThread, THREAD_QUERY_INFORMATION};

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0).ok()?;

        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        let mut initial_thread: Option<u32> = None;
        let mut is_suspended = false;

        if Thread32First(snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32OwnerProcessID == pid {
                    // First thread found is the initial thread
                    if initial_thread.is_none() {
                        initial_thread = Some(entry.th32ThreadID);

                        // Check if thread is suspended using NtQueryInformationThread
                        if let Ok(thread_handle) =
                            OpenThread(THREAD_QUERY_INFORMATION, false, entry.th32ThreadID)
                        {
                            // Use suspend count to check if thread is suspended
                            // We'll use a heuristic: try to check thread state
                            is_suspended = check_thread_suspended(thread_handle);
                            let _ = CloseHandle(thread_handle);
                        }
                    }
                }

                entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
                if Thread32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);

        initial_thread.map(|tid| (tid, is_suspended))
    }
}

/// Check if a thread handle represents a suspended thread
#[cfg(target_os = "windows")]
fn check_thread_suspended(thread_handle: windows::Win32::Foundation::HANDLE) -> bool {
    // We use NtQueryInformationThread with ThreadSuspendCount (class 35)
    // to check if the thread has a non-zero suspend count.

    type NtQueryInformationThreadFn = unsafe extern "system" fn(
        windows::Win32::Foundation::HANDLE, // ThreadHandle
        u32,                                // ThreadInformationClass
        *mut std::ffi::c_void,              // ThreadInformation
        u32,                                // ThreadInformationLength
        *mut u32,                           // ReturnLength
    ) -> i32;

    unsafe {
        let module = match windows::Win32::System::LibraryLoader::GetModuleHandleA(
            windows::core::PCSTR::from_raw(b"ntdll.dll\0".as_ptr()),
        ) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let proc = windows::Win32::System::LibraryLoader::GetProcAddress(
            module,
            windows::core::PCSTR::from_raw(b"NtQueryInformationThread\0".as_ptr()),
        );

        let nt_func: NtQueryInformationThreadFn = match proc {
            Some(f) => std::mem::transmute(f),
            None => return false,
        };

        // ThreadSuspendCount = 35
        let mut suspend_count: u32 = 0;
        let status = nt_func(
            thread_handle,
            35,
            &mut suspend_count as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<u32>() as u32,
            std::ptr::null_mut(),
        );

        // STATUS_SUCCESS = 0
        if status == 0 && suspend_count > 0 {
            return true;
        }
    }

    false
}

// =============================================================================
// LINUX STUBS
// =============================================================================

#[cfg(not(target_os = "windows"))]
impl EarlyBirdDetector {
    pub async fn analyze_thread_for_early_bird(
        &self,
        _pid: u32,
        _thread_id: u32,
    ) -> Option<EarlyBirdDetection> {
        None
    }

    pub async fn scan_all_processes(&self) -> Vec<EarlyBirdDetection> {
        Vec::new()
    }
}

#[cfg(not(target_os = "windows"))]
impl EarlyBirdCollector {
    async fn windows_monitor_loop(
        _tx: mpsc::Sender<TelemetryEvent>,
        _detector: Arc<EarlyBirdDetector>,
        _config: AgentConfig,
    ) {
        // No-op on non-Windows
        std::future::pending::<()>().await;
    }
}

#[cfg(not(target_os = "windows"))]
fn check_process_suspended_state(_pid: u32) -> Option<(u32, bool)> {
    None
}

#[cfg(not(target_os = "windows"))]
fn check_thread_suspended(_thread_handle: ()) -> bool {
    false
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_early_bird_stage_confidence() {
        assert!(EarlyBirdStage::SuspendedProcessCreated.confidence_boost() > 0.0);
        assert!(
            EarlyBirdStage::ApcQueued.confidence_boost()
                > EarlyBirdStage::MemoryAllocated.confidence_boost()
        );
    }

    #[test]
    fn test_protection_executable() {
        assert!(is_protection_executable(0x10)); // PAGE_EXECUTE
        assert!(is_protection_executable(0x20)); // PAGE_EXECUTE_READ
        assert!(is_protection_executable(0x40)); // PAGE_EXECUTE_READWRITE
        assert!(!is_protection_executable(0x04)); // PAGE_READWRITE
    }

    #[test]
    fn test_protection_to_string() {
        assert_eq!(protection_to_string(0x40), "PAGE_EXECUTE_READWRITE");
        assert_eq!(protection_to_string(0x04), "PAGE_READWRITE");
    }

    #[tokio::test]
    async fn test_detector_creation() {
        let detector = EarlyBirdDetector::new(EarlyBirdConfig::default());
        let stats = detector.get_stats().await;
        assert_eq!(stats.tracked_processes, 0);
    }

    #[tokio::test]
    async fn test_record_suspended_process() {
        let detector = EarlyBirdDetector::new(EarlyBirdConfig::default());

        let detection = detector
            .record_suspended_process(
                1234,
                "test.exe".to_string(),
                "C:\\test.exe".to_string(),
                5678,
                "parent.exe".to_string(),
                1111,
            )
            .await;

        assert!(detection.is_some());
        let d = detection.unwrap();
        assert_eq!(d.target_pid, 1234);
        assert_eq!(d.source_pid, 5678);
        assert_eq!(d.stage, EarlyBirdStage::SuspendedProcessCreated);

        let stats = detector.get_stats().await;
        assert_eq!(stats.tracked_processes, 1);
    }

    #[tokio::test]
    async fn test_full_sequence_detection() {
        let detector = EarlyBirdDetector::new(EarlyBirdConfig::default());

        // Step 1: Suspended process created
        let _ = detector
            .record_suspended_process(
                1234,
                "target.exe".to_string(),
                "C:\\target.exe".to_string(),
                5678,
                "injector.exe".to_string(),
                1111,
            )
            .await;

        // Step 2: Memory allocated
        let _ = detector
            .record_memory_allocation(1234, 5678, 0x10000, 4096, 0x40)
            .await;

        // Step 3: Memory written
        let _ = detector.record_memory_write(1234, 5678, 0x10000, 256).await;

        // Step 4: APC queued
        let apc_detection = detector
            .record_apc_queue(1234, 1111, 5678, 0x10000, 0)
            .await;
        assert!(apc_detection.is_some());
        assert_eq!(apc_detection.unwrap().stage, EarlyBirdStage::ApcQueued);

        // Step 5: Thread resumed
        let resume_detection = detector.record_thread_resume(1234, 1111, 5678).await;
        assert!(resume_detection.is_some());
        let d = resume_detection.unwrap();
        assert_eq!(d.stage, EarlyBirdStage::FullSequence);
        assert!(d.confidence >= 0.9);
    }
}
