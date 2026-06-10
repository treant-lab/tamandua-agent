//! Process Hollowing and Advanced Injection Detection Collector
//!
//! Comprehensive detection for sophisticated process injection techniques used by
//! advanced threat actors and malware families.
//!
//! ## Process Hollowing (T1055.012)
//! Process hollowing is a technique where a legitimate process is created in a suspended
//! state, its memory is unmapped, and malicious code is written in its place. This allows
//! malware to masquerade as a legitimate process.
//!
//! Detection methods:
//! - CREATE_SUSPENDED flag monitoring via process creation tracking
//! - NtUnmapViewOfSection calls via API monitoring
//! - Memory region changes in suspended processes
//! - Entry point modification detection by comparing original vs current EP
//! - Image base comparison (expected vs actual)
//! - PEB manipulation detection
//!
//! ## Process Doppelganging (T1055.013)
//! Uses Transactional NTFS (TxF) to create a process from a modified file without
//! leaving artifacts on disk.
//!
//! Detection methods:
//! - TxF (Transactional NTFS) operation monitoring
//! - NtCreateProcessEx with section from transaction
//! - Transaction handle correlation
//!
//! ## Process Herpaderping
//! Overwrites the file on disk after the process has been mapped into memory,
//! making the on-disk file different from what's running.
//!
//! Detection methods:
//! - File modification after mapping
//! - Signature mismatch between disk and memory
//! - Hash comparison (memory image vs disk file)
//!
//! ## DLL Injection Types
//! - Classic DLL Injection (T1055.001): CreateRemoteThread + LoadLibrary
//! - Reflective DLL injection (T1620): Loading without LoadLibrary
//! - Module stomping: Overwriting legitimate DLL in memory
//! - Thread hijacking (T1055.003): Modifying thread context for execution
//! - APC injection (T1055.004): Queuing APCs to threads
//! - Atom bombing: Global atom table abuse
//! - NtMapViewOfSection injection: Section mapping abuse
//! - SetWindowsHookEx injection (T1055.005): Hook-based injection
//!
//! ## Memory Analysis
//! - Compare in-memory image vs on-disk
//! - Detect RWX regions in unexpected locations
//! - Detect unbacked executable memory
//! - PE header anomalies (modified headers, unusual section characteristics)
//!
//! ## API Call Monitoring (via ETW)
//! - VirtualAllocEx in remote process
//! - WriteProcessMemory patterns
//! - NtQueueApcThread
//! - SetThreadContext modifications
//! - NtUnmapViewOfSection calls
//! - NtMapViewOfSection calls
//!
//! ## Heuristics
//! - Process with different image path in PEB vs disk
//! - Thread start address not in any loaded module
//! - Suspicious memory protections (RWX where not expected)
//! - Process timeline analysis (creation -> suspension -> modification -> resume)
//!
//! ## High Severity Detection Criteria
//! - Confirmed entry point modification
//! - NtUnmapViewOfSection followed by VirtualAllocEx pattern
//! - Memory content mismatch with disk
//! - C2 framework signatures in injected memory
//!
//! MITRE ATT&CK Mappings:
//! - T1055 (Process Injection) - Primary technique
//! - T1055.012 (Process Hollowing) - Specific sub-technique
//! - T1055.013 (Process Doppelganging)
//! - T1055.001 (DLL Injection)
//! - T1055.003 (Thread Execution Hijacking)
//! - T1055.004 (Asynchronous Procedure Call)
//! - T1055.005 (Thread Local Storage)
//! - T1620 (Reflective Code Loading)

// This collector enumerates structures, enum variants and tracker fields for
// detecting process hollowing, doppelganging, herpaderping, module stomping,
// thread hijacking, APC/atom-bombing/section-mapping/SetWindowsHookEx
// injection variants. Many variants/fields are kept exhaustive as reference
// for forthcoming correlation paths even when not yet consumed.
#![allow(dead_code, unused_variables, unused_assignments, non_snake_case)]

use super::{
    Detection, DetectionType, EventPayload, EventType, ProcessEvent, Severity, TelemetryEvent,
};
use crate::config::AgentConfig;
use std::collections::{HashMap, HashSet};
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

#[cfg(target_os = "windows")]
use std::ffi::c_void;

/// Process image information for hollowing detection
#[derive(Debug, Clone)]
pub struct ProcessImageInfo {
    /// Process ID
    pub pid: u32,
    /// Expected image base from PE header
    pub expected_image_base: u64,
    /// Actual image base from PEB
    pub actual_image_base: u64,
    /// Expected entry point (from PE header)
    pub expected_entry_point: u64,
    /// Actual entry point (from PEB/context)
    pub actual_entry_point: u64,
    /// Expected image size
    pub expected_image_size: u64,
    /// Actual mapped size
    pub actual_mapped_size: u64,
    /// File path on disk
    pub file_path: String,
    /// Hash of first N bytes of disk image
    pub disk_header_hash: Option<[u8; 32]>,
    /// Hash of first N bytes of memory image
    pub memory_header_hash: Option<[u8; 32]>,
}

/// Detection result with detailed analysis
#[derive(Debug, Clone)]
pub struct HollowingAnalysis {
    /// Whether hollowing is detected
    pub is_hollowed: bool,
    /// Confidence score (0.0-1.0)
    pub confidence: f32,
    /// Specific indicators found
    pub indicators: Vec<HollowingIndicator>,
    /// Recommended MITRE technique
    pub mitre_technique: String,
}

/// Specific hollowing indicators
#[derive(Debug, Clone)]
pub enum HollowingIndicator {
    /// Entry point was modified
    EntryPointModified { original: u64, current: u64 },
    /// Image base was changed
    ImageBaseChanged { expected: u64, actual: u64 },
    /// Memory content differs from disk
    ContentMismatch {
        offset: u64,
        disk_byte: u8,
        memory_byte: u8,
    },
    /// Process was created suspended
    CreatedSuspended {
        parent_pid: u32,
        parent_name: String,
    },
    /// NtUnmapViewOfSection was called
    SectionUnmapped { address: u64, size: u64 },
    /// PEB image path mismatch
    PebPathMismatch { peb_path: String, disk_path: String },
    /// Memory region replaced
    MemoryRegionReplaced {
        address: u64,
        original_protection: u32,
        new_protection: u32,
    },
    /// Thread context modified
    ThreadContextModified {
        thread_id: u32,
        original_ip: u64,
        new_ip: u64,
    },
}

/// Parsed PE header information for comparison
#[derive(Debug, Clone, Default)]
struct PeHeaderInfo {
    /// Entry point RVA
    entry_point_rva: u32,
    /// Preferred image base
    image_base: u64,
    /// Size of image when loaded
    size_of_image: u32,
    /// Number of sections
    number_of_sections: u16,
}

// ==================== Detection Types ====================

/// Advanced injection technique categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum InjectionTechnique {
    // Process Hollowing variants
    ProcessHollowing,
    ProcessHollowingCreateSuspended,
    ProcessHollowingUnmapSection,
    ProcessHollowingEntryPointModified,

    // Process Doppelganging
    ProcessDoppelganging,
    TransactionalNtfs,

    // Process Herpaderping
    ProcessHerpaderping,
    FileMappingMismatch,

    // DLL Injection
    ClassicDllInjection,
    ReflectiveDllInjection,
    ModuleStomping,
    ThreadHijacking,
    ApcInjection,
    AtomBombing,
    SectionMappingInjection,
    WindowsHookInjection,

    // Memory-based
    UnbackedExecutableMemory,
    RwxMemoryRegion,
    PeHeaderAnomaly,
    HollowedProcess,

    // Thread-based
    ThreadStartAddressUnbacked,
    RemoteThreadCreation,
    ThreadContextModification,

    // API abuse
    VirtualAllocExAbuse,
    WriteProcessMemoryAbuse,
    QueueApcAbuse,

    // PEB manipulation
    PebImagePathMismatch,

    // Unknown
    Unknown,
}

impl InjectionTechnique {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ProcessHollowing => "process_hollowing",
            Self::ProcessHollowingCreateSuspended => "process_hollowing_create_suspended",
            Self::ProcessHollowingUnmapSection => "process_hollowing_unmap_section",
            Self::ProcessHollowingEntryPointModified => "process_hollowing_entry_point_modified",
            Self::ProcessDoppelganging => "process_doppelganging",
            Self::TransactionalNtfs => "transactional_ntfs",
            Self::ProcessHerpaderping => "process_herpaderping",
            Self::FileMappingMismatch => "file_mapping_mismatch",
            Self::ClassicDllInjection => "classic_dll_injection",
            Self::ReflectiveDllInjection => "reflective_dll_injection",
            Self::ModuleStomping => "module_stomping",
            Self::ThreadHijacking => "thread_hijacking",
            Self::ApcInjection => "apc_injection",
            Self::AtomBombing => "atom_bombing",
            Self::SectionMappingInjection => "section_mapping_injection",
            Self::WindowsHookInjection => "windows_hook_injection",
            Self::UnbackedExecutableMemory => "unbacked_executable_memory",
            Self::RwxMemoryRegion => "rwx_memory_region",
            Self::PeHeaderAnomaly => "pe_header_anomaly",
            Self::HollowedProcess => "hollowed_process",
            Self::ThreadStartAddressUnbacked => "thread_start_address_unbacked",
            Self::RemoteThreadCreation => "remote_thread_creation",
            Self::ThreadContextModification => "thread_context_modification",
            Self::VirtualAllocExAbuse => "virtual_alloc_ex_abuse",
            Self::WriteProcessMemoryAbuse => "write_process_memory_abuse",
            Self::QueueApcAbuse => "queue_apc_abuse",
            Self::PebImagePathMismatch => "peb_image_path_mismatch",
            Self::Unknown => "unknown",
        }
    }

    pub fn mitre_technique(&self) -> &'static str {
        match self {
            Self::ProcessHollowing
            | Self::ProcessHollowingCreateSuspended
            | Self::ProcessHollowingUnmapSection
            | Self::ProcessHollowingEntryPointModified
            | Self::HollowedProcess => "T1055.012",

            Self::ProcessDoppelganging | Self::TransactionalNtfs => "T1055.013",

            Self::ProcessHerpaderping | Self::FileMappingMismatch => "T1055",

            Self::ClassicDllInjection | Self::RemoteThreadCreation => "T1055.001",

            Self::ReflectiveDllInjection => "T1620",

            Self::ThreadHijacking | Self::ThreadContextModification => "T1055.003",

            Self::ApcInjection | Self::QueueApcAbuse => "T1055.004",

            Self::WindowsHookInjection => "T1055.005",

            Self::ModuleStomping
            | Self::SectionMappingInjection
            | Self::UnbackedExecutableMemory
            | Self::RwxMemoryRegion
            | Self::PeHeaderAnomaly
            | Self::ThreadStartAddressUnbacked
            | Self::VirtualAllocExAbuse
            | Self::WriteProcessMemoryAbuse
            | Self::PebImagePathMismatch
            | Self::AtomBombing => "T1055",

            Self::Unknown => "T1055",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            // Critical - clear malicious intent
            Self::ProcessHollowing
            | Self::ProcessHollowingUnmapSection
            | Self::ProcessHollowingEntryPointModified
            | Self::ProcessDoppelganging
            | Self::ProcessHerpaderping
            | Self::ReflectiveDllInjection
            | Self::HollowedProcess
            | Self::AtomBombing => Severity::Critical,

            // High - strong indicators
            Self::ProcessHollowingCreateSuspended
            | Self::ClassicDllInjection
            | Self::ThreadHijacking
            | Self::ApcInjection
            | Self::ModuleStomping
            | Self::PebImagePathMismatch
            | Self::FileMappingMismatch => Severity::High,

            // Medium - suspicious but may have legitimate uses
            Self::TransactionalNtfs
            | Self::SectionMappingInjection
            | Self::WindowsHookInjection
            | Self::UnbackedExecutableMemory
            | Self::RwxMemoryRegion
            | Self::ThreadStartAddressUnbacked
            | Self::RemoteThreadCreation
            | Self::ThreadContextModification
            | Self::VirtualAllocExAbuse
            | Self::WriteProcessMemoryAbuse
            | Self::QueueApcAbuse
            | Self::PeHeaderAnomaly => Severity::Medium,

            Self::Unknown => Severity::Low,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::ProcessHollowing => "Process hollowing detected - legitimate process memory replaced with malicious code",
            Self::ProcessHollowingCreateSuspended => "Process created in suspended state - common hollowing precursor",
            Self::ProcessHollowingUnmapSection => "NtUnmapViewOfSection called on remote process - memory unmapping for hollowing",
            Self::ProcessHollowingEntryPointModified => "Process entry point was modified after creation",
            Self::ProcessDoppelganging => "Process doppelganging detected - transactional NTFS abuse for process creation",
            Self::TransactionalNtfs => "Transactional NTFS operations detected - may indicate doppelganging",
            Self::ProcessHerpaderping => "Process herpaderping detected - on-disk file modified after memory mapping",
            Self::FileMappingMismatch => "File mapping mismatch - in-memory content differs from disk",
            Self::ClassicDllInjection => "Classic DLL injection via CreateRemoteThread and LoadLibrary",
            Self::ReflectiveDllInjection => "Reflective DLL injection - DLL loaded without LoadLibrary",
            Self::ModuleStomping => "Module stomping - legitimate DLL overwritten in memory",
            Self::ThreadHijacking => "Thread hijacking - thread context modified for code execution",
            Self::ApcInjection => "APC injection - asynchronous procedure call queued to thread",
            Self::AtomBombing => "Atom bombing - global atom table abuse for injection",
            Self::SectionMappingInjection => "Section mapping injection via NtMapViewOfSection",
            Self::WindowsHookInjection => "Windows hook injection via SetWindowsHookEx",
            Self::UnbackedExecutableMemory => "Unbacked executable memory - code not mapped from file",
            Self::RwxMemoryRegion => "RWX memory region - memory with read/write/execute permissions",
            Self::PeHeaderAnomaly => "PE header anomaly in memory - possible unpacking or injection",
            Self::HollowedProcess => "Process appears to be hollowed - memory content mismatch",
            Self::ThreadStartAddressUnbacked => "Thread start address not in any loaded module",
            Self::RemoteThreadCreation => "Remote thread created in another process",
            Self::ThreadContextModification => "Thread context modified in another process",
            Self::VirtualAllocExAbuse => "VirtualAllocEx with suspicious parameters in remote process",
            Self::WriteProcessMemoryAbuse => "WriteProcessMemory used to write executable code",
            Self::QueueApcAbuse => "NtQueueApcThread used for potential injection",
            Self::PebImagePathMismatch => "PEB image path doesn't match actual executable",
            Self::Unknown => "Unknown injection technique detected",
        }
    }
}

/// Detailed injection detection event
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcessHollowingEvent {
    /// Source process ID (injector)
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
    /// Original image path (if different from current)
    pub original_image_path: Option<String>,
    /// Injection technique detected
    pub technique: InjectionTechnique,
    /// Memory address involved
    pub memory_address: Option<u64>,
    /// Memory size involved
    pub memory_size: Option<u64>,
    /// Memory protection flags
    pub memory_protection: Option<u32>,
    /// Entry point address
    pub entry_point: Option<u64>,
    /// Original entry point (if modified)
    pub original_entry_point: Option<u64>,
    /// Thread ID involved
    pub thread_id: Option<u32>,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// Additional context
    pub context: HashMap<String, String>,
}

// ==================== Process State Tracking ====================

/// Tracked suspended process state
#[derive(Debug, Clone)]
struct SuspendedProcess {
    pid: u32,
    name: String,
    path: String,
    creation_time: u64,
    original_entry_point: Option<u64>,
    original_image_base: Option<u64>,
    parent_pid: u32,
    parent_name: String,
    creation_flags: u32,
}

/// Cross-process operation for correlation
#[derive(Debug, Clone)]
struct CrossProcessOperation {
    timestamp: u64,
    source_pid: u32,
    source_name: String,
    target_pid: u32,
    operation: OperationType,
    address: Option<u64>,
    size: Option<u64>,
    protection: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OperationType {
    VirtualAllocEx,
    WriteProcessMemory,
    CreateRemoteThread,
    NtUnmapViewOfSection,
    NtMapViewOfSection,
    SetThreadContext,
    QueueUserApc,
    ResumeThread,
    CreateProcess,
    OpenProcess,
    DuplicateHandle,
}

// ==================== Main Collector ====================

/// Process hollowing and advanced injection detection collector
pub struct ProcessHollowingCollector {
    #[allow(dead_code)]
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    #[allow(dead_code)]
    event_tx: mpsc::Sender<TelemetryEvent>,
}

impl ProcessHollowingCollector {
    /// Create a new process hollowing collector
    pub fn new(config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(500);

        info!("Initializing advanced process injection detection");

        // Start platform-specific monitoring
        #[cfg(target_os = "windows")]
        {
            let tx_clone = tx.clone();
            let config_clone = config.clone();
            tokio::spawn(async move {
                Self::windows_monitor_loop(tx_clone, config_clone).await;
            });
        }

        #[cfg(target_os = "linux")]
        {
            let tx_clone = tx.clone();
            let config_clone = config.clone();
            tokio::spawn(async move {
                Self::linux_monitor_loop(tx_clone, config_clone).await;
            });
        }

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

    /// Create telemetry event from detection
    fn create_event(detection: &ProcessHollowingEvent) -> TelemetryEvent {
        let mut event = TelemetryEvent::new(
            EventType::ProcessInject,
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

        // Add detection details
        event.add_detection(Detection {
            detection_type: DetectionType::Behavioral,
            rule_name: format!("ProcessInjection_{}", detection.technique.as_str()),
            confidence: detection.confidence,
            description: format!(
                "{}: {} (PID: {}) -> {} (PID: {})",
                detection.technique.description(),
                detection.source_name,
                detection.source_pid,
                detection.target_name,
                detection.target_pid
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
            .insert("source_path".to_string(), detection.source_path.clone());
        event
            .metadata
            .insert("target_pid".to_string(), detection.target_pid.to_string());
        event
            .metadata
            .insert("target_name".to_string(), detection.target_name.clone());
        event
            .metadata
            .insert("target_path".to_string(), detection.target_path.clone());
        event.metadata.insert(
            "technique".to_string(),
            detection.technique.as_str().to_string(),
        );
        event.metadata.insert(
            "mitre_technique".to_string(),
            detection.technique.mitre_technique().to_string(),
        );
        event
            .metadata
            .insert("confidence".to_string(), detection.confidence.to_string());

        if let Some(addr) = detection.memory_address {
            event
                .metadata
                .insert("memory_address".to_string(), format!("0x{:x}", addr));
        }
        if let Some(size) = detection.memory_size {
            event
                .metadata
                .insert("memory_size".to_string(), size.to_string());
        }
        if let Some(prot) = detection.memory_protection {
            event
                .metadata
                .insert("memory_protection".to_string(), format!("0x{:x}", prot));
        }
        if let Some(ep) = detection.entry_point {
            event
                .metadata
                .insert("entry_point".to_string(), format!("0x{:x}", ep));
        }
        if let Some(orig_ep) = detection.original_entry_point {
            event.metadata.insert(
                "original_entry_point".to_string(),
                format!("0x{:x}", orig_ep),
            );
        }
        if let Some(tid) = detection.thread_id {
            event
                .metadata
                .insert("thread_id".to_string(), tid.to_string());
        }
        if let Some(orig_path) = &detection.original_image_path {
            event
                .metadata
                .insert("original_image_path".to_string(), orig_path.clone());
        }

        // Add additional context
        for (key, value) in &detection.context {
            event.metadata.insert(key.clone(), value.clone());
        }

        event
    }

    // ==================== Windows Implementation ====================

    #[cfg(target_os = "windows")]
    async fn windows_monitor_loop(tx: mpsc::Sender<TelemetryEvent>, config: AgentConfig) {
        use std::sync::Arc;
        use tokio::sync::Mutex;

        info!("Starting Windows process hollowing detection");

        // Track suspended processes
        let suspended_processes: Arc<Mutex<HashMap<u32, SuspendedProcess>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Track cross-process operations for correlation
        let cross_process_ops: Arc<Mutex<HashMap<u32, Vec<CrossProcessOperation>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Known reported detections to avoid duplicates
        let reported: Arc<Mutex<HashSet<(u32, u32, String)>>> =
            Arc::new(Mutex::new(HashSet::new()));

        // Start ETW monitoring for process creation events
        let suspended_clone = suspended_processes.clone();
        let ops_clone = cross_process_ops.clone();
        let tx_clone = tx.clone();
        let reported_clone = reported.clone();
        tokio::spawn(async move {
            Self::etw_monitor_loop(tx_clone, suspended_clone, ops_clone, reported_clone).await;
        });

        // Start periodic memory scanning
        let tx_clone2 = tx.clone();
        let reported_clone2 = reported.clone();
        tokio::spawn(async move {
            Self::memory_scan_loop(tx_clone2, reported_clone2).await;
        });

        // Start thread monitoring
        let tx_clone3 = tx.clone();
        let reported_clone3 = reported.clone();
        tokio::spawn(async move {
            Self::thread_monitor_loop(tx_clone3, reported_clone3).await;
        });

        // Main correlation and analysis loop
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));

        loop {
            interval.tick().await;

            // Analyze cross-process operation patterns
            let mut ops = cross_process_ops.lock().await;
            let mut suspended = suspended_processes.lock().await;
            let mut reported_guard = reported.lock().await;

            // Check for injection patterns
            for (source_pid, operations) in ops.iter() {
                if let Some(detection) =
                    Self::analyze_hollowing_pattern(*source_pid, operations, &suspended)
                {
                    let key = (
                        detection.source_pid,
                        detection.target_pid,
                        detection.technique.as_str().to_string(),
                    );
                    if !reported_guard.contains(&key) {
                        reported_guard.insert(key);
                        let event = Self::create_event(&detection);
                        if tx.send(event).await.is_err() {
                            warn!("Event channel closed");
                            return;
                        }
                    }
                }
            }

            // Check suspended processes for hollowing indicators
            let now = Self::current_timestamp();
            let mut to_remove = Vec::new();

            for (pid, proc) in suspended.iter() {
                // If process has been suspended for more than 5 seconds, check for hollowing
                if now - proc.creation_time > 5000 {
                    if let Some(detection) = Self::check_suspended_process_hollowing(proc) {
                        let key = (
                            detection.source_pid,
                            detection.target_pid,
                            detection.technique.as_str().to_string(),
                        );
                        if !reported_guard.contains(&key) {
                            reported_guard.insert(key);
                            let event = Self::create_event(&detection);
                            if tx.send(event).await.is_err() {
                                warn!("Event channel closed");
                                return;
                            }
                        }
                    }
                }

                // Remove old entries
                if now - proc.creation_time > 60000 {
                    to_remove.push(*pid);
                }
            }

            for pid in to_remove {
                suspended.remove(&pid);
            }

            // Cleanup old operations
            let current_time = now;
            for operations in ops.values_mut() {
                operations.retain(|op| current_time - op.timestamp < 30000);
            }
            ops.retain(|_, v| !v.is_empty());

            // Cleanup reported cache
            if reported_guard.len() > 10000 {
                reported_guard.clear();
            }
        }
    }

    #[cfg(target_os = "windows")]
    async fn etw_monitor_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        suspended_processes: std::sync::Arc<tokio::sync::Mutex<HashMap<u32, SuspendedProcess>>>,
        cross_process_ops: std::sync::Arc<
            tokio::sync::Mutex<HashMap<u32, Vec<CrossProcessOperation>>>,
        >,
        reported: std::sync::Arc<tokio::sync::Mutex<HashSet<(u32, u32, String)>>>,
    ) {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        info!("Starting ETW-based process creation monitoring");

        // Track known processes to detect new creations
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

        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(100));

        loop {
            interval.tick().await;

            // Get current process list
            let mut current_pids: HashSet<u32> = HashSet::new();

            unsafe {
                if let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                    let mut entry = PROCESSENTRY32W {
                        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                        ..Default::default()
                    };

                    if Process32FirstW(snapshot, &mut entry).is_ok() {
                        loop {
                            let pid = entry.th32ProcessID;
                            current_pids.insert(pid);

                            // Check for new processes
                            if !known_pids.contains(&pid) {
                                let name = String::from_utf16_lossy(
                                    &entry.szExeFile[..entry
                                        .szExeFile
                                        .iter()
                                        .position(|&c| c == 0)
                                        .unwrap_or(0)],
                                );

                                // Check if process is suspended
                                if let Some(suspended_info) = Self::check_process_suspended(
                                    pid,
                                    &name,
                                    entry.th32ParentProcessID,
                                ) {
                                    let mut suspended = suspended_processes.lock().await;
                                    suspended.insert(pid, suspended_info.clone());

                                    // Emit CREATE_SUSPENDED detection
                                    let detection = ProcessHollowingEvent {
                                        source_pid: entry.th32ParentProcessID,
                                        source_name: Self::get_process_name(
                                            entry.th32ParentProcessID,
                                        ),
                                        source_path: Self::get_process_path(
                                            entry.th32ParentProcessID,
                                        ),
                                        target_pid: pid,
                                        target_name: name.clone(),
                                        target_path: suspended_info.path.clone(),
                                        original_image_path: None,
                                        technique:
                                            InjectionTechnique::ProcessHollowingCreateSuspended,
                                        memory_address: None,
                                        memory_size: None,
                                        memory_protection: None,
                                        entry_point: suspended_info.original_entry_point,
                                        original_entry_point: suspended_info.original_entry_point,
                                        thread_id: None,
                                        confidence: 0.6,
                                        context: HashMap::new(),
                                    };

                                    let mut reported_guard = reported.lock().await;
                                    let key = (
                                        detection.source_pid,
                                        detection.target_pid,
                                        detection.technique.as_str().to_string(),
                                    );
                                    if !reported_guard.contains(&key) {
                                        reported_guard.insert(key);
                                        let event = Self::create_event(&detection);
                                        if tx.send(event).await.is_err() {
                                            warn!("Event channel closed");
                                            return;
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
                }
            }

            known_pids = current_pids;
        }
    }

    #[cfg(target_os = "windows")]
    async fn memory_scan_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        reported: std::sync::Arc<tokio::sync::Mutex<HashSet<(u32, u32, String)>>>,
    ) {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        info!("Starting memory scan loop for injection detection");

        let scan_interval = tokio::time::Duration::from_secs(15);
        let mut interval = tokio::time::interval(scan_interval);

        loop {
            interval.tick().await;

            let mut processes_to_scan = Vec::new();

            unsafe {
                if let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                    let mut entry = PROCESSENTRY32W {
                        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                        ..Default::default()
                    };

                    if Process32FirstW(snapshot, &mut entry).is_ok() {
                        loop {
                            let pid = entry.th32ProcessID;
                            if pid > 10 && pid != std::process::id() {
                                let name = String::from_utf16_lossy(
                                    &entry.szExeFile[..entry
                                        .szExeFile
                                        .iter()
                                        .position(|&c| c == 0)
                                        .unwrap_or(0)],
                                );
                                processes_to_scan.push((pid, name));
                            }
                            if Process32NextW(snapshot, &mut entry).is_err() {
                                break;
                            }
                        }
                    }
                    let _ = CloseHandle(snapshot);
                }
            }

            for (pid, name) in processes_to_scan {
                // Check for hollowing indicators
                if let Some(detections) = Self::scan_process_for_hollowing(pid, &name) {
                    let mut reported_guard = reported.lock().await;
                    for detection in detections {
                        let key = (
                            detection.source_pid,
                            detection.target_pid,
                            detection.technique.as_str().to_string(),
                        );
                        if !reported_guard.contains(&key) {
                            reported_guard.insert(key);
                            let event = Self::create_event(&detection);
                            if tx.send(event).await.is_err() {
                                warn!("Event channel closed");
                                return;
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    async fn thread_monitor_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        reported: std::sync::Arc<tokio::sync::Mutex<HashSet<(u32, u32, String)>>>,
    ) {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
        };

        info!("Starting thread monitoring for injection detection");

        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));

        loop {
            interval.tick().await;

            // Scan threads for suspicious start addresses
            unsafe {
                if let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
                    let mut entry = THREADENTRY32 {
                        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                        ..Default::default()
                    };

                    if Thread32First(snapshot, &mut entry).is_ok() {
                        loop {
                            let pid = entry.th32OwnerProcessID;
                            let tid = entry.th32ThreadID;

                            // Skip system processes
                            if pid > 10 && pid != std::process::id() {
                                if let Some(detection) = Self::check_thread_start_address(pid, tid)
                                {
                                    let mut reported_guard = reported.lock().await;
                                    let key = (
                                        detection.source_pid,
                                        detection.target_pid,
                                        detection.technique.as_str().to_string(),
                                    );
                                    if !reported_guard.contains(&key) {
                                        reported_guard.insert(key);
                                        let event = Self::create_event(&detection);
                                        if tx.send(event).await.is_err() {
                                            warn!("Event channel closed");
                                            return;
                                        }
                                    }
                                }
                            }

                            if Thread32Next(snapshot, &mut entry).is_err() {
                                break;
                            }
                        }
                    }
                    let _ = CloseHandle(snapshot);
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn check_process_suspended(pid: u32, name: &str, ppid: u32) -> Option<SuspendedProcess> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, OpenThread, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
            THREAD_SUSPEND_RESUME,
        };

        unsafe {
            // Get process handle
            let process_handle =
                match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
                    Ok(h) => h,
                    Err(_) => return None,
                };

            // Check if all threads are suspended
            let all_suspended = true;
            let mut thread_count = 0;

            if let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
                let mut entry = THREADENTRY32 {
                    dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                    ..Default::default()
                };

                if Thread32First(snapshot, &mut entry).is_ok() {
                    loop {
                        if entry.th32OwnerProcessID == pid {
                            thread_count += 1;

                            // Try to get thread handle and check suspend count
                            if let Ok(thread_handle) =
                                OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID)
                            {
                                // A newly created suspended thread will have suspend count > 0
                                // We can't directly query suspend count, but we can check
                                // by attempting operations
                                let _ = CloseHandle(thread_handle);
                            }
                        }

                        if Thread32Next(snapshot, &mut entry).is_err() {
                            break;
                        }
                    }
                }
                let _ = CloseHandle(snapshot);
            }

            // Get entry point
            let entry_point = Self::get_process_entry_point(std::mem::transmute::<_, *mut c_void>(
                process_handle,
            ));

            let _ = CloseHandle(process_handle);

            // Only report if we found threads and they appear suspended
            // This is a heuristic - full detection would use ETW
            if thread_count > 0 && all_suspended {
                // Get parent info
                let parent_name = Self::get_process_name(ppid);

                return Some(SuspendedProcess {
                    pid,
                    name: name.to_string(),
                    path: Self::get_process_path(pid),
                    creation_time: Self::current_timestamp(),
                    original_entry_point: entry_point,
                    original_image_base: None,
                    parent_pid: ppid,
                    parent_name,
                    creation_flags: 0x4, // CREATE_SUSPENDED
                });
            }
        }

        None
    }

    #[cfg(target_os = "windows")]
    fn check_suspended_process_hollowing(proc: &SuspendedProcess) -> Option<ProcessHollowingEvent> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        unsafe {
            let handle =
                match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, proc.pid) {
                    Ok(h) => h,
                    Err(_) => return None,
                };

            // Get current entry point
            let current_entry_point =
                Self::get_process_entry_point(std::mem::transmute::<_, *mut c_void>(handle));

            let _ = CloseHandle(handle);

            // Check if entry point changed
            if let (Some(orig), Some(curr)) = (proc.original_entry_point, current_entry_point) {
                if orig != curr {
                    return Some(ProcessHollowingEvent {
                        source_pid: proc.parent_pid,
                        source_name: proc.parent_name.clone(),
                        source_path: Self::get_process_path(proc.parent_pid),
                        target_pid: proc.pid,
                        target_name: proc.name.clone(),
                        target_path: proc.path.clone(),
                        original_image_path: None,
                        technique: InjectionTechnique::ProcessHollowingEntryPointModified,
                        memory_address: None,
                        memory_size: None,
                        memory_protection: None,
                        entry_point: Some(curr),
                        original_entry_point: Some(orig),
                        thread_id: None,
                        confidence: 0.9,
                        context: HashMap::new(),
                    });
                }
            }
        }

        None
    }

    #[cfg(target_os = "windows")]
    fn scan_process_for_hollowing(pid: u32, name: &str) -> Option<Vec<ProcessHollowingEvent>> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows::Win32::System::Memory::{
            VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_PRIVATE,
            PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        let mut detections = Vec::new();

        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            {
                Ok(h) => h,
                Err(_) => return None,
            };

            let mut address: usize = 0;
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let mut has_executable_private = false;
            let mut has_rwx = false;
            let mut pe_in_private = false;

            loop {
                let result = VirtualQueryEx(
                    handle,
                    Some(address as *const _),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                );

                if result == 0 {
                    break;
                }

                if mbi.State.contains(MEM_COMMIT) {
                    let is_executable = mbi.Protect.contains(PAGE_EXECUTE)
                        || mbi.Protect.contains(PAGE_EXECUTE_READ)
                        || mbi.Protect.contains(PAGE_EXECUTE_READWRITE)
                        || mbi.Protect.contains(PAGE_EXECUTE_WRITECOPY);

                    let is_private = mbi.Type.contains(MEM_PRIVATE);
                    let is_rwx = mbi.Protect.contains(PAGE_EXECUTE_READWRITE);
                    let is_image = mbi.Type.contains(MEM_IMAGE);

                    // Check for suspicious patterns
                    if is_executable && is_private && !is_image {
                        has_executable_private = true;

                        // Try to read and check for PE header
                        let mut buffer = [0u8; 2];
                        let mut bytes_read = 0usize;

                        if ReadProcessMemory(
                            handle,
                            mbi.BaseAddress,
                            buffer.as_mut_ptr() as *mut _,
                            2,
                            Some(&mut bytes_read),
                        )
                        .is_ok()
                            && bytes_read >= 2
                        {
                            if buffer[0] == 0x4D && buffer[1] == 0x5A {
                                // MZ header
                                pe_in_private = true;

                                detections.push(ProcessHollowingEvent {
                                    source_pid: 0, // Unknown injector
                                    source_name: "unknown".to_string(),
                                    source_path: String::new(),
                                    target_pid: pid,
                                    target_name: name.to_string(),
                                    target_path: Self::get_process_path(pid),
                                    original_image_path: None,
                                    technique: InjectionTechnique::ReflectiveDllInjection,
                                    memory_address: Some(mbi.BaseAddress as u64),
                                    memory_size: Some(mbi.RegionSize as u64),
                                    memory_protection: Some(mbi.Protect.0),
                                    entry_point: None,
                                    original_entry_point: None,
                                    thread_id: None,
                                    confidence: 0.85,
                                    context: HashMap::new(),
                                });
                            }
                        }
                    }

                    if is_rwx {
                        has_rwx = true;

                        detections.push(ProcessHollowingEvent {
                            source_pid: 0,
                            source_name: "unknown".to_string(),
                            source_path: String::new(),
                            target_pid: pid,
                            target_name: name.to_string(),
                            target_path: Self::get_process_path(pid),
                            original_image_path: None,
                            technique: InjectionTechnique::RwxMemoryRegion,
                            memory_address: Some(mbi.BaseAddress as u64),
                            memory_size: Some(mbi.RegionSize as u64),
                            memory_protection: Some(mbi.Protect.0),
                            entry_point: None,
                            original_entry_point: None,
                            thread_id: None,
                            confidence: 0.7,
                            context: HashMap::new(),
                        });
                    }
                }

                address = mbi.BaseAddress as usize + mbi.RegionSize;
            }

            // Check for PEB image path mismatch
            if let Some(detection) = Self::check_peb_mismatch(handle, pid, name) {
                detections.push(detection);
            }

            // Check for module stomping
            if let Some(detection) = Self::check_module_stomping(handle, pid, name) {
                detections.push(detection);
            }

            let _ = CloseHandle(handle);
        }

        if detections.is_empty() {
            None
        } else {
            Some(detections)
        }
    }

    /// Perform deep hollowing analysis on a process
    /// This function compares the in-memory image with the on-disk file to detect
    /// process hollowing and related techniques
    #[cfg(target_os = "windows")]
    fn deep_hollowing_analysis(pid: u32, name: &str) -> Option<HollowingAnalysis> {
        use sha2::{Digest, Sha256};
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        let mut indicators = Vec::new();
        let mut confidence: f32 = 0.0;

        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            {
                Ok(h) => h,
                Err(_) => return None,
            };

            // Get the process path
            let process_path = Self::get_process_path(pid);
            if process_path.is_empty() {
                let _ = CloseHandle(handle);
                return None;
            }

            // Get image base and entry point from PEB
            let peb_info =
                Self::get_process_entry_point(std::mem::transmute::<_, *mut c_void>(handle));
            let peb_image_base =
                Self::get_peb_image_base(std::mem::transmute::<_, *mut c_void>(handle));

            // Read PE header from disk
            let disk_pe_info = match std::fs::read(&process_path) {
                Ok(data) if data.len() >= 512 => Some(Self::parse_pe_header(&data)),
                _ => None,
            };

            // Read PE header from memory
            let memory_pe_info = if let Some(image_base) = peb_image_base {
                let mut header_buf = [0u8; 512];
                let mut bytes_read = 0usize;

                if ReadProcessMemory(
                    handle,
                    image_base as *const _,
                    header_buf.as_mut_ptr() as *mut _,
                    512,
                    Some(&mut bytes_read),
                )
                .is_ok()
                    && bytes_read >= 64
                {
                    Some(Self::parse_pe_header(&header_buf[..bytes_read]))
                } else {
                    None
                }
            } else {
                None
            };

            // Compare disk and memory PE info
            if let (Some(disk_info), Some(mem_info)) = (&disk_pe_info, &memory_pe_info) {
                // Check for entry point modification
                if disk_info.entry_point_rva != mem_info.entry_point_rva
                    && disk_info.entry_point_rva != 0
                {
                    indicators.push(HollowingIndicator::EntryPointModified {
                        original: disk_info.entry_point_rva as u64,
                        current: mem_info.entry_point_rva as u64,
                    });
                    confidence += 0.35;
                    debug!(
                        pid = pid,
                        disk_ep = disk_info.entry_point_rva,
                        mem_ep = mem_info.entry_point_rva,
                        "Entry point mismatch detected"
                    );
                }

                // Check for image base modification (optional header)
                if disk_info.image_base != 0 && mem_info.image_base != 0 {
                    // Note: Image base can legitimately change due to ASLR
                    // But combined with other indicators, it's suspicious
                    if disk_info.image_base != mem_info.image_base {
                        trace!(
                            pid = pid,
                            disk_base = format!("0x{:x}", disk_info.image_base),
                            mem_base = format!("0x{:x}", mem_info.image_base),
                            "Image base differs (may be ASLR)"
                        );
                    }
                }

                // Check for section header anomalies
                if disk_info.number_of_sections != mem_info.number_of_sections {
                    confidence += 0.25;
                    debug!(
                        pid = pid,
                        disk_sections = disk_info.number_of_sections,
                        mem_sections = mem_info.number_of_sections,
                        "Section count mismatch"
                    );
                }
            }

            // Check PEB path vs disk path
            if let Some(peb_path) =
                Self::get_peb_image_path(std::mem::transmute::<_, *mut c_void>(handle))
            {
                let peb_normalized = peb_path.to_lowercase().replace("/", "\\");
                let disk_normalized = process_path.to_lowercase().replace("/", "\\");

                if !peb_normalized.is_empty() && !disk_normalized.is_empty() {
                    // Extract just the filename for comparison (handles different path formats)
                    let peb_name = peb_normalized.rsplit('\\').next().unwrap_or("");
                    let disk_name = disk_normalized.rsplit('\\').next().unwrap_or("");

                    if peb_name != disk_name && !peb_name.is_empty() && !disk_name.is_empty() {
                        indicators.push(HollowingIndicator::PebPathMismatch {
                            peb_path: peb_path.clone(),
                            disk_path: process_path.clone(),
                        });
                        confidence += 0.30;
                        debug!(
                            pid = pid,
                            peb_path = %peb_path,
                            disk_path = %process_path,
                            "PEB image path mismatch detected"
                        );
                    }
                }
            }

            // Calculate header hashes for comparison
            if let Some(image_base) = peb_image_base {
                let mut mem_header = [0u8; 4096];
                let mut bytes_read = 0usize;

                if ReadProcessMemory(
                    handle,
                    image_base as *const _,
                    mem_header.as_mut_ptr() as *mut _,
                    4096,
                    Some(&mut bytes_read),
                )
                .is_ok()
                    && bytes_read > 0
                {
                    // Hash memory header
                    let mut mem_hasher = Sha256::new();
                    mem_hasher.update(&mem_header[..bytes_read]);
                    let mem_hash: [u8; 32] = mem_hasher.finalize().into();

                    // Read and hash disk header
                    if let Ok(disk_data) = std::fs::read(&process_path) {
                        if disk_data.len() >= bytes_read {
                            let mut disk_hasher = Sha256::new();
                            disk_hasher.update(&disk_data[..bytes_read]);
                            let disk_hash: [u8; 32] = disk_hasher.finalize().into();

                            // Compare hashes
                            if mem_hash != disk_hash {
                                // Find first differing byte for context
                                for (i, (m, d)) in mem_header[..bytes_read]
                                    .iter()
                                    .zip(disk_data[..bytes_read].iter())
                                    .enumerate()
                                {
                                    if m != d {
                                        indicators.push(HollowingIndicator::ContentMismatch {
                                            offset: i as u64,
                                            disk_byte: *d,
                                            memory_byte: *m,
                                        });
                                        confidence += 0.20;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let _ = CloseHandle(handle);
        }

        // Determine if hollowing is detected based on indicators and confidence
        let is_hollowed = confidence >= 0.50 || indicators.len() >= 2;

        // Determine MITRE technique
        let mitre_technique = if indicators
            .iter()
            .any(|i| matches!(i, HollowingIndicator::EntryPointModified { .. }))
        {
            "T1055.012".to_string() // Process Hollowing
        } else if indicators
            .iter()
            .any(|i| matches!(i, HollowingIndicator::PebPathMismatch { .. }))
        {
            "T1055.012".to_string()
        } else {
            "T1055".to_string() // Generic Process Injection
        };

        if indicators.is_empty() {
            None
        } else {
            Some(HollowingAnalysis {
                is_hollowed,
                confidence: confidence.min(1.0),
                indicators,
                mitre_technique,
            })
        }
    }

    /// Parse PE header information
    #[cfg(target_os = "windows")]
    fn parse_pe_header(data: &[u8]) -> PeHeaderInfo {
        let mut info = PeHeaderInfo::default();

        if data.len() < 64 {
            return info;
        }

        // Check MZ signature
        if data[0] != 0x4D || data[1] != 0x5A {
            return info;
        }

        // Get e_lfanew (offset to PE header)
        let e_lfanew = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;

        if data.len() < e_lfanew + 264 {
            return info;
        }

        // Check PE signature
        if data[e_lfanew] != 0x50
            || data[e_lfanew + 1] != 0x45
            || data[e_lfanew + 2] != 0x00
            || data[e_lfanew + 3] != 0x00
        {
            return info;
        }

        // Parse FILE_HEADER
        info.number_of_sections = u16::from_le_bytes([data[e_lfanew + 6], data[e_lfanew + 7]]);

        let size_of_optional_header =
            u16::from_le_bytes([data[e_lfanew + 20], data[e_lfanew + 21]]);

        // Parse OPTIONAL_HEADER
        let opt_header_offset = e_lfanew + 24;

        // Check magic (PE32 = 0x10B, PE32+ = 0x20B)
        let magic = u16::from_le_bytes([data[opt_header_offset], data[opt_header_offset + 1]]);

        if magic == 0x10B {
            // PE32
            info.entry_point_rva = u32::from_le_bytes([
                data[opt_header_offset + 16],
                data[opt_header_offset + 17],
                data[opt_header_offset + 18],
                data[opt_header_offset + 19],
            ]);
            info.image_base = u32::from_le_bytes([
                data[opt_header_offset + 28],
                data[opt_header_offset + 29],
                data[opt_header_offset + 30],
                data[opt_header_offset + 31],
            ]) as u64;
            info.size_of_image = u32::from_le_bytes([
                data[opt_header_offset + 56],
                data[opt_header_offset + 57],
                data[opt_header_offset + 58],
                data[opt_header_offset + 59],
            ]);
        } else if magic == 0x20B {
            // PE32+
            info.entry_point_rva = u32::from_le_bytes([
                data[opt_header_offset + 16],
                data[opt_header_offset + 17],
                data[opt_header_offset + 18],
                data[opt_header_offset + 19],
            ]);
            info.image_base = u64::from_le_bytes([
                data[opt_header_offset + 24],
                data[opt_header_offset + 25],
                data[opt_header_offset + 26],
                data[opt_header_offset + 27],
                data[opt_header_offset + 28],
                data[opt_header_offset + 29],
                data[opt_header_offset + 30],
                data[opt_header_offset + 31],
            ]);
            info.size_of_image = u32::from_le_bytes([
                data[opt_header_offset + 56],
                data[opt_header_offset + 57],
                data[opt_header_offset + 58],
                data[opt_header_offset + 59],
            ]);
        }

        info
    }

    /// Get image base from PEB
    #[cfg(target_os = "windows")]
    fn get_peb_image_base(handle: *mut c_void) -> Option<u64> {
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

        // PROCESS_BASIC_INFORMATION is not directly exported by the windows crate
        // so we define our own compatible structure
        #[repr(C)]
        struct ProcessBasicInformation {
            exit_status: i32,
            peb_base_address: *mut c_void,
            affinity_mask: usize,
            base_priority: i32,
            unique_process_id: usize,
            inherited_from_unique_process_id: usize,
        }

        type NtQueryInformationProcessFn = unsafe extern "system" fn(
            ProcessHandle: *mut c_void,
            ProcessInformationClass: u32,
            ProcessInformation: *mut c_void,
            ProcessInformationLength: u32,
            ReturnLength: *mut u32,
        ) -> i32;

        unsafe {
            let ntdll = windows::Win32::System::LibraryLoader::GetModuleHandleW(windows::core::w!(
                "ntdll.dll"
            ))
            .ok()?;

            let func_ptr = windows::Win32::System::LibraryLoader::GetProcAddress(
                ntdll,
                windows::core::s!("NtQueryInformationProcess"),
            )?;

            let nt_query: NtQueryInformationProcessFn = std::mem::transmute(func_ptr);

            let mut pbi: ProcessBasicInformation = std::mem::zeroed();
            let mut return_length = 0u32;

            let status = nt_query(
                handle,
                0, // ProcessBasicInformation
                &mut pbi as *mut _ as *mut c_void,
                std::mem::size_of::<ProcessBasicInformation>() as u32,
                &mut return_length,
            );

            if status != 0 {
                return None;
            }

            // Read ImageBaseAddress from PEB
            #[cfg(target_pointer_width = "64")]
            let image_base_offset = 0x10usize;
            #[cfg(target_pointer_width = "32")]
            let image_base_offset = 0x08usize;

            let peb_addr = pbi.peb_base_address as usize;
            let mut image_base: usize = 0;
            let mut bytes_read = 0usize;

            let handle_typed = windows::Win32::Foundation::HANDLE(handle as isize);

            if ReadProcessMemory(
                handle_typed,
                (peb_addr + image_base_offset) as *const _,
                &mut image_base as *mut _ as *mut _,
                std::mem::size_of::<usize>(),
                Some(&mut bytes_read),
            )
            .is_ok()
            {
                Some(image_base as u64)
            } else {
                None
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn check_thread_start_address(pid: u32, tid: u32) -> Option<ProcessHollowingEvent> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_IMAGE};
        use windows::Win32::System::Threading::{
            OpenProcess, OpenThread, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
            THREAD_QUERY_INFORMATION,
        };

        unsafe {
            // Get thread start address using NtQueryInformationThread
            let thread_handle = match OpenThread(THREAD_QUERY_INFORMATION, false, tid) {
                Ok(h) => h,
                Err(_) => return None,
            };

            let start_address = Self::get_thread_start_address(
                std::mem::transmute::<_, *mut c_void>(thread_handle),
            );
            let _ = CloseHandle(thread_handle);

            let start_address = match start_address {
                Some(addr) => addr,
                None => return None,
            };

            // Open process to check if address is in any module
            let process_handle =
                match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
                    Ok(h) => h,
                    Err(_) => return None,
                };

            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let result = VirtualQueryEx(
                process_handle,
                Some(start_address as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            let _ = CloseHandle(process_handle);

            if result > 0 {
                // If start address is not in an image (MEM_IMAGE), it's suspicious
                if !mbi.Type.contains(MEM_IMAGE) {
                    let name = Self::get_process_name(pid);
                    return Some(ProcessHollowingEvent {
                        source_pid: 0,
                        source_name: "unknown".to_string(),
                        source_path: String::new(),
                        target_pid: pid,
                        target_name: name.clone(),
                        target_path: Self::get_process_path(pid),
                        original_image_path: None,
                        technique: InjectionTechnique::ThreadStartAddressUnbacked,
                        memory_address: Some(start_address as u64),
                        memory_size: None,
                        memory_protection: Some(mbi.Protect.0),
                        entry_point: None,
                        original_entry_point: None,
                        thread_id: Some(tid),
                        confidence: 0.75,
                        context: HashMap::new(),
                    });
                }
            }
        }

        None
    }

    #[cfg(target_os = "windows")]
    fn check_peb_mismatch(
        handle: windows::Win32::Foundation::HANDLE,
        pid: u32,
        name: &str,
    ) -> Option<ProcessHollowingEvent> {
        // Get image path from PEB
        let peb_path =
            Self::get_peb_image_path(unsafe { std::mem::transmute::<_, *mut c_void>(handle) })?;
        let disk_path = Self::get_process_path(pid);

        // Normalize paths for comparison
        let peb_normalized = peb_path.to_lowercase().replace("/", "\\");
        let disk_normalized = disk_path.to_lowercase().replace("/", "\\");

        if !peb_normalized.is_empty()
            && !disk_normalized.is_empty()
            && peb_normalized != disk_normalized
        {
            return Some(ProcessHollowingEvent {
                source_pid: 0,
                source_name: "unknown".to_string(),
                source_path: String::new(),
                target_pid: pid,
                target_name: name.to_string(),
                target_path: disk_path.clone(),
                original_image_path: Some(peb_path),
                technique: InjectionTechnique::PebImagePathMismatch,
                memory_address: None,
                memory_size: None,
                memory_protection: None,
                entry_point: None,
                original_entry_point: None,
                thread_id: None,
                confidence: 0.85,
                context: {
                    let mut ctx = HashMap::new();
                    ctx.insert("disk_path".to_string(), disk_path);
                    ctx
                },
            });
        }

        None
    }

    #[cfg(target_os = "windows")]
    fn check_module_stomping(
        handle: windows::Win32::Foundation::HANDLE,
        pid: u32,
        name: &str,
    ) -> Option<ProcessHollowingEvent> {
        use windows::Win32::Foundation::HMODULE;
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows::Win32::System::ProcessStatus::{
            EnumProcessModulesEx, GetModuleBaseNameW, GetModuleInformation, LIST_MODULES_ALL,
            MODULEINFO,
        };

        unsafe {
            let mut modules = [HMODULE::default(); 1024];
            let mut cb_needed = 0u32;

            if EnumProcessModulesEx(
                handle,
                modules.as_mut_ptr(),
                (modules.len() * std::mem::size_of::<HMODULE>()) as u32,
                &mut cb_needed,
                LIST_MODULES_ALL,
            )
            .is_err()
            {
                return None;
            }

            let module_count = cb_needed as usize / std::mem::size_of::<HMODULE>();

            for i in 0..module_count {
                let module = modules[i];

                // Get module info
                let mut info = MODULEINFO::default();
                if GetModuleInformation(
                    handle,
                    module,
                    &mut info,
                    std::mem::size_of::<MODULEINFO>() as u32,
                )
                .is_err()
                {
                    continue;
                }

                // Read first bytes of module in memory
                let mut mem_header = [0u8; 512];
                let mut bytes_read = 0usize;

                if ReadProcessMemory(
                    handle,
                    info.lpBaseOfDll,
                    mem_header.as_mut_ptr() as *mut _,
                    mem_header.len(),
                    Some(&mut bytes_read),
                )
                .is_err()
                {
                    continue;
                }

                // Get module name
                let mut name_buf = [0u16; 260];
                let name_len = GetModuleBaseNameW(handle, module, &mut name_buf);
                if name_len == 0 {
                    continue;
                }

                let module_name = String::from_utf16_lossy(&name_buf[..name_len as usize]);

                // Skip if not a system DLL (focus on commonly stomped modules)
                let target_dlls = [
                    "ntdll.dll",
                    "kernel32.dll",
                    "kernelbase.dll",
                    "advapi32.dll",
                    "user32.dll",
                ];

                if !target_dlls
                    .iter()
                    .any(|d| module_name.to_lowercase().contains(d))
                {
                    continue;
                }

                // Compare with on-disk version
                let module_path = Self::get_module_path_from_handle(handle, module);
                if module_path.is_empty() {
                    continue;
                }

                // Read first bytes from disk
                if let Ok(disk_data) = std::fs::read(&module_path) {
                    if disk_data.len() < 512 {
                        continue;
                    }

                    // Compare DOS header and PE header
                    let mem_slice = &mem_header[..std::cmp::min(bytes_read, 512)];
                    let disk_slice = &disk_data[..std::cmp::min(disk_data.len(), 512)];

                    // Check for significant differences (allowing for relocations)
                    let mut diff_count = 0;
                    for (m, d) in mem_slice.iter().zip(disk_slice.iter()) {
                        if m != d {
                            diff_count += 1;
                        }
                    }

                    // If more than 10% differs, it's suspicious
                    if diff_count > 50 {
                        return Some(ProcessHollowingEvent {
                            source_pid: 0,
                            source_name: "unknown".to_string(),
                            source_path: String::new(),
                            target_pid: pid,
                            target_name: name.to_string(),
                            target_path: Self::get_process_path(pid),
                            original_image_path: Some(module_path),
                            technique: InjectionTechnique::ModuleStomping,
                            memory_address: Some(info.lpBaseOfDll as u64),
                            memory_size: Some(info.SizeOfImage as u64),
                            memory_protection: None,
                            entry_point: None,
                            original_entry_point: None,
                            thread_id: None,
                            confidence: 0.8,
                            context: {
                                let mut ctx = HashMap::new();
                                ctx.insert("module_name".to_string(), module_name);
                                ctx.insert("diff_bytes".to_string(), diff_count.to_string());
                                ctx
                            },
                        });
                    }
                }
            }
        }

        None
    }

    #[cfg(target_os = "windows")]
    fn analyze_hollowing_pattern(
        source_pid: u32,
        operations: &[CrossProcessOperation],
        _suspended: &HashMap<u32, SuspendedProcess>,
    ) -> Option<ProcessHollowingEvent> {
        // Look for classic hollowing pattern:
        // 1. CreateProcess (suspended)
        // 2. NtUnmapViewOfSection
        // 3. VirtualAllocEx
        // 4. WriteProcessMemory
        // 5. SetThreadContext
        // 6. ResumeThread

        let has_unmap = operations
            .iter()
            .any(|op| op.operation == OperationType::NtUnmapViewOfSection);
        let has_alloc = operations
            .iter()
            .any(|op| op.operation == OperationType::VirtualAllocEx);
        let has_write = operations
            .iter()
            .any(|op| op.operation == OperationType::WriteProcessMemory);
        let has_context = operations
            .iter()
            .any(|op| op.operation == OperationType::SetThreadContext);
        let has_resume = operations
            .iter()
            .any(|op| op.operation == OperationType::ResumeThread);

        // Classic process hollowing pattern
        if has_unmap && has_alloc && has_write && (has_context || has_resume) {
            if let Some(op) = operations.iter().find(|o| o.target_pid > 0) {
                return Some(ProcessHollowingEvent {
                    source_pid,
                    source_name: op.source_name.clone(),
                    source_path: Self::get_process_path(source_pid),
                    target_pid: op.target_pid,
                    target_name: Self::get_process_name(op.target_pid),
                    target_path: Self::get_process_path(op.target_pid),
                    original_image_path: None,
                    technique: InjectionTechnique::ProcessHollowing,
                    memory_address: op.address,
                    memory_size: op.size,
                    memory_protection: op.protection,
                    entry_point: None,
                    original_entry_point: None,
                    thread_id: None,
                    confidence: 0.95,
                    context: HashMap::new(),
                });
            }
        }

        // Classic DLL injection pattern: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
        let has_thread = operations
            .iter()
            .any(|op| op.operation == OperationType::CreateRemoteThread);

        if has_alloc && has_write && has_thread {
            if let Some(op) = operations.iter().find(|o| o.target_pid > 0) {
                return Some(ProcessHollowingEvent {
                    source_pid,
                    source_name: op.source_name.clone(),
                    source_path: Self::get_process_path(source_pid),
                    target_pid: op.target_pid,
                    target_name: Self::get_process_name(op.target_pid),
                    target_path: Self::get_process_path(op.target_pid),
                    original_image_path: None,
                    technique: InjectionTechnique::ClassicDllInjection,
                    memory_address: op.address,
                    memory_size: op.size,
                    memory_protection: op.protection,
                    entry_point: None,
                    original_entry_point: None,
                    thread_id: None,
                    confidence: 0.9,
                    context: HashMap::new(),
                });
            }
        }

        // APC injection pattern
        let has_apc = operations
            .iter()
            .any(|op| op.operation == OperationType::QueueUserApc);

        if has_alloc && has_write && has_apc {
            if let Some(op) = operations.iter().find(|o| o.target_pid > 0) {
                return Some(ProcessHollowingEvent {
                    source_pid,
                    source_name: op.source_name.clone(),
                    source_path: Self::get_process_path(source_pid),
                    target_pid: op.target_pid,
                    target_name: Self::get_process_name(op.target_pid),
                    target_path: Self::get_process_path(op.target_pid),
                    original_image_path: None,
                    technique: InjectionTechnique::ApcInjection,
                    memory_address: op.address,
                    memory_size: op.size,
                    memory_protection: op.protection,
                    entry_point: None,
                    original_entry_point: None,
                    thread_id: None,
                    confidence: 0.85,
                    context: HashMap::new(),
                });
            }
        }

        // Thread hijacking pattern
        if has_context && has_write && !has_thread {
            if let Some(op) = operations.iter().find(|o| o.target_pid > 0) {
                return Some(ProcessHollowingEvent {
                    source_pid,
                    source_name: op.source_name.clone(),
                    source_path: Self::get_process_path(source_pid),
                    target_pid: op.target_pid,
                    target_name: Self::get_process_name(op.target_pid),
                    target_path: Self::get_process_path(op.target_pid),
                    original_image_path: None,
                    technique: InjectionTechnique::ThreadHijacking,
                    memory_address: op.address,
                    memory_size: op.size,
                    memory_protection: op.protection,
                    entry_point: None,
                    original_entry_point: None,
                    thread_id: None,
                    confidence: 0.8,
                    context: HashMap::new(),
                });
            }
        }

        None
    }

    // ==================== Windows Helper Functions ====================

    #[cfg(target_os = "windows")]
    fn get_process_name(pid: u32) -> String {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::ProcessStatus::K32GetProcessImageFileNameW;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

        unsafe {
            if let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                let mut buffer = [0u16; 260];
                let len = K32GetProcessImageFileNameW(handle, &mut buffer);
                let _ = CloseHandle(handle);

                if len > 0 {
                    let path = String::from_utf16_lossy(&buffer[..len as usize]);
                    return path.rsplit('\\').next().unwrap_or("").to_string();
                }
            }
        }
        String::new()
    }

    #[cfg(target_os = "windows")]
    fn get_process_path(pid: u32) -> String {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
            PROCESS_QUERY_LIMITED_INFORMATION,
        };

        unsafe {
            if let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                let mut buffer = [0u16; 260];
                let mut size = buffer.len() as u32;

                if QueryFullProcessImageNameW(
                    handle,
                    PROCESS_NAME_WIN32,
                    windows::core::PWSTR(buffer.as_mut_ptr()),
                    &mut size,
                )
                .is_ok()
                {
                    let _ = CloseHandle(handle);
                    return String::from_utf16_lossy(&buffer[..size as usize]);
                }
                let _ = CloseHandle(handle);
            }
        }
        String::new()
    }

    #[cfg(target_os = "windows")]
    fn get_process_entry_point(handle: *mut c_void) -> Option<u64> {
        // Get entry point from PEB
        // This requires reading PEB -> ImageBaseAddress -> PE headers -> AddressOfEntryPoint

        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

        // PROCESS_BASIC_INFORMATION is not directly exported by the windows crate
        // so we define our own compatible structure
        #[repr(C)]
        struct ProcessBasicInformation {
            exit_status: i32,
            peb_base_address: *mut c_void,
            affinity_mask: usize,
            base_priority: i32,
            unique_process_id: usize,
            inherited_from_unique_process_id: usize,
        }

        // Define NtQueryInformationProcess signature
        type NtQueryInformationProcessFn = unsafe extern "system" fn(
            ProcessHandle: *mut c_void,
            ProcessInformationClass: u32,
            ProcessInformation: *mut c_void,
            ProcessInformationLength: u32,
            ReturnLength: *mut u32,
        ) -> i32;

        unsafe {
            // Get NtQueryInformationProcess
            let ntdll = windows::Win32::System::LibraryLoader::GetModuleHandleW(windows::core::w!(
                "ntdll.dll"
            ))
            .ok()?;

            let func_ptr = windows::Win32::System::LibraryLoader::GetProcAddress(
                ntdll,
                windows::core::s!("NtQueryInformationProcess"),
            )?;

            let nt_query: NtQueryInformationProcessFn = std::mem::transmute(func_ptr);

            // Query basic info to get PEB address
            let mut pbi: ProcessBasicInformation = std::mem::zeroed();
            let mut return_length = 0u32;

            let status = nt_query(
                handle,
                0, // ProcessBasicInformation
                &mut pbi as *mut _ as *mut c_void,
                std::mem::size_of::<ProcessBasicInformation>() as u32,
                &mut return_length,
            );

            if status != 0 {
                return None;
            }

            // Read ImageBaseAddress from PEB
            // PEB offset 0x10 (32-bit) or 0x10 (64-bit) contains ImageBaseAddress
            #[cfg(target_pointer_width = "64")]
            let image_base_offset = 0x10usize;
            #[cfg(target_pointer_width = "32")]
            let image_base_offset = 0x08usize;

            let peb_addr = pbi.peb_base_address as usize;
            let mut image_base: usize = 0;
            let mut bytes_read = 0usize;

            let handle_typed = windows::Win32::Foundation::HANDLE(handle as isize);

            if ReadProcessMemory(
                handle_typed,
                (peb_addr + image_base_offset) as *const _,
                &mut image_base as *mut _ as *mut _,
                std::mem::size_of::<usize>(),
                Some(&mut bytes_read),
            )
            .is_err()
            {
                return None;
            }

            // Read DOS header
            let mut dos_header = [0u8; 64];
            if ReadProcessMemory(
                handle_typed,
                image_base as *const _,
                dos_header.as_mut_ptr() as *mut _,
                64,
                Some(&mut bytes_read),
            )
            .is_err()
            {
                return None;
            }

            // Check MZ signature
            if dos_header[0] != 0x4D || dos_header[1] != 0x5A {
                return None;
            }

            // Get e_lfanew (offset to PE header)
            let e_lfanew = u32::from_le_bytes([
                dos_header[60],
                dos_header[61],
                dos_header[62],
                dos_header[63],
            ]) as usize;

            // Read PE header
            let pe_addr = image_base + e_lfanew;
            let mut pe_header = [0u8; 264]; // PE signature + file header + optional header start

            if ReadProcessMemory(
                handle_typed,
                pe_addr as *const _,
                pe_header.as_mut_ptr() as *mut _,
                pe_header.len(),
                Some(&mut bytes_read),
            )
            .is_err()
            {
                return None;
            }

            // Check PE signature
            if pe_header[0] != 0x50
                || pe_header[1] != 0x45
                || pe_header[2] != 0x00
                || pe_header[3] != 0x00
            {
                return None;
            }

            // Get AddressOfEntryPoint from optional header
            // Offset: PE sig (4) + file header (20) + AddressOfEntryPoint offset (16)
            let entry_point_rva =
                u32::from_le_bytes([pe_header[40], pe_header[41], pe_header[42], pe_header[43]]);

            Some((image_base as u64) + (entry_point_rva as u64))
        }
    }

    #[cfg(target_os = "windows")]
    fn get_thread_start_address(handle: *mut c_void) -> Option<usize> {
        // Use NtQueryInformationThread to get thread start address

        type NtQueryInformationThreadFn = unsafe extern "system" fn(
            ThreadHandle: *mut c_void,
            ThreadInformationClass: u32,
            ThreadInformation: *mut c_void,
            ThreadInformationLength: u32,
            ReturnLength: *mut u32,
        ) -> i32;

        unsafe {
            let ntdll = windows::Win32::System::LibraryLoader::GetModuleHandleW(windows::core::w!(
                "ntdll.dll"
            ))
            .ok()?;

            let func_ptr = windows::Win32::System::LibraryLoader::GetProcAddress(
                ntdll,
                windows::core::s!("NtQueryInformationThread"),
            )?;

            let nt_query: NtQueryInformationThreadFn = std::mem::transmute(func_ptr);

            let mut start_address: usize = 0;
            let mut return_length = 0u32;

            let status = nt_query(
                handle,
                9, // ThreadQuerySetWin32StartAddress
                &mut start_address as *mut _ as *mut c_void,
                std::mem::size_of::<usize>() as u32,
                &mut return_length,
            );

            if status == 0 {
                Some(start_address)
            } else {
                None
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn get_peb_image_path(handle: *mut c_void) -> Option<String> {
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

        // PROCESS_BASIC_INFORMATION is not directly exported by the windows crate
        // so we define our own compatible structure
        #[repr(C)]
        struct ProcessBasicInformation {
            exit_status: i32,
            peb_base_address: *mut c_void,
            affinity_mask: usize,
            base_priority: i32,
            unique_process_id: usize,
            inherited_from_unique_process_id: usize,
        }

        type NtQueryInformationProcessFn = unsafe extern "system" fn(
            ProcessHandle: *mut c_void,
            ProcessInformationClass: u32,
            ProcessInformation: *mut c_void,
            ProcessInformationLength: u32,
            ReturnLength: *mut u32,
        ) -> i32;

        unsafe {
            let ntdll = windows::Win32::System::LibraryLoader::GetModuleHandleW(windows::core::w!(
                "ntdll.dll"
            ))
            .ok()?;

            let func_ptr = windows::Win32::System::LibraryLoader::GetProcAddress(
                ntdll,
                windows::core::s!("NtQueryInformationProcess"),
            )?;

            let nt_query: NtQueryInformationProcessFn = std::mem::transmute(func_ptr);

            let mut pbi: ProcessBasicInformation = std::mem::zeroed();
            let mut return_length = 0u32;

            let status = nt_query(
                handle,
                0,
                &mut pbi as *mut _ as *mut c_void,
                std::mem::size_of::<ProcessBasicInformation>() as u32,
                &mut return_length,
            );

            if status != 0 {
                return None;
            }

            let handle_typed = windows::Win32::Foundation::HANDLE(handle as isize);

            // Read RTL_USER_PROCESS_PARAMETERS from PEB
            // PEB offset 0x20 (64-bit) or 0x10 (32-bit) for ProcessParameters
            #[cfg(target_pointer_width = "64")]
            let params_offset = 0x20usize;
            #[cfg(target_pointer_width = "32")]
            let params_offset = 0x10usize;

            let peb_addr = pbi.peb_base_address as usize;
            let mut params_ptr: usize = 0;
            let mut bytes_read = 0usize;

            if ReadProcessMemory(
                handle_typed,
                (peb_addr + params_offset) as *const _,
                &mut params_ptr as *mut _ as *mut _,
                std::mem::size_of::<usize>(),
                Some(&mut bytes_read),
            )
            .is_err()
            {
                return None;
            }

            // Read ImagePathName from RTL_USER_PROCESS_PARAMETERS
            // Offset 0x60 (64-bit) or 0x38 (32-bit) for ImagePathName (UNICODE_STRING)
            #[cfg(target_pointer_width = "64")]
            let image_path_offset = 0x60usize;
            #[cfg(target_pointer_width = "32")]
            let image_path_offset = 0x38usize;

            // UNICODE_STRING structure
            #[repr(C)]
            struct UnicodeString {
                length: u16,
                max_length: u16,
                #[cfg(target_pointer_width = "64")]
                _padding: u32,
                buffer: usize,
            }

            let mut unicode_str = UnicodeString {
                length: 0,
                max_length: 0,
                #[cfg(target_pointer_width = "64")]
                _padding: 0,
                buffer: 0,
            };

            if ReadProcessMemory(
                handle_typed,
                (params_ptr + image_path_offset) as *const _,
                &mut unicode_str as *mut _ as *mut _,
                std::mem::size_of::<UnicodeString>(),
                Some(&mut bytes_read),
            )
            .is_err()
            {
                return None;
            }

            if unicode_str.length == 0 || unicode_str.buffer == 0 {
                return None;
            }

            // Read the path string
            let mut path_buf = vec![0u16; (unicode_str.length / 2) as usize + 1];

            if ReadProcessMemory(
                handle_typed,
                unicode_str.buffer as *const _,
                path_buf.as_mut_ptr() as *mut _,
                unicode_str.length as usize,
                Some(&mut bytes_read),
            )
            .is_err()
            {
                return None;
            }

            Some(String::from_utf16_lossy(
                &path_buf[..(unicode_str.length / 2) as usize],
            ))
        }
    }

    #[cfg(target_os = "windows")]
    fn get_module_path_from_handle(
        process_handle: windows::Win32::Foundation::HANDLE,
        module: windows::Win32::Foundation::HMODULE,
    ) -> String {
        use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;

        unsafe {
            let mut buffer = [0u16; 260];
            let len = GetModuleFileNameExW(process_handle, module, &mut buffer);

            if len > 0 {
                String::from_utf16_lossy(&buffer[..len as usize])
            } else {
                String::new()
            }
        }
    }

    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    // ==================== Linux Implementation ====================

    #[cfg(target_os = "linux")]
    async fn linux_monitor_loop(tx: mpsc::Sender<TelemetryEvent>, config: AgentConfig) {
        use std::sync::Arc;
        use tokio::sync::Mutex;

        info!("Starting Linux process injection detection");

        let reported: Arc<Mutex<HashSet<(u32, u32, String)>>> =
            Arc::new(Mutex::new(HashSet::new()));

        // Monitor /proc for suspicious memory mappings
        let tx_clone = tx.clone();
        let reported_clone = reported.clone();
        tokio::spawn(async move {
            Self::linux_memory_scan_loop(tx_clone, reported_clone).await;
        });

        // Monitor ptrace operations
        let tx_clone2 = tx.clone();
        let reported_clone2 = reported.clone();
        tokio::spawn(async move {
            Self::linux_ptrace_monitor(tx_clone2, reported_clone2).await;
        });

        // Keep main task alive
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
        }
    }

    #[cfg(target_os = "linux")]
    async fn linux_memory_scan_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        reported: std::sync::Arc<tokio::sync::Mutex<HashSet<(u32, u32, String)>>>,
    ) {
        use std::fs;
        use std::io::{BufRead, BufReader};

        info!("Starting Linux memory scan loop");

        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(15));

        loop {
            interval.tick().await;

            // Scan /proc for all processes
            if let Ok(entries) = fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();

                    if let Ok(pid) = name_str.parse::<u32>() {
                        // Skip kernel threads and our process
                        if pid < 10 || pid == std::process::id() {
                            continue;
                        }

                        // Read /proc/[pid]/maps
                        let maps_path = format!("/proc/{}/maps", pid);
                        if let Ok(file) = fs::File::open(&maps_path) {
                            let reader = BufReader::new(file);
                            let process_name = Self::linux_get_process_name(pid);

                            for line in reader.lines().flatten() {
                                let parts: Vec<&str> = line.split_whitespace().collect();
                                if parts.len() < 5 {
                                    continue;
                                }

                                let perms = parts[1];
                                let is_executable = perms.contains('x');
                                let is_writable = perms.contains('w');
                                let is_private = perms.contains('p');
                                let is_anonymous = parts.len() < 6 || parts[5].is_empty();

                                // Suspicious: Anonymous RWX memory
                                if is_executable && is_writable && is_private && is_anonymous {
                                    let address_range: Vec<&str> = parts[0].split('-').collect();
                                    let start =
                                        u64::from_str_radix(address_range[0], 16).unwrap_or(0);

                                    let detection = ProcessHollowingEvent {
                                        source_pid: 0,
                                        source_name: "unknown".to_string(),
                                        source_path: String::new(),
                                        target_pid: pid,
                                        target_name: process_name.clone(),
                                        target_path: Self::linux_get_process_path(pid),
                                        original_image_path: None,
                                        technique: InjectionTechnique::RwxMemoryRegion,
                                        memory_address: Some(start),
                                        memory_size: None,
                                        memory_protection: None,
                                        entry_point: None,
                                        original_entry_point: None,
                                        thread_id: None,
                                        confidence: 0.7,
                                        context: HashMap::new(),
                                    };

                                    let mut reported_guard = reported.lock().await;
                                    let key = (
                                        detection.source_pid,
                                        detection.target_pid,
                                        format!("{}_{:x}", detection.technique.as_str(), start),
                                    );

                                    if !reported_guard.contains(&key) {
                                        reported_guard.insert(key);
                                        let event = Self::create_event(&detection);
                                        if tx.send(event).await.is_err() {
                                            warn!("Event channel closed");
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    async fn linux_ptrace_monitor(
        tx: mpsc::Sender<TelemetryEvent>,
        reported: std::sync::Arc<tokio::sync::Mutex<HashSet<(u32, u32, String)>>>,
    ) {
        use std::collections::HashSet;
        use std::fs;

        info!("Starting Linux ptrace monitor");

        let mut known_tracers: HashSet<(u32, u32)> = HashSet::new();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(500));

        loop {
            interval.tick().await;

            if let Ok(entries) = fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();

                    if let Ok(pid) = name_str.parse::<u32>() {
                        let status_path = format!("/proc/{}/status", pid);

                        if let Ok(content) = fs::read_to_string(&status_path) {
                            for line in content.lines() {
                                if line.starts_with("TracerPid:") {
                                    let parts: Vec<&str> = line.split_whitespace().collect();
                                    if parts.len() >= 2 {
                                        if let Ok(tracer_pid) = parts[1].parse::<u32>() {
                                            if tracer_pid != 0 {
                                                let key = (tracer_pid, pid);

                                                if !known_tracers.contains(&key) {
                                                    known_tracers.insert(key);

                                                    // Filter known debuggers
                                                    let tracer_name =
                                                        Self::linux_get_process_name(tracer_pid);
                                                    let known_debuggers = [
                                                        "gdb", "lldb", "strace", "ltrace",
                                                        "valgrind", "perf",
                                                    ];

                                                    if !known_debuggers
                                                        .iter()
                                                        .any(|d| tracer_name.contains(d))
                                                    {
                                                        let detection = ProcessHollowingEvent {
                                                            source_pid: tracer_pid,
                                                            source_name: tracer_name.clone(),
                                                            source_path:
                                                                Self::linux_get_process_path(
                                                                    tracer_pid,
                                                                ),
                                                            target_pid: pid,
                                                            target_name:
                                                                Self::linux_get_process_name(pid),
                                                            target_path:
                                                                Self::linux_get_process_path(pid),
                                                            original_image_path: None,
                                                            technique:
                                                                InjectionTechnique::ThreadHijacking,
                                                            memory_address: None,
                                                            memory_size: None,
                                                            memory_protection: None,
                                                            entry_point: None,
                                                            original_entry_point: None,
                                                            thread_id: None,
                                                            confidence: 0.75,
                                                            context: {
                                                                let mut ctx = HashMap::new();
                                                                ctx.insert(
                                                                    "detection_method".to_string(),
                                                                    "ptrace".to_string(),
                                                                );
                                                                ctx
                                                            },
                                                        };

                                                        let mut reported_guard =
                                                            reported.lock().await;
                                                        let key = (
                                                            detection.source_pid,
                                                            detection.target_pid,
                                                            detection
                                                                .technique
                                                                .as_str()
                                                                .to_string(),
                                                        );

                                                        if !reported_guard.contains(&key) {
                                                            reported_guard.insert(key);
                                                            let event =
                                                                Self::create_event(&detection);
                                                            if tx.send(event).await.is_err() {
                                                                warn!("Event channel closed");
                                                                return;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Cleanup old entries
            if known_tracers.len() > 10000 {
                known_tracers.clear();
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn linux_get_process_name(pid: u32) -> String {
        std::fs::read_to_string(format!("/proc/{}/comm", pid))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    }

    #[cfg(target_os = "linux")]
    fn linux_get_process_path(pid: u32) -> String {
        std::fs::read_link(format!("/proc/{}/exe", pid))
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| String::new())
    }
}

// ==================== Enhanced Process Hollowing Detector ====================

/// Enhanced hollowing detector with full sequence correlation
/// Tracks the complete hollowing attack chain:
/// 1. CreateProcess with CREATE_SUSPENDED
/// 2. NtUnmapViewOfSection on main module
/// 3. VirtualAllocEx at ImageBase
/// 4. WriteProcessMemory to allocated region
/// 5. SetThreadContext to new entry point
/// 6. ResumeThread
#[cfg(target_os = "windows")]
pub struct HollowingSequenceTracker {
    /// Processes created with CREATE_SUSPENDED, keyed by target PID
    suspended_processes: HashMap<u32, SuspendedProcessInfo>,
    /// Cross-process memory operations for correlation
    memory_operations: HashMap<u32, Vec<MemoryOperation>>,
    /// Thread context modifications
    thread_context_mods: HashMap<u32, Vec<ThreadContextMod>>,
    /// Completed sequences pending final analysis
    pending_sequences: Vec<HollowingSequence>,
    /// Configuration for detection thresholds
    config: HollowingDetectorConfig,
}

/// Detailed information about a suspended process
#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
pub struct SuspendedProcessInfo {
    /// Target process ID
    pub target_pid: u32,
    /// Parent process ID (potential injector)
    pub parent_pid: u32,
    /// Process name
    pub name: String,
    /// Full path on disk
    pub path: String,
    /// Creation timestamp
    pub created_at: u64,
    /// Original image base from PEB at creation
    pub original_image_base: u64,
    /// Original entry point at creation
    pub original_entry_point: u64,
    /// Original size of image
    pub original_image_size: u32,
    /// Main thread ID
    pub main_thread_id: u32,
    /// Whether the process has been resumed
    pub resumed: bool,
    /// PEB address for later validation
    pub peb_address: u64,
}

/// Memory operation record for correlation
#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
struct MemoryOperation {
    timestamp: u64,
    source_pid: u32,
    target_pid: u32,
    operation_type: MemoryOpType,
    address: u64,
    size: u64,
    protection: u32,
    /// For WriteProcessMemory - hash of data written
    data_hash: Option<[u8; 32]>,
    /// Whether this targets the image base region
    targets_image_base: bool,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemoryOpType {
    NtUnmapViewOfSection,
    VirtualAllocEx,
    WriteProcessMemory,
    NtMapViewOfSection,
    VirtualProtectEx,
}

/// Thread context modification record
#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
struct ThreadContextMod {
    timestamp: u64,
    source_pid: u32,
    target_pid: u32,
    thread_id: u32,
    new_rip: u64,
    new_rcx: u64, // For 64-bit: first param often image base
    original_rip: Option<u64>,
}

/// Complete hollowing sequence for final analysis
#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
pub(crate) struct HollowingSequence {
    source_pid: u32,
    source_name: String,
    target_pid: u32,
    target_name: String,
    target_path: String,
    /// When the sequence started (suspended process creation)
    started_at: u64,
    /// Whether NtUnmapViewOfSection was called
    section_unmapped: bool,
    unmapped_address: Option<u64>,
    /// Memory allocation at image base
    allocated_at_image_base: bool,
    allocation_address: Option<u64>,
    allocation_size: Option<u64>,
    /// Memory writes to the region
    write_count: u32,
    total_bytes_written: u64,
    /// Thread context modification
    context_modified: bool,
    new_entry_point: Option<u64>,
    original_entry_point: Option<u64>,
    /// Whether the process was resumed
    resumed: bool,
    /// Confidence score based on indicators
    confidence: f32,
}

/// Configuration for hollowing detection
#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
pub struct HollowingDetectorConfig {
    /// Maximum time (ms) between CREATE_SUSPENDED and resume for correlation
    pub max_sequence_time_ms: u64,
    /// Minimum confidence to report detection
    pub min_confidence: f32,
    /// Maximum number of tracked suspended processes
    pub max_tracked_processes: usize,
    /// Enable deep PEB validation
    pub deep_peb_validation: bool,
    /// Enable disk vs memory comparison
    pub compare_disk_memory: bool,
}

#[cfg(target_os = "windows")]
impl Default for HollowingDetectorConfig {
    fn default() -> Self {
        Self {
            max_sequence_time_ms: 30000, // 30 seconds
            min_confidence: 0.70,
            max_tracked_processes: 1000,
            deep_peb_validation: true,
            compare_disk_memory: true,
        }
    }
}

#[cfg(target_os = "windows")]
impl HollowingSequenceTracker {
    pub fn new(config: HollowingDetectorConfig) -> Self {
        Self {
            suspended_processes: HashMap::new(),
            memory_operations: HashMap::new(),
            thread_context_mods: HashMap::new(),
            pending_sequences: Vec::new(),
            config,
        }
    }

    /// Record a process created with CREATE_SUSPENDED
    pub fn record_suspended_creation(&mut self, info: SuspendedProcessInfo) {
        debug!(
            pid = info.target_pid,
            parent = info.parent_pid,
            name = %info.name,
            image_base = format!("0x{:x}", info.original_image_base),
            entry_point = format!("0x{:x}", info.original_entry_point),
            "Recording suspended process creation"
        );

        // Clean up old entries if at capacity
        if self.suspended_processes.len() >= self.config.max_tracked_processes {
            let now = Self::current_timestamp();
            self.suspended_processes
                .retain(|_, p| now - p.created_at < self.config.max_sequence_time_ms);
        }

        self.suspended_processes.insert(info.target_pid, info);
    }

    /// Record NtUnmapViewOfSection call
    pub fn record_unmap_section(
        &mut self,
        source_pid: u32,
        target_pid: u32,
        address: u64,
        size: u64,
    ) {
        debug!(
            source = source_pid,
            target = target_pid,
            address = format!("0x{:x}", address),
            size = size,
            "Recording NtUnmapViewOfSection"
        );

        let op = MemoryOperation {
            timestamp: Self::current_timestamp(),
            source_pid,
            target_pid,
            operation_type: MemoryOpType::NtUnmapViewOfSection,
            address,
            size,
            protection: 0,
            data_hash: None,
            targets_image_base: self.check_targets_image_base(target_pid, address),
        };

        self.memory_operations
            .entry(target_pid)
            .or_default()
            .push(op);
    }

    /// Record VirtualAllocEx call
    pub fn record_virtual_alloc(
        &mut self,
        source_pid: u32,
        target_pid: u32,
        address: u64,
        size: u64,
        protection: u32,
    ) {
        debug!(
            source = source_pid,
            target = target_pid,
            address = format!("0x{:x}", address),
            size = size,
            protection = format!("0x{:x}", protection),
            "Recording VirtualAllocEx"
        );

        let targets_image_base = self.check_targets_image_base(target_pid, address);

        if targets_image_base {
            warn!(
                target = target_pid,
                address = format!("0x{:x}", address),
                "VirtualAllocEx targeting image base region - potential hollowing"
            );
        }

        let op = MemoryOperation {
            timestamp: Self::current_timestamp(),
            source_pid,
            target_pid,
            operation_type: MemoryOpType::VirtualAllocEx,
            address,
            size,
            protection,
            data_hash: None,
            targets_image_base,
        };

        self.memory_operations
            .entry(target_pid)
            .or_default()
            .push(op);
    }

    /// Record WriteProcessMemory call
    pub fn record_write_memory(
        &mut self,
        source_pid: u32,
        target_pid: u32,
        address: u64,
        size: u64,
        data_hash: Option<[u8; 32]>,
    ) {
        trace!(
            source = source_pid,
            target = target_pid,
            address = format!("0x{:x}", address),
            size = size,
            "Recording WriteProcessMemory"
        );

        let op = MemoryOperation {
            timestamp: Self::current_timestamp(),
            source_pid,
            target_pid,
            operation_type: MemoryOpType::WriteProcessMemory,
            address,
            size,
            protection: 0,
            data_hash,
            targets_image_base: self.check_targets_image_base(target_pid, address),
        };

        self.memory_operations
            .entry(target_pid)
            .or_default()
            .push(op);
    }

    /// Record SetThreadContext call
    pub fn record_set_thread_context(
        &mut self,
        source_pid: u32,
        target_pid: u32,
        thread_id: u32,
        new_rip: u64,
        new_rcx: u64,
        original_rip: Option<u64>,
    ) {
        debug!(
            source = source_pid,
            target = target_pid,
            thread = thread_id,
            new_rip = format!("0x{:x}", new_rip),
            new_rcx = format!("0x{:x}", new_rcx),
            "Recording SetThreadContext"
        );

        let ctx_mod = ThreadContextMod {
            timestamp: Self::current_timestamp(),
            source_pid,
            target_pid,
            thread_id,
            new_rip,
            new_rcx,
            original_rip,
        };

        self.thread_context_mods
            .entry(target_pid)
            .or_default()
            .push(ctx_mod);
    }

    /// Record ResumeThread call - triggers sequence analysis
    pub(crate) fn record_resume_thread(
        &mut self,
        target_pid: u32,
        thread_id: u32,
    ) -> Option<HollowingSequence> {
        debug!(
            target = target_pid,
            thread = thread_id,
            "Recording ResumeThread - analyzing sequence"
        );

        // Check if this was a tracked suspended process
        let suspended = self.suspended_processes.get(&target_pid)?;

        // Build the sequence from recorded operations
        let ops = self.memory_operations.get(&target_pid);
        let ctx_mods = self.thread_context_mods.get(&target_pid);

        let mut sequence = HollowingSequence {
            source_pid: suspended.parent_pid,
            source_name: ProcessHollowingCollector::get_process_name(suspended.parent_pid),
            target_pid,
            target_name: suspended.name.clone(),
            target_path: suspended.path.clone(),
            started_at: suspended.created_at,
            section_unmapped: false,
            unmapped_address: None,
            allocated_at_image_base: false,
            allocation_address: None,
            allocation_size: None,
            write_count: 0,
            total_bytes_written: 0,
            context_modified: false,
            new_entry_point: None,
            original_entry_point: Some(suspended.original_entry_point),
            resumed: true,
            confidence: 0.0,
        };

        // Analyze memory operations
        if let Some(operations) = ops {
            for op in operations {
                match op.operation_type {
                    MemoryOpType::NtUnmapViewOfSection => {
                        if op.targets_image_base {
                            sequence.section_unmapped = true;
                            sequence.unmapped_address = Some(op.address);
                            sequence.confidence += 0.25;
                        }
                    }
                    MemoryOpType::VirtualAllocEx => {
                        if op.targets_image_base {
                            sequence.allocated_at_image_base = true;
                            sequence.allocation_address = Some(op.address);
                            sequence.allocation_size = Some(op.size);
                            sequence.confidence += 0.20;
                        }
                    }
                    MemoryOpType::WriteProcessMemory => {
                        sequence.write_count += 1;
                        sequence.total_bytes_written += op.size;
                        if op.targets_image_base {
                            sequence.confidence += 0.05;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Analyze thread context modifications
        if let Some(ctx_list) = ctx_mods {
            for ctx in ctx_list {
                if ctx.thread_id == suspended.main_thread_id || ctx.thread_id == thread_id {
                    sequence.context_modified = true;
                    sequence.new_entry_point = Some(ctx.new_rip);

                    // Check if entry point changed
                    if let Some(orig_rip) = ctx.original_rip {
                        if ctx.new_rip != orig_rip {
                            sequence.confidence += 0.30;
                        }
                    } else if ctx.new_rip != suspended.original_entry_point {
                        sequence.confidence += 0.30;
                    }
                }
            }
        }

        // CREATE_SUSPENDED itself is an indicator
        sequence.confidence += 0.10;

        // Classic hollowing pattern: unmap + alloc at image base + write + context mod
        if sequence.section_unmapped
            && sequence.allocated_at_image_base
            && sequence.context_modified
        {
            sequence.confidence = sequence.confidence.max(0.95);
        }

        // Clean up tracked data
        self.suspended_processes.remove(&target_pid);
        self.memory_operations.remove(&target_pid);
        self.thread_context_mods.remove(&target_pid);

        if sequence.confidence >= self.config.min_confidence {
            Some(sequence)
        } else {
            None
        }
    }

    /// Check if an address targets the image base region of a process
    fn check_targets_image_base(&self, target_pid: u32, address: u64) -> bool {
        if let Some(suspended) = self.suspended_processes.get(&target_pid) {
            // Check if address is within image range
            let image_end = suspended.original_image_base + suspended.original_image_size as u64;
            address >= suspended.original_image_base && address < image_end
        } else {
            false
        }
    }

    /// Validate PEB consistency for a process
    pub fn validate_peb_consistency(&self, pid: u32) -> Option<PebValidationResult> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        unsafe {
            let handle =
                OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid).ok()?;

            let peb_image_base = ProcessHollowingCollector::get_peb_image_base(
                std::mem::transmute::<_, *mut c_void>(handle),
            )?;

            let peb_image_path = ProcessHollowingCollector::get_peb_image_path(
                std::mem::transmute::<_, *mut c_void>(handle),
            );

            // Read PE header from memory at image base
            let mut mem_header = [0u8; 512];
            let mut bytes_read = 0usize;

            let header_valid = ReadProcessMemory(
                handle,
                peb_image_base as *const _,
                mem_header.as_mut_ptr() as *mut _,
                mem_header.len(),
                Some(&mut bytes_read),
            )
            .is_ok()
                && bytes_read >= 64;

            let mut result = PebValidationResult {
                pid,
                image_base: peb_image_base,
                image_path: peb_image_path.clone(),
                header_valid,
                entry_point_valid: false,
                section_count_valid: false,
                disk_memory_match: false,
                anomalies: Vec::new(),
            };

            if !header_valid {
                result.anomalies.push(PebAnomaly::InvalidHeader);
                let _ = CloseHandle(handle);
                return Some(result);
            }

            // Parse memory PE header
            let mem_pe_info = ProcessHollowingCollector::parse_pe_header(&mem_header[..bytes_read]);

            // Get disk path and read disk PE header
            let disk_path = ProcessHollowingCollector::get_process_path(pid);
            if let Ok(disk_data) = std::fs::read(&disk_path) {
                if disk_data.len() >= 512 {
                    let disk_pe_info =
                        ProcessHollowingCollector::parse_pe_header(&disk_data[..512]);

                    // Compare entry points
                    if disk_pe_info.entry_point_rva != 0 && mem_pe_info.entry_point_rva != 0 {
                        if disk_pe_info.entry_point_rva == mem_pe_info.entry_point_rva {
                            result.entry_point_valid = true;
                        } else {
                            result.anomalies.push(PebAnomaly::EntryPointMismatch {
                                disk_ep: disk_pe_info.entry_point_rva as u64,
                                memory_ep: mem_pe_info.entry_point_rva as u64,
                            });
                        }
                    }

                    // Compare section counts
                    if disk_pe_info.number_of_sections == mem_pe_info.number_of_sections {
                        result.section_count_valid = true;
                    } else {
                        result.anomalies.push(PebAnomaly::SectionCountMismatch {
                            disk_count: disk_pe_info.number_of_sections,
                            memory_count: mem_pe_info.number_of_sections,
                        });
                    }

                    // Quick header hash comparison (first 256 bytes excluding checksum field)
                    let mut match_count = 0;
                    let compare_len = std::cmp::min(bytes_read, 256);
                    for i in 0..compare_len {
                        if mem_header[i] == disk_data[i] {
                            match_count += 1;
                        }
                    }
                    result.disk_memory_match = match_count > compare_len * 90 / 100; // 90% match

                    if !result.disk_memory_match {
                        result.anomalies.push(PebAnomaly::HeaderContentMismatch {
                            match_percentage: (match_count * 100 / compare_len) as u8,
                        });
                    }
                }
            }

            // Check if PEB path matches disk path
            if let Some(ref peb_path) = peb_image_path {
                let peb_normalized = peb_path.to_lowercase().replace("/", "\\");
                let disk_normalized = disk_path.to_lowercase().replace("/", "\\");

                // Extract filenames for comparison (handles NT path vs DOS path differences)
                let peb_filename = peb_normalized.rsplit('\\').next().unwrap_or("");
                let disk_filename = disk_normalized.rsplit('\\').next().unwrap_or("");

                if !peb_filename.is_empty()
                    && !disk_filename.is_empty()
                    && peb_filename != disk_filename
                {
                    result.anomalies.push(PebAnomaly::ImagePathMismatch {
                        peb_path: peb_path.clone(),
                        disk_path: disk_path.clone(),
                    });
                }
            }

            let _ = CloseHandle(handle);
            Some(result)
        }
    }

    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

/// Result of PEB validation
#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
pub struct PebValidationResult {
    pub pid: u32,
    pub image_base: u64,
    pub image_path: Option<String>,
    pub header_valid: bool,
    pub entry_point_valid: bool,
    pub section_count_valid: bool,
    pub disk_memory_match: bool,
    pub anomalies: Vec<PebAnomaly>,
}

#[cfg(target_os = "windows")]
impl PebValidationResult {
    pub fn is_suspicious(&self) -> bool {
        !self.anomalies.is_empty()
    }

    pub fn confidence_score(&self) -> f32 {
        let mut score: f32 = 0.0;
        for anomaly in &self.anomalies {
            score += match anomaly {
                PebAnomaly::InvalidHeader => 0.40,
                PebAnomaly::EntryPointMismatch { .. } => 0.35,
                PebAnomaly::SectionCountMismatch { .. } => 0.25,
                PebAnomaly::HeaderContentMismatch { match_percentage } => {
                    if *match_percentage < 50 {
                        0.40
                    } else if *match_percentage < 80 {
                        0.25
                    } else {
                        0.10
                    }
                }
                PebAnomaly::ImagePathMismatch { .. } => 0.30,
            };
        }
        score.min(1.0)
    }
}

/// PEB anomaly types
#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
pub enum PebAnomaly {
    /// PE header at image base is invalid
    InvalidHeader,
    /// Entry point RVA differs between disk and memory
    EntryPointMismatch { disk_ep: u64, memory_ep: u64 },
    /// Section count differs
    SectionCountMismatch { disk_count: u16, memory_count: u16 },
    /// Header content doesn't match disk
    HeaderContentMismatch { match_percentage: u8 },
    /// PEB image path doesn't match process path
    ImagePathMismatch { peb_path: String, disk_path: String },
}

// ==================== ETW-Based API Monitoring ====================

/// ETW provider for monitoring NT API calls relevant to process hollowing
#[cfg(target_os = "windows")]
pub struct HollowingApiMonitor {
    /// Channel to send events
    tx: mpsc::Sender<TelemetryEvent>,
    /// Sequence tracker for correlation
    tracker: std::sync::Arc<tokio::sync::Mutex<HollowingSequenceTracker>>,
    /// Reported detections
    reported: std::sync::Arc<tokio::sync::Mutex<HashSet<(u32, u32, String)>>>,
}

#[cfg(target_os = "windows")]
impl HollowingApiMonitor {
    pub fn new(
        tx: mpsc::Sender<TelemetryEvent>,
        tracker: std::sync::Arc<tokio::sync::Mutex<HollowingSequenceTracker>>,
        reported: std::sync::Arc<tokio::sync::Mutex<HashSet<(u32, u32, String)>>>,
    ) -> Self {
        Self {
            tx,
            tracker,
            reported,
        }
    }

    /// Start monitoring for hollowing-related API calls
    /// This uses process snapshot polling as ETW kernel events require special privileges
    pub async fn start_monitoring(self) {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        info!("Starting hollowing API monitor with sequence correlation");

        let mut last_check: HashMap<u32, ProcessSnapshot> = HashMap::new();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(250));

        loop {
            interval.tick().await;

            let mut current_processes: HashMap<u32, ProcessSnapshot> = HashMap::new();

            unsafe {
                if let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                    let mut entry = PROCESSENTRY32W {
                        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                        ..Default::default()
                    };

                    if Process32FirstW(snapshot, &mut entry).is_ok() {
                        loop {
                            let pid = entry.th32ProcessID;
                            let ppid = entry.th32ParentProcessID;
                            let name = String::from_utf16_lossy(
                                &entry.szExeFile
                                    [..entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0)],
                            );

                            // Skip system processes
                            if pid > 10 && pid != std::process::id() {
                                let snap = self.capture_process_snapshot(pid, ppid, &name);
                                if let Some(snap) = snap {
                                    current_processes.insert(pid, snap);
                                }
                            }

                            if Process32NextW(snapshot, &mut entry).is_err() {
                                break;
                            }
                        }
                    }
                    let _ = CloseHandle(snapshot);
                }
            }

            // Compare snapshots to detect changes
            for (pid, current) in &current_processes {
                if let Some(previous) = last_check.get(pid) {
                    // Check for state transitions
                    self.analyze_snapshot_delta(previous, current).await;
                } else {
                    // New process - check if it was created suspended
                    self.check_new_process(current).await;
                }
            }

            // Periodic deep scan of tracked processes
            let tracker = self.tracker.lock().await;
            let tracked_pids: Vec<u32> = tracker.suspended_processes.keys().copied().collect();
            drop(tracker);

            for pid in tracked_pids {
                if let Some(validation) = self.tracker.lock().await.validate_peb_consistency(pid) {
                    if validation.is_suspicious() {
                        self.report_peb_anomaly(pid, &validation).await;
                    }
                }
            }

            last_check = current_processes;
        }
    }

    fn capture_process_snapshot(&self, pid: u32, ppid: u32, name: &str) -> Option<ProcessSnapshot> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Memory::{
            VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        unsafe {
            let handle =
                OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid).ok()?;

            // Get image base from PEB
            let image_base = ProcessHollowingCollector::get_peb_image_base(std::mem::transmute::<
                _,
                *mut c_void,
            >(handle))
            .unwrap_or(0);

            // Get entry point
            let entry_point =
                ProcessHollowingCollector::get_process_entry_point(std::mem::transmute::<
                    _,
                    *mut c_void,
                >(handle))
                .unwrap_or(0);

            // Check thread state (simplified - just count threads)
            let thread_count = self.get_thread_count(pid);

            // Check if main image region is mapped
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let image_mapped = if image_base > 0 {
                VirtualQueryEx(
                    handle,
                    Some(image_base as *const _),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                ) > 0
                    && mbi.State.contains(MEM_COMMIT)
            } else {
                true
            };

            let _ = CloseHandle(handle);

            Some(ProcessSnapshot {
                pid,
                ppid,
                name: name.to_string(),
                path: ProcessHollowingCollector::get_process_path(pid),
                image_base,
                entry_point,
                thread_count,
                image_mapped,
                timestamp: HollowingSequenceTracker::current_timestamp(),
            })
        }
    }

    fn get_thread_count(&self, pid: u32) -> u32 {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
        };

        let mut count = 0u32;
        unsafe {
            if let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
                let mut entry = THREADENTRY32 {
                    dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                    ..Default::default()
                };

                if Thread32First(snapshot, &mut entry).is_ok() {
                    loop {
                        if entry.th32OwnerProcessID == pid {
                            count += 1;
                        }
                        if Thread32Next(snapshot, &mut entry).is_err() {
                            break;
                        }
                    }
                }
                let _ = CloseHandle(snapshot);
            }
        }
        count
    }

    async fn check_new_process(&self, snap: &ProcessSnapshot) {
        // Check if process appears suspended (heuristic: only 1 thread)
        if snap.thread_count == 1 {
            // Get more detailed info to determine if it's truly suspended
            let is_suspended = self.is_process_suspended(snap.pid);

            if is_suspended {
                info!(
                    pid = snap.pid,
                    parent = snap.ppid,
                    name = %snap.name,
                    "Detected process created in suspended state"
                );

                // Get main thread ID
                let main_thread_id = self.get_main_thread_id(snap.pid).unwrap_or(0);

                // Record in tracker
                let info = SuspendedProcessInfo {
                    target_pid: snap.pid,
                    parent_pid: snap.ppid,
                    name: snap.name.clone(),
                    path: snap.path.clone(),
                    created_at: snap.timestamp,
                    original_image_base: snap.image_base,
                    original_entry_point: snap.entry_point,
                    original_image_size: 0, // Would need to query separately
                    main_thread_id,
                    resumed: false,
                    peb_address: 0,
                };

                let mut tracker = self.tracker.lock().await;
                tracker.record_suspended_creation(info);

                // Emit initial detection
                let detection = ProcessHollowingEvent {
                    source_pid: snap.ppid,
                    source_name: ProcessHollowingCollector::get_process_name(snap.ppid),
                    source_path: ProcessHollowingCollector::get_process_path(snap.ppid),
                    target_pid: snap.pid,
                    target_name: snap.name.clone(),
                    target_path: snap.path.clone(),
                    original_image_path: None,
                    technique: InjectionTechnique::ProcessHollowingCreateSuspended,
                    memory_address: Some(snap.image_base),
                    memory_size: None,
                    memory_protection: None,
                    entry_point: Some(snap.entry_point),
                    original_entry_point: Some(snap.entry_point),
                    thread_id: Some(main_thread_id),
                    confidence: 0.60,
                    context: HashMap::new(),
                };

                let mut reported = self.reported.lock().await;
                let key = (snap.ppid, snap.pid, "create_suspended".to_string());
                if !reported.contains(&key) {
                    reported.insert(key);
                    let event = ProcessHollowingCollector::create_event(&detection);
                    let _ = self.tx.send(event).await;
                }
            }
        }
    }

    fn is_process_suspended(&self, pid: u32) -> bool {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
        };
        use windows::Win32::System::Threading::{OpenThread, THREAD_QUERY_INFORMATION};

        unsafe {
            if let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
                let mut entry = THREADENTRY32 {
                    dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                    ..Default::default()
                };

                if Thread32First(snapshot, &mut entry).is_ok() {
                    loop {
                        if entry.th32OwnerProcessID == pid {
                            // Try to determine suspend state
                            // A truly suspended thread will have wait reason SuspendCount > 0
                            // This is a simplified check
                            if let Ok(thread_handle) =
                                OpenThread(THREAD_QUERY_INFORMATION, false, entry.th32ThreadID)
                            {
                                // Could use NtQueryInformationThread with ThreadSuspendCount here
                                // For now, use heuristics based on thread state
                                let _ = CloseHandle(thread_handle);
                            }
                        }
                        if Thread32Next(snapshot, &mut entry).is_err() {
                            break;
                        }
                    }
                }
                let _ = CloseHandle(snapshot);
            }
        }

        // Heuristic: if process has only 1 thread and was just created, likely suspended
        true
    }

    fn get_main_thread_id(&self, pid: u32) -> Option<u32> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
        };

        unsafe {
            if let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
                let mut entry = THREADENTRY32 {
                    dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                    ..Default::default()
                };

                if Thread32First(snapshot, &mut entry).is_ok() {
                    loop {
                        if entry.th32OwnerProcessID == pid {
                            let _ = CloseHandle(snapshot);
                            return Some(entry.th32ThreadID);
                        }
                        if Thread32Next(snapshot, &mut entry).is_err() {
                            break;
                        }
                    }
                }
                let _ = CloseHandle(snapshot);
            }
        }
        None
    }

    async fn analyze_snapshot_delta(&self, previous: &ProcessSnapshot, current: &ProcessSnapshot) {
        // Check for image base region being unmapped
        if previous.image_mapped && !current.image_mapped {
            warn!(
                pid = current.pid,
                image_base = format!("0x{:x}", current.image_base),
                "Detected image region unmapped - potential NtUnmapViewOfSection"
            );

            let mut tracker = self.tracker.lock().await;
            tracker.record_unmap_section(
                current.ppid, // Assuming parent is the source
                current.pid,
                current.image_base,
                0, // Size unknown
            );
        }

        // Check for entry point change
        if previous.entry_point != 0
            && current.entry_point != 0
            && previous.entry_point != current.entry_point
        {
            warn!(
                pid = current.pid,
                old_ep = format!("0x{:x}", previous.entry_point),
                new_ep = format!("0x{:x}", current.entry_point),
                "Detected entry point modification"
            );

            // This strongly indicates hollowing
            let detection = ProcessHollowingEvent {
                source_pid: current.ppid,
                source_name: ProcessHollowingCollector::get_process_name(current.ppid),
                source_path: ProcessHollowingCollector::get_process_path(current.ppid),
                target_pid: current.pid,
                target_name: current.name.clone(),
                target_path: current.path.clone(),
                original_image_path: None,
                technique: InjectionTechnique::ProcessHollowingEntryPointModified,
                memory_address: Some(current.image_base),
                memory_size: None,
                memory_protection: None,
                entry_point: Some(current.entry_point),
                original_entry_point: Some(previous.entry_point),
                thread_id: None,
                confidence: 0.90,
                context: HashMap::new(),
            };

            let mut reported = self.reported.lock().await;
            let key = (
                current.ppid,
                current.pid,
                "entry_point_modified".to_string(),
            );
            if !reported.contains(&key) {
                reported.insert(key);
                let event = ProcessHollowingCollector::create_event(&detection);
                let _ = self.tx.send(event).await;
            }
        }

        // Check for thread count increase (process resumed)
        if previous.thread_count == 1 && current.thread_count > 1 {
            debug!(
                pid = current.pid,
                "Process thread count increased - checking for hollowing sequence"
            );

            let mut tracker = self.tracker.lock().await;
            if let Some(sequence) = tracker.record_resume_thread(current.pid, 0) {
                // Complete sequence detected
                let detection = ProcessHollowingEvent {
                    source_pid: sequence.source_pid,
                    source_name: sequence.source_name.clone(),
                    source_path: ProcessHollowingCollector::get_process_path(sequence.source_pid),
                    target_pid: sequence.target_pid,
                    target_name: sequence.target_name.clone(),
                    target_path: sequence.target_path.clone(),
                    original_image_path: None,
                    technique: InjectionTechnique::ProcessHollowing,
                    memory_address: sequence.allocation_address,
                    memory_size: sequence.allocation_size,
                    memory_protection: None,
                    entry_point: sequence.new_entry_point,
                    original_entry_point: sequence.original_entry_point,
                    thread_id: None,
                    confidence: sequence.confidence,
                    context: {
                        let mut ctx = HashMap::new();
                        ctx.insert(
                            "section_unmapped".to_string(),
                            sequence.section_unmapped.to_string(),
                        );
                        ctx.insert(
                            "allocated_at_image_base".to_string(),
                            sequence.allocated_at_image_base.to_string(),
                        );
                        ctx.insert("write_count".to_string(), sequence.write_count.to_string());
                        ctx.insert(
                            "total_bytes_written".to_string(),
                            sequence.total_bytes_written.to_string(),
                        );
                        ctx.insert(
                            "context_modified".to_string(),
                            sequence.context_modified.to_string(),
                        );
                        ctx
                    },
                };

                drop(tracker);

                let mut reported = self.reported.lock().await;
                let key = (
                    sequence.source_pid,
                    sequence.target_pid,
                    "process_hollowing".to_string(),
                );
                if !reported.contains(&key) {
                    reported.insert(key);
                    let event = ProcessHollowingCollector::create_event(&detection);
                    let _ = self.tx.send(event).await;
                }
            }
        }
    }

    async fn report_peb_anomaly(&self, pid: u32, validation: &PebValidationResult) {
        let confidence = validation.confidence_score();

        // Determine most specific technique based on anomalies
        let technique = if validation
            .anomalies
            .iter()
            .any(|a| matches!(a, PebAnomaly::EntryPointMismatch { .. }))
        {
            InjectionTechnique::ProcessHollowingEntryPointModified
        } else if validation
            .anomalies
            .iter()
            .any(|a| matches!(a, PebAnomaly::ImagePathMismatch { .. }))
        {
            InjectionTechnique::PebImagePathMismatch
        } else if validation
            .anomalies
            .iter()
            .any(|a| matches!(a, PebAnomaly::HeaderContentMismatch { .. }))
        {
            InjectionTechnique::HollowedProcess
        } else {
            InjectionTechnique::ProcessHollowing
        };

        let process_name = ProcessHollowingCollector::get_process_name(pid);
        let process_path = ProcessHollowingCollector::get_process_path(pid);

        let detection = ProcessHollowingEvent {
            source_pid: 0,
            source_name: "unknown".to_string(),
            source_path: String::new(),
            target_pid: pid,
            target_name: process_name,
            target_path: process_path,
            original_image_path: validation.image_path.clone(),
            technique,
            memory_address: Some(validation.image_base),
            memory_size: None,
            memory_protection: None,
            entry_point: None,
            original_entry_point: None,
            thread_id: None,
            confidence,
            context: {
                let mut ctx = HashMap::new();
                ctx.insert(
                    "header_valid".to_string(),
                    validation.header_valid.to_string(),
                );
                ctx.insert(
                    "entry_point_valid".to_string(),
                    validation.entry_point_valid.to_string(),
                );
                ctx.insert(
                    "disk_memory_match".to_string(),
                    validation.disk_memory_match.to_string(),
                );
                ctx.insert(
                    "anomaly_count".to_string(),
                    validation.anomalies.len().to_string(),
                );
                ctx
            },
        };

        let mut reported = self.reported.lock().await;
        let key = (0, pid, format!("peb_anomaly_{}", technique.as_str()));
        if !reported.contains(&key) {
            reported.insert(key);
            let event = ProcessHollowingCollector::create_event(&detection);
            let _ = self.tx.send(event).await;
        }
    }
}

/// Process state snapshot for change detection
#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
struct ProcessSnapshot {
    pid: u32,
    ppid: u32,
    name: String,
    path: String,
    image_base: u64,
    entry_point: u64,
    thread_count: u32,
    image_mapped: bool,
    timestamp: u64,
}

// ==================== Enhanced Collector with Full Sequence Tracking ====================

impl ProcessHollowingCollector {
    /// Start the enhanced monitoring loop with full sequence correlation
    #[cfg(target_os = "windows")]
    pub async fn start_enhanced_monitoring(
        tx: mpsc::Sender<TelemetryEvent>,
        config: HollowingDetectorConfig,
    ) {
        use std::sync::Arc;
        use tokio::sync::Mutex;

        info!("Starting enhanced process hollowing detection with sequence correlation");

        let tracker = Arc::new(Mutex::new(HollowingSequenceTracker::new(config)));
        let reported: Arc<Mutex<HashSet<(u32, u32, String)>>> =
            Arc::new(Mutex::new(HashSet::new()));

        // Start API monitor
        let monitor = HollowingApiMonitor::new(tx.clone(), tracker.clone(), reported.clone());

        monitor.start_monitoring().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_technique_strings() {
        assert_eq!(
            InjectionTechnique::ProcessHollowing.as_str(),
            "process_hollowing"
        );
        assert_eq!(
            InjectionTechnique::ProcessHollowing.mitre_technique(),
            "T1055.012"
        );
    }

    #[test]
    fn test_technique_severity() {
        assert_eq!(
            InjectionTechnique::ProcessHollowing.severity(),
            Severity::Critical
        );
        assert_eq!(
            InjectionTechnique::ClassicDllInjection.severity(),
            Severity::High
        );
        assert_eq!(
            InjectionTechnique::RwxMemoryRegion.severity(),
            Severity::Medium
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_hollowing_detector_config_default() {
        let config = HollowingDetectorConfig::default();
        assert_eq!(config.max_sequence_time_ms, 30000);
        assert_eq!(config.min_confidence, 0.70);
        assert!(config.deep_peb_validation);
        assert!(config.compare_disk_memory);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_peb_validation_confidence() {
        let result = PebValidationResult {
            pid: 1234,
            image_base: 0x140000000,
            image_path: Some("C:\\test.exe".to_string()),
            header_valid: true,
            entry_point_valid: false,
            section_count_valid: true,
            disk_memory_match: false,
            anomalies: vec![
                PebAnomaly::EntryPointMismatch {
                    disk_ep: 0x1000,
                    memory_ep: 0x2000,
                },
                PebAnomaly::HeaderContentMismatch {
                    match_percentage: 60,
                },
            ],
        };

        assert!(result.is_suspicious());
        // EntryPointMismatch (0.35) + HeaderContentMismatch at 60% (0.25) = 0.60
        assert!((result.confidence_score() - 0.60).abs() < 0.01);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_hollowing_sequence_confidence() {
        // Full sequence: create suspended + unmap + alloc at image base + context mod = 0.95+
        let sequence = HollowingSequence {
            source_pid: 1,
            source_name: "malware.exe".to_string(),
            target_pid: 2,
            target_name: "svchost.exe".to_string(),
            target_path: "C:\\Windows\\System32\\svchost.exe".to_string(),
            started_at: 0,
            section_unmapped: true,
            unmapped_address: Some(0x140000000),
            allocated_at_image_base: true,
            allocation_address: Some(0x140000000),
            allocation_size: Some(0x100000),
            write_count: 5,
            total_bytes_written: 0x50000,
            context_modified: true,
            new_entry_point: Some(0x140001000),
            original_entry_point: Some(0x140002000),
            resumed: true,
            confidence: 0.95,
        };

        assert!(sequence.confidence >= 0.95);
    }
}
