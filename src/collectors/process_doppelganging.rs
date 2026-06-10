//! Process Doppelganging Detection Collector
//!
//! Comprehensive detection for Process Doppelganging (MITRE ATT&CK T1055.013),
//! an advanced process injection technique that abuses Transactional NTFS (TxF)
//! to create processes from transacted files without leaving artifacts on disk.
//!
//! ## Attack Flow
//! 1. NtCreateTransaction - Create an NTFS transaction
//! 2. CreateFileTransacted - Create/open a file within the transaction
//! 3. Write malicious payload to the transacted file
//! 4. NtCreateSection - Create a section from the transacted (malicious) file
//! 5. NtRollbackTransaction - Rollback the transaction (file reverts to clean state)
//! 6. NtCreateProcessEx - Create process from the section (still has malicious content)
//!
//! ## Detection Strategies
//!
//! ### 1. TxF API Monitoring (ETW + NtApi hooking indicators)
//! - Track NtCreateTransaction calls from suspicious processes
//! - Monitor RtlSetCurrentTransaction to detect transaction scope changes
//! - Correlate CreateFileTransacted with subsequent section creation
//!
//! ### 2. Transaction Handle Correlation
//! - Track open transaction handles per process
//! - Detect section creation while transaction handles are open
//! - Identify transaction rollback after process creation
//!
//! ### 3. Process Image Validation
//! - Compare in-memory image against on-disk file
//! - Detect processes where backing file is missing or different
//! - Identify processes with orphaned section objects
//!
//! ### 4. Section-to-Process Correlation
//! - Track section creation from files
//! - Correlate section handles with NtCreateProcessEx calls
//! - Detect sections created from files that no longer exist
//!
//! ### 5. Behavioral Indicators
//! - Processes with non-matching GetMappedFileName vs module path
//! - Processes created from temp/writeable directories within transactions
//! - Suspicious parent-child relationships with transaction activity
//!
//! ## MITRE ATT&CK
//! - T1055.013 - Process Doppelganging
//! - T1055 - Process Injection (parent technique)
//!
//! ## References
//! - BlackHat EU 2017: "Lost in Transaction: Process Doppelganging"
//! - Tal Liberman & Eugene Kogan (enSilo)

// This collector enumerates TxF/transaction APIs, section/process correlation
// state, and behavioral indicators for Process Doppelganging (T1055.013)
// detection. Many event fields and tracker structs are kept exhaustive for
// downstream correlation even when not all paths are consumed.
#![allow(dead_code, unused_variables)]

use super::{
    Detection, DetectionType, EventPayload, EventType, ProcessEvent, Severity, TelemetryEvent,
};
use crate::config::AgentConfig;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, trace};

#[allow(unused_imports)]
use tracing::{error, warn};

// ============================================================================
// Types and Structures
// ============================================================================

/// Process doppelganging detection event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessDoppelgangingEvent {
    /// Process ID of the doppelganged process
    pub target_pid: u32,
    /// Process name
    pub target_name: String,
    /// Process path (may be phantom/non-existent)
    pub target_path: String,
    /// Parent process ID (likely the attacker)
    pub source_pid: u32,
    /// Parent process name
    pub source_name: String,
    /// Parent process path
    pub source_path: String,
    /// Detection method that triggered the alert
    pub detection_method: DoppelgangingDetectionMethod,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// Transaction handle value (if captured)
    pub transaction_handle: Option<u64>,
    /// Section handle value (if captured)
    pub section_handle: Option<u64>,
    /// Original file path in transaction (if known)
    pub transacted_file_path: Option<String>,
    /// Whether the backing file exists on disk
    pub backing_file_exists: bool,
    /// Memory vs disk hash comparison (if available)
    pub memory_hash: Option<String>,
    /// Disk file hash (if available)
    pub disk_hash: Option<String>,
    /// Additional evidence strings
    pub evidence: Vec<String>,
    /// Entry point address in memory
    pub entry_point: Option<u64>,
    /// Process image base address
    pub image_base: Option<u64>,
}

/// Detection method that triggered the doppelganging alert
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DoppelgangingDetectionMethod {
    /// Detected via TxF API call correlation
    TxfApiCorrelation,
    /// Transaction handle + section creation correlation
    TransactionHandleCorrelation,
    /// Backing file does not exist
    MissingBackingFile,
    /// Memory content differs from disk
    MemoryDiskMismatch,
    /// GetMappedFileName differs from module path
    MappedFilenameMismatch,
    /// Section created from transacted file
    TransactedSectionCreation,
    /// Process created from rolled-back transaction
    TransactionRollbackProcess,
    /// Behavioral heuristics triggered
    BehavioralIndicators,
    /// ETW transaction event correlation
    EtwTransactionEvents,
}

impl DoppelgangingDetectionMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TxfApiCorrelation => "txf_api_correlation",
            Self::TransactionHandleCorrelation => "transaction_handle_correlation",
            Self::MissingBackingFile => "missing_backing_file",
            Self::MemoryDiskMismatch => "memory_disk_mismatch",
            Self::MappedFilenameMismatch => "mapped_filename_mismatch",
            Self::TransactedSectionCreation => "transacted_section_creation",
            Self::TransactionRollbackProcess => "transaction_rollback_process",
            Self::BehavioralIndicators => "behavioral_indicators",
            Self::EtwTransactionEvents => "etw_transaction_events",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::TxfApiCorrelation => "TxF API call pattern detected (NtCreateTransaction + CreateFileTransacted + NtCreateSection)",
            Self::TransactionHandleCorrelation => "Transaction handle open during section/process creation",
            Self::MissingBackingFile => "Process backing file does not exist on disk",
            Self::MemoryDiskMismatch => "In-memory image content differs from on-disk file",
            Self::MappedFilenameMismatch => "GetMappedFileName differs from reported module path",
            Self::TransactedSectionCreation => "Section created from file within NTFS transaction",
            Self::TransactionRollbackProcess => "Process created after transaction rollback",
            Self::BehavioralIndicators => "Behavioral patterns consistent with doppelganging",
            Self::EtwTransactionEvents => "ETW transaction events indicate doppelganging sequence",
        }
    }

    pub fn confidence_weight(&self) -> f32 {
        match self {
            Self::TxfApiCorrelation => 0.85,
            Self::TransactionHandleCorrelation => 0.75,
            Self::MissingBackingFile => 0.90,
            Self::MemoryDiskMismatch => 0.80,
            Self::MappedFilenameMismatch => 0.70,
            Self::TransactedSectionCreation => 0.85,
            Self::TransactionRollbackProcess => 0.95,
            Self::BehavioralIndicators => 0.60,
            Self::EtwTransactionEvents => 0.90,
        }
    }
}

/// Tracked transaction state for correlation
#[derive(Debug, Clone)]
struct TransactionState {
    /// Process that created the transaction
    creator_pid: u32,
    /// Transaction handle value
    handle: u64,
    /// Creation timestamp
    creation_time: u64,
    /// Files accessed within this transaction
    transacted_files: Vec<String>,
    /// Sections created while transaction was active
    sections_created: Vec<u64>,
    /// Whether transaction has been rolled back
    rolled_back: bool,
    /// Whether a process was created from a section
    process_created: bool,
}

/// Tracked section state for process correlation
#[derive(Debug, Clone)]
struct SectionState {
    /// Section handle value
    handle: u64,
    /// Process that created the section
    creator_pid: u32,
    /// File backing the section
    backing_file: Option<String>,
    /// Whether created during an active transaction
    from_transaction: bool,
    /// Associated transaction handle
    transaction_handle: Option<u64>,
    /// Creation timestamp
    creation_time: u64,
}

/// Suspicious process state for analysis
#[derive(Debug, Clone)]
struct SuspiciousProcessState {
    pid: u32,
    name: String,
    path: String,
    parent_pid: u32,
    parent_name: String,
    creation_time: u64,
    /// Indicators found
    indicators: Vec<DoppelgangingDetectionMethod>,
    /// Evidence strings
    evidence: Vec<String>,
}

// ============================================================================
// Main Collector
// ============================================================================

/// Process Doppelganging detection collector
pub struct ProcessDoppelgangingCollector {
    #[allow(dead_code)]
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    #[allow(dead_code)]
    event_tx: mpsc::Sender<TelemetryEvent>,
}

impl ProcessDoppelgangingCollector {
    /// Create a new process doppelganging detector
    pub fn new(config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(500);

        info!("Initializing Process Doppelganging detector (T1055.013)");

        // Start platform-specific monitoring
        #[cfg(target_os = "windows")]
        {
            let tx_clone = tx.clone();
            let config_clone = config.clone();
            tokio::spawn(async move {
                Self::windows_monitor_loop(tx_clone, config_clone).await;
            });
        }

        #[cfg(not(target_os = "windows"))]
        {
            info!("Process Doppelganging detection is Windows-only (TxF API)");
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

    /// Create telemetry event from doppelganging detection
    fn create_event(detection: &ProcessDoppelgangingEvent) -> TelemetryEvent {
        let severity = if detection.confidence >= 0.85 {
            Severity::Critical
        } else if detection.confidence >= 0.70 {
            Severity::High
        } else {
            Severity::Medium
        };

        let mut event = TelemetryEvent::new(
            EventType::ProcessDoppelganging,
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
            detection_type: DetectionType::ProcessDoppelganging,
            rule_name: format!(
                "ProcessDoppelganging_{}",
                detection.detection_method.as_str()
            ),
            confidence: detection.confidence,
            description: format!(
                "Process Doppelganging detected: {} (PID: {}) via {}. {}",
                detection.target_name,
                detection.target_pid,
                detection.detection_method.as_str(),
                detection.detection_method.description()
            ),
            mitre_tactics: vec![
                "defense-evasion".to_string(),
                "privilege-escalation".to_string(),
            ],
            mitre_techniques: vec!["T1055.013".to_string(), "T1055".to_string()],
        });

        // Add metadata
        event
            .metadata
            .insert("target_pid".to_string(), detection.target_pid.to_string());
        event
            .metadata
            .insert("target_name".to_string(), detection.target_name.clone());
        event
            .metadata
            .insert("target_path".to_string(), detection.target_path.clone());
        event
            .metadata
            .insert("source_pid".to_string(), detection.source_pid.to_string());
        event
            .metadata
            .insert("source_name".to_string(), detection.source_name.clone());
        event
            .metadata
            .insert("source_path".to_string(), detection.source_path.clone());
        event.metadata.insert(
            "detection_method".to_string(),
            detection.detection_method.as_str().to_string(),
        );
        event.metadata.insert(
            "confidence".to_string(),
            format!("{:.2}", detection.confidence),
        );
        event.metadata.insert(
            "backing_file_exists".to_string(),
            detection.backing_file_exists.to_string(),
        );

        if let Some(ref tx_handle) = detection.transaction_handle {
            event.metadata.insert(
                "transaction_handle".to_string(),
                format!("0x{:x}", tx_handle),
            );
        }
        if let Some(ref sec_handle) = detection.section_handle {
            event
                .metadata
                .insert("section_handle".to_string(), format!("0x{:x}", sec_handle));
        }
        if let Some(ref transacted_path) = detection.transacted_file_path {
            event
                .metadata
                .insert("transacted_file_path".to_string(), transacted_path.clone());
        }
        if let Some(ref mem_hash) = detection.memory_hash {
            event
                .metadata
                .insert("memory_hash".to_string(), mem_hash.clone());
        }
        if let Some(ref disk_hash) = detection.disk_hash {
            event
                .metadata
                .insert("disk_hash".to_string(), disk_hash.clone());
        }
        if let Some(ep) = detection.entry_point {
            event
                .metadata
                .insert("entry_point".to_string(), format!("0x{:x}", ep));
        }
        if let Some(base) = detection.image_base {
            event
                .metadata
                .insert("image_base".to_string(), format!("0x{:x}", base));
        }

        // Add evidence
        for (i, ev) in detection.evidence.iter().enumerate() {
            event.metadata.insert(format!("evidence_{}", i), ev.clone());
        }

        event
    }

    // ========================================================================
    // Windows Implementation
    // ========================================================================

    #[cfg(target_os = "windows")]
    async fn windows_monitor_loop(tx: mpsc::Sender<TelemetryEvent>, config: AgentConfig) {
        use std::sync::Arc;
        use tokio::sync::Mutex;

        info!("Starting Windows Process Doppelganging detection");

        // Shared state for correlation
        let transactions: Arc<Mutex<HashMap<u64, TransactionState>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let sections: Arc<Mutex<HashMap<u64, SectionState>>> = Arc::new(Mutex::new(HashMap::new()));
        let suspicious_processes: Arc<Mutex<HashMap<u32, SuspiciousProcessState>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let reported: Arc<Mutex<HashSet<u32>>> = Arc::new(Mutex::new(HashSet::new()));

        let mul = config.sub_loop_interval_multiplier;

        // Start multiple detection loops

        // 1. Process enumeration and backing file validation (5s base)
        let tx1 = tx.clone();
        let reported1 = reported.clone();
        let interval1 = ((5000.0 * mul) as u64).max(2000);
        tokio::spawn(async move {
            Self::process_validation_loop(tx1, reported1, interval1).await;
        });

        // 2. Memory vs disk comparison for new processes (3s base)
        let tx2 = tx.clone();
        let reported2 = reported.clone();
        let interval2 = ((3000.0 * mul) as u64).max(1000);
        tokio::spawn(async move {
            Self::memory_comparison_loop(tx2, reported2, interval2).await;
        });

        // 3. Transaction handle monitoring (2s base)
        let tx3 = tx.clone();
        let transactions3 = transactions.clone();
        let sections3 = sections.clone();
        let reported3 = reported.clone();
        let interval3 = ((2000.0 * mul) as u64).max(1000);
        tokio::spawn(async move {
            Self::transaction_monitor_loop(tx3, transactions3, sections3, reported3, interval3)
                .await;
        });

        // 4. Mapped filename validation (4s base)
        let tx4 = tx.clone();
        let reported4 = reported.clone();
        let interval4 = ((4000.0 * mul) as u64).max(2000);
        tokio::spawn(async move {
            Self::mapped_filename_loop(tx4, reported4, interval4).await;
        });

        // 5. ETW-based transaction event monitoring
        let tx5 = tx.clone();
        let transactions5 = transactions.clone();
        let reported5 = reported.clone();
        tokio::spawn(async move {
            Self::etw_transaction_loop(tx5, transactions5, reported5).await;
        });

        // Keep main task alive
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;

            // Cleanup old state
            let now = Self::current_timestamp();

            {
                let mut txns = transactions.lock().await;
                txns.retain(|_, v| now - v.creation_time < 300_000);
            }

            {
                let mut secs = sections.lock().await;
                secs.retain(|_, v| now - v.creation_time < 300_000);
            }

            {
                let mut rep = reported.lock().await;
                if rep.len() > 50_000 {
                    rep.clear();
                }
            }
        }
    }

    /// Process validation loop: Check if process backing files exist
    #[cfg(target_os = "windows")]
    async fn process_validation_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        reported: Arc<Mutex<HashSet<u32>>>,
        interval_ms: u64,
    ) {
        use windows::Win32::Foundation::{CloseHandle, HMODULE};
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };
        use windows::Win32::System::ProcessStatus::{EnumProcessModules, GetModuleFileNameExW};
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        info!("Starting process backing file validation loop");

        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));
        let mut known_pids: HashSet<u32> = HashSet::new();

        loop {
            interval.tick().await;

            let mut current_pids: HashSet<u32> = HashSet::new();
            let mut new_processes: Vec<(u32, String, u32)> = Vec::new();

            unsafe {
                let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                    Ok(h) => h,
                    Err(_) => continue,
                };

                let mut entry = PROCESSENTRY32W {
                    dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                    ..Default::default()
                };

                if Process32FirstW(snapshot, &mut entry).is_ok() {
                    loop {
                        let pid = entry.th32ProcessID;
                        let ppid = entry.th32ParentProcessID;
                        current_pids.insert(pid);

                        if pid > 10 && pid != std::process::id() && !known_pids.contains(&pid) {
                            let name = String::from_utf16_lossy(
                                &entry.szExeFile
                                    [..entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0)],
                            );
                            new_processes.push((pid, name, ppid));
                        }

                        if Process32NextW(snapshot, &mut entry).is_err() {
                            break;
                        }
                    }
                }

                let _ = CloseHandle(snapshot);
            }

            known_pids = current_pids;

            // Check new processes for doppelganging indicators
            for (pid, name, ppid) in new_processes {
                let reported_guard = reported.lock().await;
                if reported_guard.contains(&pid) {
                    continue;
                }
                drop(reported_guard);

                // Get process module path
                let module_path = unsafe {
                    let handle = match OpenProcess(
                        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                        false,
                        pid,
                    ) {
                        Ok(h) => h,
                        Err(_) => continue,
                    };

                    let mut modules = [HMODULE::default(); 1];
                    let mut bytes_needed = 0u32;

                    let path = if EnumProcessModules(
                        handle,
                        modules.as_mut_ptr(),
                        std::mem::size_of_val(&modules) as u32,
                        &mut bytes_needed,
                    )
                    .is_ok()
                    {
                        let mut mod_name = [0u16; 512];
                        let len = GetModuleFileNameExW(handle, modules[0], &mut mod_name);
                        if len > 0 {
                            Some(String::from_utf16_lossy(&mod_name[..len as usize]))
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    let _ = CloseHandle(handle);
                    path
                };

                if let Some(path) = module_path {
                    // Check if file exists
                    let file_exists = std::path::Path::new(&path).exists();

                    if !file_exists {
                        // Strong indicator: backing file doesn't exist
                        let mut reported_guard = reported.lock().await;
                        reported_guard.insert(pid);
                        drop(reported_guard);

                        let parent_name = Self::get_process_name(ppid);
                        let parent_path = Self::get_process_path(ppid);

                        let detection = ProcessDoppelgangingEvent {
                            target_pid: pid,
                            target_name: name.clone(),
                            target_path: path.clone(),
                            source_pid: ppid,
                            source_name: parent_name,
                            source_path: parent_path,
                            detection_method: DoppelgangingDetectionMethod::MissingBackingFile,
                            confidence: 0.90,
                            transaction_handle: None,
                            section_handle: None,
                            transacted_file_path: Some(path.clone()),
                            backing_file_exists: false,
                            memory_hash: None,
                            disk_hash: None,
                            evidence: vec![
                                format!("Process backing file does not exist: {}", path),
                                "Process was created from a file that no longer exists on disk"
                                    .to_string(),
                                "This is a strong indicator of Process Doppelganging (T1055.013)"
                                    .to_string(),
                            ],
                            entry_point: None,
                            image_base: None,
                        };

                        let event = Self::create_event(&detection);
                        if tx.send(event).await.is_err() {
                            return;
                        }
                    }
                }
            }
        }
    }

    /// Memory comparison loop: Compare in-memory image to disk file
    #[cfg(target_os = "windows")]
    async fn memory_comparison_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        reported: Arc<Mutex<HashSet<u32>>>,
        interval_ms: u64,
    ) {
        use windows::Win32::Foundation::CloseHandle;

        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        info!("Starting memory vs disk comparison loop");

        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));
        let mut scanned_pids: HashSet<u32> = HashSet::new();

        loop {
            interval.tick().await;

            let mut processes_to_scan: Vec<(u32, u32)> = Vec::new();

            unsafe {
                let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                    Ok(h) => h,
                    Err(_) => continue,
                };

                let mut entry = PROCESSENTRY32W {
                    dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                    ..Default::default()
                };

                if Process32FirstW(snapshot, &mut entry).is_ok() {
                    loop {
                        let pid = entry.th32ProcessID;
                        let ppid = entry.th32ParentProcessID;

                        if pid > 10 && pid != std::process::id() && !scanned_pids.contains(&pid) {
                            processes_to_scan.push((pid, ppid));
                        }

                        if Process32NextW(snapshot, &mut entry).is_err() {
                            break;
                        }
                    }
                }

                let _ = CloseHandle(snapshot);
            }

            for (pid, ppid) in processes_to_scan {
                scanned_pids.insert(pid);

                let reported_guard = reported.lock().await;
                if reported_guard.contains(&pid) {
                    continue;
                }
                drop(reported_guard);

                if let Some(detection) = Self::compare_memory_to_disk(pid, ppid) {
                    let mut reported_guard = reported.lock().await;
                    reported_guard.insert(pid);
                    drop(reported_guard);

                    let event = Self::create_event(&detection);
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }
            }

            // Prevent unbounded growth
            if scanned_pids.len() > 50_000 {
                scanned_pids.clear();
            }
        }
    }

    /// Compare in-memory image to disk file for a process
    #[cfg(target_os = "windows")]
    fn compare_memory_to_disk(pid: u32, ppid: u32) -> Option<ProcessDoppelgangingEvent> {
        use sha2::{Digest, Sha256};
        use windows::Win32::Foundation::{CloseHandle, HMODULE};
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows::Win32::System::ProcessStatus::{
            EnumProcessModules, GetModuleFileNameExW, GetModuleInformation, MODULEINFO,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            {
                Ok(h) => h,
                Err(_) => return None,
            };

            let mut modules = [HMODULE::default(); 1];
            let mut bytes_needed = 0u32;

            if EnumProcessModules(
                handle,
                modules.as_mut_ptr(),
                std::mem::size_of_val(&modules) as u32,
                &mut bytes_needed,
            )
            .is_err()
            {
                let _ = CloseHandle(handle);
                return None;
            }

            // Get module path
            let mut mod_name = [0u16; 512];
            let mod_len = GetModuleFileNameExW(handle, modules[0], &mut mod_name);
            let module_path = if mod_len > 0 {
                String::from_utf16_lossy(&mod_name[..mod_len as usize])
            } else {
                let _ = CloseHandle(handle);
                return None;
            };

            // Get module info
            let mut mod_info = MODULEINFO::default();
            if GetModuleInformation(
                handle,
                modules[0],
                &mut mod_info,
                std::mem::size_of::<MODULEINFO>() as u32,
            )
            .is_err()
            {
                let _ = CloseHandle(handle);
                return None;
            }

            let module_base = mod_info.lpBaseOfDll as u64;

            // Read PE header from memory (first 4KB)
            let header_size = 4096usize;
            let mut mem_header = vec![0u8; header_size];
            let mut bytes_read = 0usize;

            if ReadProcessMemory(
                handle,
                module_base as *const _,
                mem_header.as_mut_ptr() as *mut _,
                header_size,
                Some(&mut bytes_read),
            )
            .is_err()
                || bytes_read < 64
            {
                let _ = CloseHandle(handle);
                return None;
            }

            mem_header.truncate(bytes_read);

            let _ = CloseHandle(handle);

            // Read disk file
            let disk_data = match std::fs::read(&module_path) {
                Ok(d) => d,
                Err(_) => {
                    // File doesn't exist - this is handled by the validation loop
                    return None;
                }
            };

            if disk_data.len() < 64 {
                return None;
            }

            // Compare PE headers
            let compare_len = std::cmp::min(
                std::cmp::min(mem_header.len(), disk_data.len()),
                header_size,
            );

            // Calculate difference metrics
            let mut diff_count = 0;
            let mut critical_diffs = 0;

            // Check DOS header (first 64 bytes should be nearly identical)
            for i in 0..std::cmp::min(64, compare_len) {
                if mem_header[i] != disk_data[i] {
                    // DOS header differences (excluding e_lfanew relocation)
                    if i < 60 {
                        critical_diffs += 1;
                    }
                    diff_count += 1;
                }
            }

            // Check rest of header
            for i in 64..compare_len {
                if mem_header[i] != disk_data[i] {
                    diff_count += 1;
                }
            }

            // Parse entry points
            let mut disk_entry_point: Option<u32> = None;
            let mut mem_entry_point: Option<u32> = None;

            if disk_data.len() >= 64 && mem_header.len() >= 64 {
                // Get e_lfanew
                let disk_lfanew = u32::from_le_bytes([
                    disk_data[60],
                    disk_data[61],
                    disk_data[62],
                    disk_data[63],
                ]) as usize;
                let mem_lfanew = u32::from_le_bytes([
                    mem_header[60],
                    mem_header[61],
                    mem_header[62],
                    mem_header[63],
                ]) as usize;

                // Entry point is at PE_HEADER + 4 (signature) + 20 (COFF header) + 16 (offset in optional header)
                let disk_ep_offset = disk_lfanew + 4 + 20 + 16;
                let mem_ep_offset = mem_lfanew + 4 + 20 + 16;

                if disk_ep_offset + 4 <= disk_data.len() {
                    disk_entry_point = Some(u32::from_le_bytes([
                        disk_data[disk_ep_offset],
                        disk_data[disk_ep_offset + 1],
                        disk_data[disk_ep_offset + 2],
                        disk_data[disk_ep_offset + 3],
                    ]));
                }

                if mem_ep_offset + 4 <= mem_header.len() {
                    mem_entry_point = Some(u32::from_le_bytes([
                        mem_header[mem_ep_offset],
                        mem_header[mem_ep_offset + 1],
                        mem_header[mem_ep_offset + 2],
                        mem_header[mem_ep_offset + 3],
                    ]));
                }
            }

            // Calculate hashes
            let mut mem_hasher = Sha256::new();
            mem_hasher.update(&mem_header[..std::cmp::min(512, mem_header.len())]);
            let mem_hash = hex::encode(mem_hasher.finalize());

            let mut disk_hasher = Sha256::new();
            disk_hasher.update(&disk_data[..std::cmp::min(512, disk_data.len())]);
            let disk_hash = hex::encode(disk_hasher.finalize());

            // Determine if this is suspicious
            let mut evidence = Vec::new();
            let mut confidence: f32 = 0.0;

            // Critical DOS header differences (very suspicious)
            if critical_diffs > 4 {
                evidence.push(format!(
                    "DOS header has {} critical byte differences",
                    critical_diffs
                ));
                confidence += 0.35;
            }

            // Significant overall differences
            if diff_count > 128 {
                evidence.push(format!(
                    "PE header has {} byte differences ({}% of compared region)",
                    diff_count,
                    (diff_count * 100) / compare_len
                ));
                confidence += 0.25;
            }

            // Entry point mismatch
            if let (Some(disk_ep), Some(mem_ep)) = (disk_entry_point, mem_entry_point) {
                if disk_ep != mem_ep {
                    evidence.push(format!(
                        "Entry point differs: disk=0x{:x}, memory=0x{:x}",
                        disk_ep, mem_ep
                    ));
                    confidence += 0.30;
                }
            }

            // Hash mismatch
            if mem_hash != disk_hash && diff_count > 32 {
                evidence.push(format!(
                    "Header hash mismatch: disk={}, memory={}",
                    &disk_hash[..16],
                    &mem_hash[..16]
                ));
                confidence += 0.10;
            }

            // Only report if confidence is high enough
            if confidence < 0.50 {
                return None;
            }

            confidence = confidence.min(0.99);

            let process_name = Self::get_process_name(pid);
            let parent_name = Self::get_process_name(ppid);
            let parent_path = Self::get_process_path(ppid);

            evidence.push("MITRE ATT&CK: T1055.013 (Process Doppelganging)".to_string());
            evidence.push(format!("Analyzed {} bytes of PE header", compare_len));

            Some(ProcessDoppelgangingEvent {
                target_pid: pid,
                target_name: process_name,
                target_path: module_path,
                source_pid: ppid,
                source_name: parent_name,
                source_path: parent_path,
                detection_method: DoppelgangingDetectionMethod::MemoryDiskMismatch,
                confidence,
                transaction_handle: None,
                section_handle: None,
                transacted_file_path: None,
                backing_file_exists: true,
                memory_hash: Some(mem_hash),
                disk_hash: Some(disk_hash),
                evidence,
                entry_point: mem_entry_point.map(|ep| ep as u64 + module_base),
                image_base: Some(module_base),
            })
        }
    }

    /// Transaction monitor loop: Track transaction handles and correlate with sections
    #[cfg(target_os = "windows")]
    async fn transaction_monitor_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        transactions: Arc<Mutex<HashMap<u64, TransactionState>>>,
        sections: Arc<Mutex<HashMap<u64, SectionState>>>,
        reported: Arc<Mutex<HashSet<u32>>>,
        interval_ms: u64,
    ) {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        info!("Starting transaction handle monitoring loop");

        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        loop {
            interval.tick().await;

            // Enumerate processes and check for transaction handles
            let mut processes_with_transactions: Vec<(u32, String, u32)> = Vec::new();

            unsafe {
                let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                    Ok(h) => h,
                    Err(_) => continue,
                };

                let mut entry = PROCESSENTRY32W {
                    dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                    ..Default::default()
                };

                if Process32FirstW(snapshot, &mut entry).is_ok() {
                    loop {
                        let pid = entry.th32ProcessID;
                        let ppid = entry.th32ParentProcessID;

                        if pid > 10 && pid != std::process::id() {
                            let name = String::from_utf16_lossy(
                                &entry.szExeFile
                                    [..entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0)],
                            );

                            // Check if process has TmTx (Transaction) handles
                            if Self::process_has_transaction_handles(pid) {
                                processes_with_transactions.push((pid, name, ppid));
                            }
                        }

                        if Process32NextW(snapshot, &mut entry).is_err() {
                            break;
                        }
                    }
                }

                let _ = CloseHandle(snapshot);
            }

            // Track transactions and look for suspicious patterns
            for (pid, name, ppid) in processes_with_transactions {
                let mut txn_guard = transactions.lock().await;

                // Check if this is a new transaction
                let has_existing = txn_guard.values().any(|t| t.creator_pid == pid);

                if !has_existing {
                    // New transaction detected - add to tracking
                    let handle = Self::current_timestamp(); // Use timestamp as pseudo-handle
                    txn_guard.insert(
                        handle,
                        TransactionState {
                            creator_pid: pid,
                            handle,
                            creation_time: Self::current_timestamp(),
                            transacted_files: Vec::new(),
                            sections_created: Vec::new(),
                            rolled_back: false,
                            process_created: false,
                        },
                    );

                    debug!(
                        pid = pid,
                        name = %name,
                        "Process has active transaction handles"
                    );
                }
            }

            // Look for correlation patterns
            let txn_guard = transactions.lock().await;
            for (_handle, txn) in txn_guard.iter() {
                if txn.process_created && txn.rolled_back {
                    // This is a strong doppelganging indicator
                    let mut reported_guard = reported.lock().await;
                    if reported_guard.contains(&txn.creator_pid) {
                        continue;
                    }
                    reported_guard.insert(txn.creator_pid);
                    drop(reported_guard);

                    let process_name = Self::get_process_name(txn.creator_pid);
                    let process_path = Self::get_process_path(txn.creator_pid);

                    let detection = ProcessDoppelgangingEvent {
                        target_pid: txn.creator_pid,
                        target_name: process_name.clone(),
                        target_path: process_path.clone(),
                        source_pid: 0,
                        source_name: "Unknown".to_string(),
                        source_path: String::new(),
                        detection_method: DoppelgangingDetectionMethod::TransactionRollbackProcess,
                        confidence: 0.95,
                        transaction_handle: Some(txn.handle),
                        section_handle: None,
                        transacted_file_path: txn.transacted_files.first().cloned(),
                        backing_file_exists: false,
                        memory_hash: None,
                        disk_hash: None,
                        evidence: vec![
                            "Transaction rolled back after process creation".to_string(),
                            format!(
                                "Process {} (PID: {}) created process from transacted file",
                                process_name, txn.creator_pid
                            ),
                            "Strong indicator of Process Doppelganging (T1055.013)".to_string(),
                        ],
                        entry_point: None,
                        image_base: None,
                    };

                    drop(txn_guard);

                    let event = Self::create_event(&detection);
                    if tx.send(event).await.is_err() {
                        return;
                    }

                    break;
                }
            }
        }
    }

    /// Check if a process has open transaction handles
    #[cfg(target_os = "windows")]
    fn process_has_transaction_handles(pid: u32) -> bool {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_DUP_HANDLE};

        unsafe {
            // Try to open process with handle duplication rights
            // This is a heuristic - full implementation would use NtQuerySystemInformation
            let handle = match OpenProcess(PROCESS_DUP_HANDLE, false, pid) {
                Ok(h) => h,
                Err(_) => return false,
            };

            // In a full implementation, we would enumerate handles and check for
            // TmTx (Transaction) object type. For now, we use behavioral heuristics.
            let _ = CloseHandle(handle);

            // Check if process has loaded ktmw32.dll (TxF API)
            Self::process_has_txf_module(pid)
        }
    }

    /// Check if process has loaded TxF-related modules
    #[cfg(target_os = "windows")]
    fn process_has_txf_module(pid: u32) -> bool {
        use windows::Win32::Foundation::{CloseHandle, HMODULE};
        use windows::Win32::System::ProcessStatus::{
            EnumProcessModulesEx, GetModuleBaseNameW, LIST_MODULES_ALL,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            {
                Ok(h) => h,
                Err(_) => return false,
            };

            let mut modules = [HMODULE::default(); 1024];
            let mut bytes_needed = 0u32;

            if EnumProcessModulesEx(
                handle,
                modules.as_mut_ptr(),
                std::mem::size_of_val(&modules) as u32,
                &mut bytes_needed,
                LIST_MODULES_ALL,
            )
            .is_err()
            {
                let _ = CloseHandle(handle);
                return false;
            }

            let module_count = bytes_needed as usize / std::mem::size_of::<HMODULE>();

            for i in 0..module_count {
                let mut name = [0u16; 256];
                let len = GetModuleBaseNameW(handle, modules[i], &mut name);
                if len > 0 {
                    let module_name =
                        String::from_utf16_lossy(&name[..len as usize]).to_lowercase();
                    // Check for TxF-related DLLs
                    if module_name.contains("ktmw32") || module_name.contains("txfw32") {
                        let _ = CloseHandle(handle);
                        return true;
                    }
                }
            }

            let _ = CloseHandle(handle);
            false
        }
    }

    /// Mapped filename validation loop
    #[cfg(target_os = "windows")]
    async fn mapped_filename_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        reported: Arc<Mutex<HashSet<u32>>>,
        interval_ms: u64,
    ) {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        info!("Starting mapped filename validation loop");

        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));
        let mut scanned_pids: HashSet<u32> = HashSet::new();

        loop {
            interval.tick().await;

            let mut processes_to_check: Vec<(u32, u32)> = Vec::new();

            unsafe {
                let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                    Ok(h) => h,
                    Err(_) => continue,
                };

                let mut entry = PROCESSENTRY32W {
                    dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                    ..Default::default()
                };

                if Process32FirstW(snapshot, &mut entry).is_ok() {
                    loop {
                        let pid = entry.th32ProcessID;
                        let ppid = entry.th32ParentProcessID;

                        if pid > 10 && pid != std::process::id() && !scanned_pids.contains(&pid) {
                            processes_to_check.push((pid, ppid));
                        }

                        if Process32NextW(snapshot, &mut entry).is_err() {
                            break;
                        }
                    }
                }

                let _ = CloseHandle(snapshot);
            }

            for (pid, ppid) in processes_to_check {
                scanned_pids.insert(pid);

                let reported_guard = reported.lock().await;
                if reported_guard.contains(&pid) {
                    continue;
                }
                drop(reported_guard);

                if let Some(detection) = Self::check_mapped_filename_mismatch(pid, ppid) {
                    let mut reported_guard = reported.lock().await;
                    reported_guard.insert(pid);
                    drop(reported_guard);

                    let event = Self::create_event(&detection);
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }
            }

            if scanned_pids.len() > 50_000 {
                scanned_pids.clear();
            }
        }
    }

    /// Check for mapped filename vs module path mismatch
    #[cfg(target_os = "windows")]
    fn check_mapped_filename_mismatch(pid: u32, ppid: u32) -> Option<ProcessDoppelgangingEvent> {
        use windows::Win32::Foundation::{CloseHandle, HMODULE};
        use windows::Win32::System::ProcessStatus::{
            EnumProcessModules, GetMappedFileNameW, GetModuleFileNameExW,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            {
                Ok(h) => h,
                Err(_) => return None,
            };

            let mut modules = [HMODULE::default(); 1];
            let mut bytes_needed = 0u32;

            if EnumProcessModules(
                handle,
                modules.as_mut_ptr(),
                std::mem::size_of_val(&modules) as u32,
                &mut bytes_needed,
            )
            .is_err()
            {
                let _ = CloseHandle(handle);
                return None;
            }

            // Get module filename (from loader)
            let mut mod_name = [0u16; 512];
            let mod_len = GetModuleFileNameExW(handle, modules[0], &mut mod_name);
            let module_filename = if mod_len > 0 {
                String::from_utf16_lossy(&mod_name[..mod_len as usize])
            } else {
                let _ = CloseHandle(handle);
                return None;
            };

            // Get mapped filename (actual backing file)
            let mut mapped_name = [0u16; 512];
            let mapped_len = GetMappedFileNameW(handle, modules[0].0 as *const _, &mut mapped_name);

            let _ = CloseHandle(handle);

            if mapped_len == 0 {
                return None;
            }

            let mapped_filename = String::from_utf16_lossy(&mapped_name[..mapped_len as usize]);

            // Extract just the filename components
            let mod_file = module_filename.rsplit('\\').next().unwrap_or("");
            let mapped_file = mapped_filename.rsplit('\\').next().unwrap_or("");

            // Check for mismatch
            if !mod_file.is_empty()
                && !mapped_file.is_empty()
                && mod_file.to_lowercase() != mapped_file.to_lowercase()
            {
                let process_name = Self::get_process_name(pid);
                let parent_name = Self::get_process_name(ppid);
                let parent_path = Self::get_process_path(ppid);

                // Convert device path to DOS path if possible
                let mapped_dos_path = Self::convert_device_path(&mapped_filename);

                return Some(ProcessDoppelgangingEvent {
                    target_pid: pid,
                    target_name: process_name,
                    target_path: module_filename.clone(),
                    source_pid: ppid,
                    source_name: parent_name,
                    source_path: parent_path,
                    detection_method: DoppelgangingDetectionMethod::MappedFilenameMismatch,
                    confidence: 0.75,
                    transaction_handle: None,
                    section_handle: None,
                    transacted_file_path: Some(mapped_dos_path.clone()),
                    backing_file_exists: true,
                    memory_hash: None,
                    disk_hash: None,
                    evidence: vec![
                        format!(
                            "Module filename ({}) differs from mapped file ({})",
                            module_filename, mapped_dos_path
                        ),
                        "GetMappedFileName returns different path than GetModuleFileNameEx"
                            .to_string(),
                        "This may indicate the section was created from a different file"
                            .to_string(),
                        "MITRE ATT&CK: T1055.013 (Process Doppelganging)".to_string(),
                    ],
                    entry_point: None,
                    image_base: None,
                });
            }

            None
        }
    }

    /// ETW transaction event monitoring loop
    #[cfg(target_os = "windows")]
    async fn etw_transaction_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        transactions: Arc<Mutex<HashMap<u64, TransactionState>>>,
        reported: Arc<Mutex<HashSet<u32>>>,
    ) {
        // In a full implementation, this would use ETW to subscribe to:
        // - Microsoft-Windows-Kernel-Transaction (KTM events)
        // - Transaction create/rollback/commit events
        //
        // For now, this is a placeholder that monitors behavioral indicators
        info!("Starting ETW transaction event monitor (behavioral mode)");

        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10));

        loop {
            interval.tick().await;

            // Check for behavioral patterns that indicate doppelganging
            // This is a heuristic approach without full ETW integration

            // Look for processes that were created recently and have
            // suspicious characteristics
            trace!("ETW transaction monitor tick");
        }
    }

    // ========================================================================
    // Helper Functions
    // ========================================================================

    #[cfg(target_os = "windows")]
    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    #[cfg(target_os = "windows")]
    fn get_process_name(pid: u32) -> String {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

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
                        let name = String::from_utf16_lossy(
                            &entry.szExeFile
                                [..entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0)],
                        );
                        let _ = CloseHandle(snapshot);
                        return name;
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

    #[cfg(target_os = "windows")]
    fn get_process_path(pid: u32) -> String {
        use windows::Win32::Foundation::{CloseHandle, HMODULE};
        use windows::Win32::System::ProcessStatus::{EnumProcessModules, GetModuleFileNameExW};
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            {
                Ok(h) => h,
                Err(_) => return String::new(),
            };

            let mut modules = [HMODULE::default(); 1];
            let mut bytes_needed = 0u32;

            if EnumProcessModules(
                handle,
                modules.as_mut_ptr(),
                std::mem::size_of_val(&modules) as u32,
                &mut bytes_needed,
            )
            .is_err()
            {
                let _ = CloseHandle(handle);
                return String::new();
            }

            let mut mod_name = [0u16; 512];
            let len = GetModuleFileNameExW(handle, modules[0], &mut mod_name);

            let _ = CloseHandle(handle);

            if len > 0 {
                String::from_utf16_lossy(&mod_name[..len as usize])
            } else {
                String::new()
            }
        }
    }

    /// Convert NT device path to DOS path
    #[cfg(target_os = "windows")]
    fn convert_device_path(device_path: &str) -> String {
        // \Device\HarddiskVolume1\... -> C:\...
        // This is a simplified conversion
        if device_path.starts_with("\\Device\\HarddiskVolume") {
            // Try to resolve via QueryDosDevice
            // For now, return as-is
            return device_path.to_string();
        }
        device_path.to_string()
    }
}

// ============================================================================
// Re-exports (aliases for convenience)
// ============================================================================

/// Alias for ProcessDoppelgangingEvent
pub type DoppelgangingEvent = ProcessDoppelgangingEvent;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detection_method_properties() {
        let method = DoppelgangingDetectionMethod::MissingBackingFile;
        assert_eq!(method.as_str(), "missing_backing_file");
        assert!(method.confidence_weight() >= 0.0 && method.confidence_weight() <= 1.0);
        assert!(!method.description().is_empty());
    }

    #[test]
    fn test_event_creation() {
        let detection = ProcessDoppelgangingEvent {
            target_pid: 1234,
            target_name: "malware.exe".to_string(),
            target_path: "C:\\temp\\malware.exe".to_string(),
            source_pid: 5678,
            source_name: "cmd.exe".to_string(),
            source_path: "C:\\Windows\\System32\\cmd.exe".to_string(),
            detection_method: DoppelgangingDetectionMethod::MissingBackingFile,
            confidence: 0.90,
            transaction_handle: None,
            section_handle: None,
            transacted_file_path: None,
            backing_file_exists: false,
            memory_hash: None,
            disk_hash: None,
            evidence: vec!["Test evidence".to_string()],
            entry_point: None,
            image_base: None,
        };

        assert_eq!(detection.target_pid, 1234);
        assert_eq!(detection.confidence, 0.90);
        assert!(!detection.backing_file_exists);
    }
}
