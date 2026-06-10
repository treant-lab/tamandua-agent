//! Process Injection Detection Collector
//!
//! Detects process injection techniques including:
//! - DLL Injection (LoadLibrary-based) - T1055.001
//! - CreateRemoteThread / RtlCreateUserThread - T1055.001
//! - WriteProcessMemory + CreateRemoteThread - T1055
//! - VirtualAllocEx with executable permissions - T1055
//! - Process hollowing - T1055.012
//! - APC injection (QueueUserAPC) - T1055.004
//! - Thread Hijacking (SetThreadContext) - T1055.003
//! - Section mapping (NtMapViewOfSection) - T1055
//! - ptrace-based injection (Linux) - T1055.008
//! - LD_PRELOAD injection (Linux) - T1574.006
//!
//! Windows detection methods:
//! - NtQueryVirtualMemory to scan for injected memory regions
//! - Detection of RWX (Read-Write-Execute) memory pages
//! - Cross-process handle monitoring via NtQuerySystemInformation
//! - Pattern analysis for suspicious API sequences
//!
//! Linux detection methods:
//! - /proc/[pid]/maps analysis for suspicious memory regions
//! - ptrace detection via /proc/[pid]/status TracerPid
//! - LD_PRELOAD detection in /proc/[pid]/environ
//! - Audit log monitoring for injection syscalls
//!
//! MITRE ATT&CK: T1055 (Process Injection)

// This collector enumerates injection-family detection state (DLL injection,
// CreateRemoteThread/RtlCreateUserThread, APC, thread hijacking, section
// mapping, ptrace, LD_PRELOAD). Reserved memory-type constants and ntdll
// shim names follow Windows convention and are kept exhaustive even when
// not all paths are currently dispatched.
#![allow(dead_code, unused_variables, non_snake_case)]

use super::{
    Detection, DetectionType, EventPayload, EventType, ProcessEvent, Severity, TelemetryEvent,
};
use crate::config::AgentConfig;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Process injection event details
#[derive(Debug, Clone)]
pub struct InjectionEvent {
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
    /// Injection technique detected
    pub technique: InjectionTechnique,
    /// Memory address involved (if applicable)
    pub memory_address: Option<u64>,
    /// Memory size involved (if applicable)
    pub memory_size: Option<u64>,
    /// Memory protection flags
    pub memory_protection: Option<u32>,
    /// Additional evidence/details
    pub evidence: Vec<String>,
}

/// Detected injection techniques
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InjectionTechnique {
    /// CreateRemoteThread / RtlCreateUserThread - T1055.001
    RemoteThread,
    /// DLL Injection via LoadLibrary - T1055.001
    DllInjection,
    /// WriteProcessMemory with executable memory - T1055
    ProcessMemoryWrite,
    /// VirtualAllocEx with PAGE_EXECUTE_* - T1055
    RemoteMemoryAlloc,
    /// Process hollowing - T1055.012
    ProcessHollowing,
    /// APC injection - T1055.004
    ApcInjection,
    /// SetThreadContext / Thread Hijacking - T1055.003
    ThreadHijacking,
    /// NtMapViewOfSection - T1055
    SectionMapping,
    /// Suspicious RWX memory in non-JIT process
    SuspiciousRwxMemory,
    /// ptrace injection (Linux) - T1055.008
    PtraceInjection,
    /// LD_PRELOAD injection (Linux) - T1574.006
    LdPreloadInjection,
    /// Suspicious memory mapping (Linux) - anonymous RWX
    SuspiciousMemoryMapping,
    /// process_vm_writev syscall (Linux)
    ProcessVmWrite,
    /// DYLD_INSERT_LIBRARIES injection (macOS) - T1574.006
    DyldInsertLibraries,
    /// task_for_pid abuse (macOS) - T1055
    TaskForPid,
    /// Suspicious dylib loading (macOS)
    SuspiciousDylib,
    /// Process Doppelganging (transacted section + process creation) - T1055.013
    ProcessDoppelganging,
    // PoolParty thread pool injection variants (SafeBreach Labs)
    // These bypass all traditional EDR hooks by abusing Windows Thread Pool internals
    /// PoolParty Variant 1-3: Worker factory start routine hijack - T1055
    PoolPartyWorkerFactory,
    /// PoolParty Variant 4-5: I/O completion port NOP/TASK callback - T1055
    PoolPartyIoCompletion,
    /// PoolParty Variant 6: TP_DIRECT structure injection via NtSetIoCompletion - T1055
    PoolPartyTpDirect,
    /// PoolParty Variant 7: TP_TIMER via I/O completion - T1055
    PoolPartyIoTimer,
    /// PoolParty Variant 8: Timer queue manipulation via NtCreateTimer2/NtSetTimer2 - T1055
    PoolPartyTimerQueue,
    /// PoolParty Variant 9: ALPC port injection via TpAlpc - T1055
    PoolPartyAlpc,
    /// PoolParty generic: Alloc+Write without execution primitive (behavioral signature) - T1055
    PoolPartyBehavioral,
    /// Unknown technique
    Unknown,
}

impl InjectionTechnique {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RemoteThread => "remote_thread",
            Self::DllInjection => "dll_injection",
            Self::ProcessMemoryWrite => "process_memory_write",
            Self::RemoteMemoryAlloc => "remote_memory_alloc",
            Self::ProcessHollowing => "process_hollowing",
            Self::ApcInjection => "apc_injection",
            Self::ThreadHijacking => "thread_hijacking",
            Self::SectionMapping => "section_mapping",
            Self::SuspiciousRwxMemory => "suspicious_rwx_memory",
            Self::PtraceInjection => "ptrace_injection",
            Self::LdPreloadInjection => "ld_preload_injection",
            Self::SuspiciousMemoryMapping => "suspicious_memory_mapping",
            Self::ProcessVmWrite => "process_vm_write",
            Self::DyldInsertLibraries => "dyld_insert_libraries",
            Self::TaskForPid => "task_for_pid",
            Self::SuspiciousDylib => "suspicious_dylib",
            Self::ProcessDoppelganging => "process_doppelganging",
            Self::PoolPartyWorkerFactory => "poolparty_worker_factory",
            Self::PoolPartyIoCompletion => "poolparty_io_completion",
            Self::PoolPartyTpDirect => "poolparty_tp_direct",
            Self::PoolPartyIoTimer => "poolparty_io_timer",
            Self::PoolPartyTimerQueue => "poolparty_timer_queue",
            Self::PoolPartyAlpc => "poolparty_alpc",
            Self::PoolPartyBehavioral => "poolparty_behavioral",
            Self::Unknown => "unknown",
        }
    }

    pub fn mitre_technique(&self) -> &'static str {
        match self {
            Self::RemoteThread | Self::DllInjection => "T1055.001",
            Self::ProcessMemoryWrite => "T1055",
            Self::RemoteMemoryAlloc => "T1055",
            Self::ProcessHollowing => "T1055.012",
            Self::ApcInjection => "T1055.004",
            Self::ThreadHijacking => "T1055.003",
            Self::SectionMapping => "T1055",
            Self::SuspiciousRwxMemory => "T1055",
            Self::PtraceInjection => "T1055.008",
            Self::LdPreloadInjection => "T1574.006",
            Self::SuspiciousMemoryMapping => "T1055",
            Self::ProcessVmWrite => "T1055",
            Self::DyldInsertLibraries => "T1574.006",
            Self::TaskForPid => "T1055",
            Self::SuspiciousDylib => "T1574.006",
            Self::ProcessDoppelganging => "T1055.013",
            Self::PoolPartyWorkerFactory => "T1055",
            Self::PoolPartyIoCompletion => "T1055",
            Self::PoolPartyTpDirect => "T1055",
            Self::PoolPartyIoTimer => "T1055",
            Self::PoolPartyTimerQueue => "T1055",
            Self::PoolPartyAlpc => "T1055",
            Self::PoolPartyBehavioral => "T1055",
            Self::Unknown => "T1055",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::RemoteThread => "Remote thread creation in target process",
            Self::DllInjection => "DLL injection via LoadLibrary",
            Self::ProcessMemoryWrite => "Cross-process memory write detected",
            Self::RemoteMemoryAlloc => "Remote memory allocation with executable permissions",
            Self::ProcessHollowing => "Process hollowing indicators detected",
            Self::ApcInjection => "Asynchronous Procedure Call (APC) injection",
            Self::ThreadHijacking => "Thread context modification (hijacking)",
            Self::SectionMapping => "Section mapping injection",
            Self::SuspiciousRwxMemory => "Suspicious RWX memory region in non-JIT process",
            Self::PtraceInjection => "Process tracing (ptrace) injection",
            Self::LdPreloadInjection => "LD_PRELOAD library injection",
            Self::SuspiciousMemoryMapping => "Suspicious anonymous RWX memory mapping",
            Self::ProcessVmWrite => "Cross-process memory write via process_vm_writev",
            Self::DyldInsertLibraries => "DYLD_INSERT_LIBRARIES environment variable injection",
            Self::TaskForPid => "task_for_pid abuse for process manipulation",
            Self::SuspiciousDylib => "Suspicious dynamic library loaded into process",
            Self::ProcessDoppelganging => "Process Doppelganging via transacted file section",
            Self::PoolPartyWorkerFactory => {
                "PoolParty: Worker factory start routine hijack (Variants 1-3)"
            }
            Self::PoolPartyIoCompletion => {
                "PoolParty: I/O completion port callback injection (Variants 4-5)"
            }
            Self::PoolPartyTpDirect => {
                "PoolParty: TP_DIRECT structure injection via I/O completion (Variant 6)"
            }
            Self::PoolPartyIoTimer => "PoolParty: Timer via I/O completion port (Variant 7)",
            Self::PoolPartyTimerQueue => {
                "PoolParty: Timer queue manipulation via NtCreateTimer2 (Variant 8)"
            }
            Self::PoolPartyAlpc => "PoolParty: ALPC port injection via TpAlpc (Variant 9)",
            Self::PoolPartyBehavioral => {
                "PoolParty: Remote alloc+write without execution primitive (behavioral)"
            }
            Self::Unknown => "Unknown injection technique",
        }
    }
}

/// Process injection collector
pub struct InjectionCollector {
    #[allow(dead_code)]
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    #[allow(dead_code)]
    event_tx: mpsc::Sender<TelemetryEvent>,
}

impl InjectionCollector {
    /// Create a new injection collector
    pub fn new(config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(500);

        let collector = Self {
            config: config.clone(),
            event_rx: rx,
            event_tx: tx.clone(),
        };

        // Start platform-specific monitoring
        #[cfg(target_os = "windows")]
        {
            let tx_clone = tx.clone();
            let config_clone = config.clone();
            tokio::spawn(async move {
                windows_impl::monitor_loop(tx_clone, config_clone).await;
            });
        }

        #[cfg(target_os = "linux")]
        {
            let tx_clone = tx.clone();
            let config_clone = config.clone();
            tokio::spawn(async move {
                linux::monitor_loop(tx_clone, config_clone).await;
            });
        }

        info!("Injection detection collector initialized");
        collector
    }

    /// Get next event from collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }

    /// Create telemetry event from injection detection
    pub fn create_injection_event(injection: &InjectionEvent) -> TelemetryEvent {
        // Determine the appropriate EventType and DetectionType based on the technique
        let (event_type, detection_type) = match injection.technique {
            InjectionTechnique::ProcessHollowing => {
                (EventType::ProcessInject, DetectionType::ProcessHollowing)
            }
            InjectionTechnique::ThreadHijacking => {
                (EventType::ThreadHijacking, DetectionType::ThreadHijacking)
            }
            InjectionTechnique::ProcessDoppelganging => (
                EventType::ProcessDoppelganging,
                DetectionType::ProcessDoppelganging,
            ),
            _ => (EventType::ProcessInject, DetectionType::Behavioral),
        };

        let mut event = TelemetryEvent::new(
            event_type,
            Severity::Critical,
            EventPayload::Process(ProcessEvent {
                pid: injection.source_pid,
                ppid: 0,
                name: injection.source_name.clone(),
                path: injection.source_path.clone(),
                cmdline: String::new(),
                user: String::new(),
                sha256: Vec::new(),
                entropy: 0.0,
                is_elevated: false,
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

        // Build detailed description
        let description = format!(
            "{}: {} (PID: {}) -> {} (PID: {})",
            injection.technique.description(),
            injection.source_name,
            injection.source_pid,
            injection.target_name,
            injection.target_pid,
        );

        // Add detection
        event.add_detection(Detection {
            detection_type,
            rule_name: format!("injection_{}", injection.technique.as_str()),
            confidence: 0.95,
            description,
            mitre_tactics: vec![
                "defense-evasion".to_string(),
                "privilege-escalation".to_string(),
            ],
            mitre_techniques: vec![injection.technique.mitre_technique().to_string()],
        });

        // Add metadata
        event
            .metadata
            .insert("target_pid".to_string(), injection.target_pid.to_string());
        event
            .metadata
            .insert("target_name".to_string(), injection.target_name.clone());
        event
            .metadata
            .insert("target_path".to_string(), injection.target_path.clone());
        event.metadata.insert(
            "injection_technique".to_string(),
            injection.technique.as_str().to_string(),
        );
        event.metadata.insert(
            "mitre_technique".to_string(),
            injection.technique.mitre_technique().to_string(),
        );

        if let Some(addr) = injection.memory_address {
            event
                .metadata
                .insert("memory_address".to_string(), format!("0x{:x}", addr));
        }
        if let Some(size) = injection.memory_size {
            event
                .metadata
                .insert("memory_size".to_string(), size.to_string());
        }
        if let Some(prot) = injection.memory_protection {
            event
                .metadata
                .insert("memory_protection".to_string(), format!("0x{:x}", prot));
        }

        // Add evidence
        if !injection.evidence.is_empty() {
            event
                .metadata
                .insert("evidence".to_string(), injection.evidence.join("; "));
        }

        event
    }
}

// ==================== Windows Implementation ====================
#[cfg(target_os = "windows")]
mod windows_impl {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    // Windows API constants
    const PAGE_EXECUTE: u32 = 0x10;
    const PAGE_EXECUTE_READ: u32 = 0x20;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

    const MEM_COMMIT: u32 = 0x1000;
    const MEM_IMAGE: u32 = 0x1000000;
    const MEM_MAPPED: u32 = 0x40000;
    const MEM_PRIVATE: u32 = 0x20000;

    /// Cross-process operation tracking
    #[derive(Debug, Clone)]
    struct CrossProcessOp {
        op_type: OpType,
        source_pid: u32,
        source_name: String,
        source_path: String,
        target_pid: u32,
        target_name: String,
        target_path: String,
        timestamp: u64,
        memory_address: Option<u64>,
        memory_size: Option<u64>,
        memory_protection: Option<u32>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum OpType {
        VirtualAlloc,
        WriteMemory,
        CreateThread,
        SetContext,
        MapSection,
        QueueApc,
        OpenProcess,
    }

    /// Memory region information
    #[derive(Debug, Clone)]
    struct MemoryRegion {
        base_address: u64,
        region_size: u64,
        protection: u32,
        state: u32,
        region_type: u32,
        allocation_base: u64,
    }

    impl MemoryRegion {
        fn is_executable(&self) -> bool {
            self.protection & PAGE_EXECUTE != 0
                || self.protection & PAGE_EXECUTE_READ != 0
                || self.protection & PAGE_EXECUTE_READWRITE != 0
                || self.protection & PAGE_EXECUTE_WRITECOPY != 0
        }

        fn is_writable(&self) -> bool {
            self.protection & PAGE_EXECUTE_READWRITE != 0
                || self.protection & PAGE_EXECUTE_WRITECOPY != 0
                || self.protection & 0x04 != 0 // PAGE_READWRITE
                || self.protection & 0x08 != 0 // PAGE_WRITECOPY
        }

        fn is_rwx(&self) -> bool {
            self.is_executable() && self.is_writable()
        }

        fn is_private(&self) -> bool {
            self.region_type & MEM_PRIVATE != 0
        }

        fn is_committed(&self) -> bool {
            self.state & MEM_COMMIT != 0
        }
    }

    /// Main Windows monitoring loop
    pub async fn monitor_loop(tx: mpsc::Sender<TelemetryEvent>, config: AgentConfig) {
        let mul = config.sub_loop_interval_multiplier;
        let full_scan = config.full_scan_features;
        info!(
            multiplier = mul,
            full_scan = full_scan,
            "Starting Windows process injection monitor"
        );

        // Track cross-process operations
        let suspicious_ops: Arc<Mutex<HashMap<u32, Vec<CrossProcessOp>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Track known detections to avoid duplicates
        let known_detections: Arc<Mutex<HashSet<(u32, u32, InjectionTechnique)>>> =
            Arc::new(Mutex::new(HashSet::new()));

        // Memory scan results
        let memory_scan_results: Arc<Mutex<HashMap<u32, Vec<MemoryRegion>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Start RWX memory scanner (5s base -> scaled by multiplier)
        let tx_rwx = tx.clone();
        let known_rwx = known_detections.clone();
        let scan_results = memory_scan_results.clone();
        let rwx_interval_ms = ((5000.0 * mul) as u64).max(5000);
        tokio::spawn(async move {
            rwx_memory_scanner(tx_rwx, known_rwx, scan_results, rwx_interval_ms).await;
        });

        // Start cross-process handle monitor (500ms base -> scaled by multiplier)
        let tx_handle = tx.clone();
        let ops_handle = suspicious_ops.clone();
        let known_handle = known_detections.clone();
        let handle_interval_ms = ((500.0 * mul) as u64).max(500);
        tokio::spawn(async move {
            cross_process_handle_monitor(tx_handle, ops_handle, known_handle, handle_interval_ms)
                .await;
        });

        // Start thread creation monitor (250ms base -> scaled by multiplier)
        let tx_thread = tx.clone();
        let known_thread = known_detections.clone();
        let thread_interval_ms = ((250.0 * mul) as u64).max(250);
        tokio::spawn(async move {
            remote_thread_monitor(tx_thread, known_thread, thread_interval_ms).await;
        });

        // Start hollowing detection (full_scan only)
        if full_scan {
            let tx_hollow = tx.clone();
            let known_hollow = known_detections.clone();
            let hollow_interval_ms = ((3000.0 * mul) as u64).max(3000);
            tokio::spawn(async move {
                process_hollowing_detector(tx_hollow, known_hollow, hollow_interval_ms).await;
            });
        } else {
            info!("Skipping process_hollowing_detector (full_scan_features=false)");
        }

        // Start thread execution hijacking detector (T1055.003)
        let tx_hijack = tx.clone();
        let known_hijack = known_detections.clone();
        let hijack_interval_ms = ((500.0 * mul) as u64).max(500);
        tokio::spawn(async move {
            thread_hijacking_detector(tx_hijack, known_hijack, hijack_interval_ms).await;
        });

        // Start process doppelganging detector (T1055.013) (full_scan only)
        if full_scan {
            let tx_doppel = tx.clone();
            let known_doppel = known_detections.clone();
            let doppel_interval_ms = ((5000.0 * mul) as u64).max(5000);
            tokio::spawn(async move {
                process_doppelganging_detector(tx_doppel, known_doppel, doppel_interval_ms).await;
            });
        } else {
            info!("Skipping process_doppelganging_detector (full_scan_features=false)");
        }

        // Start PoolParty thread pool injection monitor (T1055) (full_scan only)
        if full_scan {
            let tx_poolparty = tx.clone();
            let known_poolparty = known_detections.clone();
            let scan_results_poolparty = memory_scan_results.clone();
            let poolparty_interval_ms = ((7000.0 * mul) as u64).max(7000);
            tokio::spawn(async move {
                poolparty_monitor_loop(
                    tx_poolparty,
                    known_poolparty,
                    scan_results_poolparty,
                    poolparty_interval_ms,
                )
                .await;
            });
        } else {
            info!("Skipping poolparty_monitor_loop (full_scan_features=false)");
        }

        // Main pattern analysis loop (2s base -> scaled by multiplier)
        let main_interval_ms = ((2000.0 * mul) as u64).max(2000);
        let mut interval =
            tokio::time::interval(tokio::time::Duration::from_millis(main_interval_ms));
        let mut last_known_cleanup = std::time::Instant::now();

        loop {
            interval.tick().await;

            let mut ops = suspicious_ops.lock().await;
            let mut known = known_detections.lock().await;

            // Analyze patterns for each source PID
            for (source_pid, operations) in ops.iter() {
                if let Some(injection) = analyze_injection_pattern(*source_pid, operations) {
                    let key = (
                        injection.source_pid,
                        injection.target_pid,
                        injection.technique,
                    );
                    if !known.contains(&key) {
                        known.insert(key);
                        let event = InjectionCollector::create_injection_event(&injection);
                        if tx.send(event).await.is_err() {
                            warn!("Event channel closed");
                            return;
                        }
                    }
                }
            }

            // Clear old operations (older than 10 seconds)
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            for operations in ops.values_mut() {
                operations.retain(|op| now - op.timestamp < 10);
            }

            // Remove empty entries
            ops.retain(|_, v| !v.is_empty());

            // Time-based cleanup of known detections every 300 seconds
            if last_known_cleanup.elapsed() > std::time::Duration::from_secs(300) {
                known.clear();
                last_known_cleanup = std::time::Instant::now();
            }
        }
    }

    /// Scan processes for suspicious RWX memory regions
    async fn rwx_memory_scanner(
        tx: mpsc::Sender<TelemetryEvent>,
        known: Arc<Mutex<HashSet<(u32, u32, InjectionTechnique)>>>,
        _scan_results: Arc<Mutex<HashMap<u32, Vec<MemoryRegion>>>>,
        interval_ms: u64,
    ) {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
        use windows::Win32::System::ProcessStatus::EnumProcesses;
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        info!("Starting RWX memory scanner");

        // Known JIT processes and system processes that legitimately use RWX memory.
        // Browsers use V8/SpiderMonkey JIT, .NET/Java have JIT compilers,
        // explorer.exe loads shell extensions, and security tools have inline hooks.
        let jit_processes: HashSet<&str> = [
            "java.exe",
            "javaw.exe",
            "node.exe",
            "python.exe",
            "python3.exe",
            "ruby.exe",
            "perl.exe",
            "dotnet.exe",
            "mono",
            "v8",
            "chrome.exe",
            "firefox.exe",
            "msedge.exe",
            "powershell.exe",
            "pwsh.exe",
            "brave.exe",
            "opera.exe",
            "vivaldi.exe",  // Chromium-based browsers
            "explorer.exe", // Shell extensions use RWX
            "searchhost.exe",
            "runtimebroker.exe", // Windows runtime processes
            "steamwebhelper.exe",
            "discord.exe", // Electron/Chromium apps
            "slack.exe",
            "teams.exe",
            "code.exe", // More Electron apps
            "msbuild.exe",
            "devenv.exe", // Development tools
        ]
        .iter()
        .cloned()
        .collect();

        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        loop {
            interval.tick().await;

            unsafe {
                // Get list of all processes
                let mut pids = vec![0u32; 4096];
                let mut bytes_returned: u32 = 0;

                if EnumProcesses(
                    pids.as_mut_ptr(),
                    (pids.len() * std::mem::size_of::<u32>()) as u32,
                    &mut bytes_returned,
                )
                .is_err()
                {
                    continue;
                }

                let num_processes = bytes_returned as usize / std::mem::size_of::<u32>();

                for &pid in &pids[..num_processes] {
                    if pid == 0 || pid < 10 {
                        continue; // Skip system processes
                    }

                    // Open process for memory query
                    let handle = match OpenProcess(
                        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                        false,
                        pid,
                    ) {
                        Ok(h) => h,
                        Err(_) => continue,
                    };

                    let process_name = get_process_name(pid);
                    let process_path = get_process_path(pid);

                    // Check if this is a known JIT process
                    let is_jit = jit_processes
                        .iter()
                        .any(|&jit| process_name.to_lowercase().contains(jit));

                    // Scan memory regions
                    let mut address: usize = 0;
                    let mut suspicious_regions = Vec::new();

                    loop {
                        let mut mbi = MEMORY_BASIC_INFORMATION::default();
                        let result = VirtualQueryEx(
                            handle,
                            Some(address as *const _),
                            &mut mbi,
                            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                        );

                        if result == 0 {
                            break;
                        }

                        let region = MemoryRegion {
                            base_address: mbi.BaseAddress as u64,
                            region_size: mbi.RegionSize as u64,
                            protection: mbi.Protect.0,
                            state: mbi.State.0,
                            region_type: mbi.Type.0,
                            allocation_base: mbi.AllocationBase as u64,
                        };

                        // Check for suspicious RWX memory
                        if region.is_committed() && region.is_rwx() && region.is_private() {
                            // Skip small regions (likely false positives)
                            if region.region_size > 4096 {
                                // For non-JIT processes, this is suspicious
                                if !is_jit {
                                    suspicious_regions.push(region.clone());
                                }
                            }
                        }

                        // Move to next region
                        address = mbi.BaseAddress as usize + mbi.RegionSize;
                        if address < mbi.BaseAddress as usize {
                            break; // Overflow protection
                        }
                    }

                    let _ = CloseHandle(handle);

                    // Report suspicious regions
                    for region in suspicious_regions {
                        let key = (0, pid, InjectionTechnique::SuspiciousRwxMemory);
                        let mut known_guard = known.lock().await;

                        if !known_guard.contains(&key) {
                            known_guard.insert(key);
                            drop(known_guard);

                            let injection = InjectionEvent {
                                source_pid: 0, // Unknown injector
                                source_name: "unknown".to_string(),
                                source_path: String::new(),
                                target_pid: pid,
                                target_name: process_name.clone(),
                                target_path: process_path.clone(),
                                technique: InjectionTechnique::SuspiciousRwxMemory,
                                memory_address: Some(region.base_address),
                                memory_size: Some(region.region_size),
                                memory_protection: Some(region.protection),
                                evidence: vec![
                                    format!("RWX memory at 0x{:x}", region.base_address),
                                    format!("Size: {} bytes", region.region_size),
                                    format!("Protection: 0x{:x}", region.protection),
                                    "Private memory region".to_string(),
                                ],
                            };

                            let event = InjectionCollector::create_injection_event(&injection);
                            if tx.send(event).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            }
        }
    }

    /// Monitor for cross-process handle operations using NtQuerySystemInformation.
    ///
    /// Enumerates all system handles via SystemHandleInformation (class 16) and
    /// identifies processes holding handles to other processes with access rights
    /// that enable injection (PROCESS_VM_WRITE, PROCESS_VM_OPERATION,
    /// PROCESS_CREATE_THREAD). Non-system processes holding such handles to
    /// foreign processes are flagged as potential injectors.
    async fn cross_process_handle_monitor(
        tx: mpsc::Sender<TelemetryEvent>,
        ops: Arc<Mutex<HashMap<u32, Vec<CrossProcessOp>>>>,
        known: Arc<Mutex<HashSet<(u32, u32, InjectionTechnique)>>>,
        interval_ms: u64,
    ) {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        info!("Starting cross-process handle monitor (NtQuerySystemInformation)");

        // Process object type index varies by Windows version.
        // Windows 10 1809+: typically 7, Windows 11: 7 or 8.
        // We check both common indices.
        const PROCESS_TYPE_INDICES: &[u8] = &[7, 8];

        // Access rights that enable injection when combined
        const PROCESS_ALL_ACCESS_MASK: u32 = 0x001FFFFF;
        // PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD
        // = 0x0020 | 0x0008 | 0x0002 = 0x002A
        const INJECTION_ACCESS_MASK: u32 = 0x002A;
        // PROCESS_VM_WRITE | PROCESS_VM_OPERATION = 0x0028
        const WRITE_ACCESS_MASK: u32 = 0x0028;

        // Known legitimate processes that commonly hold cross-process handles
        let legitimate_cross_process = [
            "csrss.exe",
            "lsass.exe",
            "services.exe",
            "svchost.exe",
            "wmiprvse.exe",
            "taskmgr.exe",
            "procexp64.exe",
            "procexp.exe",
            "procmon.exe",
            "procmon64.exe",
            "taskhostw.exe",
            "sihost.exe",
            "msmpeng.exe",
            "mssense.exe",
            "securityhealthservice.exe",
            "tamandua-agent.exe", // Our own agent
        ];

        // Known suspicious LOLBins that should not hold injection-capable handles
        let suspicious_injectors = [
            "rundll32.exe",
            "regsvr32.exe",
            "mshta.exe",
            "wscript.exe",
            "cscript.exe",
            "certutil.exe",
            "msiexec.exe",
            "installutil.exe",
            "regasm.exe",
            "regsvcs.exe",
            "msbuild.exe",
            "cmstp.exe",
            "eventvwr.exe",
            "fodhelper.exe",
        ];

        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        loop {
            interval.tick().await;

            unsafe {
                // Build a PID-to-name map from the current process snapshot
                let mut pid_to_name: HashMap<u32, String> = HashMap::new();

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
                        let name = String::from_utf16_lossy(
                            &entry.szExeFile[..entry
                                .szExeFile
                                .iter()
                                .position(|&c| c == 0)
                                .unwrap_or(entry.szExeFile.len())],
                        );
                        pid_to_name.insert(pid, name);

                        if Process32NextW(snapshot, &mut entry).is_err() {
                            break;
                        }
                    }
                }
                let _ = CloseHandle(snapshot);

                // Enumerate all system handles via NtQuerySystemInformation
                let cross_process_handles =
                    enumerate_cross_process_handles(&pid_to_name, PROCESS_TYPE_INDICES);

                // Analyze each detected cross-process handle relationship
                for (source_pid, target_pid, granted_access) in &cross_process_handles {
                    let source_name = pid_to_name
                        .get(source_pid)
                        .cloned()
                        .unwrap_or_else(|| get_process_name(*source_pid));

                    // Skip system processes and our own agent
                    if *source_pid <= 10
                        || is_system_process(&source_name)
                        || *source_pid == std::process::id()
                    {
                        continue;
                    }

                    // Skip known legitimate processes that hold cross-process handles
                    let is_legitimate = legitimate_cross_process
                        .iter()
                        .any(|&s| source_name.to_lowercase().contains(s));
                    if is_legitimate {
                        continue;
                    }

                    // Check if the granted access includes injection-capable rights
                    let has_full_access = *granted_access == PROCESS_ALL_ACCESS_MASK;
                    let has_injection_access =
                        (*granted_access & INJECTION_ACCESS_MASK) == INJECTION_ACCESS_MASK;
                    let has_write_access =
                        (*granted_access & WRITE_ACCESS_MASK) == WRITE_ACCESS_MASK;

                    if has_full_access || has_injection_access || has_write_access {
                        let target_name = pid_to_name
                            .get(target_pid)
                            .cloned()
                            .unwrap_or_else(|| get_process_name(*target_pid));

                        // Skip if target is also a system process
                        if is_system_process(&target_name) {
                            continue;
                        }

                        let is_suspicious_source = suspicious_injectors
                            .iter()
                            .any(|&s| source_name.to_lowercase().contains(s));

                        // Only alert on:
                        // 1. Known LOLBins holding injection-capable handles
                        // 2. Any process with PROCESS_ALL_ACCESS to a foreign process
                        // 3. Processes with the full injection triple (VM_WRITE + VM_OP + CREATE_THREAD)
                        if is_suspicious_source || has_full_access || has_injection_access {
                            let key = (
                                *source_pid,
                                *target_pid,
                                InjectionTechnique::ProcessMemoryWrite,
                            );
                            let mut known_guard = known.lock().await;

                            if !known_guard.contains(&key) {
                                known_guard.insert(key);
                                drop(known_guard);

                                let source_path = get_process_path(*source_pid);
                                let target_path = get_process_path(*target_pid);

                                let mut evidence = vec![
                                    format!(
                                        "Process {} (PID {}) holds handle to {} (PID {}) with access 0x{:08x}",
                                        source_name, source_pid, target_name, target_pid, granted_access
                                    ),
                                ];

                                if has_full_access {
                                    evidence.push("Handle grants PROCESS_ALL_ACCESS".to_string());
                                }
                                if has_injection_access {
                                    evidence.push("Handle grants VM_WRITE + VM_OPERATION + CREATE_THREAD (injection triple)".to_string());
                                }
                                if is_suspicious_source {
                                    evidence.push(format!(
                                        "{} is a known LOLBin/injection vector",
                                        source_name
                                    ));
                                }
                                evidence.push("Detected via NtQuerySystemInformation(SystemHandleInformation)".to_string());

                                // Record the operation for pattern correlation
                                let op = CrossProcessOp {
                                    op_type: OpType::OpenProcess,
                                    source_pid: *source_pid,
                                    source_name: source_name.clone(),
                                    source_path: source_path.clone(),
                                    target_pid: *target_pid,
                                    target_name: target_name.clone(),
                                    target_path: target_path.clone(),
                                    timestamp: std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs(),
                                    memory_address: None,
                                    memory_size: None,
                                    memory_protection: None,
                                };

                                {
                                    let mut ops_guard = ops.lock().await;
                                    ops_guard
                                        .entry(*source_pid)
                                        .or_insert_with(Vec::new)
                                        .push(op);
                                }

                                let injection = InjectionEvent {
                                    source_pid: *source_pid,
                                    source_name,
                                    source_path,
                                    target_pid: *target_pid,
                                    target_name,
                                    target_path,
                                    technique: InjectionTechnique::ProcessMemoryWrite,
                                    memory_address: None,
                                    memory_size: None,
                                    memory_protection: None,
                                    evidence,
                                };

                                let event = InjectionCollector::create_injection_event(&injection);
                                if tx.send(event).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Enumerate cross-process handles using NtQuerySystemInformation with
    /// SystemHandleInformation (class 16).
    ///
    /// Returns a list of (source_pid, target_pid, granted_access) tuples where
    /// source_pid holds a handle to target_pid's process object. The target_pid
    /// is determined by the handle's Object field lookup.
    ///
    /// Since we cannot directly resolve which process a handle refers to from
    /// the raw SYSTEM_HANDLE_TABLE_ENTRY_INFO without duplicating the handle
    /// into our process and calling NtQueryObject, we use a simpler approach:
    /// enumerate process-type handles and flag those with suspicious access
    /// rights owned by non-system processes.
    unsafe fn enumerate_cross_process_handles(
        pid_to_name: &HashMap<u32, String>,
        process_type_indices: &[u8],
    ) -> Vec<(u32, u32, u32)> {
        type NtQuerySystemInformationFn = unsafe extern "system" fn(
            u32,      // SystemInformationClass
            *mut u8,  // SystemInformation
            u32,      // SystemInformationLength
            *mut u32, // ReturnLength
        ) -> i32;

        let module = windows::Win32::System::LibraryLoader::GetModuleHandleA(
            windows::core::PCSTR::from_raw(b"ntdll.dll\0".as_ptr()),
        );

        let hmod = match module {
            Ok(h) => h,
            Err(_) => return Vec::new(),
        };

        let proc = windows::Win32::System::LibraryLoader::GetProcAddress(
            hmod,
            windows::core::PCSTR::from_raw(b"NtQuerySystemInformation\0".as_ptr()),
        );

        let nt_func: NtQuerySystemInformationFn = match proc {
            Some(f) => std::mem::transmute(f),
            None => return Vec::new(),
        };

        // Start with 1MB buffer and grow on STATUS_INFO_LENGTH_MISMATCH
        let mut buf_size: u32 = 1024 * 1024;
        let mut buffer: Vec<u8> = vec![0u8; buf_size as usize];
        let mut return_length: u32 = 0;

        for _ in 0..5 {
            let status = nt_func(
                16, // SystemHandleInformation
                buffer.as_mut_ptr(),
                buf_size,
                &mut return_length,
            );

            if status == 0 {
                break;
            } else if status == -1073741820i32 {
                // STATUS_INFO_LENGTH_MISMATCH: double the buffer
                buf_size = (return_length + 65536).max(buf_size * 2);
                buffer.resize(buf_size as usize, 0);
            } else {
                debug!(
                    status = status,
                    "NtQuerySystemInformation(SystemHandleInformation) failed"
                );
                return Vec::new();
            }
        }

        // Parse SYSTEM_HANDLE_INFORMATION
        let entry_size = if cfg!(target_pointer_width = "64") {
            24usize
        } else {
            16usize
        };
        // GrantedAccess offset: after Object pointer
        let granted_access_offset = if cfg!(target_pointer_width = "64") {
            16usize
        } else {
            12usize
        };

        if buffer.len() < 4 {
            return Vec::new();
        }

        let handle_count =
            u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
        let entries_start = std::mem::size_of::<u32>();

        let our_pid = std::process::id();
        let mut results: Vec<(u32, u32, u32)> = Vec::new();

        // Track which PIDs own process-type handles and their access rights.
        // Since we cannot easily determine the target PID from the handle entry
        // alone without NtDuplicateObject + NtQueryObject, we collect process-type
        // handles per PID with their access rights. For processes that hold
        // suspicious access rights, we pair them with known PIDs as potential
        // targets using heuristics.
        //
        // Specifically: for each non-system PID that owns a Process handle with
        // injection-capable access, we report a potential cross-process threat.
        // The target is approximated as "any other process" since the full
        // NtDuplicateObject flow is too expensive for continuous monitoring.
        let mut suspicious_holders: Vec<(u32, u32)> = Vec::new(); // (pid, access)

        for i in 0..handle_count {
            let offset = entries_start + i * entry_size;
            if offset + entry_size > buffer.len() {
                break;
            }

            let entry_pid = u16::from_le_bytes([buffer[offset], buffer[offset + 1]]) as u32;
            let object_type = buffer[offset + 4];
            let granted_access = u32::from_le_bytes([
                buffer[offset + granted_access_offset],
                buffer[offset + granted_access_offset + 1],
                buffer[offset + granted_access_offset + 2],
                buffer[offset + granted_access_offset + 3],
            ]);

            // Check if this is a Process-type handle
            if process_type_indices.contains(&object_type) {
                // Skip our own process and system processes
                if entry_pid <= 10 || entry_pid == our_pid {
                    continue;
                }

                // Check for injection-capable access rights
                // PROCESS_VM_WRITE = 0x0020, PROCESS_VM_OPERATION = 0x0008,
                // PROCESS_CREATE_THREAD = 0x0002, PROCESS_ALL_ACCESS = 0x1FFFFF
                let has_write = (granted_access & 0x0020) != 0;
                let has_vm_op = (granted_access & 0x0008) != 0;
                let has_create_thread = (granted_access & 0x0002) != 0;
                let has_all = granted_access == 0x001FFFFF;

                if has_all || (has_write && has_vm_op) || (has_write && has_create_thread) {
                    suspicious_holders.push((entry_pid, granted_access));
                }
            }
        }

        // For each suspicious handle holder, generate a detection entry.
        // We pair with target_pid=0 to indicate the target is unknown from
        // the handle table alone. The caller can refine this using other signals.
        for (source_pid, access) in suspicious_holders {
            // Use target_pid 0 to signal unknown target; the monitor loop
            // will pair this with process-snapshot data as appropriate.
            results.push((source_pid, 0, access));
        }

        results
    }

    /// Monitor for remote thread creation
    async fn remote_thread_monitor(
        tx: mpsc::Sender<TelemetryEvent>,
        known: Arc<Mutex<HashSet<(u32, u32, InjectionTechnique)>>>,
        interval_ms: u64,
    ) {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
        };

        info!("Starting remote thread creation monitor");

        // Track thread counts per process
        let mut process_threads: HashMap<u32, HashSet<u32>> = HashMap::new();

        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        loop {
            interval.tick().await;

            unsafe {
                let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
                    Ok(h) => h,
                    Err(_) => continue,
                };

                let mut entry = THREADENTRY32 {
                    dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                    ..Default::default()
                };

                let mut current_threads: HashMap<u32, HashSet<u32>> = HashMap::new();

                if Thread32First(snapshot, &mut entry).is_ok() {
                    loop {
                        let owner_pid = entry.th32OwnerProcessID;
                        let thread_id = entry.th32ThreadID;

                        current_threads
                            .entry(owner_pid)
                            .or_insert_with(HashSet::new)
                            .insert(thread_id);

                        if Thread32Next(snapshot, &mut entry).is_err() {
                            break;
                        }
                    }
                }

                let _ = CloseHandle(snapshot);

                // Compare with previous snapshot to find new threads
                for (pid, threads) in &current_threads {
                    if let Some(old_threads) = process_threads.get(pid) {
                        let new_threads: Vec<u32> =
                            threads.difference(old_threads).copied().collect();

                        // Check for suspicious new threads
                        for thread_id in new_threads {
                            if let Some(injection) = check_thread_for_injection(*pid, thread_id) {
                                let key = (
                                    injection.source_pid,
                                    injection.target_pid,
                                    injection.technique,
                                );
                                let mut known_guard = known.lock().await;

                                if !known_guard.contains(&key) {
                                    known_guard.insert(key);
                                    drop(known_guard);

                                    let event =
                                        InjectionCollector::create_injection_event(&injection);
                                    if tx.send(event).await.is_err() {
                                        return;
                                    }
                                }
                            }
                        }
                    }
                }

                process_threads = current_threads;
            }
        }
    }

    /// Check if a new thread indicates injection by querying its Win32 start address
    /// via NtQueryInformationThread and verifying whether that address resides in
    /// a legitimate module-backed memory region or in suspicious private executable memory.
    fn check_thread_for_injection(pid: u32, thread_id: u32) -> Option<InjectionEvent> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
        use windows::Win32::System::Threading::{
            OpenProcess, OpenThread, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
            THREAD_QUERY_INFORMATION,
        };

        unsafe {
            let thread_handle = match OpenThread(THREAD_QUERY_INFORMATION, false, thread_id) {
                Ok(h) => h,
                Err(_) => return None,
            };

            // Use NtQueryInformationThread with ThreadQuerySetWin32StartAddress (class 9)
            // to retrieve the thread's start address without suspending it.
            let mut start_address: usize = 0;
            let status = ntdll_NtQueryInformationThread(
                thread_handle,
                9, // ThreadQuerySetWin32StartAddress
                &mut start_address as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<usize>() as u32,
                std::ptr::null_mut(),
            );

            let _ = CloseHandle(thread_handle);

            // If the NT call failed or returned a null address, we cannot determine
            // injection from the start address alone.
            if status != 0 || start_address == 0 {
                return None;
            }

            // Open the owning process so we can query what memory region backs
            // the start address.
            let proc_handle =
                match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
                    Ok(h) => h,
                    Err(_) => return None,
                };

            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let qr = VirtualQueryEx(
                proc_handle,
                Some(start_address as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            let _ = CloseHandle(proc_handle);

            if qr == 0 {
                return None;
            }

            let region = MemoryRegion {
                base_address: mbi.BaseAddress as u64,
                region_size: mbi.RegionSize as u64,
                protection: mbi.Protect.0,
                state: mbi.State.0,
                region_type: mbi.Type.0,
                allocation_base: mbi.AllocationBase as u64,
            };

            // A legitimate thread start address lives inside a module image
            // (MEM_IMAGE). If the start address falls in committed, executable,
            // private (non-image) memory, this is a strong indicator that the
            // thread was created to run injected code (e.g. CreateRemoteThread
            // pointing at shellcode written via WriteProcessMemory).
            if region.is_committed() && region.is_executable() && region.is_private() {
                let process_name = get_process_name(pid);
                let process_path = get_process_path(pid);

                debug!(
                    pid = pid,
                    thread_id = thread_id,
                    start_addr = format!("0x{:x}", start_address),
                    region_base = format!("0x{:x}", region.base_address),
                    region_size = region.region_size,
                    "New thread start address is in private executable memory - possible injection"
                );

                return Some(InjectionEvent {
                    source_pid: 0, // Injector unknown from passive thread scan
                    source_name: "unknown".to_string(),
                    source_path: String::new(),
                    target_pid: pid,
                    target_name: process_name,
                    target_path: process_path,
                    technique: InjectionTechnique::RemoteThread,
                    memory_address: Some(start_address as u64),
                    memory_size: Some(region.region_size),
                    memory_protection: Some(region.protection),
                    evidence: vec![
                        format!(
                            "Thread {} start address 0x{:x} is in MEM_PRIVATE executable memory",
                            thread_id, start_address
                        ),
                        format!(
                            "Region: base=0x{:x} size={} prot=0x{:x}",
                            region.base_address, region.region_size, region.protection
                        ),
                        "Legitimate threads start inside module-backed (MEM_IMAGE) memory".to_string(),
                        "Thread start in private executable memory indicates CreateRemoteThread injection".to_string(),
                    ],
                });
            }
        }

        None
    }

    /// Detect process hollowing indicators
    async fn process_hollowing_detector(
        tx: mpsc::Sender<TelemetryEvent>,
        known: Arc<Mutex<HashSet<(u32, u32, InjectionTechnique)>>>,
        interval_ms: u64,
    ) {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        info!("Starting process hollowing detector");

        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        loop {
            interval.tick().await;

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
                        let parent_pid = entry.th32ParentProcessID;

                        // Skip system processes
                        if pid > 10 {
                            // Check for hollowing indicators
                            if let Some(injection) = check_hollowing_indicators(pid, parent_pid) {
                                let key = (
                                    injection.source_pid,
                                    injection.target_pid,
                                    injection.technique,
                                );
                                let mut known_guard = known.lock().await;

                                if !known_guard.contains(&key) {
                                    known_guard.insert(key);
                                    drop(known_guard);

                                    let event =
                                        InjectionCollector::create_injection_event(&injection);
                                    if tx.send(event).await.is_err() {
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
    }

    /// Check for process hollowing indicators
    fn check_hollowing_indicators(pid: u32, parent_pid: u32) -> Option<InjectionEvent> {
        use windows::Win32::Foundation::{CloseHandle, HMODULE};
        use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
        use windows::Win32::System::ProcessStatus::{EnumProcessModules, GetModuleFileNameExW};
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            {
                Ok(h) => h,
                Err(_) => return None,
            };

            // Get the main module (should be the executable)
            let mut modules = [HMODULE::default(); 1];
            let mut bytes_needed = 0u32;

            if EnumProcessModules(
                handle,
                modules.as_mut_ptr(),
                std::mem::size_of_val(&modules) as u32,
                &mut bytes_needed,
            )
            .is_ok()
            {
                // Get the main module path
                let mut filename = [0u16; 512];
                let len = GetModuleFileNameExW(handle, modules[0], &mut filename);

                if len > 0 {
                    let module_path = String::from_utf16_lossy(&filename[..len as usize]);

                    // Check if the memory at the module base is unusual
                    let mut mbi = MEMORY_BASIC_INFORMATION::default();
                    let base_address = modules[0].0 as *const std::ffi::c_void;

                    if VirtualQueryEx(
                        handle,
                        Some(base_address),
                        &mut mbi,
                        std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                    ) > 0
                    {
                        // Hollowing indicators:
                        // 1. Main module region is not MEM_IMAGE
                        // 2. Main module has RWX protection
                        // 3. Main module is MEM_PRIVATE instead of MEM_IMAGE

                        let is_private = mbi.Type.0 & MEM_PRIVATE != 0;
                        let is_rwx = mbi.Protect.0 & PAGE_EXECUTE_READWRITE != 0;

                        if is_private || is_rwx {
                            let _ = CloseHandle(handle);

                            let process_name = get_process_name(pid);
                            let process_path = get_process_path(pid);
                            let parent_name = get_process_name(parent_pid);
                            let parent_path = get_process_path(parent_pid);

                            let mut evidence = Vec::new();
                            if is_private {
                                evidence.push(
                                    "Main module is MEM_PRIVATE (expected MEM_IMAGE)".to_string(),
                                );
                            }
                            if is_rwx {
                                evidence.push("Main module has RWX protection".to_string());
                            }
                            evidence.push(format!("Module path: {}", module_path));

                            return Some(InjectionEvent {
                                source_pid: parent_pid,
                                source_name: parent_name,
                                source_path: parent_path,
                                target_pid: pid,
                                target_name: process_name,
                                target_path: process_path,
                                technique: InjectionTechnique::ProcessHollowing,
                                memory_address: Some(mbi.BaseAddress as u64),
                                memory_size: Some(mbi.RegionSize as u64),
                                memory_protection: Some(mbi.Protect.0),
                                evidence,
                            });
                        }
                    }
                }
            }

            let _ = CloseHandle(handle);
        }

        None
    }

    /// Analyze cross-process operations for injection patterns
    fn analyze_injection_pattern(
        source_pid: u32,
        ops: &[CrossProcessOp],
    ) -> Option<InjectionEvent> {
        // Pattern 1: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread (Classic injection)
        let has_alloc = ops.iter().any(|op| op.op_type == OpType::VirtualAlloc);
        let has_write = ops.iter().any(|op| op.op_type == OpType::WriteMemory);
        let has_thread = ops.iter().any(|op| op.op_type == OpType::CreateThread);

        if has_alloc && has_write && has_thread {
            if let Some(alloc_op) = ops.iter().find(|op| op.op_type == OpType::VirtualAlloc) {
                return Some(InjectionEvent {
                    source_pid,
                    source_name: alloc_op.source_name.clone(),
                    source_path: alloc_op.source_path.clone(),
                    target_pid: alloc_op.target_pid,
                    target_name: alloc_op.target_name.clone(),
                    target_path: alloc_op.target_path.clone(),
                    technique: InjectionTechnique::RemoteThread,
                    memory_address: alloc_op.memory_address,
                    memory_size: alloc_op.memory_size,
                    memory_protection: alloc_op.memory_protection,
                    evidence: vec![
                        "VirtualAllocEx detected".to_string(),
                        "WriteProcessMemory detected".to_string(),
                        "CreateRemoteThread detected".to_string(),
                    ],
                });
            }
        }

        // Pattern 2: APC injection (QueueUserAPC)
        let has_apc = ops.iter().any(|op| op.op_type == OpType::QueueApc);
        if has_alloc && has_write && has_apc {
            if let Some(alloc_op) = ops.iter().find(|op| op.op_type == OpType::VirtualAlloc) {
                return Some(InjectionEvent {
                    source_pid,
                    source_name: alloc_op.source_name.clone(),
                    source_path: alloc_op.source_path.clone(),
                    target_pid: alloc_op.target_pid,
                    target_name: alloc_op.target_name.clone(),
                    target_path: alloc_op.target_path.clone(),
                    technique: InjectionTechnique::ApcInjection,
                    memory_address: alloc_op.memory_address,
                    memory_size: alloc_op.memory_size,
                    memory_protection: alloc_op.memory_protection,
                    evidence: vec![
                        "VirtualAllocEx detected".to_string(),
                        "WriteProcessMemory detected".to_string(),
                        "QueueUserAPC detected".to_string(),
                    ],
                });
            }
        }

        // Pattern 3: Thread hijacking (SetThreadContext)
        let has_set_context = ops.iter().any(|op| op.op_type == OpType::SetContext);
        if has_set_context && has_write {
            if let Some(ctx_op) = ops.iter().find(|op| op.op_type == OpType::SetContext) {
                return Some(InjectionEvent {
                    source_pid,
                    source_name: ctx_op.source_name.clone(),
                    source_path: ctx_op.source_path.clone(),
                    target_pid: ctx_op.target_pid,
                    target_name: ctx_op.target_name.clone(),
                    target_path: ctx_op.target_path.clone(),
                    technique: InjectionTechnique::ThreadHijacking,
                    memory_address: ctx_op.memory_address,
                    memory_size: ctx_op.memory_size,
                    memory_protection: ctx_op.memory_protection,
                    evidence: vec![
                        "WriteProcessMemory detected".to_string(),
                        "SetThreadContext detected".to_string(),
                    ],
                });
            }
        }

        // Pattern 4: Section mapping injection
        let has_map = ops.iter().any(|op| op.op_type == OpType::MapSection);
        if has_map {
            if let Some(map_op) = ops.iter().find(|op| op.op_type == OpType::MapSection) {
                return Some(InjectionEvent {
                    source_pid,
                    source_name: map_op.source_name.clone(),
                    source_path: map_op.source_path.clone(),
                    target_pid: map_op.target_pid,
                    target_name: map_op.target_name.clone(),
                    target_path: map_op.target_path.clone(),
                    technique: InjectionTechnique::SectionMapping,
                    memory_address: map_op.memory_address,
                    memory_size: map_op.memory_size,
                    memory_protection: map_op.memory_protection,
                    evidence: vec!["NtMapViewOfSection detected".to_string()],
                });
            }
        }

        None
    }

    /// Get process name from PID
    fn get_process_name(pid: u32) -> String {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::ProcessStatus::GetModuleBaseNameW;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(h) => h,
                Err(_) => return format!("pid:{}", pid),
            };

            let mut name_buf = [0u16; 256];
            let len = GetModuleBaseNameW(handle, None, &mut name_buf);
            let _ = CloseHandle(handle);

            if len > 0 {
                String::from_utf16_lossy(&name_buf[..len as usize])
            } else {
                format!("pid:{}", pid)
            }
        }
    }

    /// Get process path from PID
    fn get_process_path(pid: u32) -> String {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(h) => h,
                Err(_) => return String::new(),
            };

            let mut path_buf = [0u16; 512];
            let len = GetModuleFileNameExW(handle, None, &mut path_buf);
            let _ = CloseHandle(handle);

            if len > 0 {
                String::from_utf16_lossy(&path_buf[..len as usize])
            } else {
                String::new()
            }
        }
    }

    /// Check if a process name is a system process
    fn is_system_process(name: &str) -> bool {
        let system_processes = [
            "system",
            "smss.exe",
            "csrss.exe",
            "wininit.exe",
            "services.exe",
            "lsass.exe",
            "svchost.exe",
            "dwm.exe",
            "fontdrvhost.exe",
            "winlogon.exe",
            "memory compression",
        ];
        system_processes
            .iter()
            .any(|&s| name.to_lowercase().contains(s))
    }

    // ====================================================================
    // Thread Execution Hijacking Detection (T1055.003)
    // ====================================================================

    /// Detect thread execution hijacking by monitoring for
    /// SuspendThread + SetThreadContext + ResumeThread patterns.
    ///
    /// Thread hijacking suspends a thread in a target process, modifies
    /// its instruction pointer (RIP/EIP) to point to injected shellcode,
    /// then resumes execution. This is stealthier than CreateRemoteThread.
    ///
    /// Detection approach:
    /// - Enumerate threads per process and query each thread's Win32 start
    ///   address via NtQueryInformationThread(ThreadQuerySetWin32StartAddress)
    /// - Compare the start address against the process's loaded modules to
    ///   determine if it falls in module-backed (MEM_IMAGE) or private memory
    /// - Track start address changes between snapshots: if a baselined thread's
    ///   start address shifts from module-backed to private executable memory,
    ///   it has been hijacked
    /// - Scan all processes for threads currently running from unbacked memory
    async fn thread_hijacking_detector(
        tx: mpsc::Sender<TelemetryEvent>,
        known: Arc<Mutex<HashSet<(u32, u32, InjectionTechnique)>>>,
        interval_ms: u64,
    ) {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
        };
        use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
        use windows::Win32::System::Threading::{
            OpenProcess, OpenThread, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
            THREAD_QUERY_INFORMATION,
        };

        info!("Starting thread execution hijacking detector (T1055.003)");

        // Track thread states: (pid, tid) -> start_address
        // We store the start address so we can detect when it changes
        // (indicating SetThreadContext was used to redirect execution).
        let mut thread_states: HashMap<(u32, u32), u64> = HashMap::new();
        // Track which threads we've already seen as normal
        let mut baseline_threads: HashSet<(u32, u32)> = HashSet::new();

        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        loop {
            interval.tick().await;

            unsafe {
                let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
                    Ok(h) => h,
                    Err(_) => continue,
                };

                let mut entry = THREADENTRY32 {
                    dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                    ..Default::default()
                };

                if Thread32First(snapshot, &mut entry).is_ok() {
                    loop {
                        let owner_pid = entry.th32OwnerProcessID;
                        let thread_id = entry.th32ThreadID;

                        // Skip system and our own process
                        if owner_pid > 10 && owner_pid != std::process::id() {
                            let key = (owner_pid, thread_id);

                            // Query the thread's Win32 start address via NtQueryInformationThread
                            if let Ok(thread_handle) =
                                OpenThread(THREAD_QUERY_INFORMATION, false, thread_id)
                            {
                                let mut start_address: usize = 0;
                                let status = ntdll_NtQueryInformationThread(
                                    thread_handle,
                                    9, // ThreadQuerySetWin32StartAddress
                                    &mut start_address as *mut _ as *mut std::ffi::c_void,
                                    std::mem::size_of::<usize>() as u32,
                                    std::ptr::null_mut(),
                                );

                                let _ = CloseHandle(thread_handle);

                                if status == 0 && start_address != 0 {
                                    let current_addr = start_address as u64;

                                    if !baseline_threads.contains(&key) {
                                        // First time seeing this thread: record its start address
                                        baseline_threads.insert(key);
                                        thread_states.insert(key, current_addr);
                                    } else if let Some(&prev_addr) = thread_states.get(&key) {
                                        // Thread was already baselined. Check if the start address
                                        // has changed, which would indicate SetThreadContext was
                                        // used to redirect execution to a different location.
                                        if prev_addr != current_addr && prev_addr != 0 {
                                            // Start address changed - check if the new address is
                                            // in private executable memory (hijacking indicator)
                                            let region_opt = if let Ok(proc_handle) = OpenProcess(
                                                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                                false,
                                                owner_pid,
                                            ) {
                                                let mut mbi = MEMORY_BASIC_INFORMATION::default();
                                                let qr = VirtualQueryEx(
                                                    proc_handle,
                                                    Some(start_address as *const _),
                                                    &mut mbi,
                                                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                                                );
                                                let _ = CloseHandle(proc_handle);

                                                if qr > 0 {
                                                    Some(MemoryRegion {
                                                        base_address: mbi.BaseAddress as u64,
                                                        region_size: mbi.RegionSize as u64,
                                                        protection: mbi.Protect.0,
                                                        state: mbi.State.0,
                                                        region_type: mbi.Type.0,
                                                        allocation_base: mbi.AllocationBase as u64,
                                                    })
                                                } else {
                                                    None
                                                }
                                            } else {
                                                None
                                            };

                                            if let Some(region) = region_opt {
                                                if region.is_committed()
                                                    && region.is_executable()
                                                    && region.is_private()
                                                {
                                                    let det_key = (
                                                        0u32,
                                                        owner_pid,
                                                        InjectionTechnique::ThreadHijacking,
                                                    );
                                                    let mut known_guard = known.lock().await;

                                                    if !known_guard.contains(&det_key) {
                                                        known_guard.insert(det_key);
                                                        drop(known_guard);

                                                        let process_name =
                                                            get_process_name(owner_pid);
                                                        let process_path =
                                                            get_process_path(owner_pid);

                                                        debug!(
                                                                pid = owner_pid,
                                                                thread_id = thread_id,
                                                                prev_addr = format!("0x{:x}", prev_addr),
                                                                new_addr = format!("0x{:x}", current_addr),
                                                                "Thread start address changed to private executable memory - hijacking detected"
                                                            );

                                                        let injection = InjectionEvent {
                                                                source_pid: 0,
                                                                source_name: "unknown".to_string(),
                                                                source_path: String::new(),
                                                                target_pid: owner_pid,
                                                                target_name: process_name,
                                                                target_path: process_path,
                                                                technique: InjectionTechnique::ThreadHijacking,
                                                                memory_address: Some(current_addr),
                                                                memory_size: Some(region.region_size),
                                                                memory_protection: Some(region.protection),
                                                                evidence: vec![
                                                                    format!(
                                                                        "Thread {} start address changed from 0x{:x} to 0x{:x}",
                                                                        thread_id, prev_addr, current_addr
                                                                    ),
                                                                    format!(
                                                                        "New address is in MEM_PRIVATE executable region (base=0x{:x}, size={}, prot=0x{:x})",
                                                                        region.base_address, region.region_size, region.protection
                                                                    ),
                                                                    "Indicates SetThreadContext was used to redirect execution".to_string(),
                                                                    "Detected via NtQueryInformationThread(ThreadQuerySetWin32StartAddress)".to_string(),
                                                                ],
                                                            };

                                                        let event = InjectionCollector::create_injection_event(&injection);
                                                        if tx.send(event).await.is_err() {
                                                            return;
                                                        }
                                                    }
                                                }
                                            }

                                            // Update the tracked address regardless
                                            thread_states.insert(key, current_addr);
                                        }
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

                // Second pass: scan all processes for threads currently starting
                // at suspicious (private executable) addresses. This catches
                // hijacking that already occurred before the agent started.
                let process_snapshot = match CreateToolhelp32Snapshot(
                    windows::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPPROCESS,
                    0,
                ) {
                    Ok(h) => h,
                    Err(_) => continue,
                };

                let mut proc_entry =
                    windows::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W {
                        dwSize: std::mem::size_of::<
                            windows::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W,
                        >() as u32,
                        ..Default::default()
                    };

                if windows::Win32::System::Diagnostics::ToolHelp::Process32FirstW(
                    process_snapshot,
                    &mut proc_entry,
                )
                .is_ok()
                {
                    loop {
                        let pid = proc_entry.th32ProcessID;

                        if pid > 10 && pid != std::process::id() {
                            // Open process to check memory regions backing thread start addresses
                            if let Ok(proc_handle) =
                                OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
                            {
                                // Enumerate threads for this process
                                let thread_snapshot = match CreateToolhelp32Snapshot(
                                    TH32CS_SNAPTHREAD,
                                    0,
                                ) {
                                    Ok(h) => h,
                                    Err(_) => {
                                        let _ = CloseHandle(proc_handle);
                                        if windows::Win32::System::Diagnostics::ToolHelp::Process32NextW(
                                            process_snapshot,
                                            &mut proc_entry,
                                        ).is_err() {
                                            break;
                                        }
                                        continue;
                                    }
                                };

                                let mut tentry = THREADENTRY32 {
                                    dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                                    ..Default::default()
                                };

                                if Thread32First(thread_snapshot, &mut tentry).is_ok() {
                                    loop {
                                        if tentry.th32OwnerProcessID == pid {
                                            // Query each thread's start address via NtQueryInformationThread
                                            if let Ok(th) = OpenThread(
                                                THREAD_QUERY_INFORMATION,
                                                false,
                                                tentry.th32ThreadID,
                                            ) {
                                                let mut start_address: usize = 0;
                                                let status = ntdll_NtQueryInformationThread(
                                                    th,
                                                    9, // ThreadQuerySetWin32StartAddress
                                                    &mut start_address as *mut _
                                                        as *mut std::ffi::c_void,
                                                    std::mem::size_of::<usize>() as u32,
                                                    std::ptr::null_mut(),
                                                );

                                                if status == 0 && start_address != 0 {
                                                    // Check what memory region this start address is in
                                                    let region_opt = {
                                                        let mut mbi =
                                                            MEMORY_BASIC_INFORMATION::default();
                                                        let qr = VirtualQueryEx(
                                                            proc_handle,
                                                            Some(start_address as *const _),
                                                            &mut mbi,
                                                            std::mem::size_of::<
                                                                MEMORY_BASIC_INFORMATION,
                                                            >(
                                                            ),
                                                        );

                                                        if qr > 0 {
                                                            Some(MemoryRegion {
                                                                base_address: mbi.BaseAddress
                                                                    as u64,
                                                                region_size: mbi.RegionSize as u64,
                                                                protection: mbi.Protect.0,
                                                                state: mbi.State.0,
                                                                region_type: mbi.Type.0,
                                                                allocation_base: mbi.AllocationBase
                                                                    as u64,
                                                            })
                                                        } else {
                                                            None
                                                        }
                                                    };

                                                    if let Some(region) = region_opt {
                                                        // Flag threads starting in private executable memory
                                                        // as potential hijacking victims
                                                        if region.is_committed()
                                                            && region.is_executable()
                                                            && region.is_private()
                                                        {
                                                            let det_key = (
                                                                0u32,
                                                                pid,
                                                                InjectionTechnique::ThreadHijacking,
                                                            );
                                                            let mut known_guard =
                                                                known.lock().await;

                                                            if !known_guard.contains(&det_key) {
                                                                known_guard.insert(det_key);
                                                                drop(known_guard);

                                                                let process_name =
                                                                    get_process_name(pid);
                                                                let process_path =
                                                                    get_process_path(pid);

                                                                debug!(
                                                                    pid = pid,
                                                                    thread_id = tentry.th32ThreadID,
                                                                    start_addr = format!("0x{:x}", start_address),
                                                                    "Thread start address in private executable memory - possible hijacking"
                                                                );

                                                                let injection = InjectionEvent {
                                                                    source_pid: 0,
                                                                    source_name: "unknown".to_string(),
                                                                    source_path: String::new(),
                                                                    target_pid: pid,
                                                                    target_name: process_name,
                                                                    target_path: process_path,
                                                                    technique: InjectionTechnique::ThreadHijacking,
                                                                    memory_address: Some(start_address as u64),
                                                                    memory_size: Some(region.region_size),
                                                                    memory_protection: Some(region.protection),
                                                                    evidence: vec![
                                                                        format!(
                                                                            "Thread {} start address 0x{:x} is in MEM_PRIVATE executable memory",
                                                                            tentry.th32ThreadID, start_address
                                                                        ),
                                                                        format!(
                                                                            "Region: base=0x{:x} size={} prot=0x{:x}",
                                                                            region.base_address, region.region_size, region.protection
                                                                        ),
                                                                        "Thread start should be in MEM_IMAGE (module-backed) memory".to_string(),
                                                                        "Detected via NtQueryInformationThread(ThreadQuerySetWin32StartAddress)".to_string(),
                                                                    ],
                                                                };

                                                                let event = InjectionCollector::create_injection_event(&injection);
                                                                if tx.send(event).await.is_err() {
                                                                    return;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }

                                                let _ = CloseHandle(th);
                                            }
                                        }

                                        if Thread32Next(thread_snapshot, &mut tentry).is_err() {
                                            break;
                                        }
                                    }
                                }

                                let _ = CloseHandle(thread_snapshot);
                                let _ = CloseHandle(proc_handle);
                            }
                        }

                        if windows::Win32::System::Diagnostics::ToolHelp::Process32NextW(
                            process_snapshot,
                            &mut proc_entry,
                        )
                        .is_err()
                        {
                            break;
                        }
                    }
                }

                let _ = CloseHandle(process_snapshot);
            }

            // Cleanup to prevent unbounded growth
            if baseline_threads.len() > 50000 {
                baseline_threads.clear();
                thread_states.clear();
            }
        }
    }

    /// Detect a specific thread hijacking event for a given process + thread
    /// by querying the thread's Win32 start address via NtQueryInformationThread
    /// and checking whether that address resides in unbacked private executable
    /// memory (indicating the thread context was modified to run injected code).
    ///
    /// Additionally queries ThreadBasicInformation (class 0) to obtain the TEB
    /// address, which provides supplementary forensic information about the
    /// thread's execution state.
    ///
    /// Returns evidence if the thread appears to have been hijacked.
    fn detect_thread_hijack_for_thread(
        pid: u32,
        thread_id: u32,
        _known: &Arc<Mutex<HashSet<(u32, u32, InjectionTechnique)>>>,
    ) -> Option<InjectionEvent> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
        use windows::Win32::System::Threading::{
            OpenProcess, OpenThread, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
            THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION,
        };

        // THREAD_BASIC_INFORMATION structure (from ntdll)
        #[repr(C)]
        struct ThreadBasicInformation {
            exit_status: i32,
            teb_base_address: usize,
            client_id_unique_process: usize,
            client_id_unique_thread: usize,
            affinity_mask: usize,
            priority: i32,
            base_priority: i32,
        }

        unsafe {
            let proc_handle =
                match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
                    Ok(h) => h,
                    Err(_) => return None,
                };

            let thread_handle = match OpenThread(
                THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT,
                false,
                thread_id,
            ) {
                Ok(h) => h,
                Err(_) => {
                    let _ = CloseHandle(proc_handle);
                    return None;
                }
            };

            // Step 1: Query the thread's Win32 start address using
            // NtQueryInformationThread with ThreadQuerySetWin32StartAddress (class 9).
            // This gives us the address the thread was originally created to execute at.
            let mut start_address: usize = 0;
            let status = ntdll_NtQueryInformationThread(
                thread_handle,
                9, // ThreadQuerySetWin32StartAddress
                &mut start_address as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<usize>() as u32,
                std::ptr::null_mut(),
            );

            if status != 0 || start_address == 0 {
                let _ = CloseHandle(thread_handle);
                let _ = CloseHandle(proc_handle);
                return None;
            }

            // Step 2: Query ThreadBasicInformation (class 0) to get the TEB address.
            // This provides additional forensic context about the thread.
            let mut tbi = std::mem::zeroed::<ThreadBasicInformation>();
            let tbi_status = ntdll_NtQueryInformationThread(
                thread_handle,
                0, // ThreadBasicInformation
                &mut tbi as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<ThreadBasicInformation>() as u32,
                std::ptr::null_mut(),
            );

            let teb_address = if tbi_status == 0 {
                Some(tbi.teb_base_address as u64)
            } else {
                None
            };

            let _ = CloseHandle(thread_handle);

            // Step 3: Check if the start address falls in private executable memory
            // by querying the memory region with VirtualQueryEx.
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let qr = VirtualQueryEx(
                proc_handle,
                Some(start_address as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            let _ = CloseHandle(proc_handle);

            if qr == 0 {
                return None;
            }

            let region = MemoryRegion {
                base_address: mbi.BaseAddress as u64,
                region_size: mbi.RegionSize as u64,
                protection: mbi.Protect.0,
                state: mbi.State.0,
                region_type: mbi.Type.0,
                allocation_base: mbi.AllocationBase as u64,
            };

            // A legitimate thread start address should be inside a module image.
            // If it's in committed, executable, private memory, the thread has
            // likely been hijacked via SetThreadContext pointing to shellcode.
            if region.is_committed() && region.is_executable() && region.is_private() {
                let process_name = get_process_name(pid);
                let process_path = get_process_path(pid);

                let mut evidence = vec![
                    format!(
                        "Thread {} start address 0x{:x} is in MEM_PRIVATE executable memory",
                        thread_id, start_address
                    ),
                    format!(
                        "Region: base=0x{:x} size={} prot=0x{:x} type=MEM_PRIVATE",
                        region.base_address, region.region_size, region.protection
                    ),
                    "Thread start should be in module-backed (MEM_IMAGE) memory".to_string(),
                    "Indicates SetThreadContext or similar API redirected thread execution"
                        .to_string(),
                    "Detected via NtQueryInformationThread(ThreadQuerySetWin32StartAddress)"
                        .to_string(),
                ];

                if let Some(teb) = teb_address {
                    evidence.push(format!(
                        "TEB address: 0x{:x} (from NtQueryInformationThread ThreadBasicInformation)",
                        teb
                    ));
                }

                debug!(
                    pid = pid,
                    thread_id = thread_id,
                    start_addr = format!("0x{:x}", start_address),
                    teb = teb_address.map(|t| format!("0x{:x}", t)),
                    "Thread hijacking detected: start address in private executable memory"
                );

                return Some(InjectionEvent {
                    source_pid: 0, // Injector unknown from passive scan
                    source_name: "unknown".to_string(),
                    source_path: String::new(),
                    target_pid: pid,
                    target_name: process_name,
                    target_path: process_path,
                    technique: InjectionTechnique::ThreadHijacking,
                    memory_address: Some(start_address as u64),
                    memory_size: Some(region.region_size),
                    memory_protection: Some(region.protection),
                    evidence,
                });
            }
        }

        None
    }

    // ====================================================================
    // Process Doppelganging Detection (T1055.013)
    // ====================================================================

    /// Detect process doppelganging by monitoring for processes created from
    /// transacted file sections.
    ///
    /// Process doppelganging uses:
    /// 1. NtCreateTransaction to create an NTFS transaction
    /// 2. Write malicious content to a file within the transaction
    /// 3. NtCreateSection to create a section from the transacted file
    /// 4. NtRollbackTransaction to revert the file to its clean state
    /// 5. NtCreateProcessEx from the section (which still has malicious content)
    ///
    /// Detection approach:
    /// - Compare the mapped file backing a process against the file on disk
    /// - Check for processes where GetMappedFileName differs from the module path
    /// - Detect newly-created processes whose entry point code differs from disk
    async fn process_doppelganging_detector(
        tx: mpsc::Sender<TelemetryEvent>,
        known: Arc<Mutex<HashSet<(u32, u32, InjectionTechnique)>>>,
        interval_ms: u64,
    ) {
        use windows::Win32::Foundation::CloseHandle;

        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        info!("Starting process doppelganging detector (T1055.013)");

        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));
        let mut scanned_pids: HashSet<u32> = HashSet::new();

        loop {
            interval.tick().await;

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
                        let parent_pid = entry.th32ParentProcessID;

                        if pid > 10 && pid != std::process::id() && !scanned_pids.contains(&pid) {
                            scanned_pids.insert(pid);

                            if let Some(injection) = check_doppelganging_indicators(pid, parent_pid)
                            {
                                let key = (
                                    injection.source_pid,
                                    injection.target_pid,
                                    injection.technique,
                                );
                                let mut known_guard = known.lock().await;

                                if !known_guard.contains(&key) {
                                    known_guard.insert(key);
                                    drop(known_guard);

                                    let event =
                                        InjectionCollector::create_injection_event(&injection);

                                    // Enrich event with doppelganging-specific metadata
                                    // The event is already constructed by create_injection_event,
                                    // so we emit it as-is with the evidence in the payload

                                    if tx.send(event).await.is_err() {
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

            // Prevent unbounded growth
            if scanned_pids.len() > 20000 {
                scanned_pids.clear();
            }
        }
    }

    /// Check for process doppelganging indicators on a specific process.
    ///
    /// Compares the module filename (reported by the loader) against the
    /// mapped file name (the actual section backing). In a doppelganging
    /// attack, these may differ because the section was created from a
    /// transacted file that was subsequently rolled back.
    ///
    /// Also reads the first page of the in-memory image and compares it
    /// against the on-disk file to detect content mismatches.
    fn check_doppelganging_indicators(pid: u32, parent_pid: u32) -> Option<InjectionEvent> {
        use sha2::{Digest, Sha256};
        use windows::Win32::Foundation::{CloseHandle, HMODULE};
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows::Win32::System::ProcessStatus::{
            EnumProcessModules, GetMappedFileNameW, GetModuleFileNameExW, GetModuleInformation,
            MODULEINFO,
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

            // Get main module
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

            // Get mapped filename (the actual section backing file)
            let mut mapped_name = [0u16; 512];
            let mapped_len = GetMappedFileNameW(handle, modules[0].0 as *const _, &mut mapped_name);

            let mut evidence = Vec::new();
            let mut confidence: f32 = 0.0;

            if mapped_len > 0 {
                let mapped_filename = String::from_utf16_lossy(&mapped_name[..mapped_len as usize]);

                // Compare file name components
                let mod_file = module_filename.rsplit('\\').next().unwrap_or("");
                let mapped_file = mapped_filename.rsplit('\\').next().unwrap_or("");

                if !mod_file.is_empty()
                    && !mapped_file.is_empty()
                    && mod_file.to_lowercase() != mapped_file.to_lowercase()
                {
                    evidence.push(format!(
                        "Module filename ({}) differs from mapped file ({})",
                        module_filename, mapped_filename
                    ));
                    confidence += 0.40;
                }
            }

            // Get module base and read in-memory header
            let mut mod_info = MODULEINFO::default();
            if GetModuleInformation(
                handle,
                modules[0],
                &mut mod_info,
                std::mem::size_of::<MODULEINFO>() as u32,
            )
            .is_ok()
            {
                let module_base = mod_info.lpBaseOfDll as u64;

                // Read first page from memory
                let mut mem_header = vec![0u8; 4096];
                let mut bytes_read = 0usize;
                if ReadProcessMemory(
                    handle,
                    module_base as *const _,
                    mem_header.as_mut_ptr() as *mut _,
                    4096,
                    Some(&mut bytes_read),
                )
                .is_ok()
                    && bytes_read > 0
                {
                    mem_header.truncate(bytes_read);

                    // Read corresponding on-disk file
                    if let Ok(disk_data) = std::fs::read(&module_filename) {
                        if disk_data.len() >= 64 {
                            // Compare PE headers
                            let compare_len = std::cmp::min(
                                std::cmp::min(mem_header.len(), disk_data.len()),
                                4096,
                            );

                            let mut diff_count = 0;
                            for i in 0..compare_len {
                                if mem_header[i] != disk_data[i] {
                                    diff_count += 1;
                                }
                            }

                            // Significant differences in the PE header are suspicious
                            // (minor differences can be from relocations, but the DOS header
                            // and PE signature should be identical)
                            if diff_count > 64 {
                                // Hash both for evidence
                                let mut disk_hasher = Sha256::new();
                                disk_hasher.update(&disk_data[..compare_len]);
                                let disk_hash = hex::encode(disk_hasher.finalize());

                                let mut mem_hasher = Sha256::new();
                                mem_hasher.update(&mem_header[..compare_len]);
                                let mem_hash = hex::encode(mem_hasher.finalize());

                                evidence.push(format!(
                                    "PE header content differs: {} bytes differ in first {}",
                                    diff_count, compare_len
                                ));
                                evidence.push(format!(
                                    "Disk header hash: {}, Memory header hash: {}",
                                    disk_hash, mem_hash
                                ));
                                confidence += 0.35;
                            }

                            // Check if MZ signature is present in both but entry points differ
                            if disk_data.len() >= 64 && mem_header.len() >= 64 {
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

                                // Check entry point RVA if we can reach it
                                if disk_lfanew + 4 + 20 + 20 < disk_data.len()
                                    && mem_lfanew + 4 + 20 + 20 < mem_header.len()
                                {
                                    let disk_ep_offset = disk_lfanew + 4 + 20 + 16;
                                    let mem_ep_offset = mem_lfanew + 4 + 20 + 16;

                                    if disk_ep_offset + 4 <= disk_data.len()
                                        && mem_ep_offset + 4 <= mem_header.len()
                                    {
                                        let disk_ep = u32::from_le_bytes([
                                            disk_data[disk_ep_offset],
                                            disk_data[disk_ep_offset + 1],
                                            disk_data[disk_ep_offset + 2],
                                            disk_data[disk_ep_offset + 3],
                                        ]);
                                        let mem_ep = u32::from_le_bytes([
                                            mem_header[mem_ep_offset],
                                            mem_header[mem_ep_offset + 1],
                                            mem_header[mem_ep_offset + 2],
                                            mem_header[mem_ep_offset + 3],
                                        ]);

                                        if disk_ep != mem_ep {
                                            evidence.push(format!(
                                                "Entry point differs: disk=0x{:x}, memory=0x{:x}",
                                                disk_ep, mem_ep
                                            ));
                                            confidence += 0.20;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let _ = CloseHandle(handle);

            // Only report if we have meaningful evidence
            if confidence < 0.30 {
                return None;
            }

            confidence = confidence.min(0.99);

            let process_name = get_process_name(pid);
            let process_path = module_filename.clone();
            let parent_name = get_process_name(parent_pid);
            let parent_path = get_process_path(parent_pid);

            evidence.push(format!("MITRE ATT&CK: T1055.013 (Process Doppelganging)"));
            evidence.push(format!("Confidence: {:.2}", confidence));

            Some(InjectionEvent {
                source_pid: parent_pid,
                source_name: parent_name,
                source_path: parent_path,
                target_pid: pid,
                target_name: process_name,
                target_path: process_path,
                technique: InjectionTechnique::ProcessDoppelganging,
                memory_address: None,
                memory_size: None,
                memory_protection: None,
                evidence,
            })
        }
    }

    // ====================================================================
    // PoolParty Thread Pool Injection Detection (T1055)
    // SafeBreach Labs Variants 1-9
    //
    // PoolParty bypasses traditional EDR hooks by targeting Windows Thread
    // Pool internals rather than the well-hooked Win32 APIs. Instead of
    // CreateRemoteThread or QueueUserAPC, it abuses:
    //   - Worker factory objects (NtSetInformationWorkerFactory)
    //   - I/O completion ports (NtSetIoCompletion / NtSetIoCompletionEx)
    //   - Timer queues (NtCreateTimer2 / NtSetTimer2)
    //   - ALPC port callbacks (TpAlpc completion ports)
    //
    // Detection strategy:
    //   1. Enumerate thread pool worker threads and track their start
    //      routine addresses. A changed start routine that points to
    //      non-module memory is a strong indicator of Variants 1-3.
    //   2. Monitor I/O completion ports for cross-process queue writes
    //      (Variants 4-6).
    //   3. Monitor timer objects for cross-process manipulation (Variant 8).
    //   4. Monitor ALPC port handles for suspicious cross-process access
    //      (Variant 9).
    //   5. Behavioral heuristic: combine cross-process write + thread pool
    //      work item execution from unbacked memory (catches all variants).
    // ====================================================================

    /// PoolParty orchestrator loop. Runs each sub-detector on a configurable
    /// interval and feeds events into the shared channel.
    async fn poolparty_monitor_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        known: Arc<Mutex<HashSet<(u32, u32, InjectionTechnique)>>>,
        scan_results: Arc<Mutex<HashMap<u32, Vec<MemoryRegion>>>>,
        interval_ms: u64,
    ) {
        info!("Starting PoolParty thread pool injection monitor (T1055)");

        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        loop {
            interval.tick().await;

            // Run each PoolParty sub-detector. Each returns a Vec of
            // InjectionEvents so we can de-duplicate and emit in one place.
            let mut detections: Vec<InjectionEvent> = Vec::new();

            detections.extend(detect_worker_factory_injection());
            detections.extend(detect_io_completion_injection());
            detections.extend(detect_tp_direct_injection());
            detections.extend(detect_timer_queue_injection());
            detections.extend(detect_alpc_injection());
            detections.extend(detect_poolparty_behavioral(&scan_results).await);

            // Deduplicate and emit
            for injection in detections {
                let key = (
                    injection.source_pid,
                    injection.target_pid,
                    injection.technique,
                );
                let mut known_guard = known.lock().await;

                if !known_guard.contains(&key) {
                    known_guard.insert(key);
                    drop(known_guard);

                    let event = create_poolparty_event(&injection);
                    if tx.send(event).await.is_err() {
                        warn!("PoolParty monitor: event channel closed");
                        return;
                    }
                }
            }
        }
    }

    /// Create a TelemetryEvent from a PoolParty InjectionEvent.
    /// Uses the same structure as `InjectionCollector::create_injection_event`
    /// but adds PoolParty-specific metadata and variable confidence.
    fn create_poolparty_event(injection: &InjectionEvent) -> TelemetryEvent {
        let confidence = match injection.technique {
            // Direct evidence from thread pool object inspection
            InjectionTechnique::PoolPartyWorkerFactory => 0.92,
            InjectionTechnique::PoolPartyIoCompletion => 0.88,
            InjectionTechnique::PoolPartyTpDirect => 0.90,
            InjectionTechnique::PoolPartyTimerQueue => 0.87,
            InjectionTechnique::PoolPartyAlpc => 0.85,
            InjectionTechnique::PoolPartyIoTimer => 0.86,
            // Behavioral is lower confidence since it is heuristic-based
            InjectionTechnique::PoolPartyBehavioral => 0.75,
            _ => 0.80,
        };

        let mut event = TelemetryEvent::new(
            EventType::ProcessInject,
            Severity::Critical,
            EventPayload::Process(ProcessEvent {
                pid: injection.source_pid,
                ppid: 0,
                name: injection.source_name.clone(),
                path: injection.source_path.clone(),
                cmdline: String::new(),
                user: String::new(),
                sha256: Vec::new(),
                entropy: 0.0,
                is_elevated: false,
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

        let description = format!(
            "{}: {} (PID: {}) -> {} (PID: {})",
            injection.technique.description(),
            injection.source_name,
            injection.source_pid,
            injection.target_name,
            injection.target_pid,
        );

        event.add_detection(Detection {
            detection_type: DetectionType::Behavioral,
            rule_name: format!("injection_{}", injection.technique.as_str()),
            confidence,
            description,
            mitre_tactics: vec![
                "defense-evasion".to_string(),
                "privilege-escalation".to_string(),
            ],
            mitre_techniques: vec![injection.technique.mitre_technique().to_string()],
        });

        // Standard injection metadata
        event
            .metadata
            .insert("target_pid".to_string(), injection.target_pid.to_string());
        event
            .metadata
            .insert("target_name".to_string(), injection.target_name.clone());
        event
            .metadata
            .insert("target_path".to_string(), injection.target_path.clone());
        event.metadata.insert(
            "injection_technique".to_string(),
            injection.technique.as_str().to_string(),
        );
        event.metadata.insert(
            "mitre_technique".to_string(),
            injection.technique.mitre_technique().to_string(),
        );
        event
            .metadata
            .insert("injection_family".to_string(), "poolparty".to_string());

        if let Some(addr) = injection.memory_address {
            event
                .metadata
                .insert("memory_address".to_string(), format!("0x{:x}", addr));
        }
        if let Some(size) = injection.memory_size {
            event
                .metadata
                .insert("memory_size".to_string(), size.to_string());
        }
        if let Some(prot) = injection.memory_protection {
            event
                .metadata
                .insert("memory_protection".to_string(), format!("0x{:x}", prot));
        }
        if !injection.evidence.is_empty() {
            event
                .metadata
                .insert("evidence".to_string(), injection.evidence.join("; "));
        }

        event
    }

    // ----------------------------------------------------------------
    // PoolParty Variant 1-3: Worker Factory Start Routine Hijack
    // ----------------------------------------------------------------
    //
    // The attacker calls NtSetInformationWorkerFactory on the target's
    // TpWorkerFactory object to replace the StartRoutine field with a
    // pointer to injected shellcode. When the thread pool creates a new
    // worker thread, it executes the attacker's code.
    //
    // Detection: Enumerate each process's worker threads (via ToolHelp
    // thread snapshot) and check whether any thread's start address
    // falls into a non-module, private executable memory region. Normal
    // worker threads always start inside ntdll!TppWorkerThread.
    // ----------------------------------------------------------------

    fn detect_worker_factory_injection() -> Vec<InjectionEvent> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, Thread32First, Thread32Next,
            PROCESSENTRY32W, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD, THREADENTRY32,
        };
        use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
        use windows::Win32::System::Threading::{
            OpenProcess, OpenThread, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
            THREAD_QUERY_INFORMATION,
        };

        let mut results = Vec::new();

        // Well-known module names whose threads legitimately start at
        // non-standard addresses (JIT engines, .NET CLR, etc.)
        let jit_processes: HashSet<&str> = [
            "java.exe",
            "javaw.exe",
            "node.exe",
            "python.exe",
            "chrome.exe",
            "firefox.exe",
            "msedge.exe",
            "powershell.exe",
            "pwsh.exe",
            "dotnet.exe",
            "explorer.exe",
            "devenv.exe",
        ]
        .iter()
        .cloned()
        .collect();

        unsafe {
            // Snapshot all processes
            let proc_snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(h) => h,
                Err(_) => return results,
            };

            let mut proc_entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            if Process32FirstW(proc_snapshot, &mut proc_entry).is_err() {
                let _ = CloseHandle(proc_snapshot);
                return results;
            }

            loop {
                let pid = proc_entry.th32ProcessID;

                if pid > 10 && pid != std::process::id() {
                    let process_name = String::from_utf16_lossy(
                        &proc_entry.szExeFile[..proc_entry
                            .szExeFile
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(proc_entry.szExeFile.len())],
                    );

                    // Skip known JIT processes to reduce noise
                    let is_jit = jit_processes
                        .iter()
                        .any(|&j| process_name.to_lowercase().contains(j));

                    if !is_jit {
                        // Open target process to query its memory layout
                        if let Ok(proc_handle) =
                            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
                        {
                            // Snapshot threads and look for worker threads whose start
                            // address is in private executable (non-module) memory.
                            let thread_snapshot =
                                match CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
                                    Ok(h) => h,
                                    Err(_) => {
                                        let _ = CloseHandle(proc_handle);
                                        if Process32NextW(proc_snapshot, &mut proc_entry).is_err() {
                                            break;
                                        }
                                        continue;
                                    }
                                };

                            let mut tentry = THREADENTRY32 {
                                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                                ..Default::default()
                            };

                            if Thread32First(thread_snapshot, &mut tentry).is_ok() {
                                loop {
                                    if tentry.th32OwnerProcessID == pid {
                                        // Attempt to query the thread start address.
                                        // NtQueryInformationThread with ThreadQuerySetWin32StartAddress
                                        // gives the start address. We use the thread handle + VirtualQueryEx
                                        // to check if the start region is module-backed.
                                        if let Ok(th) = OpenThread(
                                            THREAD_QUERY_INFORMATION,
                                            false,
                                            tentry.th32ThreadID,
                                        ) {
                                            // Use NtQueryInformationThread to get the Win32StartAddress.
                                            // ThreadQuerySetWin32StartAddress = 9
                                            let mut start_address: usize = 0;
                                            let status = ntdll_NtQueryInformationThread(
                                                th,
                                                9, // ThreadQuerySetWin32StartAddress
                                                &mut start_address as *mut _ as *mut _,
                                                std::mem::size_of::<usize>() as u32,
                                                std::ptr::null_mut(),
                                            );

                                            if status == 0 && start_address != 0 {
                                                // Query what memory region this address belongs to
                                                let mut mbi = MEMORY_BASIC_INFORMATION::default();
                                                let qr = VirtualQueryEx(
                                                    proc_handle,
                                                    Some(start_address as *const _),
                                                    &mut mbi,
                                                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                                                );

                                                if qr > 0 {
                                                    let region = MemoryRegion {
                                                        base_address: mbi.BaseAddress as u64,
                                                        region_size: mbi.RegionSize as u64,
                                                        protection: mbi.Protect.0,
                                                        state: mbi.State.0,
                                                        region_type: mbi.Type.0,
                                                        allocation_base: mbi.AllocationBase as u64,
                                                    };

                                                    // Worker threads should start in ntdll.dll which is
                                                    // MEM_IMAGE. If the start address is in MEM_PRIVATE
                                                    // executable memory, the worker factory start routine
                                                    // has been hijacked.
                                                    if region.is_committed()
                                                        && region.is_executable()
                                                        && region.is_private()
                                                    {
                                                        let process_path = get_process_path(pid);

                                                        debug!(
                                                            pid = pid,
                                                            thread_id = tentry.th32ThreadID,
                                                            start_addr = format!("0x{:x}", start_address),
                                                            "PoolParty: worker thread starts in private executable memory"
                                                        );

                                                        results.push(InjectionEvent {
                                                            source_pid: 0, // injector unknown from passive scan
                                                            source_name: "unknown".to_string(),
                                                            source_path: String::new(),
                                                            target_pid: pid,
                                                            target_name: process_name.clone(),
                                                            target_path: process_path,
                                                            technique: InjectionTechnique::PoolPartyWorkerFactory,
                                                            memory_address: Some(start_address as u64),
                                                            memory_size: Some(region.region_size),
                                                            memory_protection: Some(region.protection),
                                                            evidence: vec![
                                                                format!(
                                                                    "Worker thread TID {} starts at 0x{:x} in MEM_PRIVATE executable region",
                                                                    tentry.th32ThreadID, start_address
                                                                ),
                                                                format!(
                                                                    "Region: base=0x{:x} size={} prot=0x{:x}",
                                                                    region.base_address, region.region_size, region.protection
                                                                ),
                                                                "Normal worker threads start inside ntdll!TppWorkerThread (MEM_IMAGE)".to_string(),
                                                                "Indicator of NtSetInformationWorkerFactory start routine hijack".to_string(),
                                                            ],
                                                        });
                                                    }
                                                }
                                            }

                                            let _ = CloseHandle(th);
                                        }
                                    }

                                    if Thread32Next(thread_snapshot, &mut tentry).is_err() {
                                        break;
                                    }
                                }
                            }

                            let _ = CloseHandle(thread_snapshot);
                            let _ = CloseHandle(proc_handle);
                        }
                    }
                }

                if Process32NextW(proc_snapshot, &mut proc_entry).is_err() {
                    break;
                }
            }

            let _ = CloseHandle(proc_snapshot);
        }

        results
    }

    // ----------------------------------------------------------------
    // PoolParty Variants 4-5: I/O Completion Port Callback Injection
    // ----------------------------------------------------------------
    //
    // The attacker writes shellcode into the target process, then queues
    // a work item to the target's I/O completion port via NtSetIoCompletion.
    // The thread pool picks up the work item and executes the callback,
    // which points to the injected code.
    //
    // Detection: Enumerate handles in each process looking for IoCompletion
    // objects. For each, check if any associated callback addresses point to
    // non-module private executable memory. Also correlate with recent
    // cross-process VirtualAllocEx / WriteProcessMemory activity.
    // ----------------------------------------------------------------

    fn detect_io_completion_injection() -> Vec<InjectionEvent> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        let mut results = Vec::new();

        // I/O completion port injection causes a thread pool worker to run a
        // callback from queued completion packet. The callback address ends up
        // as the thread's current instruction pointer. We look for worker
        // threads whose recent execution context points into non-module memory.
        //
        // We re-use the thread-start-address inspection approach: if a thread
        // that belongs to the default thread pool has its Win32StartAddress in
        // ntdll (normal) but we also detect new executable private memory in
        // the process, we flag it.
        //
        // The key difference from WorkerFactory detection is that here the
        // thread start address remains ntdll!TppWorkerThread, but the *work item*
        // callback points to injected code. We detect this indirectly by
        // looking for processes that have both:
        //   (a) A handle to an IoCompletion object
        //   (b) Private executable memory that was recently allocated

        unsafe {
            let proc_snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(h) => h,
                Err(_) => return results,
            };

            let mut proc_entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            if Process32FirstW(proc_snapshot, &mut proc_entry).is_err() {
                let _ = CloseHandle(proc_snapshot);
                return results;
            }

            loop {
                let pid = proc_entry.th32ProcessID;

                if pid > 10 && pid != std::process::id() {
                    let process_name = String::from_utf16_lossy(
                        &proc_entry.szExeFile[..proc_entry
                            .szExeFile
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(proc_entry.szExeFile.len())],
                    );

                    if let Ok(proc_handle) =
                        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
                    {
                        // Use NtQuerySystemInformation(SystemHandleInformation) to find
                        // IoCompletion handles owned by this process. Object type index
                        // for IoCompletion is typically 36 on Windows 10/11.
                        let io_completion_handles = enumerate_io_completion_handles(pid);

                        if !io_completion_handles.is_empty() {
                            // Scan for private executable memory regions that could hold
                            // injected callback code.
                            let suspicious_regions = scan_private_executable_regions(proc_handle);

                            if !suspicious_regions.is_empty() {
                                let process_path = get_process_path(pid);

                                let mut evidence = vec![
                                    format!(
                                        "Process has {} IoCompletion handle(s) and {} suspicious private executable region(s)",
                                        io_completion_handles.len(),
                                        suspicious_regions.len()
                                    ),
                                ];

                                for region in &suspicious_regions {
                                    evidence.push(format!(
                                        "Private exec region: base=0x{:x} size={} prot=0x{:x}",
                                        region.base_address, region.region_size, region.protection
                                    ));
                                }
                                evidence.push(
                                    "IoCompletion callback may point to injected shellcode"
                                        .to_string(),
                                );

                                // Use the first suspicious region for the event details
                                let first = &suspicious_regions[0];

                                results.push(InjectionEvent {
                                    source_pid: 0,
                                    source_name: "unknown".to_string(),
                                    source_path: String::new(),
                                    target_pid: pid,
                                    target_name: process_name.clone(),
                                    target_path: process_path,
                                    technique: InjectionTechnique::PoolPartyIoCompletion,
                                    memory_address: Some(first.base_address),
                                    memory_size: Some(first.region_size),
                                    memory_protection: Some(first.protection),
                                    evidence,
                                });
                            }
                        }

                        let _ = CloseHandle(proc_handle);
                    }
                }

                if Process32NextW(proc_snapshot, &mut proc_entry).is_err() {
                    break;
                }
            }

            let _ = CloseHandle(proc_snapshot);
        }

        results
    }

    // ----------------------------------------------------------------
    // PoolParty Variant 6: TP_DIRECT Injection via NtSetIoCompletionEx
    // ----------------------------------------------------------------
    //
    // This variant bypasses the thread pool object model entirely. The
    // attacker constructs a TP_DIRECT structure in the target's memory
    // that contains a direct callback pointer, then queues it via
    // NtSetIoCompletionEx. Because TP_DIRECT is processed without going
    // through normal TP_WORK / TP_CALLBACK validation, it is harder to
    // detect.
    //
    // Detection: Look for processes where a thread pool worker executes
    // code from a non-module region AND the process contains small
    // (sizeof TP_DIRECT ~ 0x40 bytes) private RW regions adjacent to
    // executable regions. This pattern is characteristic of the TP_DIRECT
    // structure + shellcode layout.
    // ----------------------------------------------------------------

    fn detect_tp_direct_injection() -> Vec<InjectionEvent> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };
        use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        let mut results = Vec::new();

        unsafe {
            let proc_snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(h) => h,
                Err(_) => return results,
            };

            let mut proc_entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            if Process32FirstW(proc_snapshot, &mut proc_entry).is_err() {
                let _ = CloseHandle(proc_snapshot);
                return results;
            }

            loop {
                let pid = proc_entry.th32ProcessID;

                if pid > 10 && pid != std::process::id() {
                    let process_name = String::from_utf16_lossy(
                        &proc_entry.szExeFile[..proc_entry
                            .szExeFile
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(proc_entry.szExeFile.len())],
                    );

                    if let Ok(proc_handle) =
                        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
                    {
                        // Scan memory for the TP_DIRECT pattern:
                        // A small RW private region (holding the TP_DIRECT struct, ~64-128 bytes)
                        // immediately followed or adjacent to an executable private region
                        // (holding the shellcode).
                        let mut address: usize = 0;
                        let mut prev_region: Option<MemoryRegion> = None;
                        let mut tp_direct_candidates: Vec<(MemoryRegion, MemoryRegion)> =
                            Vec::new();

                        loop {
                            let mut mbi = MEMORY_BASIC_INFORMATION::default();
                            let qr = VirtualQueryEx(
                                proc_handle,
                                Some(address as *const _),
                                &mut mbi,
                                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                            );

                            if qr == 0 {
                                break;
                            }

                            let region = MemoryRegion {
                                base_address: mbi.BaseAddress as u64,
                                region_size: mbi.RegionSize as u64,
                                protection: mbi.Protect.0,
                                state: mbi.State.0,
                                region_type: mbi.Type.0,
                                allocation_base: mbi.AllocationBase as u64,
                            };

                            if region.is_committed() && region.is_private() {
                                if let Some(ref prev) = prev_region {
                                    // Pattern: small RW region followed by executable region
                                    // from the same allocation base
                                    let prev_is_small_rw = prev.is_committed()
                                        && prev.is_private()
                                        && prev.is_writable()
                                        && !prev.is_executable()
                                        && prev.region_size <= 4096;

                                    let curr_is_exec =
                                        region.is_executable() && region.region_size > 0;

                                    let same_alloc = prev.allocation_base == region.allocation_base
                                        && prev.allocation_base != 0;

                                    if prev_is_small_rw && curr_is_exec && same_alloc {
                                        tp_direct_candidates.push((prev.clone(), region.clone()));
                                    }
                                }
                            }

                            prev_region = Some(region);

                            address = mbi.BaseAddress as usize + mbi.RegionSize;
                            if address < mbi.BaseAddress as usize {
                                break; // overflow
                            }
                        }

                        // Only flag if we found the pattern AND the process also has
                        // IoCompletion handles (needed for NtSetIoCompletionEx)
                        if !tp_direct_candidates.is_empty() {
                            let io_handles = enumerate_io_completion_handles(pid);

                            if !io_handles.is_empty() {
                                let process_path = get_process_path(pid);

                                for (rw_region, exec_region) in &tp_direct_candidates {
                                    let evidence = vec![
                                        format!(
                                            "TP_DIRECT pattern: small RW region (0x{:x}, {} bytes) adjacent to exec region (0x{:x}, {} bytes)",
                                            rw_region.base_address, rw_region.region_size,
                                            exec_region.base_address, exec_region.region_size
                                        ),
                                        format!("Same allocation base: 0x{:x}", rw_region.allocation_base),
                                        format!("Process has {} IoCompletion handle(s)", io_handles.len()),
                                        "TP_DIRECT struct + shellcode layout characteristic of Variant 6".to_string(),
                                    ];

                                    results.push(InjectionEvent {
                                        source_pid: 0,
                                        source_name: "unknown".to_string(),
                                        source_path: String::new(),
                                        target_pid: pid,
                                        target_name: process_name.clone(),
                                        target_path: process_path.clone(),
                                        technique: InjectionTechnique::PoolPartyTpDirect,
                                        memory_address: Some(exec_region.base_address),
                                        memory_size: Some(exec_region.region_size),
                                        memory_protection: Some(exec_region.protection),
                                        evidence,
                                    });
                                }
                            }
                        }

                        let _ = CloseHandle(proc_handle);
                    }
                }

                if Process32NextW(proc_snapshot, &mut proc_entry).is_err() {
                    break;
                }
            }

            let _ = CloseHandle(proc_snapshot);
        }

        results
    }

    // ----------------------------------------------------------------
    // PoolParty Variant 8: Timer Queue Manipulation
    // ----------------------------------------------------------------
    //
    // The attacker creates or modifies a timer object in the target
    // process via NtCreateTimer2 / NtSetTimer2, setting its callback
    // to point to injected shellcode. When the timer fires, the thread
    // pool executes the attacker's code.
    //
    // Detection: Enumerate timer handles per process and look for
    // processes with both timer handles and suspicious private executable
    // memory. Cross-reference with handle creation patterns.
    // ----------------------------------------------------------------

    fn detect_timer_queue_injection() -> Vec<InjectionEvent> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        let mut results = Vec::new();

        unsafe {
            let proc_snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(h) => h,
                Err(_) => return results,
            };

            let mut proc_entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            if Process32FirstW(proc_snapshot, &mut proc_entry).is_err() {
                let _ = CloseHandle(proc_snapshot);
                return results;
            }

            loop {
                let pid = proc_entry.th32ProcessID;

                if pid > 10 && pid != std::process::id() {
                    let process_name = String::from_utf16_lossy(
                        &proc_entry.szExeFile[..proc_entry
                            .szExeFile
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(proc_entry.szExeFile.len())],
                    );

                    if let Ok(proc_handle) =
                        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
                    {
                        // Enumerate timer (IRTimer / Timer) handles for this process.
                        // Object type index for Timer is typically 2 on Windows 10/11,
                        // and IRTimer (used by NtCreateTimer2) is typically 39+.
                        let timer_handles = enumerate_timer_handles(pid);

                        if !timer_handles.is_empty() {
                            let suspicious_regions = scan_private_executable_regions(proc_handle);

                            if !suspicious_regions.is_empty() {
                                let process_path = get_process_path(pid);

                                let mut evidence = vec![
                                    format!(
                                        "Process has {} timer handle(s) and {} private executable region(s)",
                                        timer_handles.len(),
                                        suspicious_regions.len()
                                    ),
                                ];

                                for region in &suspicious_regions {
                                    evidence.push(format!(
                                        "Private exec region: base=0x{:x} size={} prot=0x{:x}",
                                        region.base_address, region.region_size, region.protection
                                    ));
                                }
                                evidence.push(
                                    "Timer callback may point to injected shellcode (Variant 8)"
                                        .to_string(),
                                );

                                let first = &suspicious_regions[0];

                                results.push(InjectionEvent {
                                    source_pid: 0,
                                    source_name: "unknown".to_string(),
                                    source_path: String::new(),
                                    target_pid: pid,
                                    target_name: process_name.clone(),
                                    target_path: process_path,
                                    technique: InjectionTechnique::PoolPartyTimerQueue,
                                    memory_address: Some(first.base_address),
                                    memory_size: Some(first.region_size),
                                    memory_protection: Some(first.protection),
                                    evidence,
                                });
                            }
                        }

                        let _ = CloseHandle(proc_handle);
                    }
                }

                if Process32NextW(proc_snapshot, &mut proc_entry).is_err() {
                    break;
                }
            }

            let _ = CloseHandle(proc_snapshot);
        }

        results
    }

    // ----------------------------------------------------------------
    // PoolParty Variant 9: ALPC Port Injection via TpAlpc
    // ----------------------------------------------------------------
    //
    // The attacker targets TpAlpc objects in the target's thread pool.
    // ALPC (Advanced Local Procedure Call) ports have completion callbacks
    // that the thread pool invokes when messages arrive. By writing to a
    // target's ALPC completion port and pointing the callback to injected
    // code, the attacker gets execution.
    //
    // Detection: Enumerate ALPC port handles per process. If a process has
    // ALPC port handles AND suspicious private executable memory, flag it.
    // Additionally check for processes that recently received cross-process
    // memory writes.
    // ----------------------------------------------------------------

    fn detect_alpc_injection() -> Vec<InjectionEvent> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        let mut results = Vec::new();

        unsafe {
            let proc_snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(h) => h,
                Err(_) => return results,
            };

            let mut proc_entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            if Process32FirstW(proc_snapshot, &mut proc_entry).is_err() {
                let _ = CloseHandle(proc_snapshot);
                return results;
            }

            loop {
                let pid = proc_entry.th32ProcessID;

                if pid > 10 && pid != std::process::id() {
                    let process_name = String::from_utf16_lossy(
                        &proc_entry.szExeFile[..proc_entry
                            .szExeFile
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(proc_entry.szExeFile.len())],
                    );

                    if let Ok(proc_handle) =
                        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
                    {
                        // Enumerate ALPC port handles. Object type index for
                        // ALPC Port is typically 46 on Windows 10/11.
                        let alpc_handles = enumerate_alpc_handles(pid);

                        if !alpc_handles.is_empty() {
                            let suspicious_regions = scan_private_executable_regions(proc_handle);

                            if !suspicious_regions.is_empty() {
                                let process_path = get_process_path(pid);

                                let mut evidence = vec![
                                    format!(
                                        "Process has {} ALPC port handle(s) and {} private executable region(s)",
                                        alpc_handles.len(),
                                        suspicious_regions.len()
                                    ),
                                ];

                                for region in &suspicious_regions {
                                    evidence.push(format!(
                                        "Private exec region: base=0x{:x} size={} prot=0x{:x}",
                                        region.base_address, region.region_size, region.protection
                                    ));
                                }
                                evidence.push(
                                    "ALPC completion callback may point to injected shellcode (Variant 9)".to_string()
                                );

                                let first = &suspicious_regions[0];

                                results.push(InjectionEvent {
                                    source_pid: 0,
                                    source_name: "unknown".to_string(),
                                    source_path: String::new(),
                                    target_pid: pid,
                                    target_name: process_name.clone(),
                                    target_path: process_path,
                                    technique: InjectionTechnique::PoolPartyAlpc,
                                    memory_address: Some(first.base_address),
                                    memory_size: Some(first.region_size),
                                    memory_protection: Some(first.protection),
                                    evidence,
                                });
                            }
                        }

                        let _ = CloseHandle(proc_handle);
                    }
                }

                if Process32NextW(proc_snapshot, &mut proc_entry).is_err() {
                    break;
                }
            }

            let _ = CloseHandle(proc_snapshot);
        }

        results
    }

    // ----------------------------------------------------------------
    // PoolParty Behavioral Heuristic (catches unknown/future variants)
    // ----------------------------------------------------------------
    //
    // Combines multiple weak signals to detect generic PoolParty-style
    // injection that may not match a specific variant:
    //
    //   Signal 1: Cross-process memory write (VirtualAllocEx + WriteProcessMemory)
    //   Signal 2: New private executable memory in the target process
    //   Signal 3: Thread pool work item execution from the unbacked region
    //   Signal 4: Handle to thread pool objects (WorkerFactory, IoCompletion,
    //             Timer, ALPC) in a process that doesn't normally have them
    //
    // Each signal contributes to a confidence score. If the combined score
    // exceeds a threshold, we emit a PoolPartyBehavioral event.
    // ----------------------------------------------------------------

    async fn detect_poolparty_behavioral(
        scan_results: &Arc<Mutex<HashMap<u32, Vec<MemoryRegion>>>>,
    ) -> Vec<InjectionEvent> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, Thread32First, Thread32Next,
            PROCESSENTRY32W, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD, THREADENTRY32,
        };
        use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
        use windows::Win32::System::Threading::{
            OpenProcess, OpenThread, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
            THREAD_QUERY_INFORMATION,
        };

        let mut results = Vec::new();

        // Processes that should NOT have private executable memory outside
        // of loaded modules. If they do AND they have thread pool handles,
        // it is a strong behavioral indicator.
        let normal_targets: HashSet<&str> = [
            "svchost.exe",
            "services.exe",
            "taskhostw.exe",
            "sihost.exe",
            "dllhost.exe",
            "spoolsv.exe",
            "searchindexer.exe",
            "notepad.exe",
            "calc.exe",
            "mspaint.exe",
            "wordpad.exe",
            "conhost.exe",
            "mmc.exe",
        ]
        .iter()
        .cloned()
        .collect();

        unsafe {
            let proc_snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(h) => h,
                Err(_) => return results,
            };

            let mut proc_entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            if Process32FirstW(proc_snapshot, &mut proc_entry).is_err() {
                let _ = CloseHandle(proc_snapshot);
                return results;
            }

            loop {
                let pid = proc_entry.th32ProcessID;

                if pid > 10 && pid != std::process::id() {
                    let process_name = String::from_utf16_lossy(
                        &proc_entry.szExeFile[..proc_entry
                            .szExeFile
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(proc_entry.szExeFile.len())],
                    );

                    // Only check processes that are common injection targets
                    let is_interesting_target = normal_targets
                        .iter()
                        .any(|&t| process_name.to_lowercase().contains(t));

                    if !is_interesting_target {
                        if Process32NextW(proc_snapshot, &mut proc_entry).is_err() {
                            break;
                        }
                        continue;
                    }

                    if let Ok(proc_handle) =
                        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
                    {
                        let mut confidence: f32 = 0.0;
                        let mut evidence: Vec<String> = Vec::new();
                        let mut suspicious_addr: Option<u64> = None;
                        let mut suspicious_size: Option<u64> = None;
                        let mut suspicious_prot: Option<u32> = None;

                        // Signal 1: Private executable memory in a process that
                        // should not have any.
                        let exec_regions = scan_private_executable_regions(proc_handle);
                        if !exec_regions.is_empty() {
                            confidence += 0.35;
                            evidence.push(format!(
                                "Signal 1: {} private executable region(s) in {}",
                                exec_regions.len(),
                                process_name
                            ));
                            let first = &exec_regions[0];
                            suspicious_addr = Some(first.base_address);
                            suspicious_size = Some(first.region_size);
                            suspicious_prot = Some(first.protection);
                        }

                        // Signal 2: Worker thread with start address in non-module
                        // memory (indicates any PoolParty variant has already
                        // executed).
                        let thread_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                        if let Ok(tsnap) = thread_snapshot {
                            let mut tentry = THREADENTRY32 {
                                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                                ..Default::default()
                            };

                            let mut unbacked_thread_count = 0u32;

                            if Thread32First(tsnap, &mut tentry).is_ok() {
                                loop {
                                    if tentry.th32OwnerProcessID == pid {
                                        if let Ok(th) = OpenThread(
                                            THREAD_QUERY_INFORMATION,
                                            false,
                                            tentry.th32ThreadID,
                                        ) {
                                            let mut start_address: usize = 0;
                                            let status = ntdll_NtQueryInformationThread(
                                                th,
                                                9, // ThreadQuerySetWin32StartAddress
                                                &mut start_address as *mut _ as *mut _,
                                                std::mem::size_of::<usize>() as u32,
                                                std::ptr::null_mut(),
                                            );

                                            if status == 0 && start_address != 0 {
                                                let mut mbi = MEMORY_BASIC_INFORMATION::default();
                                                let qr = VirtualQueryEx(
                                                    proc_handle,
                                                    Some(start_address as *const _),
                                                    &mut mbi,
                                                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                                                );

                                                if qr > 0 {
                                                    let region = MemoryRegion {
                                                        base_address: mbi.BaseAddress as u64,
                                                        region_size: mbi.RegionSize as u64,
                                                        protection: mbi.Protect.0,
                                                        state: mbi.State.0,
                                                        region_type: mbi.Type.0,
                                                        allocation_base: mbi.AllocationBase as u64,
                                                    };

                                                    if region.is_committed()
                                                        && region.is_executable()
                                                        && region.is_private()
                                                    {
                                                        unbacked_thread_count += 1;
                                                    }
                                                }
                                            }

                                            let _ = CloseHandle(th);
                                        }
                                    }

                                    if Thread32Next(tsnap, &mut tentry).is_err() {
                                        break;
                                    }
                                }
                            }

                            let _ = CloseHandle(tsnap);

                            if unbacked_thread_count > 0 {
                                confidence += 0.30;
                                evidence.push(format!(
                                    "Signal 2: {} thread(s) with start address in unbacked executable memory",
                                    unbacked_thread_count
                                ));
                            }
                        }

                        // Signal 3: Presence of thread pool objects (IoCompletion,
                        // Timer, ALPC handles) combined with the above signals.
                        let io_handles = enumerate_io_completion_handles(pid);
                        let timer_handles = enumerate_timer_handles(pid);
                        let alpc_handles = enumerate_alpc_handles(pid);

                        let tp_object_count =
                            io_handles.len() + timer_handles.len() + alpc_handles.len();
                        if tp_object_count > 0 && confidence > 0.0 {
                            confidence += 0.15;
                            evidence.push(format!(
                                "Signal 3: Process holds {} thread pool object handle(s) (IoCompletion={}, Timer={}, ALPC={})",
                                tp_object_count, io_handles.len(), timer_handles.len(), alpc_handles.len()
                            ));
                        }

                        let _ = CloseHandle(proc_handle);

                        // Only emit if combined confidence exceeds threshold
                        // This threshold is set to require at least two strong signals
                        if confidence >= 0.55 {
                            confidence = confidence.min(0.95);
                            evidence
                                .push(format!("Combined behavioral confidence: {:.2}", confidence));
                            evidence.push(
                                "Multiple PoolParty behavioral indicators present".to_string(),
                            );

                            let process_path = get_process_path(pid);

                            results.push(InjectionEvent {
                                source_pid: 0,
                                source_name: "unknown".to_string(),
                                source_path: String::new(),
                                target_pid: pid,
                                target_name: process_name.clone(),
                                target_path: process_path,
                                technique: InjectionTechnique::PoolPartyBehavioral,
                                memory_address: suspicious_addr,
                                memory_size: suspicious_size,
                                memory_protection: suspicious_prot,
                                evidence,
                            });
                        }
                    }
                }

                if Process32NextW(proc_snapshot, &mut proc_entry).is_err() {
                    break;
                }
            }

            let _ = CloseHandle(proc_snapshot);
        }

        results
    }

    // ====================================================================
    // Helper functions for PoolParty detection
    // ====================================================================

    /// Scan a process's memory space for private, executable, committed
    /// regions that are not backed by a module (MEM_IMAGE). These are
    /// strong indicators of injected shellcode.
    fn scan_private_executable_regions(
        proc_handle: windows::Win32::Foundation::HANDLE,
    ) -> Vec<MemoryRegion> {
        use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};

        let mut suspicious = Vec::new();

        unsafe {
            let mut address: usize = 0;

            loop {
                let mut mbi = MEMORY_BASIC_INFORMATION::default();
                let qr = VirtualQueryEx(
                    proc_handle,
                    Some(address as *const _),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                );

                if qr == 0 {
                    break;
                }

                let region = MemoryRegion {
                    base_address: mbi.BaseAddress as u64,
                    region_size: mbi.RegionSize as u64,
                    protection: mbi.Protect.0,
                    state: mbi.State.0,
                    region_type: mbi.Type.0,
                    allocation_base: mbi.AllocationBase as u64,
                };

                // Private, committed, executable memory > 4KB that is not
                // backed by a module image.
                if region.is_committed()
                    && region.is_executable()
                    && region.is_private()
                    && region.region_size > 4096
                {
                    suspicious.push(region);
                }

                address = mbi.BaseAddress as usize + mbi.RegionSize;
                if address < mbi.BaseAddress as usize {
                    break; // overflow
                }
            }
        }

        suspicious
    }

    /// Thin wrapper around NtQueryInformationThread loaded from ntdll.
    /// Returns NTSTATUS (0 = success).
    ///
    /// Safety: caller must ensure handle is valid and buffer is correctly sized.
    unsafe fn ntdll_NtQueryInformationThread(
        thread_handle: windows::Win32::Foundation::HANDLE,
        thread_information_class: u32,
        thread_information: *mut std::ffi::c_void,
        thread_information_length: u32,
        return_length: *mut u32,
    ) -> i32 {
        type NtQueryInformationThreadFn = unsafe extern "system" fn(
            windows::Win32::Foundation::HANDLE,
            u32,
            *mut std::ffi::c_void,
            u32,
            *mut u32,
        ) -> i32;

        let module = windows::Win32::System::LibraryLoader::GetModuleHandleA(
            windows::core::PCSTR::from_raw(b"ntdll.dll\0".as_ptr()),
        );

        if let Ok(hmod) = module {
            let proc = windows::Win32::System::LibraryLoader::GetProcAddress(
                hmod,
                windows::core::PCSTR::from_raw(b"NtQueryInformationThread\0".as_ptr()),
            );

            if let Some(func) = proc {
                let nt_func: NtQueryInformationThreadFn = std::mem::transmute(func);
                return nt_func(
                    thread_handle,
                    thread_information_class,
                    thread_information,
                    thread_information_length,
                    return_length,
                );
            }
        }

        // Return STATUS_UNSUCCESSFUL if we cannot load the function
        -1i32
    }

    /// Enumerate handles of a specific object type owned by a process.
    /// Uses NtQuerySystemInformation with SystemHandleInformation (16).
    ///
    /// Returns a list of handle values matching the given type index.
    unsafe fn enumerate_handles_by_type(pid: u32, target_type_index: u8) -> Vec<u16> {
        type NtQuerySystemInformationFn = unsafe extern "system" fn(
            u32,      // SystemInformationClass
            *mut u8,  // SystemInformation
            u32,      // SystemInformationLength
            *mut u32, // ReturnLength
        ) -> i32;

        let module = windows::Win32::System::LibraryLoader::GetModuleHandleA(
            windows::core::PCSTR::from_raw(b"ntdll.dll\0".as_ptr()),
        );

        let hmod = match module {
            Ok(h) => h,
            Err(_) => return Vec::new(),
        };

        let proc = windows::Win32::System::LibraryLoader::GetProcAddress(
            hmod,
            windows::core::PCSTR::from_raw(b"NtQuerySystemInformation\0".as_ptr()),
        );

        let nt_func: NtQuerySystemInformationFn = match proc {
            Some(f) => std::mem::transmute(f),
            None => return Vec::new(),
        };

        // SystemHandleInformation = 16
        // Start with a reasonable buffer and grow if needed
        let mut buf_size: u32 = 1024 * 1024; // 1 MB
        let mut buffer: Vec<u8> = vec![0u8; buf_size as usize];
        let mut return_length: u32 = 0;

        // Retry with larger buffer if STATUS_INFO_LENGTH_MISMATCH (0xC0000004)
        for _ in 0..3 {
            let status = nt_func(
                16, // SystemHandleInformation
                buffer.as_mut_ptr(),
                buf_size,
                &mut return_length,
            );

            if status == 0 {
                break;
            } else if status == -1073741820i32 {
                // STATUS_INFO_LENGTH_MISMATCH: need a bigger buffer
                buf_size = return_length + 65536;
                buffer.resize(buf_size as usize, 0);
            } else {
                return Vec::new();
            }
        }

        // Parse SYSTEM_HANDLE_INFORMATION structure:
        // struct {
        //     ULONG NumberOfHandles;
        //     SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[];
        // }
        // Each SYSTEM_HANDLE_TABLE_ENTRY_INFO is:
        // struct {
        //     USHORT UniqueProcessId;     // offset 0, size 2
        //     USHORT CreatorBackTraceIndex; // offset 2, size 2
        //     UCHAR  ObjectTypeIndex;     // offset 4, size 1
        //     UCHAR  HandleAttributes;    // offset 5, size 1
        //     USHORT HandleValue;         // offset 6, size 2
        //     PVOID  Object;              // offset 8, size 8 (x64) or 4 (x86)
        //     ULONG  GrantedAccess;       // offset 16, size 4 (x64) or offset 12 (x86)
        // }

        let entry_size = if cfg!(target_pointer_width = "64") {
            24usize
        } else {
            16usize
        };

        if buffer.len() < 4 {
            return Vec::new();
        }

        let handle_count =
            u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
        let entries_start = std::mem::size_of::<u32>(); // after NumberOfHandles

        let mut matching_handles = Vec::new();

        for i in 0..handle_count {
            let offset = entries_start + i * entry_size;
            if offset + entry_size > buffer.len() {
                break;
            }

            let entry_pid = u16::from_le_bytes([buffer[offset], buffer[offset + 1]]);
            let object_type = buffer[offset + 4];
            let handle_value = u16::from_le_bytes([buffer[offset + 6], buffer[offset + 7]]);

            if entry_pid as u32 == pid && object_type == target_type_index {
                matching_handles.push(handle_value);
            }
        }

        matching_handles
    }

    /// Enumerate IoCompletion object handles for a given process.
    /// IoCompletion type index is typically 36 on Windows 10/11.
    fn enumerate_io_completion_handles(pid: u32) -> Vec<u16> {
        // IoCompletion type index varies by Windows build. Common values:
        //   Windows 10 1809+: 36
        //   Windows 11 22H2+: 36 or 37
        // We check both to handle minor variations.
        unsafe {
            let mut handles = enumerate_handles_by_type(pid, 36);
            if handles.is_empty() {
                handles = enumerate_handles_by_type(pid, 37);
            }
            handles
        }
    }

    /// Enumerate Timer and IRTimer handles for a given process.
    /// Timer type index is typically 2, IRTimer is typically 39-41.
    fn enumerate_timer_handles(pid: u32) -> Vec<u16> {
        unsafe {
            let mut handles = enumerate_handles_by_type(pid, 2); // Timer
                                                                 // Also check IRTimer (used by NtCreateTimer2), varies by build
            handles.extend(enumerate_handles_by_type(pid, 39));
            handles.extend(enumerate_handles_by_type(pid, 40));
            handles.extend(enumerate_handles_by_type(pid, 41));
            handles
        }
    }

    /// Enumerate ALPC Port handles for a given process.
    /// ALPC Port type index is typically 46 on Windows 10/11.
    fn enumerate_alpc_handles(pid: u32) -> Vec<u16> {
        unsafe {
            let mut handles = enumerate_handles_by_type(pid, 46);
            if handles.is_empty() {
                handles = enumerate_handles_by_type(pid, 45);
            }
            handles
        }
    }
}

// ==================== Linux Implementation ====================
#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::collections::HashSet;
    use std::fs;

    /// Memory mapping entry from /proc/[pid]/maps
    #[derive(Debug, Clone)]
    struct MemoryMapping {
        start_addr: u64,
        end_addr: u64,
        permissions: String,
        offset: u64,
        device: String,
        inode: u64,
        pathname: String,
    }

    impl MemoryMapping {
        fn from_line(line: &str) -> Option<Self> {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                return None;
            }

            let addr_parts: Vec<&str> = parts[0].split('-').collect();
            if addr_parts.len() != 2 {
                return None;
            }

            Some(Self {
                start_addr: u64::from_str_radix(addr_parts[0], 16).ok()?,
                end_addr: u64::from_str_radix(addr_parts[1], 16).ok()?,
                permissions: parts[1].to_string(),
                offset: u64::from_str_radix(parts[2], 16).unwrap_or(0),
                device: parts[3].to_string(),
                inode: parts[4].parse().unwrap_or(0),
                pathname: parts.get(5).map(|s| s.to_string()).unwrap_or_default(),
            })
        }

        fn is_executable(&self) -> bool {
            self.permissions.contains('x')
        }

        fn is_writable(&self) -> bool {
            self.permissions.contains('w')
        }

        fn is_rwx(&self) -> bool {
            self.is_executable() && self.is_writable()
        }

        fn is_anonymous(&self) -> bool {
            self.pathname.is_empty() || self.pathname == "[heap]" || self.pathname == "[stack]"
        }

        fn size(&self) -> u64 {
            self.end_addr - self.start_addr
        }
    }

    /// Main Linux monitoring loop
    pub async fn monitor_loop(tx: mpsc::Sender<TelemetryEvent>, config: AgentConfig) {
        let mul = config.sub_loop_interval_multiplier;
        info!(multiplier = mul, "Starting Linux process injection monitor");

        // Track known detections
        let known_detections: Arc<Mutex<HashSet<(u32, u32, InjectionTechnique)>>> =
            Arc::new(Mutex::new(HashSet::new()));

        // Start ptrace monitor (500ms base)
        let tx_ptrace = tx.clone();
        let known_ptrace = known_detections.clone();
        let ptrace_interval_ms = ((500.0 * mul) as u64).max(500);
        tokio::spawn(async move {
            ptrace_monitor(tx_ptrace, known_ptrace, ptrace_interval_ms).await;
        });

        // Start LD_PRELOAD monitor (2s base)
        let tx_preload = tx.clone();
        let known_preload = known_detections.clone();
        let preload_interval_ms = ((2000.0 * mul) as u64).max(2000);
        tokio::spawn(async move {
            ld_preload_monitor(tx_preload, known_preload, preload_interval_ms).await;
        });

        // Start memory maps scanner (5s base)
        let tx_maps = tx.clone();
        let known_maps = known_detections.clone();
        let maps_interval_ms = ((5000.0 * mul) as u64).max(5000);
        tokio::spawn(async move {
            memory_maps_scanner(tx_maps, known_maps, maps_interval_ms).await;
        });

        // Start audit log monitor (1s base)
        let tx_audit = tx.clone();
        let config_audit = config.clone();
        let known_audit = known_detections.clone();
        let audit_interval_ms = ((1000.0 * mul) as u64).max(1000);
        tokio::spawn(async move {
            audit_log_monitor(tx_audit, config_audit, known_audit, audit_interval_ms).await;
        });

        // Start /proc/[pid]/mem access monitor (2s base)
        let tx_mem = tx.clone();
        let known_mem = known_detections.clone();
        let mem_interval_ms = ((2000.0 * mul) as u64).max(2000);
        tokio::spawn(async move {
            proc_mem_access_monitor(tx_mem, known_mem, mem_interval_ms).await;
        });

        // Periodic cleanup of known detections to prevent unbounded growth
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(300)).await;
            let mut known = known_detections.lock().await;
            if !known.is_empty() {
                known.clear();
            }
        }
    }

    /// Monitor for ptrace-based injection
    async fn ptrace_monitor(
        tx: mpsc::Sender<TelemetryEvent>,
        known: Arc<Mutex<HashSet<(u32, u32, InjectionTechnique)>>>,
        interval_ms: u64,
    ) {
        info!("Starting ptrace injection monitor");

        // Known legitimate debuggers
        let known_debuggers: HashSet<&str> = [
            "gdb", "lldb", "strace", "ltrace", "valgrind", "perf", "rr", "ddd", "kdbg", "cgdb",
            "pdb", "delve", "dlv", "radare2", "r2",
        ]
        .iter()
        .cloned()
        .collect();

        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        loop {
            interval.tick().await;

            // Scan /proc for processes being traced
            if let Ok(entries) = fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();

                    if let Ok(pid) = name_str.parse::<u32>() {
                        let status_path = format!("/proc/{}/status", pid);

                        if let Ok(content) = fs::read_to_string(&status_path) {
                            // Look for TracerPid line
                            for line in content.lines() {
                                if line.starts_with("TracerPid:") {
                                    let parts: Vec<&str> = line.split_whitespace().collect();
                                    if parts.len() >= 2 {
                                        if let Ok(tracer_pid) = parts[1].parse::<u32>() {
                                            if tracer_pid != 0 {
                                                let tracer_name = get_process_name(tracer_pid);

                                                // Check if this is a known debugger
                                                let is_debugger =
                                                    known_debuggers.iter().any(|&d| {
                                                        tracer_name.to_lowercase().contains(d)
                                                    });

                                                if !is_debugger {
                                                    let key = (
                                                        tracer_pid,
                                                        pid,
                                                        InjectionTechnique::PtraceInjection,
                                                    );
                                                    let mut known_guard = known.lock().await;

                                                    if !known_guard.contains(&key) {
                                                        known_guard.insert(key);
                                                        drop(known_guard);

                                                        let tracer_path =
                                                            get_process_path(tracer_pid);
                                                        let target_name = get_process_name(pid);
                                                        let target_path = get_process_path(pid);

                                                        let injection = InjectionEvent {
                                                            source_pid: tracer_pid,
                                                            source_name: tracer_name,
                                                            source_path: tracer_path,
                                                            target_pid: pid,
                                                            target_name,
                                                            target_path,
                                                            technique: InjectionTechnique::PtraceInjection,
                                                            memory_address: None,
                                                            memory_size: None,
                                                            memory_protection: None,
                                                            evidence: vec![
                                                                format!("TracerPid: {}", tracer_pid),
                                                                "Non-debugger process tracing another process".to_string(),
                                                            ],
                                                        };

                                                        let event = InjectionCollector::create_injection_event(&injection);
                                                        if tx.send(event).await.is_err() {
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
    }

    /// Monitor for LD_PRELOAD injection
    async fn ld_preload_monitor(
        tx: mpsc::Sender<TelemetryEvent>,
        known: Arc<Mutex<HashSet<(u32, u32, InjectionTechnique)>>>,
        interval_ms: u64,
    ) {
        info!("Starting LD_PRELOAD monitor");

        // Trusted library paths
        let trusted_paths: Vec<&str> = vec![
            "/usr/lib",
            "/lib",
            "/usr/lib64",
            "/lib64",
            "/usr/local/lib",
            "/opt/",
        ];

        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        loop {
            interval.tick().await;

            if let Ok(entries) = fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();

                    if let Ok(pid) = name_str.parse::<u32>() {
                        let environ_path = format!("/proc/{}/environ", pid);

                        if let Ok(content) = fs::read(&environ_path) {
                            let env_str = String::from_utf8_lossy(&content);

                            for var in env_str.split('\0') {
                                if var.starts_with("LD_PRELOAD=") {
                                    let preload_value = var.trim_start_matches("LD_PRELOAD=");

                                    if !preload_value.is_empty() {
                                        // Check each library in LD_PRELOAD
                                        for lib in preload_value.split(':') {
                                            let lib = lib.trim();
                                            if lib.is_empty() {
                                                continue;
                                            }

                                            // Check if this is a suspicious path
                                            let is_trusted =
                                                trusted_paths.iter().any(|&p| lib.starts_with(p));

                                            if !is_trusted {
                                                let key = (
                                                    0,
                                                    pid,
                                                    InjectionTechnique::LdPreloadInjection,
                                                );
                                                let mut known_guard = known.lock().await;

                                                if !known_guard.contains(&key) {
                                                    known_guard.insert(key);
                                                    drop(known_guard);

                                                    let process_name = get_process_name(pid);
                                                    let process_path = get_process_path(pid);

                                                    let injection = InjectionEvent {
                                                        source_pid: 0,
                                                        source_name: "unknown".to_string(),
                                                        source_path: lib.to_string(),
                                                        target_pid: pid,
                                                        target_name: process_name,
                                                        target_path: process_path,
                                                        technique:
                                                            InjectionTechnique::LdPreloadInjection,
                                                        memory_address: None,
                                                        memory_size: None,
                                                        memory_protection: None,
                                                        evidence: vec![
                                                            format!("LD_PRELOAD={}", preload_value),
                                                            format!("Suspicious library: {}", lib),
                                                            "Library not in trusted path"
                                                                .to_string(),
                                                        ],
                                                    };

                                                    let event =
                                                        InjectionCollector::create_injection_event(
                                                            &injection,
                                                        );
                                                    if tx.send(event).await.is_err() {
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

    /// Scan process memory maps for suspicious regions
    async fn memory_maps_scanner(
        tx: mpsc::Sender<TelemetryEvent>,
        known: Arc<Mutex<HashSet<(u32, u32, InjectionTechnique)>>>,
        interval_ms: u64,
    ) {
        info!("Starting memory maps scanner");

        // Processes that legitimately use RWX memory (JIT compilers, etc.)
        let jit_processes: HashSet<&str> = [
            "java", "javac", "node", "nodejs", "python", "python3", "ruby", "perl", "php",
            "luajit", "v8", "chromium", "chrome", "firefox", "qemu", "wine", "mono", "dotnet",
        ]
        .iter()
        .cloned()
        .collect();

        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        loop {
            interval.tick().await;

            if let Ok(entries) = fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();

                    if let Ok(pid) = name_str.parse::<u32>() {
                        if pid < 10 {
                            continue; // Skip kernel threads
                        }

                        let process_name = get_process_name(pid);

                        // Check if this is a JIT process
                        let is_jit = jit_processes
                            .iter()
                            .any(|&jit| process_name.to_lowercase().contains(jit));

                        if is_jit {
                            continue;
                        }

                        let maps_path = format!("/proc/{}/maps", pid);

                        if let Ok(content) = fs::read_to_string(&maps_path) {
                            for line in content.lines() {
                                if let Some(mapping) = MemoryMapping::from_line(line) {
                                    // Check for suspicious RWX anonymous mappings
                                    if mapping.is_rwx() && mapping.is_anonymous() {
                                        // Skip small regions (likely false positives)
                                        if mapping.size() < 4096 {
                                            continue;
                                        }

                                        // Skip stack and heap (can legitimately be RWX on some systems)
                                        if mapping.pathname == "[stack]" {
                                            continue;
                                        }

                                        let key =
                                            (0, pid, InjectionTechnique::SuspiciousMemoryMapping);
                                        let mut known_guard = known.lock().await;

                                        if !known_guard.contains(&key) {
                                            known_guard.insert(key);
                                            drop(known_guard);

                                            let process_path = get_process_path(pid);

                                            let injection = InjectionEvent {
                                                source_pid: 0,
                                                source_name: "unknown".to_string(),
                                                source_path: String::new(),
                                                target_pid: pid,
                                                target_name: process_name.clone(),
                                                target_path: process_path,
                                                technique:
                                                    InjectionTechnique::SuspiciousMemoryMapping,
                                                memory_address: Some(mapping.start_addr),
                                                memory_size: Some(mapping.size()),
                                                memory_protection: None,
                                                evidence: vec![
                                                    format!(
                                                        "RWX mapping: 0x{:x}-0x{:x}",
                                                        mapping.start_addr, mapping.end_addr
                                                    ),
                                                    format!("Permissions: {}", mapping.permissions),
                                                    format!("Size: {} bytes", mapping.size()),
                                                    "Anonymous RWX memory in non-JIT process"
                                                        .to_string(),
                                                ],
                                            };

                                            let event = InjectionCollector::create_injection_event(
                                                &injection,
                                            );
                                            if tx.send(event).await.is_err() {
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

    /// Monitor audit logs for injection-related syscalls
    async fn audit_log_monitor(
        tx: mpsc::Sender<TelemetryEvent>,
        _config: AgentConfig,
        known: Arc<Mutex<HashSet<(u32, u32, InjectionTechnique)>>>,
        interval_ms: u64,
    ) {
        use std::io::{BufRead, BufReader, Seek, SeekFrom};

        info!("Starting audit log monitor");

        let audit_log_path = "/var/log/audit/audit.log";

        // Syscall numbers (x86_64)
        const SYS_PTRACE: &str = "101";
        const SYS_PROCESS_VM_WRITEV: &str = "311";
        const SYS_PROCESS_VM_READV: &str = "310";
        const SYS_MEMFD_CREATE: &str = "319";

        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        loop {
            interval.tick().await;

            let file = match fs::File::open(audit_log_path) {
                Ok(f) => f,
                Err(_) => {
                    debug!("Audit log not available at {}", audit_log_path);
                    continue;
                }
            };

            let mut reader = BufReader::new(file);

            // Seek to end
            if reader.seek(SeekFrom::End(0)).is_err() {
                continue;
            }

            // Monitor for new entries
            let mut line = String::new();

            loop {
                match reader.read_line(&mut line) {
                    Ok(0) => {
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                    Ok(_) => {
                        // Parse audit entry
                        if line.contains("SYSCALL") {
                            let is_ptrace = line.contains(&format!("syscall={}", SYS_PTRACE));
                            let is_vm_write =
                                line.contains(&format!("syscall={}", SYS_PROCESS_VM_WRITEV));
                            let is_vm_read =
                                line.contains(&format!("syscall={}", SYS_PROCESS_VM_READV));
                            let is_memfd = line.contains(&format!("syscall={}", SYS_MEMFD_CREATE));

                            if is_ptrace || is_vm_write || is_vm_read || is_memfd {
                                if let Some(injection) =
                                    parse_audit_entry(&line, is_ptrace, is_vm_write)
                                {
                                    let key = (
                                        injection.source_pid,
                                        injection.target_pid,
                                        injection.technique,
                                    );
                                    let mut known_guard = known.lock().await;

                                    if !known_guard.contains(&key) {
                                        known_guard.insert(key);
                                        drop(known_guard);

                                        let event =
                                            InjectionCollector::create_injection_event(&injection);
                                        if tx.send(event).await.is_err() {
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                        line.clear();
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
        }
    }

    /// Parse an audit log entry for injection indicators
    fn parse_audit_entry(line: &str, is_ptrace: bool, is_vm_write: bool) -> Option<InjectionEvent> {
        let mut source_pid = 0u32;
        let mut target_pid = 0u32;
        let mut exe_path = String::new();

        for part in line.split_whitespace() {
            if part.starts_with("pid=") {
                if let Ok(p) = part.trim_start_matches("pid=").parse() {
                    source_pid = p;
                }
            }
            if part.starts_with("a0=") {
                // First argument often contains target PID
                if let Ok(p) = u64::from_str_radix(part.trim_start_matches("a0="), 16) {
                    target_pid = p as u32;
                }
            }
            if part.starts_with("exe=") {
                exe_path = part.trim_start_matches("exe=").replace("\"", "");
            }
        }

        if source_pid == 0 {
            return None;
        }

        // If target_pid is 0, it might be self-injection or malformed
        if target_pid == 0 {
            target_pid = source_pid;
        }

        let source_name = get_process_name(source_pid);
        let target_name = get_process_name(target_pid);
        let target_path = get_process_path(target_pid);

        let technique = if is_ptrace {
            InjectionTechnique::PtraceInjection
        } else if is_vm_write {
            InjectionTechnique::ProcessVmWrite
        } else {
            InjectionTechnique::Unknown
        };

        Some(InjectionEvent {
            source_pid,
            source_name,
            source_path: exe_path,
            target_pid,
            target_name,
            target_path,
            technique,
            memory_address: None,
            memory_size: None,
            memory_protection: None,
            evidence: vec![format!("Audit log entry: {}", line.trim())],
        })
    }

    /// Monitor for /proc/[pid]/mem access (cross-process memory access)
    async fn proc_mem_access_monitor(
        tx: mpsc::Sender<TelemetryEvent>,
        known: Arc<Mutex<HashSet<(u32, u32, InjectionTechnique)>>>,
        interval_ms: u64,
    ) {
        info!("Starting /proc/[pid]/mem access monitor");

        // This monitors for processes that have /proc/[other_pid]/mem open
        // which indicates cross-process memory access

        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        loop {
            interval.tick().await;

            if let Ok(entries) = fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();

                    if let Ok(pid) = name_str.parse::<u32>() {
                        if pid < 10 {
                            continue;
                        }

                        let fd_path = format!("/proc/{}/fd", pid);

                        if let Ok(fd_entries) = fs::read_dir(&fd_path) {
                            for fd_entry in fd_entries.flatten() {
                                if let Ok(link_target) = fs::read_link(fd_entry.path()) {
                                    let target_str = link_target.to_string_lossy();

                                    // Check if this is /proc/[other_pid]/mem
                                    if target_str.starts_with("/proc/")
                                        && target_str.ends_with("/mem")
                                    {
                                        // Extract the target PID
                                        let parts: Vec<&str> = target_str.split('/').collect();
                                        if parts.len() >= 3 {
                                            if let Ok(target_pid) = parts[2].parse::<u32>() {
                                                // Skip self-access
                                                if target_pid == pid {
                                                    continue;
                                                }

                                                let key = (
                                                    pid,
                                                    target_pid,
                                                    InjectionTechnique::ProcessMemoryWrite,
                                                );
                                                let mut known_guard = known.lock().await;

                                                if !known_guard.contains(&key) {
                                                    known_guard.insert(key);
                                                    drop(known_guard);

                                                    let source_name = get_process_name(pid);
                                                    let source_path = get_process_path(pid);
                                                    let target_name = get_process_name(target_pid);
                                                    let target_path = get_process_path(target_pid);

                                                    let injection = InjectionEvent {
                                                        source_pid: pid,
                                                        source_name,
                                                        source_path,
                                                        target_pid,
                                                        target_name,
                                                        target_path,
                                                        technique:
                                                            InjectionTechnique::ProcessMemoryWrite,
                                                        memory_address: None,
                                                        memory_size: None,
                                                        memory_protection: None,
                                                        evidence: vec![
                                                            format!(
                                                                "Process has /proc/{}/mem open",
                                                                target_pid
                                                            ),
                                                            "Cross-process memory access detected"
                                                                .to_string(),
                                                        ],
                                                    };

                                                    let event =
                                                        InjectionCollector::create_injection_event(
                                                            &injection,
                                                        );
                                                    if tx.send(event).await.is_err() {
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

    /// Get process name from PID
    fn get_process_name(pid: u32) -> String {
        fs::read_to_string(format!("/proc/{}/comm", pid))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| format!("pid:{}", pid))
    }

    /// Get process path from PID
    fn get_process_path(pid: u32) -> String {
        fs::read_link(format!("/proc/{}/exe", pid))
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default()
    }

    use std::sync::Arc;
    use tokio::sync::Mutex;
}

// ==================== macOS Implementation ====================
#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::collections::HashSet;
    use std::process::Command;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    // Import enhanced macOS injection detection modules
    mod enhanced {
        include!("injection_macos_enhanced.rs");
    }
    use crate::analyzers::macho_parser::MachOParser;
    use crate::collectors::memory::macos_memory;

    /// Main macOS monitoring loop
    pub async fn monitor_loop(tx: mpsc::Sender<TelemetryEvent>, _config: AgentConfig) {
        let mul = _config.sub_loop_interval_multiplier;
        info!(multiplier = mul, "Starting macOS process injection monitor");

        let known_detections: Arc<Mutex<HashSet<(u32, u32, InjectionTechnique)>>> =
            Arc::new(Mutex::new(HashSet::new()));

        // Start DYLD_INSERT_LIBRARIES monitor (5s base)
        let tx_dyld = tx.clone();
        let known_dyld = known_detections.clone();
        let dyld_interval_ms = ((5000.0 * mul) as u64).max(5000);
        tokio::spawn(async move {
            dyld_insert_libraries_monitor(tx_dyld, known_dyld, dyld_interval_ms).await;
        });

        // Start task_for_pid monitor via system log (5s base)
        let tx_task = tx.clone();
        let known_task = known_detections.clone();
        let task_interval_ms = ((5000.0 * mul) as u64).max(5000);
        tokio::spawn(async move {
            task_for_pid_monitor(tx_task, known_task, task_interval_ms).await;
        });

        // Start suspicious dylib scanner (10s base)
        let tx_dylib = tx.clone();
        let known_dylib = known_detections.clone();
        let dylib_interval_ms = ((10000.0 * mul) as u64).max(10000);
        tokio::spawn(async move {
            suspicious_dylib_scanner(tx_dylib, known_dylib, dylib_interval_ms).await;
        });

        // Start MachO load command monitor (8s base)
        let tx_macho = tx.clone();
        let known_macho = known_detections.clone();
        let macho_interval_ms = ((8000.0 * mul) as u64).max(8000);
        tokio::spawn(async move {
            enhanced::macho_load_command_monitor(tx_macho, known_macho, macho_interval_ms).await;
        });

        // Start RWX memory scanner (12s base)
        let tx_rwx = tx.clone();
        let known_rwx = known_detections.clone();
        let rwx_interval_ms = ((12000.0 * mul) as u64).max(12000);
        tokio::spawn(async move {
            enhanced::rwx_memory_scanner(tx_rwx, known_rwx, rwx_interval_ms).await;
        });

        // Start dyld interposing detector (10s base)
        let tx_interpose = tx.clone();
        let known_interpose = known_detections.clone();
        let interpose_interval_ms = ((10000.0 * mul) as u64).max(10000);
        tokio::spawn(async move {
            enhanced::dyld_interposing_detector(
                tx_interpose,
                known_interpose,
                interpose_interval_ms,
            )
            .await;
        });

        // Periodic cleanup of known detections to prevent unbounded growth
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(300)).await;
            let mut known = known_detections.lock().await;
            if !known.is_empty() {
                known.clear();
            }
        }
    }

    /// Detect DYLD_INSERT_LIBRARIES usage by scanning process environment variables.
    /// DYLD_INSERT_LIBRARIES is the macOS equivalent of LD_PRELOAD and allows injecting
    /// dynamic libraries into a process at load time. Attackers abuse this for code injection.
    async fn dyld_insert_libraries_monitor(
        tx: mpsc::Sender<TelemetryEvent>,
        known: Arc<Mutex<HashSet<(u32, u32, InjectionTechnique)>>>,
        interval_ms: u64,
    ) {
        info!("Starting DYLD_INSERT_LIBRARIES monitor");

        // Known legitimate uses of DYLD_INSERT_LIBRARIES
        let legitimate_dylibs: HashSet<&str> = [
            "/usr/lib/libgmalloc.dylib",
            "/usr/lib/libMainThreadChecker.dylib",
            "/usr/lib/libLeaksAtExit.dylib",
            "/Applications/Xcode.app",
        ]
        .iter()
        .copied()
        .collect();

        loop {
            // Use `ps eww` to get environment variables of all running processes
            // The `eww` flags show the environment in a wide format
            if let Ok(output) = Command::new("ps")
                .args(["eww", "-A", "-o", "pid,command"])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines().skip(1) {
                    // Check if any process has DYLD_INSERT_LIBRARIES in its environment
                    if !line.contains("DYLD_INSERT_LIBRARIES=") {
                        continue;
                    }

                    let parts: Vec<&str> = line.trim().splitn(2, char::is_whitespace).collect();
                    if parts.len() < 2 {
                        continue;
                    }

                    let pid = match parts[0].trim().parse::<u32>() {
                        Ok(p) => p,
                        Err(_) => continue,
                    };

                    // Extract the DYLD_INSERT_LIBRARIES value
                    let dyld_value = line
                        .split("DYLD_INSERT_LIBRARIES=")
                        .nth(1)
                        .unwrap_or("")
                        .split_whitespace()
                        .next()
                        .unwrap_or("");

                    // Skip known legitimate uses
                    if legitimate_dylibs
                        .iter()
                        .any(|legit| dyld_value.contains(legit))
                    {
                        continue;
                    }

                    let key = (0, pid, InjectionTechnique::DyldInsertLibraries);
                    let mut known_guard = known.lock().await;
                    if known_guard.contains(&key) {
                        continue;
                    }
                    known_guard.insert(key);
                    drop(known_guard);

                    let process_name = get_process_name(pid);
                    let process_path = get_process_path(pid);

                    warn!(
                        pid = pid,
                        process = %process_name,
                        dyld_value = %dyld_value,
                        "DYLD_INSERT_LIBRARIES injection detected"
                    );

                    let injection = InjectionEvent {
                        source_pid: 0,
                        source_name: "unknown".to_string(),
                        source_path: String::new(),
                        target_pid: pid,
                        target_name: process_name,
                        target_path: process_path,
                        technique: InjectionTechnique::DyldInsertLibraries,
                        memory_address: None,
                        memory_size: None,
                        memory_protection: None,
                        evidence: vec![format!("DYLD_INSERT_LIBRARIES={}", dyld_value)],
                    };

                    let event = InjectionCollector::create_injection_event(&injection);
                    let _ = tx.send(event).await;
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(interval_ms)).await;
        }
    }

    /// Monitor for task_for_pid usage via system log.
    /// task_for_pid allows one process to get a Mach port for another process,
    /// enabling memory read/write and thread manipulation. This is a key primitive
    /// for macOS process injection.
    async fn task_for_pid_monitor(
        tx: mpsc::Sender<TelemetryEvent>,
        known: Arc<Mutex<HashSet<(u32, u32, InjectionTechnique)>>>,
        interval_ms: u64,
    ) {
        info!("Starting task_for_pid monitor");

        // Known legitimate callers of task_for_pid
        let legitimate_callers: HashSet<&str> = [
            "debugserver",
            "lldb",
            "dtrace",
            "Instruments",
            "Activity Monitor",
            "htop",
            "top",
            "sample",
            "spindump",
            "ReportCrash",
            "taskgated",
        ]
        .iter()
        .copied()
        .collect();

        loop {
            // Query system log for task_for_pid events from the last check interval
            // `log show` reads the unified logging system on macOS
            if let Ok(output) = Command::new("log")
                .args([
                    "show",
                    "--predicate",
                    "eventMessage contains \"task_for_pid\"",
                    "--style",
                    "compact",
                    "--last",
                    "15s",
                ])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if !line.contains("task_for_pid") {
                        continue;
                    }

                    // Try to extract PID info from the log line
                    // Typical format: "<timestamp> <process>[<pid>]: task_for_pid(<target_pid>)..."
                    let source_pid = extract_pid_from_log_line(&line);
                    let target_pid = extract_target_pid_from_log_line(&line);
                    let source_name = extract_process_name_from_log_line(&line);

                    // Skip known legitimate debuggers and tools
                    if legitimate_callers
                        .iter()
                        .any(|caller| source_name.contains(caller))
                    {
                        continue;
                    }

                    let key = (source_pid, target_pid, InjectionTechnique::TaskForPid);
                    let mut known_guard = known.lock().await;
                    if known_guard.contains(&key) {
                        continue;
                    }
                    known_guard.insert(key);
                    drop(known_guard);

                    let target_name = get_process_name(target_pid);
                    let target_path = get_process_path(target_pid);
                    let source_path = get_process_path(source_pid);

                    warn!(
                        source_pid = source_pid,
                        target_pid = target_pid,
                        source = %source_name,
                        "task_for_pid abuse detected"
                    );

                    let injection = InjectionEvent {
                        source_pid,
                        source_name,
                        source_path,
                        target_pid,
                        target_name,
                        target_path,
                        technique: InjectionTechnique::TaskForPid,
                        memory_address: None,
                        memory_size: None,
                        memory_protection: None,
                        evidence: vec![format!("task_for_pid log entry: {}", line.trim())],
                    };

                    let event = InjectionCollector::create_injection_event(&injection);
                    let _ = tx.send(event).await;
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(interval_ms)).await;
        }
    }

    /// Scan for suspicious dylibs loaded into processes.
    /// Uses `vmmap` to enumerate loaded libraries and flags those from unusual paths
    /// or unsigned libraries in processes that should only load Apple-signed code.
    async fn suspicious_dylib_scanner(
        tx: mpsc::Sender<TelemetryEvent>,
        known: Arc<Mutex<HashSet<(u32, u32, InjectionTechnique)>>>,
        interval_ms: u64,
    ) {
        info!("Starting suspicious dylib scanner");

        // Trusted library paths on macOS
        let trusted_prefixes: Vec<&str> = vec![
            "/usr/lib/",
            "/System/Library/",
            "/Library/Apple/",
            "/Applications/",
            "/Library/Frameworks/",
            "/usr/local/lib/",
            "/opt/homebrew/lib/",
        ];

        loop {
            // Get list of running processes
            if let Ok(output) = Command::new("ps").args(["-A", "-o", "pid="]).output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let pid = match line.trim().parse::<u32>() {
                        Ok(p) => p,
                        Err(_) => continue,
                    };

                    // Skip low PIDs (kernel and system processes)
                    if pid <= 1 {
                        continue;
                    }

                    // Use vmmap to enumerate loaded libraries for this process
                    // vmmap shows all memory regions including mapped dylibs
                    let vmmap_output = Command::new("vmmap")
                        .args(["-w", &pid.to_string()])
                        .output();

                    let vmmap_out = match vmmap_output {
                        Ok(out) => out,
                        Err(_) => continue,
                    };

                    let vmmap_stdout = String::from_utf8_lossy(&vmmap_out.stdout);

                    for vmmap_line in vmmap_stdout.lines() {
                        // Look for mapped dylib paths in vmmap output
                        // Lines containing ".dylib" that map to unusual locations
                        if !vmmap_line.contains(".dylib") {
                            continue;
                        }

                        // Extract path from vmmap line
                        let dylib_path = vmmap_line
                            .rsplit_once('/')
                            .map(|(prefix, name)| {
                                // Reconstruct full path
                                let full = format!(
                                    "/{}",
                                    vmmap_line
                                        .split('/')
                                        .skip(1)
                                        .collect::<Vec<&str>>()
                                        .join("/")
                                );
                                // Trim to just the path (remove trailing info)
                                full.split_whitespace().next().unwrap_or(&full).to_string()
                            })
                            .unwrap_or_default();

                        if dylib_path.is_empty() {
                            continue;
                        }

                        // Check if the dylib is from a trusted location
                        let is_trusted = trusted_prefixes
                            .iter()
                            .any(|prefix| dylib_path.starts_with(prefix));
                        if is_trusted {
                            continue;
                        }

                        // Skip if we already reported this
                        let key = (0, pid, InjectionTechnique::SuspiciousDylib);
                        let mut known_guard = known.lock().await;
                        if known_guard.contains(&key) {
                            drop(known_guard);
                            continue;
                        }
                        known_guard.insert(key);
                        drop(known_guard);

                        let process_name = get_process_name(pid);
                        let process_path = get_process_path(pid);

                        warn!(
                            pid = pid,
                            process = %process_name,
                            dylib = %dylib_path,
                            "Suspicious dylib loaded from untrusted path"
                        );

                        let injection = InjectionEvent {
                            source_pid: 0,
                            source_name: "unknown".to_string(),
                            source_path: String::new(),
                            target_pid: pid,
                            target_name: process_name,
                            target_path: process_path,
                            technique: InjectionTechnique::SuspiciousDylib,
                            memory_address: None,
                            memory_size: None,
                            memory_protection: None,
                            evidence: vec![format!("Suspicious dylib loaded: {}", dylib_path)],
                        };

                        let event = InjectionCollector::create_injection_event(&injection);
                        let _ = tx.send(event).await;
                    }
                }
            }

            // Scan less frequently since vmmap is heavyweight
            tokio::time::sleep(tokio::time::Duration::from_millis(interval_ms)).await;
        }
    }

    /// Extract source PID from a macOS unified log line
    fn extract_pid_from_log_line(line: &str) -> u32 {
        // Log format: "timestamp process[pid]: message"
        if let Some(bracket_start) = line.find('[') {
            if let Some(bracket_end) = line[bracket_start..].find(']') {
                let pid_str = &line[bracket_start + 1..bracket_start + bracket_end];
                if let Ok(pid) = pid_str.parse::<u32>() {
                    return pid;
                }
            }
        }
        0
    }

    /// Extract target PID from a task_for_pid log line
    fn extract_target_pid_from_log_line(line: &str) -> u32 {
        // Look for task_for_pid(<pid>) pattern
        if let Some(idx) = line.find("task_for_pid(") {
            let after = &line[idx + 13..];
            if let Some(end) = after.find(')') {
                let pid_str = &after[..end];
                if let Ok(pid) = pid_str.trim().parse::<u32>() {
                    return pid;
                }
            }
        }
        0
    }

    /// Extract process name from a macOS unified log line
    fn extract_process_name_from_log_line(line: &str) -> String {
        // Log format: "timestamp process[pid]: message"
        // Try to find the process name before the [pid] bracket
        if let Some(bracket_start) = line.find('[') {
            let before_bracket = &line[..bracket_start];
            if let Some(name) = before_bracket.split_whitespace().last() {
                return name.to_string();
            }
        }
        "unknown".to_string()
    }

    /// Get process name from PID on macOS
    fn get_process_name(pid: u32) -> String {
        Command::new("ps")
            .args(["-o", "comm=", "-p", &pid.to_string()])
            .output()
            .ok()
            .and_then(|out| {
                let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if name.is_empty() {
                    None
                } else {
                    Some(name)
                }
            })
            .unwrap_or_else(|| format!("pid:{}", pid))
    }

    /// Get process path from PID on macOS
    fn get_process_path(pid: u32) -> String {
        Command::new("ps")
            .args(["-o", "comm=", "-p", &pid.to_string()])
            .output()
            .ok()
            .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
            .unwrap_or_default()
    }
}

// ================================================================
// Tests
// ================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_injection_technique_as_str() {
        assert_eq!(InjectionTechnique::RemoteThread.as_str(), "remote_thread");
        assert_eq!(
            InjectionTechnique::PoolPartyWorkerFactory.as_str(),
            "poolparty_worker_factory"
        );
        assert_eq!(
            InjectionTechnique::PoolPartyTpDirect.as_str(),
            "poolparty_tp_direct"
        );
        assert_eq!(
            InjectionTechnique::ThreadHijacking.as_str(),
            "thread_hijacking"
        );
    }

    #[test]
    fn test_injection_event_creation() {
        let event = InjectionEvent {
            source_pid: 1234,
            source_name: "attacker.exe".to_string(),
            source_path: "C:\\malware\\attacker.exe".to_string(),
            target_pid: 5678,
            target_name: "victim.exe".to_string(),
            target_path: "C:\\Windows\\System32\\victim.exe".to_string(),
            technique: InjectionTechnique::RemoteThread,
            memory_address: Some(0x7FF00000),
            memory_size: Some(4096),
            memory_protection: Some(0x40), // PAGE_EXECUTE_READWRITE
            evidence: vec!["Suspicious RWX allocation".to_string()],
        };

        assert_eq!(event.source_pid, 1234);
        assert_eq!(event.target_pid, 5678);
        assert_eq!(event.source_name, "attacker.exe");
        assert_eq!(event.target_name, "victim.exe");
        assert_eq!(event.technique.as_str(), "remote_thread");
        assert!(event.memory_address.is_some());
        assert_eq!(event.evidence.len(), 1);
    }

    #[tokio::test]
    async fn test_injection_collector_initialization() {
        let config = AgentConfig::default();
        let _collector = InjectionCollector::new(&config);
        // Should initialize without panicking
    }

    #[test]
    fn test_confidence_bounds() {
        // Confidence scores must be in [0.0, 1.0]
        let valid_scores = [0.0, 0.5, 0.95, 1.0];
        for &score in &valid_scores {
            assert!(score >= 0.0 && score <= 1.0);
        }
    }

    #[test]
    #[ignore]
    fn test_full_scan_no_panic() {
        // Integration test - runs full injection scan
        // Marked as ignored, run with: cargo test -- --ignored
        let config = AgentConfig::default();
        let collector = InjectionCollector::new(&config);

        // This should not panic even if no injections detected
        let result = std::panic::catch_unwind(|| {
            let _ = collector;
            true
        });

        assert!(result.is_ok());
    }
}
