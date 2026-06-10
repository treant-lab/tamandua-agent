//! Stack Pivot Detection Module
//!
//! Detects ROP (Return-Oriented Programming) and JOP (Jump-Oriented Programming) attacks
//! by monitoring for stack pointer manipulation that moves RSP/ESP out of the legitimate
//! thread stack region.
//!
//! ## Detection Methods
//!
//! 1. **TEB Stack Bounds Validation**
//!    - Compare RSP against TEB.StackBase/StackLimit for each thread
//!    - Detect when RSP points outside the allocated stack region
//!
//! 2. **Memory Region Classification**
//!    - Check if RSP points to heap, mapped files, or other non-stack memory
//!    - Identify stack pivots to shellcode in heap allocations
//!
//! 3. **RSP Change Heuristics**
//!    - Detect sudden large RSP changes that indicate stack pivot gadgets
//!    - Monitor RSP deltas during context switches
//!
//! 4. **ETW Integration**
//!    - Hook thread creation to track legitimate stack bounds
//!    - Monitor context switches for RSP validation
//!    - Use ETW stack walking for validation
//!
//! ## MITRE ATT&CK Mapping
//!
//! - T1055.012: Process Hollowing (stack pivot often used post-injection)
//! - T1574: Hijack Execution Flow (ROP/JOP for control flow hijacking)
//! - T1055: Process Injection (stack pivot enables shellcode execution)
//!
//! ## Implementation Notes
//!
//! Stack pivots are commonly used in:
//! - ROP chain execution (pivot RSP to controlled buffer with gadget addresses)
//! - JOP attacks (similar technique with indirect jumps)
//! - Shellcode execution after exploitation
//! - Bypassing CFI/CET protections in some scenarios
//!
//! The detector maintains per-thread state to:
//! - Baseline legitimate stack bounds when threads are created
//! - Track RSP changes over time
//! - Correlate with other injection indicators (memory permissions, etc.)

use crate::collectors::{
    Detection, DetectionType, EventPayload, EventType, ProcessEvent, Severity, TelemetryEvent,
};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{info, trace, warn};

// ============================================================================
// Types and Structures
// ============================================================================

/// Stack bounds for a thread, obtained from TEB
#[derive(Debug, Clone, Copy)]
pub struct StackBounds {
    /// Stack base address (high address, bottom of stack in memory layout)
    pub base: usize,
    /// Stack limit address (low address, top of allocated stack)
    pub limit: usize,
    /// Total stack size in bytes
    pub size: usize,
}

impl StackBounds {
    /// Check if an address is within the valid stack region
    pub fn contains(&self, address: usize) -> bool {
        address >= self.limit && address <= self.base
    }

    /// Calculate how far an address is from the valid stack region
    pub fn distance_from_stack(&self, address: usize) -> isize {
        if address > self.base {
            (address - self.base) as isize
        } else if address < self.limit {
            -((self.limit - address) as isize)
        } else {
            0
        }
    }
}

/// Result of stack pivot check
#[derive(Debug, Clone)]
pub struct StackPivotResult {
    /// Whether a stack pivot was detected
    pub is_pivot: bool,
    /// Thread ID
    pub tid: u32,
    /// Process ID
    pub pid: u32,
    /// Current RSP value
    pub current_rsp: usize,
    /// Expected stack bounds
    pub expected_bounds: Option<StackBounds>,
    /// Memory region type where RSP points
    pub memory_region_type: MemoryRegionType,
    /// Deviation from stack (positive = above base, negative = below limit)
    pub deviation: isize,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// Likely attack technique
    pub likely_technique: LikelyTechnique,
    /// Additional evidence collected
    pub evidence: Vec<String>,
}

/// Memory region type classification for RSP location
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryRegionType {
    /// Thread stack (legitimate)
    Stack,
    /// Heap allocation (suspicious for RSP)
    Heap,
    /// Memory-mapped file
    MappedFile,
    /// Private allocation (VirtualAlloc)
    PrivateAllocation,
    /// Image section (DLL/EXE)
    Image,
    /// Unknown or unreadable
    Unknown,
}

impl MemoryRegionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Stack => "stack",
            Self::Heap => "heap",
            Self::MappedFile => "mapped_file",
            Self::PrivateAllocation => "private_allocation",
            Self::Image => "image",
            Self::Unknown => "unknown",
        }
    }

    /// Check if this region type is suspicious for RSP
    pub fn is_suspicious_for_rsp(&self) -> bool {
        matches!(
            self,
            Self::Heap | Self::MappedFile | Self::PrivateAllocation | Self::Image
        )
    }
}

/// Likely attack technique based on pivot characteristics
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LikelyTechnique {
    /// Return-Oriented Programming (ROP chain)
    Rop,
    /// Jump-Oriented Programming
    Jop,
    /// Call-Oriented Programming
    Cop,
    /// Stack spray (large pivot)
    StackSpray,
    /// Heap spray with stack pivot
    HeapSpray,
    /// Shellcode execution setup
    ShellcodeSetup,
    /// Unknown technique
    Unknown,
}

impl LikelyTechnique {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Rop => "ROP",
            Self::Jop => "JOP",
            Self::Cop => "COP",
            Self::StackSpray => "Stack spray",
            Self::HeapSpray => "Heap spray",
            Self::ShellcodeSetup => "Shellcode setup",
            Self::Unknown => "Unknown",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Rop => "Return-Oriented Programming - RSP pivoted to ROP gadget chain",
            Self::Jop => "Jump-Oriented Programming - Stack pivot for indirect jump attacks",
            Self::Cop => "Call-Oriented Programming - Stack manipulated for call gadget chain",
            Self::StackSpray => "Stack spray attack - RSP moved to sprayed region",
            Self::HeapSpray => "Heap spray with stack pivot - RSP points to heap spray",
            Self::ShellcodeSetup => "Shellcode execution setup - RSP pivoted before shellcode",
            Self::Unknown => "Unknown stack manipulation technique",
        }
    }

    pub fn mitre_techniques(&self) -> Vec<&'static str> {
        match self {
            Self::Rop | Self::Jop | Self::Cop => vec!["T1574", "T1055"],
            Self::StackSpray | Self::HeapSpray => vec!["T1055", "T1055.012"],
            Self::ShellcodeSetup => vec!["T1055", "T1055.012", "T1574"],
            Self::Unknown => vec!["T1055"],
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Self::Rop | Self::Jop | Self::Cop => Severity::Critical,
            Self::StackSpray | Self::HeapSpray => Severity::Critical,
            Self::ShellcodeSetup => Severity::Critical,
            Self::Unknown => Severity::High,
        }
    }
}

/// Stack pivot alert with full context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackPivotAlert {
    /// Process ID
    pub pid: u32,
    /// Thread ID
    pub tid: u32,
    /// Process name
    pub process_name: String,
    /// Process path
    pub process_path: String,
    /// Expected stack base (high address)
    pub expected_stack_base: usize,
    /// Expected stack limit (low address)
    pub expected_stack_limit: usize,
    /// Actual RSP value
    pub actual_rsp: usize,
    /// Deviation from valid stack region
    pub deviation: isize,
    /// Memory region type where RSP points
    pub memory_region_type: String,
    /// Likely attack technique
    pub likely_technique: String,
    /// Technique description
    pub technique_description: String,
    /// MITRE ATT&CK techniques
    pub mitre_techniques: Vec<String>,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// Evidence collected
    pub evidence: Vec<String>,
    /// Timestamp
    pub timestamp: u64,
}

/// Configuration for stack pivot detection
#[derive(Debug, Clone)]
pub struct StackPivotConfig {
    /// Enable detection
    pub enabled: bool,
    /// Monitoring interval in milliseconds
    pub interval_ms: u64,
    /// Maximum threads to track (memory limit)
    pub max_tracked_threads: usize,
    /// Minimum confidence for alerting
    pub min_confidence: f32,
    /// RSP change threshold for suspicious activity (bytes)
    pub rsp_change_threshold: usize,
    /// Maximum deviation from stack before alerting
    pub max_stack_deviation: usize,
    /// Processes to exclude from monitoring (lowercased)
    pub excluded_processes: HashSet<String>,
    /// Enable deep memory analysis for pivot target
    pub deep_memory_analysis: bool,
    /// Track RSP history per thread
    pub track_rsp_history: bool,
    /// RSP history size per thread
    pub rsp_history_size: usize,
}

impl Default for StackPivotConfig {
    fn default() -> Self {
        let mut excluded = HashSet::new();
        // System processes that may legitimately manipulate stacks
        excluded.insert("csrss.exe".to_lowercase());
        excluded.insert("services.exe".to_lowercase());
        excluded.insert("lsass.exe".to_lowercase());
        excluded.insert("smss.exe".to_lowercase());
        excluded.insert("wininit.exe".to_lowercase());
        excluded.insert("system".to_lowercase());

        Self {
            enabled: true,
            interval_ms: 500,
            max_tracked_threads: 100_000,
            min_confidence: 0.7,
            rsp_change_threshold: 1024 * 1024, // 1MB sudden change is suspicious
            max_stack_deviation: 64 * 1024,    // 64KB from stack bounds
            excluded_processes: excluded,
            deep_memory_analysis: true,
            track_rsp_history: true,
            rsp_history_size: 10,
        }
    }
}

/// Thread stack tracking information
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ThreadStackInfo {
    /// Thread ID
    tid: u32,
    /// Process ID
    pid: u32,
    /// Stack bounds from TEB
    bounds: StackBounds,
    /// Last known RSP
    last_rsp: usize,
    /// RSP history for trend analysis
    rsp_history: VecDeque<usize>,
    /// When this thread was first seen
    first_seen: Instant,
    /// Last check timestamp
    last_checked: Instant,
    /// Number of times this thread showed suspicious RSP
    suspicious_count: u32,
    /// Whether we've already alerted on this thread
    alerted: bool,
}

// ============================================================================
// Main Detector Implementation
// ============================================================================

/// Stack pivot detector for ROP/JOP attack detection
pub struct StackPivotDetector {
    config: StackPivotConfig,
    /// Track stack bounds per thread: (pid, tid) -> ThreadStackInfo
    thread_stacks: Arc<RwLock<HashMap<(u32, u32), ThreadStackInfo>>>,
    /// Known detections to avoid duplicate alerts
    known_detections: Arc<Mutex<HashSet<(u32, u32)>>>,
    /// Event sender
    event_tx: mpsc::Sender<TelemetryEvent>,
}

impl StackPivotDetector {
    /// Create a new stack pivot detector
    pub fn new(config: StackPivotConfig, event_tx: mpsc::Sender<TelemetryEvent>) -> Self {
        info!("Creating StackPivotDetector with config: {:?}", config);
        Self {
            config,
            thread_stacks: Arc::new(RwLock::new(HashMap::new())),
            known_detections: Arc::new(Mutex::new(HashSet::new())),
            event_tx,
        }
    }

    /// Check stack pointer validity for a thread
    pub async fn check_stack_pointer(&self, pid: u32, tid: u32, rsp: usize) -> StackPivotResult {
        let thread_stacks = self.thread_stacks.read().await;

        // Get or infer stack bounds
        let bounds = if let Some(info) = thread_stacks.get(&(pid, tid)) {
            Some(info.bounds)
        } else {
            // Try to get stack bounds dynamically
            drop(thread_stacks);
            match Self::get_thread_stack_bounds_internal(pid, tid).await {
                Ok(b) => Some(b),
                Err(_) => None,
            }
        };

        // Determine if RSP is in valid region
        let (is_pivot, deviation, confidence) = if let Some(ref b) = bounds {
            if b.contains(rsp) {
                (false, 0isize, 0.0f32)
            } else {
                let dev = b.distance_from_stack(rsp);
                let conf = self.calculate_pivot_confidence(dev.unsigned_abs(), b.size);
                (true, dev, conf)
            }
        } else {
            // Without bounds, use heuristics
            let mem_type = self.classify_memory_region(pid, rsp).await;
            let suspicious = mem_type.is_suspicious_for_rsp();
            (suspicious, 0, if suspicious { 0.6 } else { 0.0 })
        };

        // Classify memory region where RSP points
        let memory_region_type = self.classify_memory_region(pid, rsp).await;

        // Determine likely technique
        let likely_technique = self.infer_technique(&memory_region_type, deviation);

        // Collect evidence
        let mut evidence = Vec::new();
        if is_pivot {
            evidence.push(format!("RSP 0x{:X} outside stack bounds", rsp));
            if let Some(ref b) = bounds {
                evidence.push(format!("Expected stack: 0x{:X} - 0x{:X}", b.limit, b.base));
            }
            evidence.push(format!("Memory region: {}", memory_region_type.as_str()));
            evidence.push(format!("Deviation: {} bytes", deviation));
        }

        StackPivotResult {
            is_pivot,
            tid,
            pid,
            current_rsp: rsp,
            expected_bounds: bounds,
            memory_region_type,
            deviation,
            confidence,
            likely_technique,
            evidence,
        }
    }

    /// Get thread stack bounds from TEB
    #[cfg(target_os = "windows")]
    pub async fn get_thread_stack_bounds(tid: u32) -> Result<StackBounds> {
        Self::get_thread_stack_bounds_internal(std::process::id(), tid).await
    }

    /// Internal implementation for getting stack bounds
    #[cfg(target_os = "windows")]
    async fn get_thread_stack_bounds_internal(pid: u32, tid: u32) -> Result<StackBounds> {
        use std::ffi::c_void;
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
        use windows::Win32::System::Threading::{
            OpenProcess, OpenThread, PROCESS_VM_READ, THREAD_QUERY_INFORMATION,
        };

        // THREAD_BASIC_INFORMATION structure
        #[repr(C)]
        struct ThreadBasicInformation {
            exit_status: i32,
            teb_base_address: *mut c_void,
            client_id_unique_process: usize,
            client_id_unique_thread: usize,
            affinity_mask: usize,
            priority: i32,
            base_priority: i32,
        }

        // NT_TIB structure (first part of TEB containing stack info)
        #[repr(C)]
        struct NtTib {
            exception_list: *mut c_void,
            stack_base: *mut c_void,
            stack_limit: *mut c_void,
            sub_system_tib: *mut c_void,
            fiber_data_or_version: usize,
            arbitrary_user_pointer: *mut c_void,
            self_: *mut NtTib,
        }

        type NtQueryInformationThreadFn = unsafe extern "system" fn(
            windows::Win32::Foundation::HANDLE,
            u32,
            *mut c_void,
            u32,
            *mut u32,
        ) -> i32;

        unsafe {
            // Load NtQueryInformationThread
            let ntdll: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
            let module = LoadLibraryW(PCWSTR(ntdll.as_ptr()))?;

            let proc_name =
                std::ffi::CStr::from_bytes_with_nul_unchecked(b"NtQueryInformationThread\0");
            let func_addr = GetProcAddress(
                module,
                windows::core::PCSTR(proc_name.as_ptr() as *const u8),
            )
            .ok_or_else(|| anyhow!("Failed to get NtQueryInformationThread"))?;
            let nt_query: NtQueryInformationThreadFn = std::mem::transmute(func_addr);

            // Open thread
            let thread_handle = OpenThread(THREAD_QUERY_INFORMATION, false, tid)?;

            // Query thread basic information to get TEB address
            let mut tbi = std::mem::zeroed::<ThreadBasicInformation>();
            let status = nt_query(
                thread_handle,
                0, // ThreadBasicInformation
                &mut tbi as *mut _ as *mut c_void,
                std::mem::size_of::<ThreadBasicInformation>() as u32,
                std::ptr::null_mut(),
            );

            if status != 0 {
                let _ = CloseHandle(thread_handle);
                return Err(anyhow!("NtQueryInformationThread failed: 0x{:X}", status));
            }

            let teb_address = tbi.teb_base_address;
            let _ = CloseHandle(thread_handle);

            if teb_address.is_null() {
                return Err(anyhow!("TEB address is null for thread {}", tid));
            }

            // Open process to read TEB
            let process_handle = OpenProcess(PROCESS_VM_READ, false, pid)?;

            // Read NT_TIB from TEB (NT_TIB is at the start of TEB)
            let mut nt_tib = std::mem::zeroed::<NtTib>();
            let mut bytes_read = 0usize;

            let read_result = ReadProcessMemory(
                process_handle,
                teb_address,
                &mut nt_tib as *mut _ as *mut c_void,
                std::mem::size_of::<NtTib>(),
                Some(&mut bytes_read),
            );

            let _ = CloseHandle(process_handle);

            if read_result.is_err() {
                return Err(anyhow!("Failed to read TEB for thread {}", tid));
            }

            let stack_base = nt_tib.stack_base as usize;
            let stack_limit = nt_tib.stack_limit as usize;

            if stack_base == 0 || stack_limit == 0 || stack_base <= stack_limit {
                return Err(anyhow!(
                    "Invalid stack bounds: base=0x{:X}, limit=0x{:X}",
                    stack_base,
                    stack_limit
                ));
            }

            Ok(StackBounds {
                base: stack_base,
                limit: stack_limit,
                size: stack_base - stack_limit,
            })
        }
    }

    /// Non-Windows stub
    #[cfg(not(target_os = "windows"))]
    pub async fn get_thread_stack_bounds(tid: u32) -> Result<StackBounds> {
        Err(anyhow!("Stack bounds detection is Windows-only"))
    }

    #[cfg(not(target_os = "windows"))]
    async fn get_thread_stack_bounds_internal(_pid: u32, _tid: u32) -> Result<StackBounds> {
        Err(anyhow!("Stack bounds detection is Windows-only"))
    }

    /// Check if RSP points to a valid memory region (stack vs heap/other)
    pub async fn is_stack_in_valid_region(&self, pid: u32, rsp: usize) -> bool {
        let mem_type = self.classify_memory_region(pid, rsp).await;
        mem_type == MemoryRegionType::Stack
    }

    /// Classify the memory region at a given address
    #[cfg(target_os = "windows")]
    async fn classify_memory_region(&self, pid: u32, address: usize) -> MemoryRegionType {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Memory::{
            VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            {
                Ok(h) => h,
                Err(_) => return MemoryRegionType::Unknown,
            };

            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let result = VirtualQueryEx(
                handle,
                Some(address as *const std::ffi::c_void),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            let _ = CloseHandle(handle);

            if result == 0 {
                return MemoryRegionType::Unknown;
            }

            // Classify based on memory type
            let mem_type = mbi.Type.0;

            if mem_type == MEM_IMAGE.0 {
                return MemoryRegionType::Image;
            }

            if mem_type == MEM_MAPPED.0 {
                return MemoryRegionType::MappedFile;
            }

            if mem_type == MEM_PRIVATE.0 {
                // Private memory could be stack, heap, or other allocation
                // Use heuristics to distinguish

                // Check if allocation base suggests heap (typically lower addresses)
                // Stack is typically in high address space on 64-bit Windows
                let alloc_base = mbi.AllocationBase as usize;

                // Stacks on 64-bit Windows are typically above 0x000000XX_XXXXXXXX
                // Heaps are typically in lower regions
                // This is a heuristic and not 100% reliable
                #[cfg(target_arch = "x86_64")]
                {
                    if alloc_base > 0x0000_0100_0000_0000 {
                        // High address - likely stack
                        return MemoryRegionType::Stack;
                    }
                }

                // Check region size - stacks have typical sizes (1MB default)
                if mbi.RegionSize >= 1024 * 1024 && mbi.RegionSize <= 8 * 1024 * 1024 {
                    // Could be stack, need more checks
                    // For now, classify as private allocation
                }

                // If we can't determine it's a stack, treat as heap/private
                return MemoryRegionType::Heap;
            }

            MemoryRegionType::Unknown
        }
    }

    #[cfg(not(target_os = "windows"))]
    async fn classify_memory_region(&self, _pid: u32, _address: usize) -> MemoryRegionType {
        MemoryRegionType::Unknown
    }

    /// Detect suspicious RSP changes between samples
    pub fn detect_suspicious_rsp_change(&self, old_rsp: usize, new_rsp: usize) -> bool {
        let delta = if new_rsp > old_rsp {
            new_rsp - old_rsp
        } else {
            old_rsp - new_rsp
        };

        // Stack typically grows/shrinks by function frame sizes (tens to thousands of bytes)
        // A sudden change of > threshold is suspicious
        delta > self.config.rsp_change_threshold
    }

    /// Calculate confidence based on deviation from stack
    fn calculate_pivot_confidence(&self, deviation: usize, stack_size: usize) -> f32 {
        // Higher deviation relative to stack size = higher confidence
        let ratio = deviation as f32 / stack_size as f32;

        // If deviation is more than the stack size, very high confidence
        if ratio >= 1.0 {
            0.95
        } else if ratio >= 0.5 {
            0.85 + (ratio - 0.5) * 0.2
        } else if ratio >= 0.1 {
            0.7 + (ratio - 0.1) * 0.375
        } else {
            0.5 + ratio * 2.0
        }
    }

    /// Infer the likely technique based on memory region and deviation
    fn infer_technique(&self, mem_type: &MemoryRegionType, deviation: isize) -> LikelyTechnique {
        match mem_type {
            MemoryRegionType::Heap => {
                if deviation.unsigned_abs() > 1024 * 1024 {
                    LikelyTechnique::HeapSpray
                } else {
                    LikelyTechnique::Rop
                }
            }
            MemoryRegionType::PrivateAllocation => LikelyTechnique::ShellcodeSetup,
            MemoryRegionType::MappedFile => LikelyTechnique::Rop,
            MemoryRegionType::Image => LikelyTechnique::Rop,
            MemoryRegionType::Stack => LikelyTechnique::Unknown,
            MemoryRegionType::Unknown => LikelyTechnique::Unknown,
        }
    }

    /// Start the monitoring loop
    pub async fn start_monitoring(&self) {
        if !self.config.enabled {
            info!("Stack pivot detection is disabled");
            return;
        }

        info!(
            interval_ms = self.config.interval_ms,
            "Starting stack pivot detector (T1055.012, T1574)"
        );

        #[cfg(target_os = "windows")]
        {
            self.windows_monitor_loop().await;
        }

        #[cfg(not(target_os = "windows"))]
        {
            info!("Stack pivot detection is currently Windows-only");
        }
    }

    /// Main monitoring loop for Windows
    #[cfg(target_os = "windows")]
    async fn windows_monitor_loop(&self) {
        let mut interval =
            tokio::time::interval(tokio::time::Duration::from_millis(self.config.interval_ms));

        loop {
            interval.tick().await;

            // Enumerate all threads
            let threads = self.enumerate_threads().await;

            // Check each thread
            for (pid, tid) in threads {
                // Skip excluded processes
                if self.is_process_excluded(pid).await {
                    continue;
                }

                // Get thread context and check RSP
                if let Ok(rsp) = self.get_thread_rsp(pid, tid).await {
                    let result = self.check_stack_pointer(pid, tid, rsp).await;

                    if result.is_pivot && result.confidence >= self.config.min_confidence {
                        // Check if we already alerted
                        let mut known = self.known_detections.lock().await;
                        if !known.contains(&(pid, tid)) {
                            known.insert((pid, tid));
                            drop(known);

                            // Generate and send alert
                            self.send_alert(&result).await;
                        }
                    }
                }
            }

            // Cleanup stale state periodically
            self.cleanup_stale_state().await;
        }
    }

    /// Enumerate all threads
    #[cfg(target_os = "windows")]
    async fn enumerate_threads(&self) -> Vec<(u32, u32)> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
        };

        let mut threads = Vec::new();
        let my_pid = std::process::id();

        unsafe {
            let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
                Ok(h) => h,
                Err(_) => return threads,
            };

            let mut entry = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..Default::default()
            };

            if Thread32First(snapshot, &mut entry).is_ok() {
                loop {
                    let pid = entry.th32OwnerProcessID;
                    let tid = entry.th32ThreadID;

                    // Skip system processes and ourselves
                    if pid > 10 && pid != my_pid {
                        threads.push((pid, tid));
                    }

                    if Thread32Next(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
        }

        threads
    }

    /// Get thread RSP value
    #[cfg(target_os = "windows")]
    async fn get_thread_rsp(&self, _pid: u32, tid: u32) -> Result<usize> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::Debug::{
            GetThreadContext, CONTEXT, CONTEXT_ALL_AMD64,
        };
        use windows::Win32::System::Threading::{
            OpenThread, ResumeThread, SuspendThread, THREAD_GET_CONTEXT, THREAD_SUSPEND_RESUME,
        };

        unsafe {
            let thread_handle = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, false, tid)?;

            // Suspend thread to get accurate context
            let suspend_count = SuspendThread(thread_handle);
            if suspend_count == u32::MAX {
                let _ = CloseHandle(thread_handle);
                return Err(anyhow!("Failed to suspend thread {}", tid));
            }

            let mut context = CONTEXT::default();
            context.ContextFlags = CONTEXT_ALL_AMD64;

            let result = GetThreadContext(thread_handle, &mut context);

            // Always resume
            ResumeThread(thread_handle);
            let _ = CloseHandle(thread_handle);

            if result.is_err() {
                return Err(anyhow!("Failed to get thread context for {}", tid));
            }

            #[cfg(target_arch = "x86_64")]
            {
                Ok(context.Rsp as usize)
            }

            #[cfg(target_arch = "x86")]
            {
                Ok(context.Esp as usize)
            }
        }
    }

    /// Check if a process is in the exclusion list
    async fn is_process_excluded(&self, pid: u32) -> bool {
        // Get process name
        if let Some(name) = self.get_process_name(pid).await {
            self.config
                .excluded_processes
                .contains(&name.to_lowercase())
        } else {
            false
        }
    }

    /// Get process name by PID
    #[cfg(target_os = "windows")]
    async fn get_process_name(&self, pid: u32) -> Option<String> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::ProcessStatus::GetModuleBaseNameW;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

        unsafe {
            if let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                let mut name_buf = vec![0u16; 256];
                let len = GetModuleBaseNameW(handle, None, &mut name_buf);
                let _ = CloseHandle(handle);

                if len > 0 {
                    return Some(String::from_utf16_lossy(&name_buf[..len as usize]));
                }
            }
        }
        None
    }

    #[cfg(not(target_os = "windows"))]
    async fn get_process_name(&self, _pid: u32) -> Option<String> {
        None
    }

    /// Get process path by PID
    #[cfg(target_os = "windows")]
    fn get_process_path(&self, pid: u32) -> String {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

        unsafe {
            if let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                let mut path_buf = vec![0u16; 512];
                let len = GetModuleFileNameExW(handle, None, &mut path_buf);
                let _ = CloseHandle(handle);

                if len > 0 {
                    return String::from_utf16_lossy(&path_buf[..len as usize]);
                }
            }
        }
        String::new()
    }

    #[cfg(not(target_os = "windows"))]
    fn get_process_path(&self, _pid: u32) -> String {
        String::new()
    }

    /// Send alert for detected stack pivot
    async fn send_alert(&self, result: &StackPivotResult) {
        let process_name = self
            .get_process_name(result.pid)
            .await
            .unwrap_or_else(|| format!("pid_{}", result.pid));
        let process_path = self.get_process_path(result.pid);

        let alert = StackPivotAlert {
            pid: result.pid,
            tid: result.tid,
            process_name: process_name.clone(),
            process_path: process_path.clone(),
            expected_stack_base: result.expected_bounds.map(|b| b.base).unwrap_or(0),
            expected_stack_limit: result.expected_bounds.map(|b| b.limit).unwrap_or(0),
            actual_rsp: result.current_rsp,
            deviation: result.deviation,
            memory_region_type: result.memory_region_type.as_str().to_string(),
            likely_technique: result.likely_technique.as_str().to_string(),
            technique_description: result.likely_technique.description().to_string(),
            mitre_techniques: result
                .likely_technique
                .mitre_techniques()
                .iter()
                .map(|s| s.to_string())
                .collect(),
            confidence: result.confidence,
            evidence: result.evidence.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        };

        // Log the detection
        warn!(
            pid = alert.pid,
            tid = alert.tid,
            process = %alert.process_name,
            technique = %alert.likely_technique,
            rsp = format!("0x{:X}", alert.actual_rsp),
            confidence = alert.confidence,
            "Stack pivot detected"
        );

        // Create and send telemetry event
        let event = self.create_telemetry_event(&alert);
        if self.event_tx.send(event).await.is_err() {
            warn!("Failed to send stack pivot alert event");
        }
    }

    /// Create TelemetryEvent from StackPivotAlert
    fn create_telemetry_event(&self, alert: &StackPivotAlert) -> TelemetryEvent {
        let severity = if alert.confidence >= 0.9 {
            Severity::Critical
        } else if alert.confidence >= 0.7 {
            Severity::High
        } else {
            Severity::Medium
        };

        let mut event = TelemetryEvent::new(
            EventType::MemoryScan,
            severity.clone(),
            EventPayload::Process(ProcessEvent {
                pid: alert.pid,
                ppid: 0,
                name: alert.process_name.clone(),
                path: alert.process_path.clone(),
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

        // Add detection
        event.add_detection(Detection {
            detection_type: DetectionType::MemoryThreat,
            rule_name: format!(
                "stack_pivot_{}",
                alert.likely_technique.to_lowercase().replace(' ', "_")
            ),
            confidence: alert.confidence,
            description: format!(
                "Stack pivot detected: {} - {} (PID: {}, TID: {})",
                alert.likely_technique, alert.technique_description, alert.pid, alert.tid
            ),
            mitre_tactics: vec![
                "defense-evasion".to_string(),
                "privilege-escalation".to_string(),
                "execution".to_string(),
            ],
            mitre_techniques: alert.mitre_techniques.clone(),
        });

        // Add metadata
        event
            .metadata
            .insert("thread_id".to_string(), alert.tid.to_string());
        event.metadata.insert(
            "actual_rsp".to_string(),
            format!("0x{:X}", alert.actual_rsp),
        );
        event.metadata.insert(
            "expected_stack_base".to_string(),
            format!("0x{:X}", alert.expected_stack_base),
        );
        event.metadata.insert(
            "expected_stack_limit".to_string(),
            format!("0x{:X}", alert.expected_stack_limit),
        );
        event
            .metadata
            .insert("deviation".to_string(), alert.deviation.to_string());
        event.metadata.insert(
            "memory_region_type".to_string(),
            alert.memory_region_type.clone(),
        );
        event.metadata.insert(
            "likely_technique".to_string(),
            alert.likely_technique.clone(),
        );
        event
            .metadata
            .insert("confidence".to_string(), format!("{:.2}", alert.confidence));
        event
            .metadata
            .insert("evidence".to_string(), alert.evidence.join("; "));

        event
    }

    /// Cleanup stale state
    async fn cleanup_stale_state(&self) {
        let stale_threshold = Duration::from_secs(300); // 5 minutes
        let now = Instant::now();

        // Cleanup thread tracking
        {
            let mut threads = self.thread_stacks.write().await;
            threads.retain(|_, info| now.duration_since(info.last_checked) < stale_threshold);
        }

        // Periodically clear old detections
        {
            let mut known = self.known_detections.lock().await;
            if known.len() > 50000 {
                known.clear();
            }
        }
    }

    /// Register a thread for tracking (called on thread creation events)
    pub async fn register_thread(&self, pid: u32, tid: u32) {
        if let Ok(bounds) = Self::get_thread_stack_bounds_internal(pid, tid).await {
            let mut threads = self.thread_stacks.write().await;

            // Don't exceed max tracked threads
            if threads.len() >= self.config.max_tracked_threads {
                // Remove oldest entry
                let oldest = threads
                    .iter()
                    .min_by_key(|(_, v)| v.last_checked)
                    .map(|(k, _)| *k);
                if let Some(key) = oldest {
                    threads.remove(&key);
                }
            }

            threads.insert(
                (pid, tid),
                ThreadStackInfo {
                    tid,
                    pid,
                    bounds,
                    last_rsp: 0,
                    rsp_history: VecDeque::with_capacity(self.config.rsp_history_size),
                    first_seen: Instant::now(),
                    last_checked: Instant::now(),
                    suspicious_count: 0,
                    alerted: false,
                },
            );

            trace!(
                pid,
                tid,
                base = bounds.base,
                limit = bounds.limit,
                "Registered thread stack"
            );
        }
    }

    /// Unregister a thread (called on thread termination)
    pub async fn unregister_thread(&self, pid: u32, tid: u32) {
        let mut threads = self.thread_stacks.write().await;
        threads.remove(&(pid, tid));

        let mut known = self.known_detections.lock().await;
        known.remove(&(pid, tid));
    }
}

// ============================================================================
// Collector Integration
// ============================================================================

/// Stack pivot collector that wraps the detector
pub struct StackPivotCollector {
    #[allow(dead_code)]
    config: crate::config::AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    #[allow(dead_code)]
    event_tx: mpsc::Sender<TelemetryEvent>,
}

impl StackPivotCollector {
    /// Create a new stack pivot collector
    pub fn new(config: &crate::config::AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(500);

        info!("Initializing stack pivot detection collector (T1055.012, T1574)");

        // Create detector config from agent config
        let detector_config = StackPivotConfig {
            enabled: true,
            interval_ms: ((500.0 * config.sub_loop_interval_multiplier) as u64).max(250),
            ..Default::default()
        };

        // Start detector in background
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            let detector = StackPivotDetector::new(detector_config, tx_clone);
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
// Utility Functions
// ============================================================================

/// Scan a specific thread for stack pivot
pub async fn check_thread_stack_pivot(pid: u32, tid: u32) -> Result<StackPivotResult> {
    let (tx, _rx) = mpsc::channel(1);
    let detector = StackPivotDetector::new(StackPivotConfig::default(), tx);

    #[cfg(target_os = "windows")]
    {
        let rsp = detector.get_thread_rsp(pid, tid).await?;
        Ok(detector.check_stack_pointer(pid, tid, rsp).await)
    }

    #[cfg(not(target_os = "windows"))]
    {
        Err(anyhow!("Stack pivot detection is Windows-only"))
    }
}

/// Scan all threads in a process for stack pivots
pub async fn scan_process_for_stack_pivots(pid: u32) -> Result<Vec<StackPivotResult>> {
    let (tx, _rx) = mpsc::channel(1);
    let detector = StackPivotDetector::new(StackPivotConfig::default(), tx);
    let mut results = Vec::new();

    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
        };

        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)?;

            let mut entry = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..Default::default()
            };

            if Thread32First(snapshot, &mut entry).is_ok() {
                loop {
                    if entry.th32OwnerProcessID == pid {
                        let tid = entry.th32ThreadID;
                        if let Ok(rsp) = detector.get_thread_rsp(pid, tid).await {
                            let result = detector.check_stack_pointer(pid, tid, rsp).await;
                            if result.is_pivot {
                                results.push(result);
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

    Ok(results)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stack_bounds_contains() {
        let bounds = StackBounds {
            base: 0x1000_0000,
            limit: 0x0FF0_0000,
            size: 0x0010_0000,
        };

        assert!(bounds.contains(0x0FF8_0000));
        assert!(bounds.contains(0x1000_0000)); // base
        assert!(bounds.contains(0x0FF0_0000)); // limit
        assert!(!bounds.contains(0x1001_0000)); // above base
        assert!(!bounds.contains(0x0FE0_0000)); // below limit
    }

    #[test]
    fn test_stack_bounds_distance() {
        let bounds = StackBounds {
            base: 0x1000_0000,
            limit: 0x0FF0_0000,
            size: 0x0010_0000,
        };

        // Within bounds
        assert_eq!(bounds.distance_from_stack(0x0FF8_0000), 0);

        // Above base
        assert_eq!(bounds.distance_from_stack(0x1001_0000), 0x0001_0000);

        // Below limit
        assert_eq!(bounds.distance_from_stack(0x0FE0_0000), -0x0010_0000);
    }

    #[test]
    fn test_memory_region_type_suspicious() {
        assert!(!MemoryRegionType::Stack.is_suspicious_for_rsp());
        assert!(MemoryRegionType::Heap.is_suspicious_for_rsp());
        assert!(MemoryRegionType::MappedFile.is_suspicious_for_rsp());
        assert!(MemoryRegionType::PrivateAllocation.is_suspicious_for_rsp());
        assert!(MemoryRegionType::Image.is_suspicious_for_rsp());
    }

    #[test]
    fn test_likely_technique_metadata() {
        assert_eq!(LikelyTechnique::Rop.as_str(), "ROP");
        assert!(LikelyTechnique::Rop.mitre_techniques().contains(&"T1574"));
        assert_eq!(LikelyTechnique::Rop.severity(), Severity::Critical);
    }

    #[test]
    fn test_default_config() {
        let config = StackPivotConfig::default();
        assert!(config.enabled);
        assert!(config
            .excluded_processes
            .contains(&"csrss.exe".to_lowercase()));
        assert_eq!(config.rsp_change_threshold, 1024 * 1024);
    }

    #[test]
    fn test_pivot_confidence_calculation() {
        let (tx, _rx) = mpsc::channel(1);
        let detector = StackPivotDetector::new(StackPivotConfig::default(), tx);

        // Large deviation = high confidence
        let conf = detector.calculate_pivot_confidence(2_000_000, 1_000_000);
        assert!(conf >= 0.9);

        // Medium deviation
        let conf = detector.calculate_pivot_confidence(500_000, 1_000_000);
        assert!(conf >= 0.7 && conf < 0.95);

        // Small deviation
        let conf = detector.calculate_pivot_confidence(50_000, 1_000_000);
        assert!(conf >= 0.5 && conf < 0.7);
    }

    #[test]
    fn test_rsp_change_detection() {
        let (tx, _rx) = mpsc::channel(1);
        let detector = StackPivotDetector::new(StackPivotConfig::default(), tx);

        // Normal stack operation (small change)
        assert!(!detector.detect_suspicious_rsp_change(0x1000_0000, 0x1000_0100));

        // Suspicious large change
        assert!(detector.detect_suspicious_rsp_change(0x1000_0000, 0x0800_0000));
    }

    #[test]
    fn test_technique_inference() {
        let (tx, _rx) = mpsc::channel(1);
        let detector = StackPivotDetector::new(StackPivotConfig::default(), tx);

        assert_eq!(
            detector.infer_technique(&MemoryRegionType::Heap, 100_000),
            LikelyTechnique::Rop
        );
        assert_eq!(
            detector.infer_technique(&MemoryRegionType::Heap, 2_000_000),
            LikelyTechnique::HeapSpray
        );
        assert_eq!(
            detector.infer_technique(&MemoryRegionType::PrivateAllocation, 0),
            LikelyTechnique::ShellcodeSetup
        );
    }
}
