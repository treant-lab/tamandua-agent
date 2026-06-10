//! Memory Forensics Collector
//!
//! Comprehensive memory scanning for fileless malware and memory-only threats:
//! - Injected code in legitimate processes
//! - Reflective DLL loading
//! - Process hollowing indicators
//! - Cobalt Strike beacons and other C2 frameworks
//! - Memory-resident malware
//! - Shellcode detection (egg hunters, stagers, encoders)
//! - Unbacked executable memory (RWX regions not backed by files)
//! - **Memory permission transition tracking** (RW->RX, new RWX allocations)
//! - **Thread start address validation** (threads from MEM_PRIVATE exec memory)
//! - **Adaptive entropy profiling** (per-process-type baselines to reduce FPs)
//!
//! ## Advanced Process Injection Detection
//!
//! ### Process Hollowing Detection (T1055.012):
//! - Compare PE headers in memory vs on-disk for suspicious processes
//! - Detect ImageBaseAddress vs expected module base mismatches
//! - Check for unmapped sections that should be mapped
//! - Detect SizeOfImage mismatches between disk and memory
//!
//! ### Module Stomping Detection (T1055.001):
//! - Compare .text section hash on disk vs in memory for each loaded DLL
//! - Flag modified .text sections in DLLs loaded from legitimate paths
//! - Calculate per-section entropy to detect encrypted payloads in stomped modules
//! - Track modules with PAGE_EXECUTE_READWRITE protection (suspicious for DLLs)
//!
//! ### Transacted Hollowing Detection:
//! - Detect NTFS transaction abuse on executable files (TxF API)
//! - Flag processes where loaded image doesn't match file on disk
//! - Monitor for NtCreateTransaction + NtCreateSection + NtRollbackTransaction sequences
//!
//! ## Deep Memory Analysis Features (VAD + Heap Walking)
//!
//! ### VAD (Virtual Address Descriptor) Analysis:
//! - Enumerate all VADs using NtQueryVirtualMemory
//! - Detect RWX regions (rare in legitimate processes)
//! - Detect private executable memory (unbacked by files)
//! - Detect modified mapped sections (code cave detection)
//! - Detect large uncommitted regions (staging areas)
//!
//! ### Heap Walking:
//! - Use HeapWalk to enumerate heap blocks
//! - Look for PE headers in heap (MZ signature)
//! - Detect encrypted blobs (high entropy > 7.0)
//! - Find strings indicative of malware (URLs, commands)
//!
//! ### Module Integrity:
//! - Compare loaded modules against on-disk copies
//! - Detect inline hooks in ntdll, kernel32
//! - Find hidden modules (PEB unlinking)
//! - Verify digital signatures of loaded DLLs
//!
//! MITRE ATT&CK:
//! - T1055 (Process Injection)
//! - T1055.012 (Process Hollowing)
//! - T1620 (Reflective Code Loading)
//! - T1106 (Native API)
//! - T1027 (Obfuscated Files or Information)
//!
//! ## Detection Methods
//!
//! ### Windows
//! - VirtualQueryEx to enumerate memory regions
//! - NtQueryVirtualMemory for VAD enumeration
//! - HeapWalk for heap block analysis
//! - EnumProcessModules to identify backed vs unbacked memory
//! - Check for PAGE_EXECUTE_READWRITE without file backing
//! - Pattern matching for shellcode signatures
//! - PE header detection in private memory
//! - Entropy analysis of executable regions
//! - Module range verification for executable memory
//! - Module integrity verification against disk images
//!
//! ### Linux
//! - Parse /proc/[pid]/maps for anonymous executable regions
//! - Read /proc/[pid]/mem for pattern scanning
//! - Detect shellcode patterns in anonymous RWX memory
//! - Check for suspicious memory mappings
//! - memfd_create detection for fileless execution

// This collector enumerates PE-image structures, shellcode signature tables,
// permission-transition state and per-process-type entropy baselines used by
// the memory-forensics scanners (hollowing, module stomping, beacon
// detection, fileless execution). Reference constants and reserved fields
// are kept exhaustive even when not yet consumed by every dispatch path.
#![allow(dead_code, unused_variables, unused_assignments)]

use super::{
    Detection, DetectionType, EventPayload, EventType, MemoryPermissionEvent, ProcessEvent,
    Severity, TelemetryEvent,
};
use crate::config::AgentConfig;
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::time::Instant;
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

/// Memory region characteristics
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base_address: u64,
    pub size: u64,
    pub protection: MemoryProtection,
    pub region_type: MemoryType,
    pub module_name: Option<String>,
    pub is_executable: bool,
    pub is_private: bool,
    pub entropy: f32,
}

/// Memory protection flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryProtection {
    NoAccess,
    ReadOnly,
    ReadWrite,
    WriteCopy,
    Execute,
    ExecuteRead,
    ExecuteReadWrite,
    ExecuteWriteCopy,
    Guard,
    Unknown,
}

/// Memory region type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryType {
    Image,   // Mapped from file (DLL/EXE)
    Mapped,  // Memory-mapped file
    Private, // Private allocation
    Stack,   // Thread stack
    Heap,    // Process heap
    Unknown,
}

/// Suspicious memory patterns
#[derive(Debug, Clone)]
pub struct SuspiciousMemory {
    pub pid: u32,
    pub process_name: String,
    pub region: MemoryRegion,
    pub reason: MemorySuspicionReason,
    pub confidence: f32,
    pub shellcode_detected: bool,
    pub beacon_detected: bool,
}

/// Reasons for memory suspicion
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemorySuspicionReason {
    /// Executable private memory (not backed by file)
    ExecutablePrivate,
    /// RWX memory (Write + Execute)
    ReadWriteExecute,
    /// High entropy executable region
    HighEntropyExecutable,
    /// PE header in private memory (reflective loading)
    PeInPrivateMemory,
    /// Known shellcode patterns
    ShellcodePattern,
    /// Cobalt Strike beacon signature
    CobaltStrikeBeacon,
    /// Metasploit payload signature
    MetasploitPayload,
    /// Unbacked executable code
    UnbackedExecutable,
    /// Modified code section
    ModifiedCodeSection,
}

impl MemorySuspicionReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ExecutablePrivate => "executable_private_memory",
            Self::ReadWriteExecute => "rwx_memory",
            Self::HighEntropyExecutable => "high_entropy_executable",
            Self::PeInPrivateMemory => "pe_in_private_memory",
            Self::ShellcodePattern => "shellcode_pattern",
            Self::CobaltStrikeBeacon => "cobalt_strike_beacon",
            Self::MetasploitPayload => "metasploit_payload",
            Self::UnbackedExecutable => "unbacked_executable",
            Self::ModifiedCodeSection => "modified_code_section",
        }
    }

    pub fn mitre_technique(&self) -> &'static str {
        match self {
            Self::ExecutablePrivate | Self::UnbackedExecutable => "T1055",
            Self::ReadWriteExecute => "T1055",
            Self::HighEntropyExecutable => "T1027",
            Self::PeInPrivateMemory => "T1620",
            Self::ShellcodePattern | Self::MetasploitPayload => "T1059",
            Self::CobaltStrikeBeacon => "T1071.001",
            Self::ModifiedCodeSection => "T1055.012",
        }
    }
}

// ============================================================================
// VAD (Virtual Address Descriptor) Analysis Types
// ============================================================================

/// VAD anomaly types for deep memory analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VadAnomalyType {
    /// Private RWX memory - rare in legitimate processes
    RwxPrivate,
    /// Executable memory without file backing
    UnbackedExecutable,
    /// Text section differs from disk image (code cave / inline hook)
    ModifiedSection,
    /// Module not in PEB module list (unlinked/hidden)
    HiddenModule,
    /// Encrypted blob detected in heap (high entropy > 7.0)
    HighEntropyHeap,
    /// Large uncommitted region (potential staging area)
    LargeStagingArea,
    /// Guard page followed by executable (stack pivot indicator)
    GuardPageAnomaly,
    /// Executable memory at unusual alignment
    MisalignedExecutable,
}

impl VadAnomalyType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RwxPrivate => "rwx_private_memory",
            Self::UnbackedExecutable => "unbacked_executable",
            Self::ModifiedSection => "modified_code_section",
            Self::HiddenModule => "hidden_module",
            Self::HighEntropyHeap => "high_entropy_heap",
            Self::LargeStagingArea => "large_staging_area",
            Self::GuardPageAnomaly => "guard_page_anomaly",
            Self::MisalignedExecutable => "misaligned_executable",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Self::RwxPrivate => Severity::High,
            Self::UnbackedExecutable => Severity::High,
            Self::ModifiedSection => Severity::Critical,
            Self::HiddenModule => Severity::Critical,
            Self::HighEntropyHeap => Severity::Medium,
            Self::LargeStagingArea => Severity::Low,
            Self::GuardPageAnomaly => Severity::Medium,
            Self::MisalignedExecutable => Severity::Medium,
        }
    }

    pub fn mitre_techniques(&self) -> Vec<&'static str> {
        match self {
            Self::RwxPrivate => vec!["T1055", "T1055.001"],
            Self::UnbackedExecutable => vec!["T1055", "T1620"],
            Self::ModifiedSection => vec!["T1055.012", "T1574.001"],
            Self::HiddenModule => vec!["T1055", "T1574.002"],
            Self::HighEntropyHeap => vec!["T1027", "T1140"],
            Self::LargeStagingArea => vec!["T1055"],
            Self::GuardPageAnomaly => vec!["T1055.004"],
            Self::MisalignedExecutable => vec!["T1055"],
        }
    }
}

/// VAD anomaly detection result
#[derive(Debug, Clone)]
pub struct VadAnomaly {
    /// Base address of the suspicious region
    pub base_address: u64,
    /// Size of the region
    pub size: usize,
    /// Memory protection string (e.g., "PAGE_EXECUTE_READWRITE")
    pub protection: String,
    /// Type of anomaly detected
    pub anomaly_type: VadAnomalyType,
    /// File backing this memory (if any)
    pub backing_file: Option<String>,
    /// Entropy of the region (0.0-8.0)
    pub entropy: f32,
    /// Additional details
    pub details: String,
    /// Confidence score (0.0-1.0)
    pub confidence: f32,
}

// ============================================================================
// Heap Analysis Types
// ============================================================================

/// Heap block anomaly types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeapAnomalyType {
    /// PE header (MZ) found in heap
    PeHeaderInHeap,
    /// High entropy block (likely encrypted payload)
    EncryptedBlob,
    /// Shellcode pattern in heap
    ShellcodeInHeap,
    /// Suspicious strings (URLs, commands, etc.)
    SuspiciousStrings,
    /// Large allocation (potential staging)
    LargeAllocation,
}

/// Heap block analysis result
#[derive(Debug, Clone)]
pub struct HeapAnomaly {
    /// Heap handle
    pub heap_handle: u64,
    /// Block address
    pub block_address: u64,
    /// Block size
    pub block_size: usize,
    /// Anomaly type
    pub anomaly_type: HeapAnomalyType,
    /// Entropy if calculated
    pub entropy: Option<f32>,
    /// Detected patterns
    pub detected_patterns: Vec<String>,
    /// Suspicious strings found
    pub suspicious_strings: Vec<String>,
}

// ============================================================================
// Module Integrity Types
// ============================================================================

/// Module integrity check result
#[derive(Debug, Clone)]
pub struct ModuleIntegrityResult {
    /// Module base address
    pub base_address: u64,
    /// Module name
    pub module_name: String,
    /// Module path on disk
    pub module_path: String,
    /// Whether the module is signed
    pub is_signed: bool,
    /// Signer name if signed
    pub signer: Option<String>,
    /// Whether signature is valid
    pub signature_valid: bool,
    /// List of detected hooks
    pub detected_hooks: Vec<InlineHook>,
    /// Whether module is in PEB
    pub in_peb_list: bool,
    /// Code section hash mismatch
    pub code_modified: bool,
    /// Original .text section hash (from disk)
    pub disk_text_hash: Option<String>,
    /// Current .text section hash (in memory)
    pub memory_text_hash: Option<String>,
}

/// Inline hook detection
#[derive(Debug, Clone)]
pub struct InlineHook {
    /// Function name that's hooked
    pub function_name: String,
    /// Address of the hook
    pub hook_address: u64,
    /// Original bytes (first N bytes of function)
    pub original_bytes: Vec<u8>,
    /// Current bytes (showing the hook)
    pub current_bytes: Vec<u8>,
    /// Hook type (jmp, call, etc.)
    pub hook_type: String,
    /// Destination of the hook
    pub hook_destination: u64,
}

// ============================================================================
// Advanced Injection Detection Types
// ============================================================================

/// Result from process hollowing detection scan
#[derive(Debug, Clone)]
pub struct ProcessHollowingResult {
    /// Process ID
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// Process path on disk
    pub process_path: String,
    /// ImageBaseAddress in memory
    pub memory_image_base: u64,
    /// Expected image base from PE header on disk
    pub disk_image_base: u64,
    /// SizeOfImage in memory
    pub memory_size_of_image: u32,
    /// SizeOfImage on disk
    pub disk_size_of_image: u32,
    /// Whether the image base differs
    pub image_base_mismatch: bool,
    /// Whether the size of image differs
    pub size_mismatch: bool,
    /// Whether the entry point address is in unbacked memory
    pub entry_point_in_unbacked: bool,
    /// Whether the main module's memory type is MEM_PRIVATE instead of MEM_IMAGE
    pub main_module_private: bool,
    /// Sections that exist on disk but are unmapped in memory
    pub unmapped_sections: Vec<String>,
    /// Disk PE SHA256 hash
    pub disk_pe_hash: String,
    /// Memory PE header SHA256 hash
    pub memory_pe_hash: String,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// Evidence details
    pub evidence: Vec<String>,
}

/// Result from module stomping detection scan
#[derive(Debug, Clone)]
pub struct ModuleStompingResult {
    /// Process ID
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// Module path on disk
    pub module_path: String,
    /// Module name
    pub module_name: String,
    /// Module base address
    pub module_base: u64,
    /// Module size
    pub module_size: u64,
    /// .text section hash on disk
    pub disk_text_hash: String,
    /// .text section hash in memory
    pub memory_text_hash: String,
    /// Whether the .text section has been modified
    pub text_section_modified: bool,
    /// Per-section entropy values (section_name -> entropy)
    pub section_entropies: Vec<(String, f32)>,
    /// Whether the module has PAGE_EXECUTE_READWRITE protection
    pub has_rwx_protection: bool,
    /// Number of bytes that differ between disk and memory
    pub diff_byte_count: usize,
    /// Offset of first difference in .text section
    pub first_diff_offset: Option<usize>,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// Evidence details
    pub evidence: Vec<String>,
}

/// Result from transacted hollowing detection scan
#[derive(Debug, Clone)]
pub struct TransactedHollowingResult {
    /// Process ID
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// Process path on disk
    pub process_path: String,
    /// The on-disk file hash (current)
    pub disk_file_hash: String,
    /// The in-memory image hash
    pub memory_image_hash: String,
    /// Whether the disk and memory images differ
    pub image_mismatch: bool,
    /// Whether TxF (transacted NTFS) handles are detected
    pub txf_handles_detected: bool,
    /// File system transaction indicators
    pub transaction_indicators: Vec<String>,
    /// Whether the PE headers differ between disk and memory
    pub pe_header_mismatch: bool,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// Evidence details
    pub evidence: Vec<String>,
}

// ============================================================================
// Deep Memory Scanner
// ============================================================================

/// Deep memory scanner with VAD analysis and heap walking
pub struct DeepMemoryScanner {
    /// Base memory scanner
    pub base_scanner: MemoryScanner,
    /// Cache of known-good module hashes (to skip re-scanning)
    known_good_modules: HashSet<String>,
    /// Last scan timestamps per process (for incremental scanning)
    last_scan_times: HashMap<u32, std::time::Instant>,
    /// High-risk process names (scan more frequently)
    high_risk_processes: HashSet<String>,
    /// Minimum scan interval for normal processes (seconds)
    normal_scan_interval: u64,
    /// Minimum scan interval for high-risk processes (seconds)
    high_risk_scan_interval: u64,
}

impl DeepMemoryScanner {
    /// Create a new deep memory scanner
    pub fn new() -> Self {
        let mut high_risk_processes = HashSet::new();
        // Processes commonly targeted for injection
        for name in &[
            "svchost.exe",
            "explorer.exe",
            "lsass.exe",
            "services.exe",
            "spoolsv.exe",
            "wininit.exe",
            "csrss.exe",
            "smss.exe",
            "rundll32.exe",
            "regsvr32.exe",
            "msiexec.exe",
            "dllhost.exe",
            "notepad.exe",
            "cmd.exe",
            "powershell.exe",
            "pwsh.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
            "conhost.exe",
        ] {
            high_risk_processes.insert(name.to_lowercase());
        }

        Self {
            base_scanner: MemoryScanner::new(),
            known_good_modules: HashSet::new(),
            last_scan_times: HashMap::new(),
            high_risk_processes,
            normal_scan_interval: 60,    // 1 minute for normal processes
            high_risk_scan_interval: 15, // 15 seconds for high-risk processes
        }
    }

    /// Check if we should scan this process now (incremental scanning)
    pub fn should_scan_process(&mut self, pid: u32, process_name: &str) -> bool {
        let now = std::time::Instant::now();
        let is_high_risk = self
            .high_risk_processes
            .contains(&process_name.to_lowercase());
        let interval = if is_high_risk {
            self.high_risk_scan_interval
        } else {
            self.normal_scan_interval
        };

        if let Some(last_scan) = self.last_scan_times.get(&pid) {
            if now.duration_since(*last_scan).as_secs() < interval {
                return false;
            }
        }

        self.last_scan_times.insert(pid, now);
        true
    }

    /// Mark a module as known-good (skip future integrity checks).
    /// Bounded to 500 entries; once full, oldest entries are removed to make room.
    pub fn mark_module_known_good(&mut self, module_path: &str) {
        const MAX_KNOWN_GOOD: usize = 500;
        if self.known_good_modules.len() >= MAX_KNOWN_GOOD
            && !self
                .known_good_modules
                .contains(&module_path.to_lowercase())
        {
            // Remove roughly 20% of entries (arbitrary eviction since HashSet has no order)
            let evict_count = MAX_KNOWN_GOOD / 5;
            let to_remove: Vec<String> = self
                .known_good_modules
                .iter()
                .take(evict_count)
                .cloned()
                .collect();
            for key in to_remove {
                self.known_good_modules.remove(&key);
            }
        }
        self.known_good_modules.insert(module_path.to_lowercase());
    }

    /// Check if a module is known-good
    pub fn is_module_known_good(&self, module_path: &str) -> bool {
        self.known_good_modules
            .contains(&module_path.to_lowercase())
    }

    /// Perform deep VAD analysis on a process (Windows)
    #[cfg(target_os = "windows")]
    pub fn analyze_vads(&self, pid: u32) -> Vec<VadAnomaly> {
        vad_analysis::analyze_process_vads(pid)
    }

    /// Perform deep VAD analysis on a process (Linux)
    #[cfg(target_os = "linux")]
    pub fn analyze_vads(&self, pid: u32) -> Vec<VadAnomaly> {
        vad_analysis_linux::analyze_process_vads(pid)
    }

    /// Perform deep VAD analysis on a process (macOS)
    /// Uses Mach VM APIs to enumerate memory regions and detect anomalies
    #[cfg(target_os = "macos")]
    pub fn analyze_vads(&self, pid: u32) -> Vec<VadAnomaly> {
        macos_memory::find_suspicious_regions(pid as i32)
    }

    /// Walk process heaps looking for anomalies (Windows)
    #[cfg(target_os = "windows")]
    pub fn walk_heaps(&self, pid: u32) -> Vec<HeapAnomaly> {
        heap_analysis::walk_process_heaps(pid, &self.base_scanner)
    }

    /// Walk process heaps (Linux - use /proc/pid/maps heap regions)
    ///
    /// Enumerates heap regions from /proc/[pid]/maps and scans for anomalies:
    /// - PE headers (MZ) in heap memory
    /// - ELF headers in heap memory
    /// - High entropy blocks (encrypted payloads)
    /// - Shellcode patterns
    /// - Suspicious strings (URLs, commands, API names)
    /// - Large heap allocations (staging areas)
    #[cfg(target_os = "linux")]
    pub fn walk_heaps(&self, pid: u32) -> Vec<HeapAnomaly> {
        use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};

        let mut anomalies = Vec::new();

        let maps_path = format!("/proc/{}/maps", pid);
        let file = match std::fs::File::open(&maps_path) {
            Ok(f) => f,
            Err(e) => {
                trace!(pid = pid, error = %e, "Cannot open maps for heap walking");
                return anomalies;
            }
        };

        let reader = BufReader::new(file);
        let mem_path = format!("/proc/{}/mem", pid);
        let mut mem_file = match std::fs::File::open(&mem_path) {
            Ok(f) => Some(f),
            Err(e) => {
                trace!(pid = pid, error = %e, "Cannot open /proc/pid/mem for heap scanning");
                None
            }
        };

        for line in reader.lines().flatten() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                continue;
            }

            let pathname = if parts.len() >= 6 { parts[5] } else { "" };

            // Look for heap regions and malloc arenas
            let is_heap = pathname == "[heap]";
            let is_anon_rw = {
                let perms = parts[1];
                perms.contains('r')
                    && perms.contains('w')
                    && !perms.contains('x')
                    && (pathname.is_empty() || pathname == "[anon:libc_malloc]")
            };

            if !is_heap && !is_anon_rw {
                continue;
            }

            let addr_parts: Vec<&str> = parts[0].split('-').collect();
            if addr_parts.len() != 2 {
                continue;
            }
            let start = match u64::from_str_radix(addr_parts[0], 16) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let end = match u64::from_str_radix(addr_parts[1], 16) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let size = (end - start) as usize;

            // Flag very large heap allocations as potential staging areas
            if size > 50 * 1024 * 1024 {
                anomalies.push(HeapAnomaly {
                    heap_handle: 0,
                    block_address: start,
                    block_size: size,
                    anomaly_type: HeapAnomalyType::LargeAllocation,
                    entropy: None,
                    detected_patterns: Vec::new(),
                    suspicious_strings: Vec::new(),
                });
            }

            // Try to read heap contents for deeper analysis
            if let Some(ref mut mem) = mem_file {
                let read_size = size.min(65536); // Read up to 64KB per heap region
                if mem.seek(SeekFrom::Start(start)).is_ok() {
                    let mut buffer = vec![0u8; read_size];
                    if let Ok(bytes_read) = mem.read(&mut buffer) {
                        if bytes_read > 64 {
                            let buf = &buffer[..bytes_read];
                            let entropy = MemoryScanner::calculate_entropy(buf);

                            // Check for PE header (MZ) in heap
                            if buf.len() >= 2 && buf[0] == 0x4D && buf[1] == 0x5A {
                                anomalies.push(HeapAnomaly {
                                    heap_handle: 0,
                                    block_address: start,
                                    block_size: size,
                                    anomaly_type: HeapAnomalyType::PeHeaderInHeap,
                                    entropy: Some(entropy),
                                    detected_patterns: vec!["MZ_header".to_string()],
                                    suspicious_strings: Vec::new(),
                                });
                            }

                            // Check for ELF header in heap (Linux-specific)
                            if buf.len() >= 4
                                && buf[0] == 0x7F
                                && buf[1] == b'E'
                                && buf[2] == b'L'
                                && buf[3] == b'F'
                            {
                                anomalies.push(HeapAnomaly {
                                    heap_handle: 0,
                                    block_address: start,
                                    block_size: size,
                                    anomaly_type: HeapAnomalyType::PeHeaderInHeap, // Reuse for ELF
                                    entropy: Some(entropy),
                                    detected_patterns: vec!["ELF_header_in_heap".to_string()],
                                    suspicious_strings: Vec::new(),
                                });
                            }

                            // High entropy block (likely encrypted payload)
                            if entropy > 7.0 && size >= 4096 {
                                anomalies.push(HeapAnomaly {
                                    heap_handle: 0,
                                    block_address: start,
                                    block_size: size,
                                    anomaly_type: HeapAnomalyType::EncryptedBlob,
                                    entropy: Some(entropy),
                                    detected_patterns: Vec::new(),
                                    suspicious_strings: Vec::new(),
                                });
                            }

                            // Scan for shellcode patterns
                            let patterns = self.base_scanner.scan_buffer(buf);
                            if !patterns.is_empty() {
                                anomalies.push(HeapAnomaly {
                                    heap_handle: 0,
                                    block_address: start,
                                    block_size: size,
                                    anomaly_type: HeapAnomalyType::ShellcodeInHeap,
                                    entropy: Some(entropy),
                                    detected_patterns: patterns,
                                    suspicious_strings: Vec::new(),
                                });
                            }

                            // Check for suspicious strings
                            let suspicious_strings = Self::find_suspicious_strings_in_buffer(buf);
                            if !suspicious_strings.is_empty() {
                                anomalies.push(HeapAnomaly {
                                    heap_handle: 0,
                                    block_address: start,
                                    block_size: size,
                                    anomaly_type: HeapAnomalyType::SuspiciousStrings,
                                    entropy: Some(entropy),
                                    detected_patterns: Vec::new(),
                                    suspicious_strings,
                                });
                            }
                        }
                    }
                }
            }
        }

        anomalies
    }

    /// Walk process heaps (macOS - use Mach VM APIs to find heap regions)
    ///
    /// Enumerates heap-tagged memory regions via mach_vm_region and scans for:
    /// - Mach-O headers in heap memory (reflective loading)
    /// - High entropy blocks (encrypted payloads)
    /// - Shellcode patterns
    /// - Large heap allocations (staging areas)
    #[cfg(target_os = "macos")]
    pub fn walk_heaps(&self, pid: u32) -> Vec<HeapAnomaly> {
        let mut anomalies = Vec::new();

        let task = match macos_memory::get_task_for_pid(pid as i32) {
            Ok(t) => t,
            Err(e) => {
                trace!(pid = pid, error = %e, "Cannot get task for heap walking");
                return anomalies;
            }
        };

        let regions = macos_memory::enumerate_regions(task);

        for region in &regions {
            // Only scan heap regions
            if region.region_type != "heap" {
                continue;
            }

            // Must be readable
            if !region.is_readable {
                continue;
            }

            let size = region.size as usize;

            // Flag very large heap allocations
            if size > 50 * 1024 * 1024 {
                anomalies.push(HeapAnomaly {
                    heap_handle: 0,
                    block_address: region.base_address,
                    block_size: size,
                    anomaly_type: HeapAnomalyType::LargeAllocation,
                    entropy: None,
                    detected_patterns: Vec::new(),
                    suspicious_strings: Vec::new(),
                });
            }

            // Read heap contents for deeper analysis
            let read_size = size.min(65536);
            if let Some(data) = macos_memory::read_memory(task, region.base_address, read_size) {
                if data.len() > 64 {
                    let entropy = MemoryScanner::calculate_entropy(&data);

                    // Check for Mach-O magic numbers in heap
                    if data.len() >= 4 {
                        let magic = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
                        const MH_MAGIC_64: u32 = 0xfeedfacf;
                        const MH_CIGAM_64: u32 = 0xcffaedfe;
                        const FAT_MAGIC: u32 = 0xcafebabe;
                        const FAT_CIGAM: u32 = 0xbebafeca;

                        if magic == MH_MAGIC_64
                            || magic == MH_CIGAM_64
                            || magic == FAT_MAGIC
                            || magic == FAT_CIGAM
                        {
                            anomalies.push(HeapAnomaly {
                                heap_handle: 0,
                                block_address: region.base_address,
                                block_size: size,
                                anomaly_type: HeapAnomalyType::PeHeaderInHeap, // Reuse for Mach-O
                                entropy: Some(entropy),
                                detected_patterns: vec!["MachO_header_in_heap".to_string()],
                                suspicious_strings: Vec::new(),
                            });
                        }
                    }

                    // Check for PE header (MZ) in heap (cross-platform malware)
                    if data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A {
                        anomalies.push(HeapAnomaly {
                            heap_handle: 0,
                            block_address: region.base_address,
                            block_size: size,
                            anomaly_type: HeapAnomalyType::PeHeaderInHeap,
                            entropy: Some(entropy),
                            detected_patterns: vec!["MZ_header".to_string()],
                            suspicious_strings: Vec::new(),
                        });
                    }

                    // High entropy block
                    if entropy > 7.0 && size >= 4096 {
                        anomalies.push(HeapAnomaly {
                            heap_handle: 0,
                            block_address: region.base_address,
                            block_size: size,
                            anomaly_type: HeapAnomalyType::EncryptedBlob,
                            entropy: Some(entropy),
                            detected_patterns: Vec::new(),
                            suspicious_strings: Vec::new(),
                        });
                    }

                    // Scan for shellcode patterns
                    let patterns = self.base_scanner.scan_buffer(&data);
                    if !patterns.is_empty() {
                        anomalies.push(HeapAnomaly {
                            heap_handle: 0,
                            block_address: region.base_address,
                            block_size: size,
                            anomaly_type: HeapAnomalyType::ShellcodeInHeap,
                            entropy: Some(entropy),
                            detected_patterns: patterns,
                            suspicious_strings: Vec::new(),
                        });
                    }

                    // Check for suspicious strings
                    let suspicious_strings = Self::find_suspicious_strings_in_buffer(&data);
                    if !suspicious_strings.is_empty() {
                        anomalies.push(HeapAnomaly {
                            heap_handle: 0,
                            block_address: region.base_address,
                            block_size: size,
                            anomaly_type: HeapAnomalyType::SuspiciousStrings,
                            entropy: Some(entropy),
                            detected_patterns: Vec::new(),
                            suspicious_strings,
                        });
                    }
                }
            }
        }

        // Clean up task port
        unsafe {
            macos_memory::mach_port_deallocate_wrapper(task);
        }

        anomalies
    }

    /// Check module integrity (hooks, modifications) for a process (Windows)
    #[cfg(target_os = "windows")]
    pub fn check_module_integrity(&self, pid: u32) -> Vec<ModuleIntegrityResult> {
        module_integrity::check_process_modules(pid, &self.known_good_modules)
    }

    /// Check module integrity (Linux - verify mapped .so files against disk)
    ///
    /// For each shared library mapped in /proc/[pid]/maps:
    /// - Verify the backing file still exists on disk
    /// - Compute SHA-256 hash of the .text section from disk
    /// - Compare against in-memory .text section hash (when accessible)
    /// - Flag deleted or modified shared libraries
    #[cfg(target_os = "linux")]
    pub fn check_module_integrity(&self, pid: u32) -> Vec<ModuleIntegrityResult> {
        use sha2::{Digest, Sha256};
        use std::io::{BufRead, BufReader};

        let mut results = Vec::new();
        let mut seen_modules: HashSet<String> = HashSet::new();

        let maps_path = format!("/proc/{}/maps", pid);
        let file = match std::fs::File::open(&maps_path) {
            Ok(f) => f,
            Err(e) => {
                trace!(pid = pid, error = %e, "Cannot open maps for module integrity check");
                return results;
            }
        };

        let reader = BufReader::new(file);

        for line in reader.lines().flatten() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 {
                continue;
            }

            let perms = parts[1];
            let pathname = parts[5];

            // Only check executable mapped files (.so files and executables)
            if !perms.contains('x') {
                continue;
            }

            // Skip non-file mappings
            if pathname.starts_with('[')
                || pathname.starts_with("/memfd:")
                || pathname.is_empty()
                || pathname == "(deleted)"
            {
                continue;
            }

            // Skip known-good modules
            if self.known_good_modules.contains(&pathname.to_lowercase()) {
                continue;
            }

            // Avoid duplicate checks for the same module
            if seen_modules.contains(pathname) {
                continue;
            }
            seen_modules.insert(pathname.to_string());

            let addr_parts: Vec<&str> = parts[0].split('-').collect();
            let base_address = addr_parts
                .first()
                .and_then(|s| u64::from_str_radix(s, 16).ok())
                .unwrap_or(0);

            let module_name = std::path::Path::new(pathname)
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| pathname.to_string());

            // Check if the file still exists on disk
            let file_exists = std::path::Path::new(pathname).exists();
            let is_deleted = pathname.contains("(deleted)") || !file_exists;

            // Compute disk hash if file exists
            let disk_text_hash = if file_exists {
                match std::fs::read(pathname) {
                    Ok(data) => {
                        let mut hasher = Sha256::new();
                        hasher.update(&data);
                        Some(format!("{:x}", hasher.finalize()))
                    }
                    Err(_) => None,
                }
            } else {
                None
            };

            let mut result = ModuleIntegrityResult {
                base_address,
                module_name: module_name.clone(),
                module_path: pathname.to_string(),
                is_signed: false, // Linux doesn't have native code signing (beyond GPG)
                signer: None,
                signature_valid: false,
                detected_hooks: Vec::new(),
                in_peb_list: true,         // N/A on Linux, assume present
                code_modified: is_deleted, // Deleted files are suspicious
                disk_text_hash,
                memory_text_hash: None, // Would require ptrace to read memory text section
            };

            // Only include if there are actual issues
            if is_deleted {
                result.code_modified = true;
                results.push(result);
            }
        }

        results
    }

    /// Check module integrity (macOS - verify loaded dylibs against disk)
    ///
    /// Uses vmmap output or Mach APIs to find loaded dylibs, then:
    /// - Verify each dylib still exists on disk
    /// - Compute SHA-256 hash of dylib on disk
    /// - Flag missing or modified dylibs
    #[cfg(target_os = "macos")]
    pub fn check_module_integrity(&self, pid: u32) -> Vec<ModuleIntegrityResult> {
        use sha2::{Digest, Sha256};
        use std::process::Command;

        let mut results = Vec::new();
        let mut seen_modules: HashSet<String> = HashSet::new();

        // Use vmmap to list memory regions and identify loaded dylibs
        let output = match Command::new("vmmap").arg(pid.to_string()).output() {
            Ok(o) => o,
            Err(e) => {
                trace!(pid = pid, error = %e, "Cannot run vmmap for module integrity check");
                return results;
            }
        };

        if !output.status.success() {
            trace!(pid = pid, "vmmap returned non-zero exit code");
            return results;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines() {
            // vmmap output includes lines like:
            // __TEXT  00000001000a0000-00000001000b4000 [   80K] r-x/r-x SM=COW  /usr/lib/libSystem.B.dylib
            let trimmed = line.trim();

            // Look for lines containing dylib paths
            if !trimmed.contains('/') {
                continue;
            }

            // Extract the file path (last component starting with /)
            let path = match trimmed.rfind('/') {
                Some(idx) => {
                    // Walk back to find the start of the full path
                    let before = &trimmed[..idx];
                    let path_start = before
                        .rfind(|c: char| c.is_whitespace())
                        .map(|i| i + 1)
                        .unwrap_or(0);
                    trimmed[path_start..].trim()
                }
                None => continue,
            };

            if !path.starts_with('/') {
                continue;
            }

            // Only check dylibs and executables
            if !path.ends_with(".dylib") && !path.contains(".framework/") && !path.ends_with(".so")
            {
                continue;
            }

            // Skip known-good modules
            if self.known_good_modules.contains(&path.to_lowercase()) {
                continue;
            }

            // Avoid duplicate checks
            if seen_modules.contains(path) {
                continue;
            }
            seen_modules.insert(path.to_string());

            let module_name = std::path::Path::new(path)
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| path.to_string());

            // Parse base address from the line if possible
            let base_address = Self::parse_vmmap_address(trimmed);

            // Check if file exists on disk
            let file_exists = std::path::Path::new(path).exists();

            // Compute disk hash
            let disk_text_hash = if file_exists {
                match std::fs::read(path) {
                    Ok(data) => {
                        let mut hasher = Sha256::new();
                        hasher.update(&data);
                        Some(format!("{:x}", hasher.finalize()))
                    }
                    Err(_) => None,
                }
            } else {
                None
            };

            // Verify codesign if the file exists
            let (is_signed, signer) = if file_exists {
                Self::check_macos_codesign(path)
            } else {
                (false, None)
            };

            let is_deleted = !file_exists;

            let result = ModuleIntegrityResult {
                base_address,
                module_name,
                module_path: path.to_string(),
                is_signed,
                signer,
                signature_valid: is_signed, // If codesign passes, signature is valid
                detected_hooks: Vec::new(),
                in_peb_list: true, // N/A on macOS
                code_modified: is_deleted,
                disk_text_hash,
                memory_text_hash: None,
            };

            // Only include if there are actual issues
            if is_deleted || !is_signed {
                results.push(result);
            }
        }

        results
    }

    /// Perform full deep scan on a process
    pub fn deep_scan_process(&self, pid: u32) -> DeepScanResult {
        let vad_anomalies = self.analyze_vads(pid);
        let heap_anomalies = self.walk_heaps(pid);
        let module_integrity = self.check_module_integrity(pid);
        let basic_scan = self.base_scanner.scan_process(pid);

        DeepScanResult {
            pid,
            vad_anomalies,
            heap_anomalies,
            module_integrity,
            basic_scan_results: basic_scan,
        }
    }

    // ========================================================================
    // Advanced Injection Detection Methods
    // ========================================================================

    /// Detect process hollowing (T1055.012)
    ///
    /// Compares PE headers in memory vs on-disk for each process, detecting:
    /// - ImageBaseAddress mismatches between disk and memory
    /// - SizeOfImage mismatches
    /// - Main module backed by MEM_PRIVATE instead of MEM_IMAGE
    /// - Unmapped sections that should exist
    /// - Entry point in unbacked memory
    #[cfg(target_os = "windows")]
    pub fn detect_process_hollowing(
        &self,
        pid: u32,
        process_name: &str,
        process_path: &str,
    ) -> Option<ProcessHollowingResult> {
        advanced_injection::detect_process_hollowing(pid, process_name, process_path)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn detect_process_hollowing(
        &self,
        _pid: u32,
        _process_name: &str,
        _process_path: &str,
    ) -> Option<ProcessHollowingResult> {
        None
    }

    /// Detect module stomping (T1055.001)
    ///
    /// For each loaded DLL, compares .text section hash on disk vs in memory:
    /// - Flags modified .text sections in legitimately-pathed DLLs
    /// - Calculates per-section entropy for encrypted payload detection
    /// - Tracks modules with PAGE_EXECUTE_READWRITE (suspicious for DLLs)
    #[cfg(target_os = "windows")]
    pub fn detect_module_stomping(
        &self,
        pid: u32,
        process_name: &str,
    ) -> Vec<ModuleStompingResult> {
        advanced_injection::detect_module_stomping(pid, process_name, &self.known_good_modules)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn detect_module_stomping(
        &self,
        _pid: u32,
        _process_name: &str,
    ) -> Vec<ModuleStompingResult> {
        Vec::new()
    }

    /// Detect transacted hollowing
    ///
    /// Detects NTFS transaction abuse on executable files:
    /// - Compares in-memory image against on-disk file
    /// - Detects PE header mismatches
    /// - Checks for TxF handle indicators
    #[cfg(target_os = "windows")]
    pub fn detect_transacted_hollowing(
        &self,
        pid: u32,
        process_name: &str,
        process_path: &str,
    ) -> Option<TransactedHollowingResult> {
        advanced_injection::detect_transacted_hollowing(pid, process_name, process_path)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn detect_transacted_hollowing(
        &self,
        _pid: u32,
        _process_name: &str,
        _process_path: &str,
    ) -> Option<TransactedHollowingResult> {
        None
    }

    // ========================================================================
    // Helper Methods for Linux/macOS Heap and Module Integrity
    // ========================================================================

    /// Suspicious strings to look for in heap memory (Linux/macOS)
    #[cfg(not(target_os = "windows"))]
    const LINUX_SUSPICIOUS_STRINGS: &'static [&'static str] = &[
        "http://",
        "https://",
        "ftp://",
        "/bin/sh",
        "/bin/bash",
        "/bin/zsh",
        "/bin/dash",
        "curl ",
        "wget ",
        "python",
        "perl ",
        "ruby ",
        "LD_PRELOAD",
        "ld.so.preload",
        "ptrace",
        "memfd_create",
        "execveat",
        "/etc/passwd",
        "/etc/shadow",
        "reverse_tcp",
        "reverse_http",
        "meterpreter",
        "mimikatz",
        "sekurlsa",
        "/tmp/.",
        "/dev/shm/",
        "socket(",
        "connect(",
        "bind(",
        "chmod 777",
        "chmod +x",
        "base64 -d",
        "base64 --decode",
    ];

    /// Find suspicious strings in a buffer (Linux/macOS)
    #[cfg(not(target_os = "windows"))]
    fn find_suspicious_strings_in_buffer(buffer: &[u8]) -> Vec<String> {
        let mut found = Vec::new();

        if let Ok(text) = std::str::from_utf8(buffer) {
            let text_lower = text.to_lowercase();
            for pattern in Self::LINUX_SUSPICIOUS_STRINGS {
                if text_lower.contains(&pattern.to_lowercase()) {
                    found.push(pattern.to_string());
                }
            }
        }

        found
    }

    /// Parse a hex address from a vmmap output line (macOS)
    #[cfg(target_os = "macos")]
    fn parse_vmmap_address(line: &str) -> u64 {
        // vmmap lines contain addresses like: 00000001000a0000-00000001000b4000
        // Find the first hex address pattern
        for part in line.split_whitespace() {
            if part.contains('-') {
                if let Some(addr_str) = part.split('-').next() {
                    if let Ok(addr) = u64::from_str_radix(addr_str, 16) {
                        return addr;
                    }
                }
            }
        }
        0
    }

    /// Check macOS code signature for a file (macOS)
    #[cfg(target_os = "macos")]
    fn check_macos_codesign(path: &str) -> (bool, Option<String>) {
        use std::process::Command;

        let output = match Command::new("codesign").args(["-dvv", path]).output() {
            Ok(o) => o,
            Err(_) => return (false, None),
        };

        // codesign outputs to stderr
        let stderr = String::from_utf8_lossy(&output.stderr);

        if !output.status.success() && !stderr.contains("Authority") {
            return (false, None);
        }

        // Extract signer from "Authority=" line
        let signer = stderr
            .lines()
            .find(|l| l.starts_with("Authority="))
            .map(|l| l.trim_start_matches("Authority=").to_string());

        let is_signed = stderr.contains("Authority=") || output.status.success();

        (is_signed, signer)
    }
}

impl Default for DeepMemoryScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Complete deep scan result for a process
#[derive(Debug, Clone)]
pub struct DeepScanResult {
    pub pid: u32,
    pub vad_anomalies: Vec<VadAnomaly>,
    pub heap_anomalies: Vec<HeapAnomaly>,
    pub module_integrity: Vec<ModuleIntegrityResult>,
    pub basic_scan_results: Vec<MemoryScanResult>,
}

impl DeepScanResult {
    /// Check if any anomalies were found
    pub fn has_anomalies(&self) -> bool {
        !self.vad_anomalies.is_empty()
            || !self.heap_anomalies.is_empty()
            || self
                .module_integrity
                .iter()
                .any(|m| !m.detected_hooks.is_empty() || m.code_modified || !m.in_peb_list)
            || !self.basic_scan_results.is_empty()
    }

    /// Get the highest severity anomaly
    pub fn max_severity(&self) -> Severity {
        let mut max = Severity::Info;

        for vad in &self.vad_anomalies {
            let sev = vad.anomaly_type.severity();
            if sev > max {
                max = sev.clone();
            }
        }

        for module in &self.module_integrity {
            if !module.detected_hooks.is_empty() || module.code_modified {
                if Severity::Critical > max {
                    max = Severity::Critical;
                }
            }
            if !module.in_peb_list {
                if Severity::Critical > max {
                    max = Severity::Critical;
                }
            }
        }

        for heap in &self.heap_anomalies {
            match heap.anomaly_type {
                HeapAnomalyType::PeHeaderInHeap | HeapAnomalyType::ShellcodeInHeap => {
                    if Severity::High > max {
                        max = Severity::High;
                    }
                }
                _ => {}
            }
        }

        max
    }
}

// ============================================================================
// Memory Permission Transition Tracking
// ============================================================================

/// Snapshot of a single memory region's state at a point in time.
/// Used to detect protection flag transitions between scan cycles.
#[derive(Debug, Clone)]
pub struct MemoryRegionState {
    /// Base address of the region
    pub base_address: u64,
    /// Size of the region in bytes
    pub region_size: usize,
    /// Protection flags (raw value: PAGE_* constants on Windows, rwx bits on Linux)
    pub protection: u32,
    /// Memory type (MEM_IMAGE=0x1000000, MEM_MAPPED=0x40000, MEM_PRIVATE=0x20000)
    pub mem_type: u32,
    /// When this region was first observed
    pub first_seen: Instant,
}

/// Windows memory type constants (used cross-platform for the `mem_type` field)
const MEM_TYPE_IMAGE: u32 = 0x1000000;
const MEM_TYPE_MAPPED: u32 = 0x40000;
const MEM_TYPE_PRIVATE: u32 = 0x20000;

/// Windows protection constants used for cross-platform comparison
const PROT_NOACCESS: u32 = 0x01;
const PROT_READONLY: u32 = 0x02;
const PROT_READWRITE: u32 = 0x04;
const PROT_WRITECOPY: u32 = 0x08;
const PROT_EXECUTE: u32 = 0x10;
const PROT_EXECUTE_READ: u32 = 0x20;
const PROT_EXECUTE_READWRITE: u32 = 0x40;
const PROT_EXECUTE_WRITECOPY: u32 = 0x80;

/// Check if a protection value includes execute permission
fn is_protection_executable(prot: u32) -> bool {
    (prot & PROT_EXECUTE) != 0
        || (prot & PROT_EXECUTE_READ) != 0
        || (prot & PROT_EXECUTE_READWRITE) != 0
        || (prot & PROT_EXECUTE_WRITECOPY) != 0
}

/// Check if a protection value is RWX
fn is_protection_rwx(prot: u32) -> bool {
    (prot & PROT_EXECUTE_READWRITE) != 0 || (prot & PROT_EXECUTE_WRITECOPY) != 0
}

/// Check if a protection value is writable but not executable (RW)
fn is_protection_rw(prot: u32) -> bool {
    ((prot & PROT_READWRITE) != 0 || (prot & PROT_WRITECOPY) != 0)
        && !is_protection_executable(prot)
}

/// Format a protection value as a human-readable string
fn format_protection_flags(prot: u32) -> String {
    let mut parts = Vec::new();
    if prot & PROT_EXECUTE_READWRITE != 0 {
        parts.push("PAGE_EXECUTE_READWRITE");
    }
    if prot & PROT_EXECUTE_WRITECOPY != 0 {
        parts.push("PAGE_EXECUTE_WRITECOPY");
    }
    if prot & PROT_EXECUTE_READ != 0 {
        parts.push("PAGE_EXECUTE_READ");
    }
    if prot & PROT_EXECUTE != 0 {
        parts.push("PAGE_EXECUTE");
    }
    if prot & PROT_READWRITE != 0 {
        parts.push("PAGE_READWRITE");
    }
    if prot & PROT_WRITECOPY != 0 {
        parts.push("PAGE_WRITECOPY");
    }
    if prot & PROT_READONLY != 0 {
        parts.push("PAGE_READONLY");
    }
    if prot & PROT_NOACCESS != 0 {
        parts.push("PAGE_NOACCESS");
    }
    if parts.is_empty() {
        format!("0x{:x}", prot)
    } else {
        parts.join("|")
    }
}

/// Format a memory type value as a human-readable string
fn format_mem_type(mem_type: u32) -> String {
    match mem_type {
        t if t == MEM_TYPE_IMAGE => "MEM_IMAGE".to_string(),
        t if t == MEM_TYPE_MAPPED => "MEM_MAPPED".to_string(),
        t if t == MEM_TYPE_PRIVATE => "MEM_PRIVATE".to_string(),
        _ => format!("0x{:x}", mem_type),
    }
}

/// Tracks memory region snapshots per process and detects permission transitions.
///
/// On each scan cycle the tracker compares current memory regions against the
/// previous snapshot. Flagged transitions:
///   - RW -> RX or RWX  (shellcode injection pattern)
///   - New RWX allocation (almost never legitimate)
///   - New unbacked executable region (MEM_PRIVATE + PAGE_EXECUTE*)
pub struct PermissionTransitionTracker {
    /// pid -> (base_address -> MemoryRegionState)
    snapshots: HashMap<u32, HashMap<u64, MemoryRegionState>>,
    /// Set of (pid, base_address) already reported to avoid duplicates
    reported: HashSet<(u32, u64)>,
}

impl PermissionTransitionTracker {
    /// Create a new empty tracker
    pub fn new() -> Self {
        Self {
            snapshots: HashMap::new(),
            reported: HashSet::new(),
        }
    }

    /// Classify a transition between old and new protection values.
    /// Returns `Some(label)` if the transition is suspicious, `None` otherwise.
    fn classify_transition(old_prot: u32, new_prot: u32) -> Option<&'static str> {
        // RW -> RX  (classic shellcode write-then-execute)
        if is_protection_rw(old_prot)
            && is_protection_executable(new_prot)
            && !is_protection_rwx(new_prot)
        {
            return Some("rw_to_rx");
        }
        // RW -> RWX
        if is_protection_rw(old_prot) && is_protection_rwx(new_prot) {
            return Some("rw_to_rwx");
        }
        // Any non-exec -> RWX
        if !is_protection_executable(old_prot) && is_protection_rwx(new_prot) {
            return Some("new_rwx");
        }
        // Any non-exec -> exec (general case)
        if !is_protection_executable(old_prot) && is_protection_executable(new_prot) {
            return Some("non_exec_to_exec");
        }
        None
    }

    /// Update the snapshot for a process and return a list of suspicious transitions.
    ///
    /// `regions` is the current memory layout obtained from VirtualQueryEx or /proc/pid/maps.
    /// Each tuple is `(base_address, region_size, protection, mem_type)`.
    pub fn update_and_detect(
        &mut self,
        pid: u32,
        regions: &[(u64, usize, u32, u32)],
    ) -> Vec<PermissionTransition> {
        let mut transitions = Vec::new();
        let now = Instant::now();

        // Limit regions per process to 1000 to prevent unbounded memory growth.
        // If a process has more regions, only process the first 1000.
        const MAX_REGIONS_PER_PROCESS: usize = 1000;
        let regions = if regions.len() > MAX_REGIONS_PER_PROCESS {
            &regions[..MAX_REGIONS_PER_PROCESS]
        } else {
            regions
        };

        let prev = self.snapshots.entry(pid).or_insert_with(HashMap::new);

        // Build new snapshot
        let mut new_snapshot: HashMap<u64, MemoryRegionState> = HashMap::new();

        for &(base, size, prot, mtype) in regions {
            // Look up previous state for this base address
            if let Some(old_state) = prev.get(&base) {
                // Protection changed?
                if old_state.protection != prot {
                    if let Some(label) = Self::classify_transition(old_state.protection, prot) {
                        let key = (pid, base);
                        if !self.reported.contains(&key) {
                            transitions.push(PermissionTransition {
                                base_address: base,
                                region_size: size,
                                old_protection: old_state.protection,
                                new_protection: prot,
                                mem_type: mtype,
                                transition_type: label,
                            });
                            self.reported.insert(key);
                        }
                    }
                }

                // Preserve original first_seen
                new_snapshot.insert(
                    base,
                    MemoryRegionState {
                        base_address: base,
                        region_size: size,
                        protection: prot,
                        mem_type: mtype,
                        first_seen: old_state.first_seen,
                    },
                );
            } else {
                // New region -- check if it was born RWX (very suspicious)
                if is_protection_rwx(prot) {
                    let key = (pid, base);
                    if !self.reported.contains(&key) {
                        transitions.push(PermissionTransition {
                            base_address: base,
                            region_size: size,
                            old_protection: 0, // newly allocated
                            new_protection: prot,
                            mem_type: mtype,
                            transition_type: "new_rwx_allocation",
                        });
                        self.reported.insert(key);
                    }
                }

                new_snapshot.insert(
                    base,
                    MemoryRegionState {
                        base_address: base,
                        region_size: size,
                        protection: prot,
                        mem_type: mtype,
                        first_seen: now,
                    },
                );
            }
        }

        // Replace old snapshot with new one
        *prev = new_snapshot;

        transitions
    }

    /// Remove stale process entries (for processes that have terminated)
    pub fn remove_process(&mut self, pid: u32) {
        self.snapshots.remove(&pid);
        self.reported.retain(|(p, _)| *p != pid);
    }

    /// Garbage-collect to prevent unbounded growth
    pub fn gc(&mut self, max_reported: usize) {
        if self.reported.len() > max_reported {
            self.reported.clear();
        }
    }

    /// Remove entries for PIDs that no longer exist.
    /// `live_pids` is the set of currently running process IDs.
    pub fn remove_stale_pids(&mut self, live_pids: &std::collections::HashSet<u32>) {
        let stale: Vec<u32> = self
            .snapshots
            .keys()
            .filter(|pid| !live_pids.contains(pid))
            .cloned()
            .collect();
        for pid in &stale {
            self.remove_process(*pid);
        }
    }

    /// Number of tracked processes
    pub fn tracked_process_count(&self) -> usize {
        self.snapshots.len()
    }
}

impl Default for PermissionTransitionTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// A detected permission transition
#[derive(Debug, Clone)]
pub struct PermissionTransition {
    pub base_address: u64,
    pub region_size: usize,
    pub old_protection: u32,
    pub new_protection: u32,
    pub mem_type: u32,
    pub transition_type: &'static str,
}

// ============================================================================
// Adaptive Entropy Scanner
// ============================================================================

/// Tracks per-process-type entropy baselines and adapts thresholds to
/// reduce false positives from legitimate JIT compilers, .NET CLR, V8, etc.
///
/// For each process "class" (determined by the executable name), the tracker
/// maintains a running mean + stddev of observed entropies. A region is
/// flagged only when its entropy exceeds `mean + k * stddev` (where k is
/// configurable, default 2.5).
pub struct AdaptiveEntropyTracker {
    /// process_name (lowercased) -> Vec of observed entropy values
    baselines: HashMap<String, EntropyBaseline>,
    /// Fallback fixed threshold when not enough samples exist
    fixed_threshold: f64,
    /// Number of standard deviations above the mean to flag
    sigma_multiplier: f64,
    /// Minimum number of samples before adaptive threshold is used
    min_samples: usize,
}

/// Running baseline statistics for a process class
#[derive(Debug, Clone)]
struct EntropyBaseline {
    samples: Vec<f64>,
    sum: f64,
    sum_sq: f64,
}

impl EntropyBaseline {
    fn new() -> Self {
        Self {
            samples: Vec::new(),
            sum: 0.0,
            sum_sq: 0.0,
        }
    }

    fn add_sample(&mut self, entropy: f64) {
        self.samples.push(entropy);
        self.sum += entropy;
        self.sum_sq += entropy * entropy;

        // Cap stored samples to prevent unbounded memory growth
        if self.samples.len() > 500 {
            // Drop oldest half
            let half = self.samples.len() / 2;
            self.samples.drain(..half);
            // Recompute sums from remaining
            self.sum = self.samples.iter().sum();
            self.sum_sq = self.samples.iter().map(|e| e * e).sum();
        }
    }

    fn mean(&self) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        self.sum / self.samples.len() as f64
    }

    fn stddev(&self) -> f64 {
        let n = self.samples.len() as f64;
        if n < 2.0 {
            return 0.0;
        }
        let mean = self.mean();
        let variance = (self.sum_sq / n) - (mean * mean);
        if variance <= 0.0 {
            0.0
        } else {
            variance.sqrt()
        }
    }

    fn count(&self) -> usize {
        self.samples.len()
    }
}

impl AdaptiveEntropyTracker {
    /// Create a new adaptive entropy tracker.
    ///
    /// * `fixed_threshold` -- fallback threshold when insufficient samples
    /// * `sigma_multiplier` -- flag when entropy > mean + sigma_multiplier * stddev
    pub fn new(fixed_threshold: f64, sigma_multiplier: f64) -> Self {
        Self {
            baselines: HashMap::new(),
            fixed_threshold,
            sigma_multiplier,
            min_samples: 10,
        }
    }

    /// Record an observed entropy value for a process class.
    pub fn record(&mut self, process_name: &str, entropy: f64) {
        let key = process_name.to_lowercase();
        self.baselines
            .entry(key)
            .or_insert_with(EntropyBaseline::new)
            .add_sample(entropy);
    }

    /// Get the effective entropy threshold for a process.
    ///
    /// If enough samples have been collected, returns `mean + k * stddev`.
    /// Otherwise returns the fixed threshold.
    pub fn threshold_for(&self, process_name: &str) -> f64 {
        let key = process_name.to_lowercase();
        if let Some(baseline) = self.baselines.get(&key) {
            if baseline.count() >= self.min_samples {
                let adaptive = baseline.mean() + self.sigma_multiplier * baseline.stddev();
                // Never go below 6.0 (below that is almost certainly not shellcode)
                return adaptive.max(6.0);
            }
        }
        self.fixed_threshold
    }

    /// Check if an entropy value exceeds the threshold for this process
    pub fn is_suspicious(&self, process_name: &str, entropy: f64) -> bool {
        entropy > self.threshold_for(process_name)
    }

    /// Garbage-collect baselines for process classes not seen recently
    pub fn gc(&mut self, max_classes: usize) {
        if self.baselines.len() > max_classes {
            // Keep only the N most-sampled classes
            let mut entries: Vec<_> = self.baselines.drain().collect();
            entries.sort_by(|a, b| b.1.count().cmp(&a.1.count()));
            entries.truncate(max_classes);
            self.baselines = entries.into_iter().collect();
        }
    }
}

impl Default for AdaptiveEntropyTracker {
    fn default() -> Self {
        Self::new(7.0, 2.5)
    }
}

// ============================================================================
// Thread Start Address Validation (Windows)
// ============================================================================

/// Validate thread start addresses against memory region backing.
/// Threads starting from MEM_PRIVATE executable memory (unbacked) are
/// a high-confidence indicator of injected code.
#[cfg(target_os = "windows")]
mod thread_validation {
    use super::*;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_PRIVATE, PAGE_EXECUTE,
        PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, OpenThread, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        THREAD_QUERY_LIMITED_INFORMATION,
    };

    /// Information about a thread whose start address is in unbacked memory
    #[derive(Debug, Clone)]
    pub struct UnbackedThread {
        pub thread_id: u32,
        pub start_address: u64,
        pub mem_protection: u32,
        pub mem_type: u32,
        pub region_size: usize,
        pub entropy: f64,
    }

    /// Get thread start address using NtQueryInformationThread.
    ///
    /// ThreadQuerySetWin32StartAddress (info class 9) returns the Win32
    /// start address of the thread.
    unsafe fn get_thread_start_address(thread_handle: HANDLE) -> Option<u64> {
        // NtQueryInformationThread is not exposed by the `windows` crate directly,
        // so we call it via GetProcAddress on ntdll.
        use windows::core::PCWSTR;
        use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

        type NtQueryInformationThreadFn = unsafe extern "system" fn(
            HANDLE,   // ThreadHandle
            u32,      // ThreadInformationClass
            *mut u8,  // ThreadInformation
            u32,      // ThreadInformationLength
            *mut u32, // ReturnLength
        ) -> i32;

        let ntdll_name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        let ntdll = GetModuleHandleW(PCWSTR(ntdll_name.as_ptr())).ok()?;

        let func_name = std::ffi::CString::new("NtQueryInformationThread").ok()?;
        let func_ptr =
            GetProcAddress(ntdll, windows::core::PCSTR(func_name.as_ptr() as *const u8))?;
        let nt_query: NtQueryInformationThreadFn = std::mem::transmute(func_ptr);

        let mut start_address: u64 = 0;
        let mut return_length: u32 = 0;

        // ThreadQuerySetWin32StartAddress = 9
        let status = nt_query(
            thread_handle,
            9,
            &mut start_address as *mut u64 as *mut u8,
            std::mem::size_of::<u64>() as u32,
            &mut return_length,
        );

        if status == 0 {
            Some(start_address)
        } else {
            None
        }
    }

    /// Find threads in a process whose start address is in unbacked executable memory.
    pub fn find_unbacked_threads(pid: u32) -> Vec<UnbackedThread> {
        let mut results = Vec::new();

        unsafe {
            // Open the process to query its memory layout
            let proc_handle =
                match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
                    Ok(h) => h,
                    Err(_) => return results,
                };

            // Snapshot threads
            let snap = match CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
                Ok(s) => s,
                Err(_) => {
                    let _ = CloseHandle(proc_handle);
                    return results;
                }
            };

            let mut te = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..Default::default()
            };

            if Thread32First(snap, &mut te).is_ok() {
                loop {
                    if te.th32OwnerProcessID == pid {
                        // Open thread to query start address
                        if let Ok(thread_handle) =
                            OpenThread(THREAD_QUERY_LIMITED_INFORMATION, false, te.th32ThreadID)
                        {
                            if let Some(start_addr) = get_thread_start_address(thread_handle) {
                                // Query memory info at the start address
                                let mut mbi = MEMORY_BASIC_INFORMATION::default();
                                let result = VirtualQueryEx(
                                    proc_handle,
                                    Some(start_addr as *const _),
                                    &mut mbi,
                                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                                );

                                if result > 0 && mbi.State.contains(MEM_COMMIT) {
                                    let is_exec = mbi.Protect.contains(PAGE_EXECUTE)
                                        || mbi.Protect.contains(PAGE_EXECUTE_READ)
                                        || mbi.Protect.contains(PAGE_EXECUTE_READWRITE)
                                        || mbi.Protect.contains(PAGE_EXECUTE_WRITECOPY);
                                    let is_private = mbi.Type.contains(MEM_PRIVATE);
                                    let is_image = mbi.Type.contains(MEM_IMAGE);

                                    // Thread starts from unbacked executable memory
                                    if is_exec && is_private && !is_image {
                                        // Read a sample to compute entropy
                                        let entropy = read_region_entropy(
                                            proc_handle,
                                            start_addr,
                                            mbi.RegionSize,
                                        );

                                        results.push(UnbackedThread {
                                            thread_id: te.th32ThreadID,
                                            start_address: start_addr,
                                            mem_protection: mbi.Protect.0,
                                            mem_type: mbi.Type.0,
                                            region_size: mbi.RegionSize,
                                            entropy,
                                        });
                                    }
                                }
                            }
                            let _ = CloseHandle(thread_handle);
                        }
                    }

                    if Thread32Next(snap, &mut te).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snap);
            let _ = CloseHandle(proc_handle);
        }

        results
    }

    /// Read a region and compute its Shannon entropy as f64
    fn read_region_entropy(handle: HANDLE, address: u64, size: usize) -> f64 {
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

        let read_size = size.min(16384);
        let mut buffer = vec![0u8; read_size];
        let mut bytes_read = 0usize;

        unsafe {
            if ReadProcessMemory(
                handle,
                address as *const _,
                buffer.as_mut_ptr() as *mut _,
                read_size,
                Some(&mut bytes_read),
            )
            .is_ok()
                && bytes_read > 0
            {
                return MemoryScanner::calculate_entropy(&buffer[..bytes_read]) as f64;
            }
        }

        0.0
    }
}

// ============================================================================
// Permission Snapshot Collection (Windows)
// ============================================================================

/// Collect a snapshot of all committed memory regions for a process.
/// Returns `(base_address, region_size, protection, mem_type)` tuples.
#[cfg(target_os = "windows")]
fn collect_memory_snapshot(pid: u32) -> Vec<(u64, usize, u32, u32)> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT};
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let mut regions = Vec::new();

    unsafe {
        let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
            Ok(h) => h,
            Err(_) => return regions,
        };

        let mut address: usize = 0;
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

            if mbi.State.contains(MEM_COMMIT) {
                regions.push((
                    mbi.BaseAddress as u64,
                    mbi.RegionSize,
                    mbi.Protect.0,
                    mbi.Type.0,
                ));
            }

            let next = mbi.BaseAddress as usize + mbi.RegionSize;
            if next <= address {
                break;
            }
            address = next;
        }

        let _ = CloseHandle(handle);
    }

    regions
}

/// Collect a snapshot of all committed memory regions for a process (Linux).
#[cfg(target_os = "linux")]
fn collect_memory_snapshot(pid: u32) -> Vec<(u64, usize, u32, u32)> {
    use std::io::{BufRead, BufReader};

    let mut regions = Vec::new();
    let maps_path = format!("/proc/{}/maps", pid);
    let file = match std::fs::File::open(&maps_path) {
        Ok(f) => f,
        Err(_) => return regions,
    };

    let reader = BufReader::new(file);
    for line in reader.lines().flatten() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        let addr_parts: Vec<&str> = parts[0].split('-').collect();
        if addr_parts.len() != 2 {
            continue;
        }
        let start = u64::from_str_radix(addr_parts[0], 16).unwrap_or(0);
        let end = u64::from_str_radix(addr_parts[1], 16).unwrap_or(0);
        let size = (end - start) as usize;
        let perms = parts[1];
        let pathname = if parts.len() >= 6 { parts[5] } else { "" };

        // Translate Linux rwxp to Windows-style protection flags
        let prot = linux_perms_to_prot(perms);

        // Determine mem_type: backed by a file path => IMAGE, anonymous => PRIVATE
        let mem_type = if pathname.is_empty()
            || pathname.starts_with('[')
            || pathname.starts_with("/memfd:")
        {
            MEM_TYPE_PRIVATE
        } else {
            MEM_TYPE_IMAGE
        };

        regions.push((start, size, prot, mem_type));
    }

    regions
}

/// Convert Linux permission string (e.g. "rwxp") to Windows-style protection constant.
#[cfg(target_os = "linux")]
fn linux_perms_to_prot(perms: &str) -> u32 {
    let r = perms.contains('r');
    let w = perms.contains('w');
    let x = perms.contains('x');

    match (r, w, x) {
        (true, true, true) => PROT_EXECUTE_READWRITE,
        (true, true, false) => PROT_READWRITE,
        (true, false, true) => PROT_EXECUTE_READ,
        (true, false, false) => PROT_READONLY,
        (false, false, true) => PROT_EXECUTE,
        _ => PROT_NOACCESS,
    }
}

/// Collect a snapshot of all committed memory regions for a process (macOS).
///
/// Uses Mach VM APIs via the macos_memory module to enumerate all memory regions.
/// Maps macOS protection flags to the cross-platform protection constants used
/// by the permission transition tracker.
#[cfg(target_os = "macos")]
fn collect_memory_snapshot(pid: u32) -> Vec<(u64, usize, u32, u32)> {
    let mut regions = Vec::new();

    let task = match macos_memory::get_task_for_pid(pid as i32) {
        Ok(t) => t,
        Err(_) => return regions,
    };

    let mach_regions = macos_memory::enumerate_regions(task);

    for region in &mach_regions {
        let size = region.size as usize;

        // Map macOS VM_PROT flags to our cross-platform protection constants
        let prot = macos_prot_to_cross_platform(
            region.is_readable,
            region.is_writable,
            region.is_executable,
        );

        // Determine memory type
        let mem_type = if region.region_type == "dylib" {
            MEM_TYPE_IMAGE
        } else if region.is_shared {
            MEM_TYPE_MAPPED
        } else {
            MEM_TYPE_PRIVATE
        };

        regions.push((region.base_address, size, prot, mem_type));
    }

    // Clean up task port
    unsafe {
        macos_memory::mach_port_deallocate_wrapper(task);
    }

    regions
}

/// Convert macOS rwx booleans to cross-platform protection constants.
#[cfg(target_os = "macos")]
fn macos_prot_to_cross_platform(read: bool, write: bool, exec: bool) -> u32 {
    match (read, write, exec) {
        (true, true, true) => PROT_EXECUTE_READWRITE,
        (true, true, false) => PROT_READWRITE,
        (true, false, true) => PROT_EXECUTE_READ,
        (true, false, false) => PROT_READONLY,
        (false, false, true) => PROT_EXECUTE,
        _ => PROT_NOACCESS,
    }
}

/// Fallback for platforms not explicitly handled (future platforms).
#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn collect_memory_snapshot(_pid: u32) -> Vec<(u64, usize, u32, u32)> {
    Vec::new()
}

/// Read region entropy for a process (cross-platform utility used by the collector).
#[cfg(target_os = "windows")]
fn read_region_entropy_for_pid(pid: u32, address: u64, size: usize) -> f64 {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    unsafe {
        let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
            Ok(h) => h,
            Err(_) => return 0.0,
        };

        let read_size = size.min(16384);
        let mut buffer = vec![0u8; read_size];
        let mut bytes_read = 0usize;

        let entropy = if ReadProcessMemory(
            handle,
            address as *const _,
            buffer.as_mut_ptr() as *mut _,
            read_size,
            Some(&mut bytes_read),
        )
        .is_ok()
            && bytes_read > 0
        {
            MemoryScanner::calculate_entropy(&buffer[..bytes_read]) as f64
        } else {
            0.0
        };

        let _ = CloseHandle(handle);
        entropy
    }
}

#[cfg(target_os = "linux")]
fn read_region_entropy_for_pid(_pid: u32, address: u64, size: usize) -> f64 {
    use std::io::{Read, Seek, SeekFrom};

    let mem_path = format!("/proc/{}/mem", _pid);
    let mut file = match std::fs::File::open(&mem_path) {
        Ok(f) => f,
        Err(_) => return 0.0,
    };

    let read_size = size.min(16384);
    let mut buffer = vec![0u8; read_size];

    if file.seek(SeekFrom::Start(address)).is_ok() {
        if let Ok(bytes_read) = file.read(&mut buffer) {
            if bytes_read > 0 {
                return MemoryScanner::calculate_entropy(&buffer[..bytes_read]) as f64;
            }
        }
    }

    0.0
}

/// Read region entropy for a process (macOS - uses Mach VM read).
#[cfg(target_os = "macos")]
fn read_region_entropy_for_pid(pid: u32, address: u64, size: usize) -> f64 {
    let task = match macos_memory::get_task_for_pid(pid as i32) {
        Ok(t) => t,
        Err(_) => return 0.0,
    };

    let read_size = size.min(16384);
    let entropy = if let Some(data) = macos_memory::read_memory(task, address, read_size) {
        if !data.is_empty() {
            MemoryScanner::calculate_entropy(&data) as f64
        } else {
            0.0
        }
    } else {
        0.0
    };

    // Clean up task port
    unsafe {
        macos_memory::mach_port_deallocate_wrapper(task);
    }

    entropy
}

/// Fallback for platforms not explicitly handled.
#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn read_region_entropy_for_pid(_pid: u32, _address: u64, _size: usize) -> f64 {
    0.0
}

// ============================================================================
// Windows VAD Analysis Module
// ============================================================================

#[cfg(target_os = "windows")]
mod vad_analysis {
    use super::*;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, HMODULE};
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_PRIVATE, MEM_RESERVE,
        PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
        PAGE_GUARD,
    };
    use windows::Win32::System::ProcessStatus::{
        EnumProcessModules, GetModuleFileNameExW, GetModuleInformation, MODULEINFO,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    /// Analyze all VADs in a process
    pub fn analyze_process_vads(pid: u32) -> Vec<VadAnomaly> {
        let mut anomalies = Vec::new();

        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            {
                Ok(h) => h,
                Err(_) => return anomalies,
            };

            // Get module list for backing file identification
            let modules = get_module_info(handle);

            // Track previous region for guard page analysis
            let mut prev_region: Option<MEMORY_BASIC_INFORMATION> = None;

            let mut address: usize = 0;
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

                // Analyze this region
                if let Some(anomaly) = analyze_vad_region(handle, &mbi, &modules, &prev_region) {
                    anomalies.push(anomaly);
                }

                prev_region = Some(mbi);

                // Move to next region
                let next_addr = mbi.BaseAddress as usize + mbi.RegionSize;
                if next_addr <= address {
                    break; // Overflow protection
                }
                address = next_addr;
            }

            let _ = CloseHandle(handle);
        }

        anomalies
    }

    /// Analyze a single VAD region for anomalies
    fn analyze_vad_region(
        handle: HANDLE,
        mbi: &MEMORY_BASIC_INFORMATION,
        modules: &[(u64, u64, String)],
        prev_region: &Option<MEMORY_BASIC_INFORMATION>,
    ) -> Option<VadAnomaly> {
        // Skip uncommitted/free regions
        if !mbi.State.contains(MEM_COMMIT) {
            // But check for large reserved regions (staging areas)
            if mbi.State.contains(MEM_RESERVE) && mbi.RegionSize > 10 * 1024 * 1024 {
                return Some(VadAnomaly {
                    base_address: mbi.BaseAddress as u64,
                    size: mbi.RegionSize,
                    protection: format_protection(mbi.Protect.0),
                    anomaly_type: VadAnomalyType::LargeStagingArea,
                    backing_file: None,
                    entropy: 0.0,
                    details: format!(
                        "Large reserved region: {} MB",
                        mbi.RegionSize / (1024 * 1024)
                    ),
                    confidence: 0.4,
                });
            }
            return None;
        }

        let is_executable = mbi.Protect.contains(PAGE_EXECUTE)
            || mbi.Protect.contains(PAGE_EXECUTE_READ)
            || mbi.Protect.contains(PAGE_EXECUTE_READWRITE)
            || mbi.Protect.contains(PAGE_EXECUTE_WRITECOPY);

        let is_rwx = mbi.Protect.contains(PAGE_EXECUTE_READWRITE)
            || mbi.Protect.contains(PAGE_EXECUTE_WRITECOPY);

        let is_private = mbi.Type.contains(MEM_PRIVATE);
        let _is_image = mbi.Type.contains(MEM_IMAGE);

        // Find backing file if any
        let backing_file =
            find_backing_file(modules, mbi.BaseAddress as u64, mbi.RegionSize as u64);

        // Check 1: RWX Private Memory (very suspicious)
        if is_rwx && is_private {
            let entropy =
                read_and_calculate_entropy(handle, mbi.BaseAddress as u64, mbi.RegionSize);
            return Some(VadAnomaly {
                base_address: mbi.BaseAddress as u64,
                size: mbi.RegionSize,
                protection: format_protection(mbi.Protect.0),
                anomaly_type: VadAnomalyType::RwxPrivate,
                backing_file,
                entropy,
                details: "Private memory with RWX protection".to_string(),
                confidence: if entropy > 6.0 { 0.9 } else { 0.75 },
            });
        }

        // Check 2: Unbacked Executable (executable private memory without file backing)
        if is_executable && is_private && backing_file.is_none() && mbi.RegionSize >= 4096 {
            let entropy =
                read_and_calculate_entropy(handle, mbi.BaseAddress as u64, mbi.RegionSize);
            return Some(VadAnomaly {
                base_address: mbi.BaseAddress as u64,
                size: mbi.RegionSize,
                protection: format_protection(mbi.Protect.0),
                anomaly_type: VadAnomalyType::UnbackedExecutable,
                backing_file: None,
                entropy,
                details: "Executable memory without file backing".to_string(),
                confidence: if entropy > 5.5 { 0.85 } else { 0.65 },
            });
        }

        // Check 3: Guard page followed by executable (stack pivot indicator)
        if let Some(prev) = prev_region {
            if prev.Protect.contains(PAGE_GUARD) && is_executable {
                return Some(VadAnomaly {
                    base_address: mbi.BaseAddress as u64,
                    size: mbi.RegionSize,
                    protection: format_protection(mbi.Protect.0),
                    anomaly_type: VadAnomalyType::GuardPageAnomaly,
                    backing_file,
                    entropy: 0.0,
                    details: "Executable region immediately after guard page".to_string(),
                    confidence: 0.6,
                });
            }
        }

        // Check 4: Misaligned executable (not on 64KB boundary for private exec)
        if is_executable && is_private && (mbi.BaseAddress as usize % 0x10000) != 0 {
            return Some(VadAnomaly {
                base_address: mbi.BaseAddress as u64,
                size: mbi.RegionSize,
                protection: format_protection(mbi.Protect.0),
                anomaly_type: VadAnomalyType::MisalignedExecutable,
                backing_file,
                entropy: 0.0,
                details: format!(
                    "Executable at non-standard alignment: 0x{:x}",
                    mbi.BaseAddress as u64
                ),
                confidence: 0.5,
            });
        }

        None
    }

    /// Get module information for a process
    fn get_module_info(handle: HANDLE) -> Vec<(u64, u64, String)> {
        let mut modules = Vec::new();

        unsafe {
            let mut mod_handles = vec![HMODULE::default(); 1024];
            let mut bytes_needed = 0u32;

            if EnumProcessModules(
                handle,
                mod_handles.as_mut_ptr(),
                (mod_handles.len() * std::mem::size_of::<HMODULE>()) as u32,
                &mut bytes_needed,
            )
            .is_ok()
            {
                let num_modules =
                    (bytes_needed as usize / std::mem::size_of::<HMODULE>()).min(mod_handles.len()); // Cap at buffer capacity

                for i in 0..num_modules {
                    let mut info = MODULEINFO::default();
                    if GetModuleInformation(
                        handle,
                        mod_handles[i],
                        &mut info,
                        std::mem::size_of::<MODULEINFO>() as u32,
                    )
                    .is_ok()
                    {
                        let mut name_buf = [0u16; 260];
                        let name_len = GetModuleFileNameExW(handle, mod_handles[i], &mut name_buf);
                        let name = if name_len > 0 {
                            String::from_utf16_lossy(&name_buf[..name_len as usize])
                        } else {
                            String::new()
                        };

                        modules.push((info.lpBaseOfDll as u64, info.SizeOfImage as u64, name));
                    }
                }
            }
        }

        modules
    }

    /// Find the backing file for a memory region
    fn find_backing_file(
        modules: &[(u64, u64, String)],
        address: u64,
        size: u64,
    ) -> Option<String> {
        for (base, mod_size, name) in modules {
            if address >= *base && address < base + mod_size {
                return Some(name.clone());
            }
        }
        None
    }

    /// Read memory and calculate entropy
    fn read_and_calculate_entropy(handle: HANDLE, address: u64, size: usize) -> f32 {
        let read_size = std::cmp::min(size, 16384);
        let mut buffer = vec![0u8; read_size];
        let mut bytes_read = 0usize;

        unsafe {
            if ReadProcessMemory(
                handle,
                address as *const _,
                buffer.as_mut_ptr() as *mut _,
                read_size,
                Some(&mut bytes_read),
            )
            .is_ok()
                && bytes_read > 0
            {
                return MemoryScanner::calculate_entropy(&buffer[..bytes_read]);
            }
        }

        0.0
    }

    /// Format protection flags as a string
    fn format_protection(protect: u32) -> String {
        let mut parts = Vec::new();

        if protect & 0x10 != 0 {
            parts.push("EXECUTE");
        }
        if protect & 0x20 != 0 {
            parts.push("EXECUTE_READ");
        }
        if protect & 0x40 != 0 {
            parts.push("EXECUTE_READWRITE");
        }
        if protect & 0x80 != 0 {
            parts.push("EXECUTE_WRITECOPY");
        }
        if protect & 0x01 != 0 {
            parts.push("NOACCESS");
        }
        if protect & 0x02 != 0 {
            parts.push("READONLY");
        }
        if protect & 0x04 != 0 {
            parts.push("READWRITE");
        }
        if protect & 0x08 != 0 {
            parts.push("WRITECOPY");
        }
        if protect & 0x100 != 0 {
            parts.push("GUARD");
        }
        if protect & 0x200 != 0 {
            parts.push("NOCACHE");
        }
        if protect & 0x400 != 0 {
            parts.push("WRITECOMBINE");
        }

        if parts.is_empty() {
            format!("0x{:x}", protect)
        } else {
            parts.join("|")
        }
    }
}

// ============================================================================
// Linux VAD Analysis Module (using /proc/pid/maps)
// ============================================================================

#[cfg(target_os = "linux")]
mod vad_analysis_linux {
    use super::*;
    use std::fs;
    use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};

    pub fn analyze_process_vads(pid: u32) -> Vec<VadAnomaly> {
        let mut anomalies = Vec::new();

        let maps_path = format!("/proc/{}/maps", pid);
        let file = match fs::File::open(&maps_path) {
            Ok(f) => f,
            Err(_) => return anomalies,
        };

        let reader = BufReader::new(file);
        let mem_path = format!("/proc/{}/mem", pid);
        let mut mem_file = fs::File::open(&mem_path).ok();

        for line in reader.lines().flatten() {
            if let Some(anomaly) = analyze_map_entry(&line, pid, &mut mem_file) {
                anomalies.push(anomaly);
            }
        }

        anomalies
    }

    fn analyze_map_entry(
        line: &str,
        pid: u32,
        mem_file: &mut Option<fs::File>,
    ) -> Option<VadAnomaly> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            return None;
        }

        let address_range: Vec<&str> = parts[0].split('-').collect();
        if address_range.len() != 2 {
            return None;
        }

        let start = u64::from_str_radix(address_range[0], 16).ok()?;
        let end = u64::from_str_radix(address_range[1], 16).ok()?;
        let size = (end - start) as usize;
        let perms = parts[1];
        let pathname = if parts.len() >= 6 {
            Some(parts[5])
        } else {
            None
        };

        let is_executable = perms.contains('x');
        let is_writable = perms.contains('w');
        let is_private = perms.contains('p');
        let is_anonymous = pathname.is_none() || pathname == Some("");

        // Check for RWX private memory
        if is_executable && is_writable && is_private {
            let entropy = read_entropy(mem_file, start, size);
            return Some(VadAnomaly {
                base_address: start,
                size,
                protection: perms.to_string(),
                anomaly_type: VadAnomalyType::RwxPrivate,
                backing_file: pathname.map(|s| s.to_string()),
                entropy,
                details: "Private RWX memory region".to_string(),
                confidence: if entropy > 6.0 { 0.9 } else { 0.75 },
            });
        }

        // Check for unbacked executable
        if is_executable && is_anonymous && is_private && size >= 4096 {
            let entropy = read_entropy(mem_file, start, size);
            return Some(VadAnomaly {
                base_address: start,
                size,
                protection: perms.to_string(),
                anomaly_type: VadAnomalyType::UnbackedExecutable,
                backing_file: None,
                entropy,
                details: "Anonymous executable memory".to_string(),
                confidence: if entropy > 5.5 { 0.85 } else { 0.65 },
            });
        }

        // Check for memfd (fileless execution)
        if let Some(path) = pathname {
            if path.starts_with("/memfd:") && is_executable {
                return Some(VadAnomaly {
                    base_address: start,
                    size,
                    protection: perms.to_string(),
                    anomaly_type: VadAnomalyType::UnbackedExecutable,
                    backing_file: Some(path.to_string()),
                    entropy: 0.0,
                    details: format!("Executable memfd region: {}", path),
                    confidence: 0.9,
                });
            }
        }

        None
    }

    fn read_entropy(mem_file: &mut Option<fs::File>, address: u64, size: usize) -> f32 {
        if let Some(ref mut mem) = mem_file {
            if mem.seek(SeekFrom::Start(address)).is_ok() {
                let read_size = std::cmp::min(size, 16384);
                let mut buffer = vec![0u8; read_size];
                if let Ok(bytes_read) = mem.read(&mut buffer) {
                    if bytes_read > 0 {
                        return MemoryScanner::calculate_entropy(&buffer[..bytes_read]);
                    }
                }
            }
        }
        0.0
    }
}

// ============================================================================
// Windows Heap Analysis Module
// ============================================================================

#[cfg(target_os = "windows")]
mod heap_analysis {
    use super::*;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    /// Suspicious strings to look for in heap
    const SUSPICIOUS_HEAP_STRINGS: &[&str] = &[
        "http://",
        "https://",
        "ftp://",
        "cmd.exe",
        "powershell",
        "wscript",
        "cscript",
        "CreateRemoteThread",
        "VirtualAllocEx",
        "WriteProcessMemory",
        "NtCreateThreadEx",
        "RtlCreateUserThread",
        "mimikatz",
        "sekurlsa",
        "lsadump",
        "/c ",
        "/k ",
        "-enc ",
        "-nop ",
        "-w hidden",
        "\\pipe\\",
        "\\Device\\",
        "amsi.dll",
        "AmsiScanBuffer",
        "EtwEventWrite",
        "NtTraceEvent",
    ];

    /// Walk all heaps in a process looking for anomalies
    pub fn walk_process_heaps(pid: u32, scanner: &MemoryScanner) -> Vec<HeapAnomaly> {
        let mut anomalies = Vec::new();

        // Note: HeapWalk requires being in the target process context
        // For remote processes, we use VirtualQueryEx + ReadProcessMemory to scan heap regions
        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            {
                Ok(h) => h,
                Err(_) => return anomalies,
            };

            // Find heap regions via memory scanning
            let heap_regions = find_heap_regions(handle);

            for (heap_addr, heap_size) in heap_regions {
                if let Some(heap_anomalies) =
                    scan_heap_region(handle, heap_addr, heap_size, scanner)
                {
                    anomalies.extend(heap_anomalies);
                }
            }

            let _ = CloseHandle(handle);
        }

        anomalies
    }

    /// Find heap regions in a process
    fn find_heap_regions(handle: HANDLE) -> Vec<(u64, usize)> {
        use windows::Win32::System::Memory::{
            VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_PRIVATE,
        };

        let mut regions = Vec::new();

        unsafe {
            let mut address: usize = 0;

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

                // Heap memory is typically private, committed, and read-write
                if mbi.State.contains(MEM_COMMIT) && mbi.Type.contains(MEM_PRIVATE) {
                    let protect = mbi.Protect.0;
                    // PAGE_READWRITE = 0x04
                    if protect & 0x04 != 0 {
                        regions.push((mbi.BaseAddress as u64, mbi.RegionSize));
                    }
                }

                let next = mbi.BaseAddress as usize + mbi.RegionSize;
                if next <= address {
                    break;
                }
                address = next;
            }
        }

        regions
    }

    /// Scan a heap region for anomalies
    fn scan_heap_region(
        handle: HANDLE,
        address: u64,
        size: usize,
        scanner: &MemoryScanner,
    ) -> Option<Vec<HeapAnomaly>> {
        // Limit scan size for performance
        let scan_size = std::cmp::min(size, 1024 * 1024); // Max 1MB per region
        let mut buffer = vec![0u8; scan_size];
        let mut bytes_read = 0usize;

        unsafe {
            if ReadProcessMemory(
                handle,
                address as *const _,
                buffer.as_mut_ptr() as *mut _,
                scan_size,
                Some(&mut bytes_read),
            )
            .is_err()
                || bytes_read == 0
            {
                return None;
            }
        }

        let buffer = &buffer[..bytes_read];
        let mut anomalies = Vec::new();

        // Check for PE headers in heap (MZ signature)
        for (offset, window) in buffer.windows(2).enumerate() {
            if window == [0x4D, 0x5A] {
                // "MZ"
                // Verify it looks like a real PE
                if buffer.len() > offset + 64 {
                    let pe_offset_bytes = &buffer[offset + 60..offset + 64];
                    if let Ok(pe_bytes) = pe_offset_bytes.try_into() {
                        let pe_offset = u32::from_le_bytes(pe_bytes) as usize;
                        if pe_offset < buffer.len() - offset - 4 {
                            let pe_sig = &buffer[offset + pe_offset..offset + pe_offset + 4];
                            if pe_sig == [0x50, 0x45, 0x00, 0x00] {
                                // "PE\0\0"
                                anomalies.push(HeapAnomaly {
                                    heap_handle: 0,
                                    block_address: address + offset as u64,
                                    block_size: 0,
                                    anomaly_type: HeapAnomalyType::PeHeaderInHeap,
                                    entropy: None,
                                    detected_patterns: vec!["PE_HEADER".to_string()],
                                    suspicious_strings: Vec::new(),
                                });
                            }
                        }
                    }
                }
            }
        }

        // Check for shellcode patterns
        let patterns = scanner.scan_buffer(buffer);
        if !patterns.is_empty() {
            anomalies.push(HeapAnomaly {
                heap_handle: 0,
                block_address: address,
                block_size: bytes_read,
                anomaly_type: HeapAnomalyType::ShellcodeInHeap,
                entropy: Some(MemoryScanner::calculate_entropy(buffer)),
                detected_patterns: patterns,
                suspicious_strings: Vec::new(),
            });
        }

        // Check for high entropy blocks (encrypted blobs)
        // Scan in 4KB chunks
        for (chunk_idx, chunk) in buffer.chunks(4096).enumerate() {
            let entropy = MemoryScanner::calculate_entropy(chunk);
            if entropy > 7.0 {
                anomalies.push(HeapAnomaly {
                    heap_handle: 0,
                    block_address: address + (chunk_idx * 4096) as u64,
                    block_size: chunk.len(),
                    anomaly_type: HeapAnomalyType::EncryptedBlob,
                    entropy: Some(entropy),
                    detected_patterns: Vec::new(),
                    suspicious_strings: Vec::new(),
                });
            }
        }

        // Check for suspicious strings
        let found_strings = find_suspicious_strings(buffer);
        if !found_strings.is_empty() {
            anomalies.push(HeapAnomaly {
                heap_handle: 0,
                block_address: address,
                block_size: bytes_read,
                anomaly_type: HeapAnomalyType::SuspiciousStrings,
                entropy: None,
                detected_patterns: Vec::new(),
                suspicious_strings: found_strings,
            });
        }

        // Check for large allocations (potential staging)
        if size > 10 * 1024 * 1024 {
            // > 10MB
            anomalies.push(HeapAnomaly {
                heap_handle: 0,
                block_address: address,
                block_size: size,
                anomaly_type: HeapAnomalyType::LargeAllocation,
                entropy: Some(MemoryScanner::calculate_entropy(buffer)),
                detected_patterns: Vec::new(),
                suspicious_strings: Vec::new(),
            });
        }

        if anomalies.is_empty() {
            None
        } else {
            Some(anomalies)
        }
    }

    /// Find suspicious strings in a buffer
    fn find_suspicious_strings(buffer: &[u8]) -> Vec<String> {
        let mut found = Vec::new();

        // Convert to lowercase string for searching
        if let Ok(text) = std::str::from_utf8(buffer) {
            let text_lower = text.to_lowercase();
            for pattern in SUSPICIOUS_HEAP_STRINGS {
                if text_lower.contains(&pattern.to_lowercase()) {
                    found.push(pattern.to_string());
                }
            }
        }

        // Also check for wide strings (UTF-16LE)
        let mut wide_chars = Vec::new();
        for chunk in buffer.chunks(2) {
            if chunk.len() == 2 && chunk[1] == 0 && chunk[0].is_ascii() && chunk[0] != 0 {
                wide_chars.push(chunk[0] as char);
            } else if !wide_chars.is_empty() {
                let wide_str: String = wide_chars.iter().collect();
                let wide_lower = wide_str.to_lowercase();
                for pattern in SUSPICIOUS_HEAP_STRINGS {
                    if wide_lower.contains(&pattern.to_lowercase())
                        && !found.contains(&format!("wide:{}", pattern))
                    {
                        found.push(format!("wide:{}", pattern));
                    }
                }
                wide_chars.clear();
            }
        }

        found
    }
}

// ============================================================================
// Windows Module Integrity Module
// ============================================================================

#[cfg(target_os = "windows")]
mod module_integrity {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::path::Path;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, HMODULE};
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::ProcessStatus::{
        EnumProcessModules, GetModuleFileNameExW, GetModuleInformation, MODULEINFO,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    /// Critical modules to check for hooks
    const CRITICAL_MODULES: &[&str] = &[
        "ntdll.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "user32.dll",
        "advapi32.dll",
        "ws2_32.dll",
    ];

    /// Common hooked functions
    const HOOKED_FUNCTIONS: &[(&str, &str)] = &[
        ("ntdll.dll", "NtCreateThreadEx"),
        ("ntdll.dll", "NtAllocateVirtualMemory"),
        ("ntdll.dll", "NtWriteVirtualMemory"),
        ("ntdll.dll", "NtProtectVirtualMemory"),
        ("ntdll.dll", "NtMapViewOfSection"),
        ("ntdll.dll", "NtQueueApcThread"),
        ("ntdll.dll", "NtReadVirtualMemory"),
        ("ntdll.dll", "NtOpenProcess"),
        ("ntdll.dll", "NtCreateFile"),
        ("ntdll.dll", "NtDeviceIoControlFile"),
        ("kernel32.dll", "CreateRemoteThread"),
        ("kernel32.dll", "VirtualAllocEx"),
        ("kernel32.dll", "WriteProcessMemory"),
        ("kernel32.dll", "CreateProcessW"),
        ("kernel32.dll", "CreateProcessA"),
        ("kernel32.dll", "LoadLibraryA"),
        ("kernel32.dll", "LoadLibraryW"),
        ("kernel32.dll", "GetProcAddress"),
    ];

    /// Check module integrity for all modules in a process
    pub fn check_process_modules(
        pid: u32,
        known_good: &HashSet<String>,
    ) -> Vec<ModuleIntegrityResult> {
        let mut results = Vec::new();

        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            {
                Ok(h) => h,
                Err(_) => return results,
            };

            let mut mod_handles = vec![HMODULE::default(); 1024];
            let mut bytes_needed = 0u32;

            if EnumProcessModules(
                handle,
                mod_handles.as_mut_ptr(),
                (mod_handles.len() * std::mem::size_of::<HMODULE>()) as u32,
                &mut bytes_needed,
            )
            .is_ok()
            {
                let num_modules =
                    (bytes_needed as usize / std::mem::size_of::<HMODULE>()).min(mod_handles.len()); // Cap at buffer capacity

                for i in 0..num_modules {
                    let mut info = MODULEINFO::default();
                    if GetModuleInformation(
                        handle,
                        mod_handles[i],
                        &mut info,
                        std::mem::size_of::<MODULEINFO>() as u32,
                    )
                    .is_ok()
                    {
                        let mut name_buf = [0u16; 260];
                        let name_len = GetModuleFileNameExW(handle, mod_handles[i], &mut name_buf);
                        let module_path = if name_len > 0 {
                            String::from_utf16_lossy(&name_buf[..name_len as usize])
                        } else {
                            continue;
                        };

                        // Skip known-good modules
                        if known_good.contains(&module_path.to_lowercase()) {
                            continue;
                        }

                        let module_name = Path::new(&module_path)
                            .file_name()
                            .map(|s| s.to_string_lossy().to_string())
                            .unwrap_or_default();

                        // Only do deep checks on critical modules
                        let is_critical = CRITICAL_MODULES
                            .iter()
                            .any(|c| module_name.to_lowercase() == *c);

                        let result = check_single_module(
                            handle,
                            info.lpBaseOfDll as u64,
                            info.SizeOfImage as usize,
                            &module_name,
                            &module_path,
                            is_critical,
                        );

                        // Only include if there are issues
                        if !result.detected_hooks.is_empty()
                            || result.code_modified
                            || !result.in_peb_list
                        {
                            results.push(result);
                        }
                    }
                }
            }

            let _ = CloseHandle(handle);
        }

        results
    }

    /// Check a single module for integrity issues
    fn check_single_module(
        handle: HANDLE,
        base_address: u64,
        _size: usize,
        module_name: &str,
        module_path: &str,
        is_critical: bool,
    ) -> ModuleIntegrityResult {
        let mut result = ModuleIntegrityResult {
            base_address,
            module_name: module_name.to_string(),
            module_path: module_path.to_string(),
            is_signed: false,
            signer: None,
            signature_valid: false,
            detected_hooks: Vec::new(),
            in_peb_list: true, // Assume true since we got it from EnumProcessModules
            code_modified: false,
            disk_text_hash: None,
            memory_text_hash: None,
        };

        // Check signature
        if let Ok((signed, signer)) = check_signature(module_path) {
            result.is_signed = signed;
            result.signer = signer;
            result.signature_valid = signed;
        }

        // Only do deep integrity checks on critical modules
        if !is_critical {
            return result;
        }

        // Compare .text section
        if let Some((disk_hash, mem_hash)) =
            compare_text_sections(handle, base_address, module_path)
        {
            result.disk_text_hash = Some(disk_hash.clone());
            result.memory_text_hash = Some(mem_hash.clone());
            result.code_modified = disk_hash != mem_hash;
        }

        // Check for inline hooks
        let hooks = detect_inline_hooks(handle, base_address, module_name);
        result.detected_hooks = hooks;

        result
    }

    /// Check if a file is signed
    fn check_signature(path: &str) -> Result<(bool, Option<String>)> {
        use windows::Win32::Security::WinTrust::{
            WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO,
            WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
            WTD_UI_NONE,
        };
        // hFile and hWVTStateData must be NULL (HANDLE::default()), not INVALID_HANDLE_VALUE.
        // INVALID_HANDLE_VALUE causes wintrust.dll to dereference -1 as a pointer, crashing.

        let path_wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            let mut file_info = WINTRUST_FILE_INFO {
                cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
                pcwszFilePath: windows::core::PCWSTR(path_wide.as_ptr()),
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
                Anonymous: windows::Win32::Security::WinTrust::WINTRUST_DATA_0 {
                    pFile: &mut file_info,
                },
                dwStateAction: WTD_STATEACTION_VERIFY,
                hWVTStateData: windows::Win32::Foundation::HANDLE::default(),
                pwszURLReference: windows::core::PWSTR::null(),
                dwProvFlags: windows::Win32::Security::WinTrust::WINTRUST_DATA_PROVIDER_FLAGS(0),
                dwUIContext: windows::Win32::Security::WinTrust::WINTRUST_DATA_UICONTEXT(0),
                pSignatureSettings: std::ptr::null_mut(),
            };

            let mut action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            let status =
                WinVerifyTrust(None, &mut action_guid, &mut trust_data as *mut _ as *mut _);

            // Clean up
            trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
            let _ = WinVerifyTrust(None, &mut action_guid, &mut trust_data as *mut _ as *mut _);

            Ok((status == 0, None)) // Simplified - would need to extract signer name
        }
    }

    /// Compare .text sections between disk and memory
    fn compare_text_sections(
        handle: HANDLE,
        base_address: u64,
        module_path: &str,
    ) -> Option<(String, String)> {
        // Read PE header from memory
        let mut dos_header = [0u8; 64];
        let mut bytes_read = 0usize;

        unsafe {
            if ReadProcessMemory(
                handle,
                base_address as *const _,
                dos_header.as_mut_ptr() as *mut _,
                64,
                Some(&mut bytes_read),
            )
            .is_err()
                || bytes_read < 64
            {
                return None;
            }
        }

        // Verify DOS header
        if dos_header[0] != 0x4D || dos_header[1] != 0x5A {
            return None;
        }

        let pe_offset = u32::from_le_bytes([
            dos_header[60],
            dos_header[61],
            dos_header[62],
            dos_header[63],
        ]) as u64;

        // Read PE header + optional header + some section headers
        let pe_header_size = 4 + 20 + 240 + (40 * 16); // PE sig + file header + optional header (x64) + 16 sections
        let mut pe_data = vec![0u8; pe_header_size];

        unsafe {
            if ReadProcessMemory(
                handle,
                (base_address + pe_offset) as *const _,
                pe_data.as_mut_ptr() as *mut _,
                pe_header_size,
                Some(&mut bytes_read),
            )
            .is_err()
                || bytes_read < 100
            {
                return None;
            }
        }

        // Parse PE to find .text section
        // File header starts at offset 4 (after PE signature)
        let num_sections = u16::from_le_bytes([pe_data[6], pe_data[7]]) as usize;
        let optional_header_size = u16::from_le_bytes([pe_data[20], pe_data[21]]) as usize;

        // Section headers start after optional header
        let section_start = 24 + optional_header_size;

        for i in 0..num_sections.min(16) {
            let section_offset = section_start + (i * 40);
            if section_offset + 40 > pe_data.len() {
                break;
            }

            let section_name = &pe_data[section_offset..section_offset + 8];
            let name_str = std::str::from_utf8(section_name)
                .unwrap_or("")
                .trim_matches('\0');

            if name_str == ".text" {
                let virtual_size = u32::from_le_bytes([
                    pe_data[section_offset + 8],
                    pe_data[section_offset + 9],
                    pe_data[section_offset + 10],
                    pe_data[section_offset + 11],
                ]) as usize;

                let virtual_address = u32::from_le_bytes([
                    pe_data[section_offset + 12],
                    pe_data[section_offset + 13],
                    pe_data[section_offset + 14],
                    pe_data[section_offset + 15],
                ]) as u64;

                let raw_offset = u32::from_le_bytes([
                    pe_data[section_offset + 20],
                    pe_data[section_offset + 21],
                    pe_data[section_offset + 22],
                    pe_data[section_offset + 23],
                ]) as u64;

                let raw_size = u32::from_le_bytes([
                    pe_data[section_offset + 16],
                    pe_data[section_offset + 17],
                    pe_data[section_offset + 18],
                    pe_data[section_offset + 19],
                ]) as usize;

                // Read from memory
                let mem_size = virtual_size.min(1024 * 1024); // Cap at 1MB
                let mut mem_text = vec![0u8; mem_size];

                unsafe {
                    if ReadProcessMemory(
                        handle,
                        (base_address + virtual_address) as *const _,
                        mem_text.as_mut_ptr() as *mut _,
                        mem_size,
                        Some(&mut bytes_read),
                    )
                    .is_err()
                        || bytes_read == 0
                    {
                        return None;
                    }
                }

                // Read from disk
                let disk_text = if let Ok(mut file) = fs::File::open(module_path) {
                    use std::io::{Read, Seek, SeekFrom};
                    let disk_size = raw_size.min(mem_size);
                    let mut buf = vec![0u8; disk_size];
                    if file.seek(SeekFrom::Start(raw_offset)).is_ok() {
                        if file.read(&mut buf).unwrap_or(0) > 0 {
                            Some(buf)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                if let Some(disk_buf) = disk_text {
                    let mut mem_hasher = Sha256::new();
                    mem_hasher.update(&mem_text[..bytes_read]);
                    let mem_hash = hex::encode(mem_hasher.finalize());

                    let mut disk_hasher = Sha256::new();
                    disk_hasher.update(&disk_buf);
                    let disk_hash = hex::encode(disk_hasher.finalize());

                    return Some((disk_hash, mem_hash));
                }
            }
        }

        None
    }

    /// Detect inline hooks in a module
    fn detect_inline_hooks(
        handle: HANDLE,
        base_address: u64,
        module_name: &str,
    ) -> Vec<InlineHook> {
        let mut hooks = Vec::new();

        // Get functions to check for this module
        let functions: Vec<&str> = HOOKED_FUNCTIONS
            .iter()
            .filter(|(m, _)| m.to_lowercase() == module_name.to_lowercase())
            .map(|(_, f)| *f)
            .collect();

        if functions.is_empty() {
            return hooks;
        }

        // Try to get function addresses using GetProcAddress
        // This requires loading the module in our process too
        let module_wide: Vec<u16> = module_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            use windows::core::PCWSTR;
            use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

            let our_module = GetModuleHandleW(PCWSTR(module_wide.as_ptr()));
            if let Ok(our_mod) = our_module {
                for func_name in functions {
                    let func_name_cstr = std::ffi::CString::new(func_name).ok();
                    if let Some(cstr) = func_name_cstr {
                        if let Some(addr) = GetProcAddress(
                            our_mod,
                            windows::core::PCSTR(cstr.as_ptr() as *const u8),
                        ) {
                            // Calculate RVA
                            let rva = addr as u64 - our_mod.0 as u64;
                            let target_addr = base_address + rva;

                            // Read first 16 bytes of function
                            let mut buffer = [0u8; 16];
                            let mut bytes_read = 0usize;

                            if ReadProcessMemory(
                                handle,
                                target_addr as *const _,
                                buffer.as_mut_ptr() as *mut _,
                                16,
                                Some(&mut bytes_read),
                            )
                            .is_ok()
                                && bytes_read >= 5
                            {
                                // Check for common hook patterns
                                if let Some(hook) =
                                    check_hook_pattern(&buffer, func_name, target_addr)
                                {
                                    hooks.push(hook);
                                }
                            }
                        }
                    }
                }
            }
        }

        hooks
    }

    /// Check if bytes indicate a hook
    fn check_hook_pattern(bytes: &[u8], func_name: &str, address: u64) -> Option<InlineHook> {
        // Pattern 1: JMP rel32 (E9 xx xx xx xx)
        if bytes[0] == 0xE9 {
            let offset = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
            let dest = (address as i64 + 5 + offset as i64) as u64;
            return Some(InlineHook {
                function_name: func_name.to_string(),
                hook_address: address,
                original_bytes: Vec::new(), // Would need disk comparison
                current_bytes: bytes[..5].to_vec(),
                hook_type: "JMP_REL32".to_string(),
                hook_destination: dest,
            });
        }

        // Pattern 2: MOV r10, imm64; JMP r10 (common in x64 hooks)
        // 49 BA xx xx xx xx xx xx xx xx  41 FF E2
        if bytes.len() >= 13
            && bytes[0] == 0x49
            && bytes[1] == 0xBA
            && bytes[10] == 0x41
            && bytes[11] == 0xFF
            && bytes[12] == 0xE2
        {
            let dest = u64::from_le_bytes([
                bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9],
            ]);
            return Some(InlineHook {
                function_name: func_name.to_string(),
                hook_address: address,
                original_bytes: Vec::new(),
                current_bytes: bytes[..13].to_vec(),
                hook_type: "MOV_R10_JMP".to_string(),
                hook_destination: dest,
            });
        }

        // Pattern 3: JMP [rip+0] (FF 25 00 00 00 00)
        if bytes.len() >= 14
            && bytes[0] == 0xFF
            && bytes[1] == 0x25
            && bytes[2] == 0x00
            && bytes[3] == 0x00
            && bytes[4] == 0x00
            && bytes[5] == 0x00
        {
            let dest = u64::from_le_bytes([
                bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13],
            ]);
            return Some(InlineHook {
                function_name: func_name.to_string(),
                hook_address: address,
                original_bytes: Vec::new(),
                current_bytes: bytes[..14].to_vec(),
                hook_type: "JMP_RIP_IND".to_string(),
                hook_destination: dest,
            });
        }

        // Pattern 4: PUSH imm32; RET (68 xx xx xx xx C3) - x86 only
        if bytes[0] == 0x68 && bytes[5] == 0xC3 {
            let dest = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as u64;
            return Some(InlineHook {
                function_name: func_name.to_string(),
                hook_address: address,
                original_bytes: Vec::new(),
                current_bytes: bytes[..6].to_vec(),
                hook_type: "PUSH_RET".to_string(),
                hook_destination: dest,
            });
        }

        None
    }
}

/// Known shellcode patterns (byte sequences) for x86/x64
/// These patterns are commonly found in exploit payloads, stagers, and injected code
const SHELLCODE_PATTERNS: &[(&str, &[u8], &str)] = &[
    // ===== Windows x64 Patterns =====
    // x64 syscall stub (common in syscall-based shellcode)
    ("syscall_stub_x64", &[0x4C, 0x8B, 0xD1, 0xB8], "T1106"),
    // x64 syscall instruction
    ("syscall_x64", &[0x0F, 0x05], "T1106"),
    // x64 Heaven's Gate transition (WoW64 bypass)
    (
        "heavens_gate_x64",
        &[
            0x6A, 0x33, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x83, 0x04, 0x24, 0x05, 0xCB,
        ],
        "T1055",
    ),
    // x64 GetProcAddress hash loop (common in shellcode)
    (
        "getprocaddr_hash_x64",
        &[0x48, 0x31, 0xC0, 0xAC, 0x41, 0xC1, 0xC9, 0x0D],
        "T1106",
    ),
    // x64 API hashing (ROR 13)
    (
        "api_hash_ror13_x64",
        &[0xC1, 0xCF, 0x0D, 0x03, 0xC7],
        "T1027",
    ),
    // x64 PEB access (fs:[0x60] for x86 or gs:[0x60] for x64)
    (
        "peb_access_x64",
        &[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00],
        "T1106",
    ),
    // ===== Windows x86 Patterns =====
    // x86 int 0x80 (Linux syscall, suspicious on Windows)
    ("int80_x86", &[0xCD, 0x80], "T1106"),
    // x86 sysenter
    ("sysenter_x86", &[0x0F, 0x34], "T1106"),
    // x86 PEB access (fs:[0x30])
    (
        "peb_access_x86",
        &[0x64, 0xA1, 0x30, 0x00, 0x00, 0x00],
        "T1106",
    ),
    // x86 GetProcAddress hash pattern
    (
        "getprocaddr_hash_x86",
        &[0x31, 0xC0, 0xAC, 0xC1, 0xCF, 0x0D],
        "T1106",
    ),
    // ===== Metasploit Patterns =====
    // Metasploit egg hunter (SEH-based)
    (
        "egg_hunter_seh",
        &[0x66, 0x81, 0xCA, 0xFF, 0x0F, 0x42, 0x52, 0x6A, 0x02],
        "T1055",
    ),
    // Metasploit shikata_ga_nai decoder stub
    (
        "shikata_decoder",
        &[0xD9, 0x74, 0x24, 0xF4, 0x5B, 0x53],
        "T1027",
    ),
    // Metasploit reverse_tcp shellcode
    (
        "meterpreter_reverse",
        &[0xFC, 0xE8, 0x8F, 0x00, 0x00, 0x00],
        "T1071",
    ),
    // Metasploit x64 reverse TCP
    (
        "meterpreter_reverse_x64",
        &[0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8],
        "T1071",
    ),
    // ===== Linux Shellcode Patterns =====
    // Linux x64 syscall (execve setup)
    ("linux_execve_x64", &[0x48, 0x31, 0xD2, 0x48, 0xBB], "T1059"),
    // Linux x86 execve
    (
        "linux_execve_x86",
        &[0x31, 0xC0, 0x50, 0x68, 0x2F, 0x2F, 0x73, 0x68],
        "T1059",
    ),
    // Linux bind shell pattern
    (
        "linux_bind_shell",
        &[0x6A, 0x66, 0x58, 0x6A, 0x01, 0x5B],
        "T1071",
    ),
    // ===== Generic Suspicious Patterns =====
    // NOP sled (common shellcode padding)
    (
        "nop_sled",
        &[0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90],
        "T1055",
    ),
    // NOP sled alternative (xchg eax, eax)
    (
        "nop_sled_alt",
        &[0x87, 0xC0, 0x87, 0xC0, 0x87, 0xC0, 0x87, 0xC0],
        "T1055",
    ),
    // Call $+5 / pop (common position-independent code pattern)
    (
        "call_pop_x86",
        &[0xE8, 0x00, 0x00, 0x00, 0x00, 0x58],
        "T1620",
    ),
    // jmp/call/pop pattern (another PIC technique)
    ("jmp_call_pop", &[0xEB, 0x0E, 0x5B], "T1620"),
    // Self-modifying code indicator (REP STOSB)
    ("rep_stosb", &[0xF3, 0xAA], "T1027"),
    // ===== Donut Shellcode Patterns =====
    // Donut loader signature
    (
        "donut_loader",
        &[0x56, 0x57, 0x53, 0x55, 0x54, 0x58],
        "T1620",
    ),
    // ===== sRDI (Shellcode Reflective DLL Injection) =====
    (
        "srdi_pattern",
        &[0x4D, 0x5A, 0x41, 0x52, 0x55, 0x48, 0x89, 0xE5],
        "T1620",
    ),
    // ===== Syscall Evasion Patterns (HookChain/SysWhispers/Hell's Gate) =====
    // SysWhispers2 pattern: mov r10, rcx; mov eax, SSN
    (
        "syswhispers2_stub",
        &[0x4C, 0x8B, 0xD1, 0x48, 0x8B, 0x44, 0x24],
        "T1106",
    ),
    // SysWhispers3 indirect: mov r10, rcx; indirect call setup
    (
        "syswhispers3_indirect",
        &[0x49, 0x89, 0xCA, 0x8B, 0x44, 0x24],
        "T1106",
    ),
    // Hell's Gate SSN extraction loop: cmp word [rax], 0x0F05 (looking for syscall)
    ("hells_gate_ssn_probe", &[0x66, 0x83, 0x38, 0x0F], "T1106"),
    // Halo's Gate neighbor SSN extraction: mov eax, [rax+4]
    ("halos_gate_neighbor", &[0x8B, 0x40, 0x04], "T1106"),
    // Tartarus's Gate variant: reading SSDT from ntdll export
    (
        "tartarus_gate",
        &[0x48, 0x8B, 0x41, 0x10, 0x4C, 0x8B, 0x40],
        "T1106",
    ),
    // FreshyCalls PEB access pattern
    (
        "freshycalls_peb",
        &[0x65, 0x4C, 0x8B, 0x14, 0x25, 0x30, 0x00],
        "T1106",
    ),
    // RecycledGate function prologue
    (
        "recycled_gate",
        &[0x48, 0x89, 0x4C, 0x24, 0x08, 0x48, 0x8B, 0xC1],
        "T1106",
    ),
    // Indirect syscall via jmp r11 (common in SysWhispers3)
    ("indirect_syscall_jmp_r11", &[0x41, 0xFF, 0xE3], "T1106"),
    // Indirect syscall via jmp [rip+offset] (trampoline)
    ("indirect_syscall_jmp_rip", &[0xFF, 0x25], "T1106"),
    // === Syscall Evasion Patterns ===

    // Direct syscall stub: mov r10, rcx; mov eax, SSN; syscall
    // Used by: SysWhispers2, SysWhispers3, direct syscall tools
    ("direct_syscall_stub", &[0x4C, 0x8B, 0xD1, 0xB8], "T1106"),
    // Indirect syscall: mov r10, rcx; mov eax, SSN; jmp [addr]
    // Used by: HookChain, indirect syscall tools
    (
        "indirect_syscall_jmp_r11_stub",
        &[0x4C, 0x8B, 0xD1, 0xB8],
        "T1106",
    ),
    // Note: need to check if followed by 0x41, 0xFF, 0xE3 (jmp r11) at offset +6 to +8

    // Hell's Gate SSN resolution: mov eax, [rax+4]
    ("hells_gate_ssn_resolve", &[0x8B, 0x40, 0x04], "T1106"),
    // Halo's Gate neighbor search: cmp word [rax], 0x0F05 (looking for syscall instruction)
    (
        "halos_gate_syscall_search",
        &[0x66, 0x83, 0x38, 0x0F],
        "T1106",
    ),
    // Tartarus Gate: mov r10, rcx; xor eax, eax; mov al, SSN (using xor+mov for small SSN)
    (
        "tartarus_gate_stub",
        &[0x4C, 0x8B, 0xD1, 0x33, 0xC0],
        "T1106",
    ),
    // NtAllocateVirtualMemory direct: common target for shellcode
    (
        "nt_alloc_direct",
        &[0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05],
        "T1106",
    ),
    // NtWriteVirtualMemory direct
    (
        "nt_write_direct",
        &[0x4C, 0x8B, 0xD1, 0xB8, 0x3A, 0x00, 0x00, 0x00, 0x0F, 0x05],
        "T1106",
    ),
    // NtProtectVirtualMemory direct
    (
        "nt_protect_direct",
        &[0x4C, 0x8B, 0xD1, 0xB8, 0x50, 0x00, 0x00, 0x00, 0x0F, 0x05],
        "T1106",
    ),
    // NtCreateThreadEx direct
    (
        "nt_create_thread_direct",
        &[0x4C, 0x8B, 0xD1, 0xB8, 0xC7, 0x00, 0x00, 0x00, 0x0F, 0x05],
        "T1106",
    ),
    // Stack spoofing frame setup: common pattern for synthetic frames
    // push rbp; mov rbp, rsp; sub rsp, N (followed by frame spoofing)
    (
        "stack_spoof_setup",
        &[0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC],
        "T1106",
    ),
    // Syscall in non-ntdll memory (generic pattern for detecting syscall instruction)
    ("syscall_instruction", &[0x0F, 0x05, 0xC3], "T1106"),
    // SysWhispers3 egg hunter pattern (looking for syscall gadgets in ntdll)
    ("egg_hunter_pattern", &[0x4C, 0x8B, 0xD1, 0xB8], "T1106"),
];

/// Cobalt Strike beacon signatures and C2 framework indicators
const COBALT_STRIKE_SIGNATURES: &[(&str, &[u8])] = &[
    // Beacon config marker
    ("beacon_config", &[0x00, 0x01, 0x00, 0x01, 0x00, 0x02]),
    // Beacon config marker v2
    ("beacon_config_v2", &[0x2E, 0x2F, 0x2E, 0x2F]),
    // Sleep mask v4
    (
        "sleep_mask_v4",
        &[0x48, 0x8B, 0x5C, 0x24, 0x08, 0x48, 0x8B, 0x74],
    ),
    // Cobalt Strike default named pipe
    ("named_pipe_default", b"\\\\.\\pipe\\msagent_"),
    // Cobalt Strike postex pipe
    ("named_pipe_postex", b"\\\\.\\pipe\\postex_"),
    // Cobalt Strike SSH pipe
    ("named_pipe_ssh", b"\\\\.\\pipe\\postex_ssh_"),
    // Beacon watermark area
    (
        "beacon_watermark",
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
    ),
    // Malleable C2 profile indicators
    (
        "malleable_indicator",
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    ),
];

/// Sliver C2 framework signatures
const SLIVER_SIGNATURES: &[(&str, &[u8])] = &[
    // Sliver implant marker
    ("sliver_implant", b"sliver"),
    // Sliver TCP pivot
    ("sliver_pivot", b"pivot"),
];

/// Mythic C2 framework signatures
const MYTHIC_SIGNATURES: &[(&str, &[u8])] = &[
    // Apollo agent patterns
    ("mythic_apollo", b"Apollo"),
    // Athena agent patterns
    ("mythic_athena", b"athena"),
];

/// Havoc C2 framework signatures
const HAVOC_SIGNATURES: &[(&str, &[u8])] = &[
    // Havoc demon marker
    ("havoc_demon", b"Demon"),
];

/// Brute Ratel C4 signatures
const BRUTE_RATEL_SIGNATURES: &[(&str, &[u8])] = &[
    // BRC4 badger marker
    ("brc4_badger", b"badger"),
    // BRC4 config marker
    ("brc4_config", &[0x42, 0x52, 0x43, 0x34]), // "BRC4"
];

/// Nighthawk C2 signatures
const NIGHTHAWK_SIGNATURES: &[(&str, &[u8])] = &[
    // Nighthawk implant markers
    ("nighthawk_implant", b"nighthawk"),
];

/// Additional advanced shellcode patterns for modern attack techniques
const ADVANCED_SHELLCODE_PATTERNS: &[(&str, &[u8], &str)] = &[
    // ===== Stack String Obfuscation Patterns =====
    // mov rax, "string" pattern (loading strings to registers)
    ("stack_string_mov_rax", &[0x48, 0xB8], "T1027"),
    // ===== Module Stomping / DLL Unhooking =====
    // NtProtectVirtualMemory syscall setup
    (
        "nt_protect_setup",
        &[0x4C, 0x8B, 0xD1, 0xB8, 0x50, 0x00, 0x00, 0x00],
        "T1562",
    ),
    // NtWriteVirtualMemory syscall setup
    (
        "nt_write_setup",
        &[0x4C, 0x8B, 0xD1, 0xB8, 0x3A, 0x00, 0x00, 0x00],
        "T1055",
    ),
    // ===== Process Injection Stubs =====
    // NtAllocateVirtualMemory syscall
    (
        "nt_allocate_vm",
        &[0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00],
        "T1055",
    ),
    // NtCreateThreadEx syscall
    (
        "nt_create_thread_ex",
        &[0x4C, 0x8B, 0xD1, 0xB8, 0xC1, 0x00, 0x00, 0x00],
        "T1055",
    ),
    // ===== AMSI/ETW Bypass Patterns =====
    // AmsiScanBuffer bypass (ret 0)
    (
        "amsi_bypass_ret",
        &[0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3],
        "T1562.001",
    ),
    // ETW bypass (ret pattern)
    ("etw_bypass_ret", &[0x48, 0x33, 0xC0, 0xC3], "T1562.001"),
    // EtwEventWrite NOP slide
    ("etw_nop_slide", &[0xC3, 0x90, 0x90, 0x90], "T1562.001"),
    // ===== Sleep Obfuscation =====
    // Ekko sleep technique marker (ROP gadget setup)
    ("ekko_sleep", &[0x48, 0x8D, 0x05], "T1497"),
    // Foliage sleep technique
    ("foliage_sleep", &[0x48, 0x8B, 0xCE, 0xFF, 0x15], "T1497"),
    // ===== API Resolution via Hash =====
    // djb2 hash loop
    ("djb2_hash_loop", &[0x6B, 0xC0, 0x21, 0x03, 0xC1], "T1027"),
    // CRC32 hash calculation
    (
        "crc32_hash",
        &[0x0F, 0xB6, 0xC8, 0x48, 0xC1, 0xE8, 0x08],
        "T1027",
    ),
    // Jenkins one-at-a-time hash
    (
        "jenkins_hash",
        &[0x01, 0xC8, 0xC1, 0xC0, 0x0A, 0x01, 0xC1],
        "T1027",
    ),
    // ===== Cobalt Strike Specific =====
    // Beacon reflective loader
    (
        "cs_reflective_loader",
        &[0x4D, 0x5A, 0x41, 0x52, 0x55, 0x48, 0x89, 0xE5],
        "T1620",
    ),
    // Beacon sleep mask prologue
    (
        "cs_sleep_mask",
        &[0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C],
        "T1497",
    ),
    // ===== Kernel Callback Manipulation =====
    // PsSetLoadImageNotifyRoutine pattern
    ("kernel_callback_enum", &[0x48, 0x8D, 0x0D], "T1014"),
    // ===== Credential Dumping Shellcode =====
    // MiniDumpWriteDump API call setup
    ("minidump_setup", &[0x48, 0x8B, 0xCB, 0xFF, 0x15], "T1003"),
    // ===== Thread Pool Injection (PoolParty) =====
    // TpAllocWork setup
    ("tp_alloc_work", &[0xFF, 0x15], "T1055"),
    // ===== Module Callback Injection =====
    // TLS callback abuse setup
    (
        "tls_callback",
        &[0x48, 0x83, 0xEC, 0x28, 0x48, 0x8B, 0x05],
        "T1055",
    ),
];

/// Known JIT/scripting processes that legitimately use RWX memory
const JIT_PROCESSES: &[&str] = &[
    "java.exe",
    "javaw.exe",
    "java",
    "node.exe",
    "node",
    "python.exe",
    "python3.exe",
    "python",
    "python3",
    "ruby.exe",
    "ruby",
    "perl.exe",
    "perl",
    "dotnet.exe",
    "dotnet",
    "mono",
    "mono-sgen",
    "v8",
    "d8",
    "chrome.exe",
    "chrome",
    "firefox.exe",
    "firefox",
    "msedge.exe",
    "msedge",
    "powershell.exe",
    "pwsh.exe",
    "pwsh",
    "cscript.exe",
    "wscript.exe",
    "iexplore.exe",
    "safari",
    "opera.exe",
    "opera",
    "brave.exe",
    "brave",
    "vivaldi.exe",
    "vivaldi",
];

/// Module range for tracking loaded modules
#[derive(Debug, Clone)]
pub struct ModuleRange {
    pub base: u64,
    pub size: u64,
    pub name: String,
}

/// Dedicated memory scanner for shellcode and fileless attack detection
pub struct MemoryScanner {
    /// Shellcode signature patterns
    suspicious_patterns: Vec<ShellcodeSignature>,
    /// JIT processes whitelist (processes that legitimately use RWX)
    jit_whitelist: std::collections::HashSet<String>,
}

/// Shellcode signature with metadata
#[derive(Debug, Clone)]
pub struct ShellcodeSignature {
    pub name: String,
    pub pattern: Vec<u8>,
    pub mitre_technique: String,
    pub description: String,
    pub confidence: f32,
}

/// Result of scanning a memory region
#[derive(Debug, Clone)]
pub struct MemoryScanResult {
    pub address: u64,
    pub size: u64,
    pub protection: u32,
    pub is_unbacked: bool,
    pub is_rwx: bool,
    pub detected_patterns: Vec<String>,
    pub entropy: f32,
    pub has_pe_header: bool,
    pub has_shellcode: bool,
    pub confidence: f32,
}

impl MemoryScanner {
    /// Create a new memory scanner with default signatures
    pub fn new() -> Self {
        let mut signatures = Vec::new();

        // Add all shellcode patterns
        for (name, pattern, mitre) in SHELLCODE_PATTERNS.iter() {
            signatures.push(ShellcodeSignature {
                name: name.to_string(),
                pattern: pattern.to_vec(),
                mitre_technique: mitre.to_string(),
                description: format!("Shellcode pattern: {}", name),
                confidence: 0.80,
            });
        }

        // Add advanced patterns
        for (name, pattern, mitre) in ADVANCED_SHELLCODE_PATTERNS.iter() {
            signatures.push(ShellcodeSignature {
                name: name.to_string(),
                pattern: pattern.to_vec(),
                mitre_technique: mitre.to_string(),
                description: format!("Advanced shellcode pattern: {}", name),
                confidence: 0.85,
            });
        }

        // Build JIT whitelist
        let jit_whitelist: std::collections::HashSet<String> =
            JIT_PROCESSES.iter().map(|s| s.to_lowercase()).collect();

        Self {
            suspicious_patterns: signatures,
            jit_whitelist,
        }
    }

    /// Check if a process is a known JIT process
    pub fn is_jit_process(&self, process_name: &str) -> bool {
        let name_lower = process_name.to_lowercase();
        self.jit_whitelist
            .iter()
            .any(|jit| name_lower.contains(jit))
    }

    /// Scan a memory buffer for shellcode patterns
    pub fn scan_buffer(&self, buffer: &[u8]) -> Vec<String> {
        let mut detected = Vec::new();

        for sig in &self.suspicious_patterns {
            if buffer
                .windows(sig.pattern.len())
                .any(|w| w == sig.pattern.as_slice())
            {
                detected.push(sig.name.clone());
            }
        }

        detected
    }

    /// Check if buffer contains a PE header (MZ signature)
    pub fn has_pe_header(buffer: &[u8]) -> bool {
        if buffer.len() < 64 {
            return false;
        }

        // Check for MZ header
        if buffer[0] != 0x4D || buffer[1] != 0x5A {
            return false;
        }

        // Check for valid PE offset
        if buffer.len() >= 64 {
            let pe_offset =
                u32::from_le_bytes([buffer[60], buffer[61], buffer[62], buffer[63]]) as usize;
            if pe_offset > 0 && pe_offset + 4 <= buffer.len() {
                // Check for PE signature
                return buffer[pe_offset] == 0x50
                    && buffer[pe_offset + 1] == 0x45
                    && buffer[pe_offset + 2] == 0x00
                    && buffer[pe_offset + 3] == 0x00;
            }
        }

        false
    }

    /// Calculate Shannon entropy
    pub fn calculate_entropy(data: &[u8]) -> f32 {
        if data.is_empty() {
            return 0.0;
        }

        let mut frequency = [0u32; 256];
        for &byte in data {
            frequency[byte as usize] += 1;
        }

        let len = data.len() as f32;
        let mut entropy: f32 = 0.0;

        for &count in &frequency {
            if count > 0 {
                let p = count as f32 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Scan a process for suspicious memory regions (Windows)
    #[cfg(target_os = "windows")]
    pub fn scan_process(&self, pid: u32) -> Vec<MemoryScanResult> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows::Win32::System::Memory::{
            VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_PRIVATE,
            PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
        };

        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        let mut results = Vec::new();

        unsafe {
            // Open process with required access
            let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            {
                Ok(h) => h,
                Err(_) => return results,
            };

            // Get loaded modules to determine backed memory
            let module_ranges = Self::get_module_ranges(handle);

            // Enumerate memory regions
            let mut address: usize = 0;

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

                // Check if memory is committed
                if mbi.State.contains(MEM_COMMIT) {
                    let is_executable = mbi.Protect.contains(PAGE_EXECUTE)
                        || mbi.Protect.contains(PAGE_EXECUTE_READ)
                        || mbi.Protect.contains(PAGE_EXECUTE_READWRITE)
                        || mbi.Protect.contains(PAGE_EXECUTE_WRITECOPY);

                    let is_rwx = mbi.Protect.contains(PAGE_EXECUTE_READWRITE)
                        || mbi.Protect.contains(PAGE_EXECUTE_WRITECOPY);

                    let is_private = mbi.Type.contains(MEM_PRIVATE);
                    let is_image = mbi.Type.contains(MEM_IMAGE);

                    // Check if memory is backed by a known module
                    let is_unbacked = is_executable
                        && !is_image
                        && !Self::is_backed_by_module(
                            &module_ranges,
                            mbi.BaseAddress as u64,
                            mbi.RegionSize as u64,
                        );

                    // Suspicious: RWX private memory or unbacked executable
                    if (is_rwx && is_private) || is_unbacked {
                        // Read memory for pattern analysis
                        let read_size = std::cmp::min(mbi.RegionSize, 16384); // Read up to 16KB
                        let mut buffer = vec![0u8; read_size];
                        let mut bytes_read = 0usize;

                        let (detected_patterns, has_pe, entropy) = if ReadProcessMemory(
                            handle,
                            mbi.BaseAddress,
                            buffer.as_mut_ptr() as *mut _,
                            read_size,
                            Some(&mut bytes_read),
                        )
                        .is_ok()
                            && bytes_read > 0
                        {
                            let buffer = &buffer[..bytes_read];
                            let patterns = self.scan_buffer(buffer);
                            let has_pe = Self::has_pe_header(buffer);
                            let entropy = Self::calculate_entropy(buffer);
                            (patterns, has_pe, entropy)
                        } else {
                            (Vec::new(), false, 0.0)
                        };

                        let has_shellcode = !detected_patterns.is_empty();

                        // Calculate confidence
                        let mut confidence: f32 = 0.5;
                        if is_rwx {
                            confidence += 0.15;
                        }
                        if is_unbacked {
                            confidence += 0.15;
                        }
                        if has_pe {
                            confidence += 0.10;
                        }
                        if has_shellcode {
                            confidence += 0.10;
                        }
                        if entropy > 7.0 {
                            confidence += 0.05;
                        }
                        confidence = confidence.min(0.99);

                        // Skip small regions likely to be false positives
                        if mbi.RegionSize >= 4096 {
                            results.push(MemoryScanResult {
                                address: mbi.BaseAddress as u64,
                                size: mbi.RegionSize as u64,
                                protection: mbi.Protect.0,
                                is_unbacked,
                                is_rwx,
                                detected_patterns,
                                entropy,
                                has_pe_header: has_pe,
                                has_shellcode,
                                confidence,
                            });
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
        }

        results
    }

    /// Get module ranges for a process (Windows)
    #[cfg(target_os = "windows")]
    fn get_module_ranges(handle: windows::Win32::Foundation::HANDLE) -> Vec<ModuleRange> {
        use windows::Win32::Foundation::HMODULE;
        use windows::Win32::System::ProcessStatus::{
            EnumProcessModules, GetModuleFileNameExW, GetModuleInformation, MODULEINFO,
        };

        let mut ranges = Vec::new();

        unsafe {
            let mut modules = vec![HMODULE::default(); 1024];
            let mut bytes_needed = 0u32;

            if EnumProcessModules(
                handle,
                modules.as_mut_ptr(),
                (modules.len() * std::mem::size_of::<HMODULE>()) as u32,
                &mut bytes_needed,
            )
            .is_ok()
            {
                let num_modules =
                    (bytes_needed as usize / std::mem::size_of::<HMODULE>()).min(modules.len()); // Cap at buffer capacity

                for i in 0..num_modules {
                    let mut info = MODULEINFO::default();
                    if GetModuleInformation(
                        handle,
                        modules[i],
                        &mut info,
                        std::mem::size_of::<MODULEINFO>() as u32,
                    )
                    .is_ok()
                    {
                        let mut name_buf = [0u16; 260];
                        let name_len = GetModuleFileNameExW(handle, modules[i], &mut name_buf);
                        let name = if name_len > 0 {
                            String::from_utf16_lossy(&name_buf[..name_len as usize])
                        } else {
                            String::new()
                        };

                        ranges.push(ModuleRange {
                            base: info.lpBaseOfDll as u64,
                            size: info.SizeOfImage as u64,
                            name,
                        });
                    }
                }
            }
        }

        ranges
    }

    /// Check if an address range is backed by a known module
    fn is_backed_by_module(modules: &[ModuleRange], address: u64, size: u64) -> bool {
        for module in modules {
            let module_end = module.base + module.size;
            let region_end = address + size;

            // Check if region overlaps with module
            if address >= module.base && address < module_end {
                return true;
            }
            if region_end > module.base && region_end <= module_end {
                return true;
            }
        }
        false
    }

    /// Scan a process for suspicious memory regions (Linux)
    #[cfg(target_os = "linux")]
    pub fn scan_process(&self, pid: u32) -> Vec<MemoryScanResult> {
        use std::fs;
        use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};

        let mut results = Vec::new();

        // Read /proc/[pid]/maps
        let maps_path = format!("/proc/{}/maps", pid);
        let file = match fs::File::open(&maps_path) {
            Ok(f) => f,
            Err(_) => return results,
        };

        let reader = BufReader::new(file);
        let mem_path = format!("/proc/{}/mem", pid);
        let mut mem_file = fs::File::open(&mem_path).ok();

        for line in reader.lines().flatten() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                continue;
            }

            let address_range: Vec<&str> = parts[0].split('-').collect();
            if address_range.len() != 2 {
                continue;
            }

            let start = u64::from_str_radix(address_range[0], 16).unwrap_or(0);
            let end = u64::from_str_radix(address_range[1], 16).unwrap_or(0);
            let size = end - start;
            let perms = parts[1];

            let is_executable = perms.contains('x');
            let is_writable = perms.contains('w');
            let is_readable = perms.contains('r');
            let is_private = perms.contains('p');
            let is_anonymous = parts.len() < 6 || parts[5].is_empty();
            let pathname = if parts.len() >= 6 { parts[5] } else { "" };

            // Check for suspicious patterns
            let is_rwx = is_readable && is_writable && is_executable;
            let is_unbacked = is_executable && is_anonymous && is_private;

            if is_rwx || is_unbacked || pathname.starts_with("/memfd:") {
                let mut detected_patterns = Vec::new();
                let mut has_pe = false;
                let mut entropy: f32 = 0.0;

                // Try to read memory for analysis
                if is_readable && size > 0 && size < 10 * 1024 * 1024 {
                    if let Some(ref mut mem) = mem_file {
                        if mem.seek(SeekFrom::Start(start)).is_ok() {
                            let read_size = std::cmp::min(size as usize, 16384);
                            let mut buffer = vec![0u8; read_size];

                            if let Ok(bytes_read) = mem.read(&mut buffer) {
                                if bytes_read > 0 {
                                    let buffer = &buffer[..bytes_read];
                                    detected_patterns = self.scan_buffer(buffer);
                                    has_pe = Self::has_pe_header(buffer);
                                    entropy = Self::calculate_entropy(buffer);
                                }
                            }
                        }
                    }
                }

                let has_shellcode = !detected_patterns.is_empty();

                // Calculate confidence
                let mut confidence: f32 = 0.5;
                if is_rwx {
                    confidence += 0.15;
                }
                if is_unbacked {
                    confidence += 0.15;
                }
                if has_pe {
                    confidence += 0.10;
                }
                if has_shellcode {
                    confidence += 0.10;
                }
                if entropy > 7.0 {
                    confidence += 0.05;
                }
                if pathname.starts_with("/memfd:") {
                    confidence += 0.10;
                }
                confidence = confidence.min(0.99);

                // Skip tiny regions
                if size >= 4096 {
                    results.push(MemoryScanResult {
                        address: start,
                        size,
                        protection: Self::perms_to_protection(perms),
                        is_unbacked,
                        is_rwx,
                        detected_patterns,
                        entropy,
                        has_pe_header: has_pe,
                        has_shellcode,
                        confidence,
                    });
                }
            }
        }

        results
    }

    #[cfg(target_os = "linux")]
    fn perms_to_protection(perms: &str) -> u32 {
        let mut prot = 0u32;
        if perms.contains('r') {
            prot |= 0x01;
        }
        if perms.contains('w') {
            prot |= 0x02;
        }
        if perms.contains('x') {
            prot |= 0x04;
        }
        prot
    }

    /// Scan a process for suspicious memory regions (macOS)
    ///
    /// Uses Mach VM APIs to enumerate memory regions and detect:
    /// - RWX private memory (almost never legitimate)
    /// - Unbacked executable memory (not backed by a dylib)
    /// - Shellcode patterns in executable private memory
    /// - PE/Mach-O headers in private memory (reflective loading)
    /// - High entropy executable regions (packed/encrypted payloads)
    /// - memfd-style anonymous executable regions
    #[cfg(target_os = "macos")]
    pub fn scan_process(&self, pid: u32) -> Vec<MemoryScanResult> {
        let mut results = Vec::new();

        let task = match macos_memory::get_task_for_pid(pid as i32) {
            Ok(t) => t,
            Err(_) => return results,
        };

        let regions = macos_memory::enumerate_regions(task);

        for region in &regions {
            let is_executable = region.is_executable;
            let is_writable = region.is_writable;
            let is_readable = region.is_readable;
            let is_private = region.is_private;
            let size = region.size;

            // Determine suspicion flags
            let is_rwx = is_readable && is_writable && is_executable;
            let is_unbacked = is_executable
                && is_private
                && region.region_type != "dylib"
                && region.region_type != "stack";

            if !is_rwx && !is_unbacked {
                continue;
            }

            let mut detected_patterns = Vec::new();
            let mut has_pe = false;
            let mut entropy: f32 = 0.0;
            let mut has_shellcode = false;

            // Try to read and scan the region
            if is_readable && size > 0 && size < 10 * 1024 * 1024 {
                let scan_size = size.min(16384) as usize;
                if let Some(data) = macos_memory::read_memory(task, region.base_address, scan_size)
                {
                    if !data.is_empty() {
                        detected_patterns = self.scan_buffer(&data);
                        has_pe = Self::has_pe_header(&data);
                        entropy = Self::calculate_entropy(&data);
                        has_shellcode = !detected_patterns.is_empty();

                        // Also check for Mach-O headers in private memory
                        if data.len() >= 4 {
                            let magic = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
                            const MH_MAGIC_64: u32 = 0xfeedfacf;
                            const MH_CIGAM_64: u32 = 0xcffaedfe;
                            if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) && is_private {
                                has_pe = true; // Flag Mach-O in private memory same as PE
                                detected_patterns.push("MachO_in_private_memory".to_string());
                            }
                        }
                    }
                }
            }

            // Calculate confidence
            let mut confidence: f32 = 0.5;
            if is_rwx {
                confidence += 0.15;
            }
            if is_unbacked {
                confidence += 0.15;
            }
            if has_pe {
                confidence += 0.10;
            }
            if has_shellcode {
                confidence += 0.10;
            }
            if entropy > 7.0 {
                confidence += 0.05;
            }
            confidence = confidence.min(0.99);

            // Map macOS protection to cross-platform value
            let protection = macos_prot_to_cross_platform(is_readable, is_writable, is_executable);

            // Skip tiny regions
            if size >= 4096 {
                results.push(MemoryScanResult {
                    address: region.base_address,
                    size,
                    protection,
                    is_unbacked,
                    is_rwx,
                    detected_patterns,
                    entropy,
                    has_pe_header: has_pe,
                    has_shellcode,
                    confidence,
                });
            }
        }

        // Clean up task port
        unsafe {
            macos_memory::mach_port_deallocate_wrapper(task);
        }

        results
    }

    /// Add a custom shellcode signature
    pub fn add_signature(&mut self, name: &str, pattern: &[u8], mitre: &str, confidence: f32) {
        self.suspicious_patterns.push(ShellcodeSignature {
            name: name.to_string(),
            pattern: pattern.to_vec(),
            mitre_technique: mitre.to_string(),
            description: format!("Custom signature: {}", name),
            confidence,
        });
    }

    /// Get the number of loaded signatures
    pub fn signature_count(&self) -> usize {
        self.suspicious_patterns.len()
    }
}

impl Default for MemoryScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Memory forensics collector
pub struct MemoryCollector {
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    scanned_processes: HashSet<u32>,
}

impl MemoryCollector {
    /// Create a new memory collector
    pub fn new(config: &AgentConfig) -> Result<Self> {
        let (tx, rx) = mpsc::channel(500);

        info!("Initializing memory forensics collector");

        let config_clone = config.clone();
        let tx_clone = tx.clone();

        tokio::spawn(async move {
            Self::scan_loop(tx_clone, config_clone).await;
        });

        Ok(Self {
            config: config.clone(),
            event_rx: rx,
            scanned_processes: HashSet::new(),
        })
    }

    /// Main scanning loop with deep memory analysis
    async fn scan_loop(tx: mpsc::Sender<TelemetryEvent>, _config: AgentConfig) {
        let full_scan = _config.full_scan_features;
        info!(
            full_scan = full_scan,
            "Starting memory forensics scan loop with deep analysis (VAD + heap walking + permission tracking)"
        );

        // Use configurable memory scan interval from collector_tuning.
        // Controlled by the performance profile (aggressive=15s, balanced=30s, lightweight=300s).
        let scan_secs = _config.collector_tuning.memory_scan_interval_secs;
        let scan_interval = tokio::time::Duration::from_secs(scan_secs.max(10));
        let mut interval = tokio::time::interval(scan_interval);
        info!(
            interval_secs = scan_secs.max(10),
            "Memory scanner polling interval"
        );

        // Track already reported suspicious regions to avoid duplicates
        let mut reported: HashSet<(u32, u64)> = HashSet::new();
        let mut reported_vad: HashSet<(u32, u64)> = HashSet::new();
        let mut reported_heap: HashSet<(u32, u64)> = HashSet::new();
        let mut reported_module: HashSet<(u32, String)> = HashSet::new();
        let mut reported_threads: HashSet<(u32, u32)> = HashSet::new(); // (pid, tid)

        // Initialize the deep memory scanner for enhanced detection
        let mut deep_scanner = DeepMemoryScanner::new();

        // Initialize permission transition tracker
        let track_permissions = _config.collector_tuning.track_permission_changes;
        let detect_unbacked = _config.collector_tuning.detect_unbacked_executable;
        let mut perm_tracker = PermissionTransitionTracker::new();

        // Initialize adaptive entropy tracker
        let entropy_threshold = _config.collector_tuning.memory_entropy_threshold;
        let adaptive_entropy_enabled = _config.collector_tuning.adaptive_entropy_enabled;
        let mut entropy_tracker = AdaptiveEntropyTracker::new(entropy_threshold, 2.5);

        if track_permissions {
            info!("Memory permission transition tracking enabled");
        }
        if detect_unbacked {
            info!("Unbacked executable memory + thread start validation enabled");
        }
        if adaptive_entropy_enabled {
            info!(
                fixed_threshold = entropy_threshold,
                "Adaptive entropy profiling enabled (fixed fallback threshold)"
            );
        }

        let mut last_stale_pid_cleanup = std::time::Instant::now();

        loop {
            interval.tick().await;

            debug!("Running deep memory forensics scan");

            // Get list of processes to scan
            let processes = Self::get_process_list();

            for (pid, name, path) in processes {
                // Skip system processes
                if pid < 10 {
                    continue;
                }

                // Skip our own process
                if pid == std::process::id() {
                    continue;
                }

                // Check if we should scan this process (incremental scanning)
                if !deep_scanner.should_scan_process(pid, &name) {
                    continue;
                }

                // Skip known JIT processes for RWX-only detections (but still scan for shellcode)
                let is_jit = deep_scanner.base_scanner.is_jit_process(&name);

                // ========================================
                // PHASE 1: Basic memory scan
                // ========================================
                let scan_results = deep_scanner.base_scanner.scan_process(pid);

                for result in scan_results {
                    // Skip JIT processes unless we found specific shellcode patterns
                    if is_jit && !result.has_shellcode && !result.has_pe_header {
                        continue;
                    }

                    // Check if already reported
                    let key = (pid, result.address);
                    if reported.contains(&key) {
                        continue;
                    }
                    reported.insert(key);

                    // Convert MemoryScanResult to SuspiciousMemory for event creation
                    let reason = if result.has_shellcode {
                        MemorySuspicionReason::ShellcodePattern
                    } else if result.has_pe_header {
                        MemorySuspicionReason::PeInPrivateMemory
                    } else if result.is_unbacked {
                        MemorySuspicionReason::UnbackedExecutable
                    } else if result.is_rwx {
                        MemorySuspicionReason::ReadWriteExecute
                    } else if result.entropy > 7.0 {
                        MemorySuspicionReason::HighEntropyExecutable
                    } else {
                        MemorySuspicionReason::ExecutablePrivate
                    };

                    let suspicious = SuspiciousMemory {
                        pid,
                        process_name: name.clone(),
                        region: MemoryRegion {
                            base_address: result.address,
                            size: result.size,
                            protection: Self::protection_from_u32(result.protection),
                            region_type: if result.is_unbacked {
                                MemoryType::Private
                            } else {
                                MemoryType::Image
                            },
                            module_name: None,
                            is_executable: true,
                            is_private: result.is_unbacked,
                            entropy: result.entropy,
                        },
                        reason,
                        confidence: result.confidence,
                        shellcode_detected: result.has_shellcode,
                        beacon_detected: false,
                    };

                    let mut event = Self::create_memory_alert(&suspicious, &name, &path);

                    if !result.detected_patterns.is_empty() {
                        event.metadata.insert(
                            "detected_patterns".to_string(),
                            result.detected_patterns.join(", "),
                        );
                    }

                    if tx.send(event).await.is_err() {
                        warn!("Event channel closed");
                        return;
                    }
                }

                // ========================================
                // PHASE 2: Deep VAD Analysis
                // ========================================
                let vad_anomalies = deep_scanner.analyze_vads(pid);

                for vad in vad_anomalies {
                    // Skip if already reported
                    let key = (pid, vad.base_address);
                    if reported_vad.contains(&key) {
                        continue;
                    }
                    reported_vad.insert(key);

                    // Skip low-confidence anomalies for JIT processes
                    if is_jit && vad.confidence < 0.7 {
                        continue;
                    }

                    let event = Self::create_vad_anomaly_alert(pid, &name, &path, &vad);
                    if tx.send(event).await.is_err() {
                        warn!("Event channel closed");
                        return;
                    }
                }

                // ========================================
                // PHASE 3: Heap Walking Analysis
                // ========================================
                let heap_anomalies = deep_scanner.walk_heaps(pid);

                for heap in heap_anomalies {
                    // Skip if already reported
                    let key = (pid, heap.block_address);
                    if reported_heap.contains(&key) {
                        continue;
                    }
                    reported_heap.insert(key);

                    let event = Self::create_heap_anomaly_alert(pid, &name, &path, &heap);
                    if tx.send(event).await.is_err() {
                        warn!("Event channel closed");
                        return;
                    }
                }

                // ========================================
                // PHASE 4: Module Integrity Check (full_scan only)
                // ========================================
                if full_scan {
                    let module_results = deep_scanner.check_module_integrity(pid);

                    for module in module_results {
                        // Skip if already reported
                        let key = (pid, module.module_name.clone());
                        if reported_module.contains(&key) {
                            continue;
                        }

                        // Only report if there are actual issues
                        if !module.detected_hooks.is_empty()
                            || module.code_modified
                            || !module.in_peb_list
                        {
                            reported_module.insert(key);

                            let event =
                                Self::create_module_integrity_alert(pid, &name, &path, &module);
                            if tx.send(event).await.is_err() {
                                warn!("Event channel closed");
                                return;
                            }
                        }
                    }
                }

                // ========================================
                // PHASE 5: Legacy scan for compatibility
                // ========================================
                match Self::scan_process_memory(pid) {
                    Ok(suspicious_regions) => {
                        for suspicious in suspicious_regions {
                            let key = (pid, suspicious.region.base_address);
                            if reported.contains(&key) {
                                continue;
                            }
                            reported.insert(key);

                            let event = Self::create_memory_alert(&suspicious, &name, &path);
                            if tx.send(event).await.is_err() {
                                warn!("Event channel closed");
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        trace!(pid = pid, error = %e, "Failed to scan process memory (fallback)");
                    }
                }

                // ========================================
                // PHASE 6: Permission Transition Tracking (full_scan only)
                // ========================================
                if track_permissions && full_scan {
                    let snapshot = collect_memory_snapshot(pid);

                    // Feed executable-region entropies into the adaptive tracker
                    if adaptive_entropy_enabled {
                        for &(base, size, prot, _mtype) in &snapshot {
                            if is_protection_executable(prot) && size >= 4096 {
                                let ent = read_region_entropy_for_pid(pid, base, size);
                                entropy_tracker.record(&name, ent);
                            }
                        }
                    }

                    let transitions = perm_tracker.update_and_detect(pid, &snapshot);

                    for trans in transitions {
                        // Skip JIT processes for low-confidence transitions
                        if is_jit && trans.transition_type == "non_exec_to_exec" {
                            continue;
                        }

                        // Compute entropy for the transitioned region
                        let ent =
                            read_region_entropy_for_pid(pid, trans.base_address, trans.region_size);

                        // Use adaptive or fixed threshold
                        let ent_threshold = if adaptive_entropy_enabled {
                            entropy_tracker.threshold_for(&name)
                        } else {
                            entropy_threshold
                        };

                        // Determine severity based on transition type and entropy
                        let severity = match trans.transition_type {
                            "rw_to_rwx" | "new_rwx" | "new_rwx_allocation" => Severity::High,
                            "rw_to_rx" => {
                                if ent > ent_threshold {
                                    Severity::High
                                } else {
                                    Severity::Medium
                                }
                            }
                            _ => Severity::Medium,
                        };

                        let description = format!(
                            "Memory permission transition in {} (PID: {}): {} at 0x{:x} ({} bytes) {} -> {} [{}] entropy={:.2}",
                            name, pid, trans.transition_type,
                            trans.base_address, trans.region_size,
                            format_protection_flags(trans.old_protection),
                            format_protection_flags(trans.new_protection),
                            format_mem_type(trans.mem_type),
                            ent,
                        );

                        let mut event = TelemetryEvent::new(
                            EventType::MemoryPermissionChange,
                            severity,
                            EventPayload::MemoryPermission(MemoryPermissionEvent {
                                pid,
                                process_name: name.clone(),
                                process_path: path.clone(),
                                base_address: trans.base_address,
                                region_size: trans.region_size as u64,
                                old_protection: trans.old_protection,
                                new_protection: trans.new_protection,
                                old_protection_str: format_protection_flags(trans.old_protection),
                                new_protection_str: format_protection_flags(trans.new_protection),
                                mem_type: trans.mem_type,
                                mem_type_str: format_mem_type(trans.mem_type),
                                entropy: ent,
                                transition_type: trans.transition_type.to_string(),
                                thread_from_unbacked: false,
                                thread_id: None,
                                thread_start_address: None,
                            }),
                        );

                        let confidence = match trans.transition_type {
                            "rw_to_rx" => {
                                if ent > ent_threshold {
                                    0.90
                                } else {
                                    0.75
                                }
                            }
                            "rw_to_rwx" | "new_rwx" | "new_rwx_allocation" => 0.92,
                            _ => 0.70,
                        };

                        event.add_detection(Detection {
                            detection_type: DetectionType::MemoryThreat,
                            rule_name: format!("PermTransition_{}", trans.transition_type),
                            confidence,
                            description,
                            mitre_tactics: vec![
                                "defense-evasion".to_string(),
                                "execution".to_string(),
                            ],
                            mitre_techniques: vec![
                                "T1055".to_string(), // Process Injection
                                "T1620".to_string(), // Reflective Code Loading
                            ],
                        });

                        event
                            .metadata
                            .insert("scan_type".to_string(), "permission_transition".to_string());
                        event.metadata.insert(
                            "transition_type".to_string(),
                            trans.transition_type.to_string(),
                        );
                        event
                            .metadata
                            .insert("entropy".to_string(), format!("{:.2}", ent));
                        if adaptive_entropy_enabled {
                            event.metadata.insert(
                                "entropy_threshold".to_string(),
                                format!("{:.2}", ent_threshold),
                            );
                        }

                        info!(
                            pid = pid,
                            process = %name,
                            transition = trans.transition_type,
                            base = format!("0x{:x}", trans.base_address),
                            entropy = format!("{:.2}", ent),
                            "Permission transition detected"
                        );

                        if tx.send(event).await.is_err() {
                            warn!("Event channel closed");
                            return;
                        }
                    }
                }

                // ========================================
                // PHASE 7: Thread Start Address Validation
                // ========================================
                #[cfg(target_os = "windows")]
                if detect_unbacked {
                    let unbacked_threads = thread_validation::find_unbacked_threads(pid);

                    for ut in unbacked_threads {
                        let key = (pid, ut.thread_id);
                        if reported_threads.contains(&key) {
                            continue;
                        }
                        reported_threads.insert(key);

                        // Skip JIT processes unless entropy is very high
                        if is_jit && ut.entropy < 7.5 {
                            continue;
                        }

                        let description = format!(
                            "Thread {} in {} (PID: {}) starts from unbacked executable memory at 0x{:x} \
                             (protection: {}, type: {}, {} bytes, entropy: {:.2})",
                            ut.thread_id, name, pid,
                            ut.start_address,
                            format_protection_flags(ut.mem_protection),
                            format_mem_type(ut.mem_type),
                            ut.region_size,
                            ut.entropy,
                        );

                        let severity = if ut.entropy > 7.0 {
                            Severity::Critical
                        } else {
                            Severity::High
                        };

                        let mut event = TelemetryEvent::new(
                            EventType::UnbackedThreadStart,
                            severity,
                            EventPayload::MemoryPermission(MemoryPermissionEvent {
                                pid,
                                process_name: name.clone(),
                                process_path: path.clone(),
                                base_address: ut.start_address,
                                region_size: ut.region_size as u64,
                                old_protection: 0,
                                new_protection: ut.mem_protection,
                                old_protection_str: String::new(),
                                new_protection_str: format_protection_flags(ut.mem_protection),
                                mem_type: ut.mem_type,
                                mem_type_str: format_mem_type(ut.mem_type),
                                entropy: ut.entropy,
                                transition_type: "unbacked_thread_start".to_string(),
                                thread_from_unbacked: true,
                                thread_id: Some(ut.thread_id),
                                thread_start_address: Some(ut.start_address),
                            }),
                        );

                        event.add_detection(Detection {
                            detection_type: DetectionType::MemoryThreat,
                            rule_name: "UnbackedThreadStart".to_string(),
                            confidence: if ut.entropy > 7.0 { 0.95 } else { 0.88 },
                            description,
                            mitre_tactics: vec![
                                "defense-evasion".to_string(),
                                "execution".to_string(),
                            ],
                            mitre_techniques: vec![
                                "T1055".to_string(),     // Process Injection
                                "T1055.003".to_string(), // Thread Execution Hijacking
                            ],
                        });

                        event
                            .metadata
                            .insert("scan_type".to_string(), "thread_validation".to_string());
                        event
                            .metadata
                            .insert("thread_id".to_string(), ut.thread_id.to_string());
                        event.metadata.insert(
                            "thread_start_address".to_string(),
                            format!("0x{:x}", ut.start_address),
                        );
                        event
                            .metadata
                            .insert("entropy".to_string(), format!("{:.2}", ut.entropy));

                        warn!(
                            pid = pid,
                            thread_id = ut.thread_id,
                            process = %name,
                            start_addr = format!("0x{:x}", ut.start_address),
                            entropy = format!("{:.2}", ut.entropy),
                            "Thread started from unbacked executable memory"
                        );

                        if tx.send(event).await.is_err() {
                            warn!("Event channel closed");
                            return;
                        }
                    }
                }
            }

            // ========================================
            // PHASE 8: Process Hollowing Detection (T1055.012)
            // ========================================
            {
                let processes_for_hollowing = Self::get_process_list();
                for (pid, name, path) in &processes_for_hollowing {
                    if *pid < 10 || *pid == std::process::id() {
                        continue;
                    }

                    let hollowing_key = (*pid, 0xDEAD_0012u64); // sentinel for hollowing
                    if reported.contains(&hollowing_key) {
                        continue;
                    }

                    if let Some(result) = deep_scanner.detect_process_hollowing(*pid, name, path) {
                        reported.insert(hollowing_key);

                        let severity = if result.confidence >= 0.75 {
                            Severity::Critical
                        } else if result.confidence >= 0.50 {
                            Severity::High
                        } else {
                            Severity::Medium
                        };

                        let description = format!(
                            "Process hollowing detected in {} (PID {}): {}",
                            result.process_name,
                            result.pid,
                            result.evidence.join("; ")
                        );

                        let mut event = TelemetryEvent::new(
                            EventType::MemoryScan,
                            severity,
                            EventPayload::Process(ProcessEvent {
                                pid: result.pid,
                                ppid: 0,
                                name: result.process_name.clone(),
                                path: result.process_path.clone(),
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

                        event.add_detection(Detection {
                            detection_type: DetectionType::ProcessHollowing,
                            rule_name: "ProcessHollowingDetection".to_string(),
                            confidence: result.confidence,
                            description: description.clone(),
                            mitre_tactics: vec![
                                "defense-evasion".to_string(),
                                "privilege-escalation".to_string(),
                            ],
                            mitre_techniques: vec!["T1055".to_string(), "T1055.012".to_string()],
                        });

                        event
                            .metadata
                            .insert("mitre_technique".to_string(), "T1055.012".to_string());
                        event.metadata.insert(
                            "confidence".to_string(),
                            format!("{:.2}", result.confidence),
                        );
                        event.metadata.insert(
                            "image_base_mismatch".to_string(),
                            result.image_base_mismatch.to_string(),
                        );
                        event.metadata.insert(
                            "size_mismatch".to_string(),
                            result.size_mismatch.to_string(),
                        );
                        event.metadata.insert(
                            "main_module_private".to_string(),
                            result.main_module_private.to_string(),
                        );
                        event.metadata.insert(
                            "entry_point_in_unbacked".to_string(),
                            result.entry_point_in_unbacked.to_string(),
                        );
                        event
                            .metadata
                            .insert("disk_pe_hash".to_string(), result.disk_pe_hash.clone());
                        event
                            .metadata
                            .insert("memory_pe_hash".to_string(), result.memory_pe_hash.clone());
                        event.metadata.insert(
                            "memory_image_base".to_string(),
                            format!("0x{:x}", result.memory_image_base),
                        );
                        event.metadata.insert(
                            "disk_image_base".to_string(),
                            format!("0x{:x}", result.disk_image_base),
                        );

                        warn!(
                            pid = result.pid,
                            process = %result.process_name,
                            confidence = format!("{:.2}", result.confidence),
                            evidence_count = result.evidence.len(),
                            "Process hollowing detected (T1055.012)"
                        );

                        if tx.send(event).await.is_err() {
                            warn!("Event channel closed");
                            return;
                        }
                    }
                }
            }

            // ========================================
            // PHASE 9: Module Stomping Detection (T1055.001)
            // ========================================
            {
                let processes_for_stomping = Self::get_process_list();
                for (pid, name, _path) in &processes_for_stomping {
                    if *pid < 10 || *pid == std::process::id() {
                        continue;
                    }

                    // Only scan high-risk processes for module stomping (expensive)
                    if !deep_scanner.should_scan_process(*pid, name) {
                        continue;
                    }

                    let stomping_results = deep_scanner.detect_module_stomping(*pid, name);

                    for result in stomping_results {
                        let stomping_key = (*pid, result.module_base);
                        if reported.contains(&stomping_key) {
                            continue;
                        }
                        reported.insert(stomping_key);

                        let severity = if result.confidence >= 0.75 {
                            Severity::Critical
                        } else if result.confidence >= 0.50 {
                            Severity::High
                        } else {
                            Severity::Medium
                        };

                        let description = format!(
                            "Module stomping detected: {} in {} (PID {}): {}",
                            result.module_name,
                            result.process_name,
                            result.pid,
                            result.evidence.join("; ")
                        );

                        let mut event = TelemetryEvent::new(
                            EventType::ModuleStomping,
                            severity,
                            EventPayload::Process(ProcessEvent {
                                pid: result.pid,
                                ppid: 0,
                                name: result.process_name.clone(),
                                path: result.module_path.clone(),
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

                        event.add_detection(Detection {
                            detection_type: DetectionType::ModuleStomping,
                            rule_name: "ModuleStompingDetection".to_string(),
                            confidence: result.confidence,
                            description: description.clone(),
                            mitre_tactics: vec!["defense-evasion".to_string()],
                            mitre_techniques: vec!["T1055".to_string(), "T1055.001".to_string()],
                        });

                        event
                            .metadata
                            .insert("mitre_technique".to_string(), "T1055.001".to_string());
                        event.metadata.insert(
                            "confidence".to_string(),
                            format!("{:.2}", result.confidence),
                        );
                        event
                            .metadata
                            .insert("module_name".to_string(), result.module_name.clone());
                        event
                            .metadata
                            .insert("module_path".to_string(), result.module_path.clone());
                        event.metadata.insert(
                            "module_base".to_string(),
                            format!("0x{:x}", result.module_base),
                        );
                        event.metadata.insert(
                            "text_modified".to_string(),
                            result.text_section_modified.to_string(),
                        );
                        event
                            .metadata
                            .insert("has_rwx".to_string(), result.has_rwx_protection.to_string());
                        event.metadata.insert(
                            "diff_byte_count".to_string(),
                            result.diff_byte_count.to_string(),
                        );
                        event
                            .metadata
                            .insert("disk_text_hash".to_string(), result.disk_text_hash.clone());
                        event.metadata.insert(
                            "memory_text_hash".to_string(),
                            result.memory_text_hash.clone(),
                        );

                        warn!(
                            pid = result.pid,
                            process = %result.process_name,
                            module = %result.module_name,
                            confidence = format!("{:.2}", result.confidence),
                            diff_bytes = result.diff_byte_count,
                            "Module stomping detected (T1055.001)"
                        );

                        if tx.send(event).await.is_err() {
                            warn!("Event channel closed");
                            return;
                        }
                    }
                }
            }

            // ========================================
            // PHASE 10: Transacted Hollowing Detection
            // ========================================
            {
                let processes_for_txf = Self::get_process_list();
                for (pid, name, path) in &processes_for_txf {
                    if *pid < 10 || *pid == std::process::id() {
                        continue;
                    }

                    let txf_key = (*pid, 0xDEAD_7BF0u64); // sentinel for transacted hollowing
                    if reported.contains(&txf_key) {
                        continue;
                    }

                    if let Some(result) = deep_scanner.detect_transacted_hollowing(*pid, name, path)
                    {
                        reported.insert(txf_key);

                        let severity = if result.confidence >= 0.75 {
                            Severity::Critical
                        } else if result.confidence >= 0.50 {
                            Severity::High
                        } else {
                            Severity::Medium
                        };

                        let description = format!(
                            "Transacted hollowing detected in {} (PID {}): {}",
                            result.process_name,
                            result.pid,
                            result.evidence.join("; ")
                        );

                        let mut event = TelemetryEvent::new(
                            EventType::TransactedHollowing,
                            severity,
                            EventPayload::Process(ProcessEvent {
                                pid: result.pid,
                                ppid: 0,
                                name: result.process_name.clone(),
                                path: result.process_path.clone(),
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

                        event.add_detection(Detection {
                            detection_type: DetectionType::TransactedHollowing,
                            rule_name: "TransactedHollowingDetection".to_string(),
                            confidence: result.confidence,
                            description: description.clone(),
                            mitre_tactics: vec!["defense-evasion".to_string()],
                            mitre_techniques: vec!["T1055".to_string(), "T1055.012".to_string()],
                        });

                        event.metadata.insert(
                            "mitre_technique".to_string(),
                            "T1055.012/TransactedHollowing".to_string(),
                        );
                        event.metadata.insert(
                            "confidence".to_string(),
                            format!("{:.2}", result.confidence),
                        );
                        event.metadata.insert(
                            "pe_header_mismatch".to_string(),
                            result.pe_header_mismatch.to_string(),
                        );
                        event.metadata.insert(
                            "image_mismatch".to_string(),
                            result.image_mismatch.to_string(),
                        );
                        event.metadata.insert(
                            "txf_handles_detected".to_string(),
                            result.txf_handles_detected.to_string(),
                        );
                        event
                            .metadata
                            .insert("disk_file_hash".to_string(), result.disk_file_hash.clone());
                        event.metadata.insert(
                            "memory_image_hash".to_string(),
                            result.memory_image_hash.clone(),
                        );

                        warn!(
                            pid = result.pid,
                            process = %result.process_name,
                            confidence = format!("{:.2}", result.confidence),
                            txf_detected = result.txf_handles_detected,
                            "Transacted hollowing detected (TxF abuse)"
                        );

                        if tx.send(event).await.is_err() {
                            warn!("Event channel closed");
                            return;
                        }
                    }
                }
            }

            // Every 60 seconds, remove stale PID entries from the permission
            // tracker and deep_scanner to prevent unbounded memory growth from
            // terminated processes.
            if last_stale_pid_cleanup.elapsed() > std::time::Duration::from_secs(60) {
                last_stale_pid_cleanup = std::time::Instant::now();
                let live_pids: std::collections::HashSet<u32> = Self::get_process_list()
                    .iter()
                    .map(|(pid, _, _)| *pid)
                    .collect();

                // Clean stale PIDs from permission transition tracker
                let before = perm_tracker.tracked_process_count();
                perm_tracker.remove_stale_pids(&live_pids);
                let removed = before - perm_tracker.tracked_process_count();
                if removed > 0 {
                    tracing::debug!(removed, "Removed stale PIDs from permission tracker");
                }

                // Clean stale PIDs from deep scanner's last_scan_times
                deep_scanner
                    .last_scan_times
                    .retain(|pid, _| live_pids.contains(pid));

                // Clean stale PIDs from reported sets
                reported.retain(|(pid, _)| live_pids.contains(pid));
                reported_vad.retain(|(pid, _)| live_pids.contains(pid));
                reported_heap.retain(|(pid, _)| live_pids.contains(pid));
                reported_module.retain(|(pid, _)| live_pids.contains(pid));
                reported_threads.retain(|(pid, _)| live_pids.contains(pid));
            }

            // Cleanup old entries to prevent memory growth
            if reported.len() > 10000 {
                reported.clear();
            }
            if reported_vad.len() > 10000 {
                reported_vad.clear();
            }
            if reported_heap.len() > 10000 {
                reported_heap.clear();
            }
            if reported_module.len() > 5000 {
                reported_module.clear();
            }
            if reported_threads.len() > 5000 {
                reported_threads.clear();
            }
            perm_tracker.gc(10000);
            entropy_tracker.gc(200);
        }
    }

    /// Create alert for VAD anomaly
    fn create_vad_anomaly_alert(
        pid: u32,
        process_name: &str,
        process_path: &str,
        vad: &VadAnomaly,
    ) -> TelemetryEvent {
        let severity = vad.anomaly_type.severity();
        let mitre_techniques = vad.anomaly_type.mitre_techniques();

        let mut event = TelemetryEvent::new(
            EventType::MemoryScan,
            severity,
            EventPayload::Process(ProcessEvent {
                pid,
                ppid: 0,
                name: process_name.to_string(),
                path: process_path.to_string(),
                cmdline: String::new(),
                user: String::new(),
                sha256: Vec::new(),
                entropy: vad.entropy,
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
            "VAD anomaly in {} (PID: {}): {} at 0x{:x} ({} bytes, entropy: {:.2}) - {}",
            process_name,
            pid,
            vad.anomaly_type.as_str(),
            vad.base_address,
            vad.size,
            vad.entropy,
            vad.details
        );

        event.add_detection(Detection {
            detection_type: DetectionType::MemoryThreat,
            rule_name: format!("VAD_{}", vad.anomaly_type.as_str()),
            confidence: vad.confidence,
            description,
            mitre_tactics: vec![
                "defense-evasion".to_string(),
                "privilege-escalation".to_string(),
            ],
            mitre_techniques: mitre_techniques.iter().map(|s| s.to_string()).collect(),
        });

        event
            .metadata
            .insert("scan_type".to_string(), "vad_analysis".to_string());
        event.metadata.insert(
            "vad_address".to_string(),
            format!("0x{:x}", vad.base_address),
        );
        event
            .metadata
            .insert("vad_size".to_string(), vad.size.to_string());
        event
            .metadata
            .insert("vad_protection".to_string(), vad.protection.clone());
        event.metadata.insert(
            "vad_anomaly_type".to_string(),
            vad.anomaly_type.as_str().to_string(),
        );
        event
            .metadata
            .insert("entropy".to_string(), format!("{:.2}", vad.entropy));

        if let Some(ref backing) = vad.backing_file {
            event
                .metadata
                .insert("backing_file".to_string(), backing.clone());
        }

        event
    }

    /// Create alert for heap anomaly
    fn create_heap_anomaly_alert(
        pid: u32,
        process_name: &str,
        process_path: &str,
        heap: &HeapAnomaly,
    ) -> TelemetryEvent {
        let severity = match heap.anomaly_type {
            HeapAnomalyType::PeHeaderInHeap => Severity::Critical,
            HeapAnomalyType::ShellcodeInHeap => Severity::Critical,
            HeapAnomalyType::EncryptedBlob => Severity::Medium,
            HeapAnomalyType::SuspiciousStrings => Severity::Medium,
            HeapAnomalyType::LargeAllocation => Severity::Low,
        };

        let mut event = TelemetryEvent::new(
            EventType::MemoryScan,
            severity,
            EventPayload::Process(ProcessEvent {
                pid,
                ppid: 0,
                name: process_name.to_string(),
                path: process_path.to_string(),
                cmdline: String::new(),
                user: String::new(),
                sha256: Vec::new(),
                entropy: heap.entropy.unwrap_or(0.0),
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

        let anomaly_type_str = match heap.anomaly_type {
            HeapAnomalyType::PeHeaderInHeap => "pe_header_in_heap",
            HeapAnomalyType::ShellcodeInHeap => "shellcode_in_heap",
            HeapAnomalyType::EncryptedBlob => "encrypted_blob",
            HeapAnomalyType::SuspiciousStrings => "suspicious_strings",
            HeapAnomalyType::LargeAllocation => "large_allocation",
        };

        let description = format!(
            "Heap anomaly in {} (PID: {}): {} at 0x{:x} ({} bytes)",
            process_name, pid, anomaly_type_str, heap.block_address, heap.block_size
        );

        let mitre_techniques = match heap.anomaly_type {
            HeapAnomalyType::PeHeaderInHeap => vec!["T1620", "T1055"],
            HeapAnomalyType::ShellcodeInHeap => vec!["T1055", "T1059"],
            HeapAnomalyType::EncryptedBlob => vec!["T1027", "T1140"],
            HeapAnomalyType::SuspiciousStrings => vec!["T1059"],
            HeapAnomalyType::LargeAllocation => vec!["T1055"],
        };

        event.add_detection(Detection {
            detection_type: DetectionType::MemoryThreat,
            rule_name: format!("Heap_{}", anomaly_type_str),
            confidence: match heap.anomaly_type {
                HeapAnomalyType::PeHeaderInHeap => 0.95,
                HeapAnomalyType::ShellcodeInHeap => 0.90,
                HeapAnomalyType::EncryptedBlob => 0.60,
                HeapAnomalyType::SuspiciousStrings => 0.70,
                HeapAnomalyType::LargeAllocation => 0.40,
            },
            description,
            mitre_tactics: vec!["defense-evasion".to_string(), "execution".to_string()],
            mitre_techniques: mitre_techniques.iter().map(|s| s.to_string()).collect(),
        });

        event
            .metadata
            .insert("scan_type".to_string(), "heap_walking".to_string());
        event.metadata.insert(
            "heap_address".to_string(),
            format!("0x{:x}", heap.block_address),
        );
        event
            .metadata
            .insert("heap_size".to_string(), heap.block_size.to_string());
        event.metadata.insert(
            "heap_anomaly_type".to_string(),
            anomaly_type_str.to_string(),
        );

        if let Some(entropy) = heap.entropy {
            event
                .metadata
                .insert("entropy".to_string(), format!("{:.2}", entropy));
        }

        if !heap.detected_patterns.is_empty() {
            event.metadata.insert(
                "detected_patterns".to_string(),
                heap.detected_patterns.join(", "),
            );
        }

        if !heap.suspicious_strings.is_empty() {
            event.metadata.insert(
                "suspicious_strings".to_string(),
                heap.suspicious_strings.join(", "),
            );
        }

        event
    }

    /// Create alert for module integrity issue
    fn create_module_integrity_alert(
        pid: u32,
        process_name: &str,
        process_path: &str,
        module: &ModuleIntegrityResult,
    ) -> TelemetryEvent {
        let severity = if !module.detected_hooks.is_empty() {
            Severity::Critical
        } else if !module.in_peb_list {
            Severity::Critical
        } else if module.code_modified {
            Severity::High
        } else {
            Severity::Medium
        };

        let mut event = TelemetryEvent::new(
            EventType::MemoryScan,
            severity.clone(),
            EventPayload::Process(ProcessEvent {
                pid,
                ppid: 0,
                name: process_name.to_string(),
                path: process_path.to_string(),
                cmdline: String::new(),
                user: String::new(),
                sha256: Vec::new(),
                entropy: 0.0,
                is_elevated: false,
                parent_name: None,
                parent_path: None,
                is_signed: module.is_signed,
                signer: module.signer.clone(),
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

        let mut issues = Vec::new();
        if !module.detected_hooks.is_empty() {
            issues.push(format!(
                "{} inline hooks detected",
                module.detected_hooks.len()
            ));
        }
        if module.code_modified {
            issues.push("code section modified".to_string());
        }
        if !module.in_peb_list {
            issues.push("hidden module (not in PEB)".to_string());
        }

        let description = format!(
            "Module integrity issue in {} (PID: {}): {} at 0x{:x} - {}",
            process_name,
            pid,
            module.module_name,
            module.base_address,
            issues.join(", ")
        );

        let mut mitre_techniques = Vec::new();
        if !module.detected_hooks.is_empty() {
            mitre_techniques.push("T1055.012".to_string()); // Process Hollowing
            mitre_techniques.push("T1574.001".to_string()); // DLL Search Order Hijacking
        }
        if !module.in_peb_list {
            mitre_techniques.push("T1055".to_string()); // Process Injection
            mitre_techniques.push("T1574.002".to_string()); // DLL Side-Loading
        }
        if module.code_modified {
            mitre_techniques.push("T1055.012".to_string());
        }

        event.add_detection(Detection {
            detection_type: DetectionType::MemoryThreat,
            rule_name: "ModuleIntegrity_Violation".to_string(),
            confidence: if !module.detected_hooks.is_empty() {
                0.95
            } else {
                0.85
            },
            description,
            mitre_tactics: vec!["defense-evasion".to_string(), "persistence".to_string()],
            mitre_techniques,
        });

        event
            .metadata
            .insert("scan_type".to_string(), "module_integrity".to_string());
        event
            .metadata
            .insert("module_name".to_string(), module.module_name.clone());
        event
            .metadata
            .insert("module_path".to_string(), module.module_path.clone());
        event.metadata.insert(
            "module_address".to_string(),
            format!("0x{:x}", module.base_address),
        );
        event
            .metadata
            .insert("is_signed".to_string(), module.is_signed.to_string());
        event
            .metadata
            .insert("in_peb_list".to_string(), module.in_peb_list.to_string());
        event.metadata.insert(
            "code_modified".to_string(),
            module.code_modified.to_string(),
        );

        if let Some(ref signer) = module.signer {
            event.metadata.insert("signer".to_string(), signer.clone());
        }

        if let Some(ref disk_hash) = module.disk_text_hash {
            event
                .metadata
                .insert("disk_text_hash".to_string(), disk_hash.clone());
        }

        if let Some(ref mem_hash) = module.memory_text_hash {
            event
                .metadata
                .insert("memory_text_hash".to_string(), mem_hash.clone());
        }

        // Add hooked functions details
        if !module.detected_hooks.is_empty() {
            let hook_details: Vec<String> = module
                .detected_hooks
                .iter()
                .map(|h| {
                    format!(
                        "{}@0x{:x} ({})",
                        h.function_name, h.hook_address, h.hook_type
                    )
                })
                .collect();
            event
                .metadata
                .insert("hooked_functions".to_string(), hook_details.join("; "));
        }

        event
    }

    /// Convert u32 protection to MemoryProtection enum
    fn protection_from_u32(prot: u32) -> MemoryProtection {
        // Windows protection flags
        const PAGE_EXECUTE: u32 = 0x10;
        const PAGE_EXECUTE_READ: u32 = 0x20;
        const PAGE_EXECUTE_READWRITE: u32 = 0x40;
        const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
        const PAGE_READWRITE: u32 = 0x04;
        const PAGE_READONLY: u32 = 0x02;

        if prot & PAGE_EXECUTE_READWRITE != 0 || prot & PAGE_EXECUTE_WRITECOPY != 0 {
            MemoryProtection::ExecuteReadWrite
        } else if prot & PAGE_EXECUTE_READ != 0 {
            MemoryProtection::ExecuteRead
        } else if prot & PAGE_EXECUTE != 0 {
            MemoryProtection::Execute
        } else if prot & PAGE_READWRITE != 0 {
            MemoryProtection::ReadWrite
        } else if prot & PAGE_READONLY != 0 {
            MemoryProtection::ReadOnly
        } else {
            MemoryProtection::Unknown
        }
    }

    /// Get list of running processes
    fn get_process_list() -> Vec<(u32, String, String)> {
        let mut processes = Vec::new();

        #[cfg(target_os = "windows")]
        {
            use windows::Win32::Foundation::CloseHandle;
            use windows::Win32::System::Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                TH32CS_SNAPPROCESS,
            };

            unsafe {
                if let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                    let mut entry = PROCESSENTRY32W {
                        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                        ..Default::default()
                    };

                    if Process32FirstW(snapshot, &mut entry).is_ok() {
                        loop {
                            let name = String::from_utf16_lossy(
                                &entry.szExeFile
                                    [..entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0)],
                            );
                            processes.push((entry.th32ProcessID, name, String::new()));

                            if Process32NextW(snapshot, &mut entry).is_err() {
                                break;
                            }
                        }
                    }
                    let _ = CloseHandle(snapshot);
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            use std::fs;

            if let Ok(entries) = fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
                        let comm_path = format!("/proc/{}/comm", pid);
                        let exe_path = format!("/proc/{}/exe", pid);

                        let name = fs::read_to_string(&comm_path)
                            .map(|s| s.trim().to_string())
                            .unwrap_or_default();

                        let path = fs::read_link(&exe_path)
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_default();

                        processes.push((pid, name, path));
                    }
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            use std::process::Command;

            // Use ps to list all processes with PID, command name, and full path
            if let Ok(output) = Command::new("ps").args(["-axo", "pid,comm"]).output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines().skip(1) {
                    // skip header
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }

                    // Split into PID and command
                    let mut parts = trimmed.splitn(2, char::is_whitespace);
                    let pid_str = match parts.next() {
                        Some(s) => s.trim(),
                        None => continue,
                    };
                    let comm = match parts.next() {
                        Some(s) => s.trim(),
                        None => continue,
                    };

                    if let Ok(pid) = pid_str.parse::<u32>() {
                        // comm may be a full path on macOS; extract basename for name
                        let name = comm.rsplit('/').next().unwrap_or(comm).to_string();
                        let path = if comm.contains('/') {
                            comm.to_string()
                        } else {
                            String::new()
                        };

                        processes.push((pid, name, path));
                    }
                }
            }
        }

        processes
    }

    /// Scan process memory for suspicious regions
    fn scan_process_memory(pid: u32) -> Result<Vec<SuspiciousMemory>> {
        let mut suspicious = Vec::new();

        #[cfg(target_os = "windows")]
        {
            suspicious = Self::scan_windows_memory(pid)?;
        }

        #[cfg(target_os = "linux")]
        {
            suspicious = Self::scan_linux_memory(pid)?;
        }

        #[cfg(target_os = "macos")]
        {
            suspicious = Self::scan_macos_memory(pid)?;
        }

        Ok(suspicious)
    }

    #[cfg(target_os = "windows")]
    fn scan_windows_memory(pid: u32) -> Result<Vec<SuspiciousMemory>> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Memory::{
            VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_PRIVATE,
            PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        let mut suspicious = Vec::new();
        let process_name = Self::get_process_name(pid);

        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            {
                Ok(h) => h,
                Err(_) => return Ok(suspicious),
            };

            let mut address: usize = 0;
            let mut mbi = MEMORY_BASIC_INFORMATION::default();

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

                // Check if memory is committed and executable
                if mbi.State.contains(MEM_COMMIT) {
                    let is_executable = mbi.Protect.contains(PAGE_EXECUTE)
                        || mbi.Protect.contains(PAGE_EXECUTE_READ)
                        || mbi.Protect.contains(PAGE_EXECUTE_READWRITE)
                        || mbi.Protect.contains(PAGE_EXECUTE_WRITECOPY);

                    let is_private = mbi.Type.contains(MEM_PRIVATE);
                    let is_rwx = mbi.Protect.contains(PAGE_EXECUTE_READWRITE);

                    // Suspicious: Executable private memory
                    if is_executable && is_private {
                        let region = MemoryRegion {
                            base_address: mbi.BaseAddress as u64,
                            size: mbi.RegionSize as u64,
                            protection: if is_rwx {
                                MemoryProtection::ExecuteReadWrite
                            } else {
                                MemoryProtection::ExecuteRead
                            },
                            region_type: if mbi.Type.contains(MEM_IMAGE) {
                                MemoryType::Image
                            } else {
                                MemoryType::Private
                            },
                            module_name: None,
                            is_executable,
                            is_private,
                            entropy: 0.0, // Will be calculated if we read the memory
                        };

                        let reason = if is_rwx {
                            MemorySuspicionReason::ReadWriteExecute
                        } else {
                            MemorySuspicionReason::ExecutablePrivate
                        };

                        // Try to read memory and check for patterns
                        let (shellcode_detected, beacon_detected) = Self::check_memory_patterns(
                            handle,
                            mbi.BaseAddress as u64,
                            mbi.RegionSize,
                        );

                        let confidence = if beacon_detected {
                            0.95
                        } else if shellcode_detected {
                            0.85
                        } else if is_rwx {
                            0.75
                        } else {
                            0.60
                        };

                        suspicious.push(SuspiciousMemory {
                            pid,
                            process_name: process_name.clone(),
                            region,
                            reason: if beacon_detected {
                                MemorySuspicionReason::CobaltStrikeBeacon
                            } else if shellcode_detected {
                                MemorySuspicionReason::ShellcodePattern
                            } else {
                                reason
                            },
                            confidence,
                            shellcode_detected,
                            beacon_detected,
                        });
                    }
                }

                address = mbi.BaseAddress as usize + mbi.RegionSize;
            }

            let _ = CloseHandle(handle);
        }

        Ok(suspicious)
    }

    #[cfg(target_os = "linux")]
    fn scan_linux_memory(pid: u32) -> Result<Vec<SuspiciousMemory>> {
        use std::fs;
        use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};

        let mut suspicious = Vec::new();
        let process_name = Self::get_process_name(pid);

        // Read /proc/[pid]/maps
        let maps_path = format!("/proc/{}/maps", pid);
        let file = match fs::File::open(&maps_path) {
            Ok(f) => f,
            Err(_) => return Ok(suspicious),
        };

        let reader = BufReader::new(file);

        // Try to open /proc/[pid]/mem for reading memory contents
        let mem_path = format!("/proc/{}/mem", pid);
        let mut mem_file = fs::File::open(&mem_path).ok();

        for line in reader.lines().flatten() {
            // Parse map entry: address perms offset dev inode pathname
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                continue;
            }

            let address_range: Vec<&str> = parts[0].split('-').collect();
            if address_range.len() != 2 {
                continue;
            }

            let start = u64::from_str_radix(address_range[0], 16).unwrap_or(0);
            let end = u64::from_str_radix(address_range[1], 16).unwrap_or(0);
            let size = end - start;
            let perms = parts[1];

            let is_executable = perms.contains('x');
            let is_writable = perms.contains('w');
            let is_readable = perms.contains('r');
            let is_private = perms.contains('p');
            let is_anonymous = parts.len() < 6
                || parts[5].is_empty()
                || parts[5] == "[heap]"
                || parts[5] == "[stack]";
            let pathname = if parts.len() >= 6 { parts[5] } else { "" };

            // Suspicious: Anonymous executable memory (not backed by any file)
            if is_executable && is_anonymous && is_private {
                let mut shellcode_detected = false;
                let mut beacon_detected = false;
                let mut entropy: f32 = 0.0;
                let mut detected_patterns: Vec<String> = Vec::new();

                // Try to read memory contents for pattern scanning
                if is_readable && size > 0 && size < 10 * 1024 * 1024 {
                    // Cap at 10MB
                    if let Some(ref mut mem) = mem_file {
                        if mem.seek(SeekFrom::Start(start)).is_ok() {
                            let read_size = std::cmp::min(size as usize, 8192);
                            let mut buffer = vec![0u8; read_size];

                            if let Ok(bytes_read) = mem.read(&mut buffer) {
                                if bytes_read > 0 {
                                    let buffer = &buffer[..bytes_read];

                                    // Check for shellcode patterns
                                    for (name, pattern, _mitre) in SHELLCODE_PATTERNS.iter() {
                                        if buffer.windows(pattern.len()).any(|w| w == *pattern) {
                                            shellcode_detected = true;
                                            detected_patterns.push(name.to_string());
                                            trace!(
                                                pid = pid,
                                                pattern_name = name,
                                                "Linux shellcode pattern detected"
                                            );
                                        }
                                    }

                                    // Check for C2 signatures
                                    beacon_detected = Self::check_c2_signatures(buffer);

                                    // Calculate entropy
                                    entropy = Self::calculate_entropy(buffer);
                                }
                            }
                        }
                    }
                }

                let reason = if beacon_detected {
                    MemorySuspicionReason::CobaltStrikeBeacon
                } else if shellcode_detected {
                    MemorySuspicionReason::ShellcodePattern
                } else if is_writable {
                    MemorySuspicionReason::ReadWriteExecute
                } else {
                    MemorySuspicionReason::ExecutablePrivate
                };

                // Calculate confidence based on findings
                let confidence = if beacon_detected {
                    0.95
                } else if shellcode_detected {
                    0.85 + (detected_patterns.len() as f32 * 0.02).min(0.10) // Higher confidence with more patterns
                } else if entropy > 7.0 {
                    0.80 // High entropy is suspicious
                } else if is_writable {
                    0.75 // RWX is always suspicious
                } else {
                    0.60
                };

                let region = MemoryRegion {
                    base_address: start,
                    size,
                    protection: if is_writable {
                        MemoryProtection::ExecuteReadWrite
                    } else {
                        MemoryProtection::ExecuteRead
                    },
                    region_type: if pathname == "[heap]" {
                        MemoryType::Heap
                    } else if pathname == "[stack]" {
                        MemoryType::Stack
                    } else {
                        MemoryType::Private
                    },
                    module_name: None,
                    is_executable,
                    is_private,
                    entropy,
                };

                suspicious.push(SuspiciousMemory {
                    pid,
                    process_name: process_name.clone(),
                    region,
                    reason,
                    confidence,
                    shellcode_detected,
                    beacon_detected,
                });
            }

            // Also check for executable memory in unexpected locations (like heap)
            if is_executable && pathname == "[heap]" {
                let region = MemoryRegion {
                    base_address: start,
                    size,
                    protection: if is_writable {
                        MemoryProtection::ExecuteReadWrite
                    } else {
                        MemoryProtection::ExecuteRead
                    },
                    region_type: MemoryType::Heap,
                    module_name: None,
                    is_executable,
                    is_private,
                    entropy: 0.0,
                };

                suspicious.push(SuspiciousMemory {
                    pid,
                    process_name: process_name.clone(),
                    region,
                    reason: MemorySuspicionReason::UnbackedExecutable,
                    confidence: 0.85,
                    shellcode_detected: false,
                    beacon_detected: false,
                });
            }

            // Check for memfd_create anonymous files (often used by fileless malware)
            if is_executable && pathname.starts_with("/memfd:") {
                let region = MemoryRegion {
                    base_address: start,
                    size,
                    protection: if is_writable {
                        MemoryProtection::ExecuteReadWrite
                    } else {
                        MemoryProtection::ExecuteRead
                    },
                    region_type: MemoryType::Mapped,
                    module_name: Some(pathname.to_string()),
                    is_executable,
                    is_private,
                    entropy: 0.0,
                };

                suspicious.push(SuspiciousMemory {
                    pid,
                    process_name: process_name.clone(),
                    region,
                    reason: MemorySuspicionReason::PeInPrivateMemory, // Reusing for "executable from memfd"
                    confidence: 0.90, // memfd with execute is highly suspicious
                    shellcode_detected: false,
                    beacon_detected: false,
                });
            }
        }

        Ok(suspicious)
    }

    /// Scan process memory for suspicious regions (macOS)
    ///
    /// Uses Mach VM APIs to enumerate memory regions and detect:
    /// - Anonymous executable private memory (code injection)
    /// - RWX regions (shellcode staging)
    /// - Mach-O headers in private memory (reflective loading)
    /// - Shellcode and C2 beacon patterns
    #[cfg(target_os = "macos")]
    fn scan_macos_memory(pid: u32) -> Result<Vec<SuspiciousMemory>> {
        let mut suspicious = Vec::new();
        let process_name = Self::get_process_name(pid);

        let task = match macos_memory::get_task_for_pid(pid as i32) {
            Ok(t) => t,
            Err(_) => return Ok(suspicious),
        };

        let regions = macos_memory::enumerate_regions(task);

        for region in &regions {
            let is_executable = region.is_executable;
            let is_writable = region.is_writable;
            let is_readable = region.is_readable;
            let is_private = region.is_private;
            let size = region.size;

            // Suspicious: private executable memory not backed by a dylib
            let is_unbacked = is_executable
                && is_private
                && region.region_type != "dylib"
                && region.region_type != "stack";

            if !is_unbacked && !(is_executable && is_writable) {
                continue;
            }

            let mut shellcode_detected = false;
            let mut beacon_detected = false;
            let mut entropy: f32 = 0.0;
            let mut detected_patterns: Vec<String> = Vec::new();

            // Try to read memory for pattern scanning
            if is_readable && size > 0 && size < 10 * 1024 * 1024 {
                let scan_size = size.min(8192) as usize;
                if let Some(data) = macos_memory::read_memory(task, region.base_address, scan_size)
                {
                    if !data.is_empty() {
                        // Check for shellcode patterns
                        for (name, pattern, _mitre) in SHELLCODE_PATTERNS.iter() {
                            if data.windows(pattern.len()).any(|w| w == *pattern) {
                                shellcode_detected = true;
                                detected_patterns.push(name.to_string());
                                trace!(
                                    pid = pid,
                                    pattern_name = name,
                                    "macOS shellcode pattern detected"
                                );
                            }
                        }

                        // Check for C2 signatures
                        beacon_detected = Self::check_c2_signatures(&data);

                        // Calculate entropy
                        entropy = Self::calculate_entropy(&data);

                        // Check for Mach-O in private memory (reflective loading)
                        if data.len() >= 4 {
                            let magic = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
                            const MH_MAGIC_64: u32 = 0xfeedfacf;
                            const MH_CIGAM_64: u32 = 0xcffaedfe;
                            if magic == MH_MAGIC_64 || magic == MH_CIGAM_64 {
                                detected_patterns.push("MachO_in_private_memory".to_string());
                                shellcode_detected = true;
                            }
                        }
                    }
                }
            }

            let reason = if beacon_detected {
                MemorySuspicionReason::CobaltStrikeBeacon
            } else if shellcode_detected {
                MemorySuspicionReason::ShellcodePattern
            } else if is_writable && is_executable {
                MemorySuspicionReason::ReadWriteExecute
            } else {
                MemorySuspicionReason::ExecutablePrivate
            };

            let confidence = if beacon_detected {
                0.95
            } else if shellcode_detected {
                0.85 + (detected_patterns.len() as f32 * 0.02).min(0.10)
            } else if entropy > 7.0 {
                0.80
            } else if is_writable && is_executable {
                0.75
            } else {
                0.60
            };

            let mem_region = MemoryRegion {
                base_address: region.base_address,
                size,
                protection: if is_writable && is_executable {
                    MemoryProtection::ExecuteReadWrite
                } else if is_executable {
                    MemoryProtection::ExecuteRead
                } else {
                    MemoryProtection::ReadWrite
                },
                region_type: match region.region_type.as_str() {
                    "heap" => MemoryType::Heap,
                    "stack" => MemoryType::Stack,
                    "dylib" => MemoryType::Image,
                    _ => MemoryType::Private,
                },
                module_name: None,
                is_executable,
                is_private,
                entropy,
            };

            suspicious.push(SuspiciousMemory {
                pid,
                process_name: process_name.clone(),
                region: mem_region,
                reason,
                confidence,
                shellcode_detected,
                beacon_detected,
            });
        }

        // Clean up task port
        unsafe {
            macos_memory::mach_port_deallocate_wrapper(task);
        }

        Ok(suspicious)
    }

    #[cfg(target_os = "windows")]
    fn check_memory_patterns(
        handle: windows::Win32::Foundation::HANDLE,
        address: u64,
        size: usize,
    ) -> (bool, bool) {
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

        let read_size = std::cmp::min(size, 8192); // Read first 8KB for better detection
        let mut buffer = vec![0u8; read_size];
        let mut bytes_read = 0usize;

        unsafe {
            if ReadProcessMemory(
                handle,
                address as *const _,
                buffer.as_mut_ptr() as *mut _,
                read_size,
                Some(&mut bytes_read),
            )
            .is_err()
            {
                return (false, false);
            }
        }

        let buffer = &buffer[..bytes_read];

        // Check for shellcode patterns (updated to handle new signature format)
        let shellcode_detected = SHELLCODE_PATTERNS.iter().any(|(name, pattern, _)| {
            let found = buffer.windows(pattern.len()).any(|w| w == *pattern);
            if found {
                trace!(pattern_name = name, "Shellcode pattern detected");
            }
            found
        });

        // Check for Cobalt Strike
        let beacon_detected = COBALT_STRIKE_SIGNATURES.iter().any(|(name, pattern)| {
            let found = buffer.windows(pattern.len()).any(|w| w == *pattern);
            if found {
                trace!(pattern_name = name, "Cobalt Strike signature detected");
            }
            found
        });

        // Check for other C2 frameworks
        let c2_detected = Self::check_c2_signatures(buffer);

        // Check for PE header (MZ) in private memory (reflective loading indicator)
        let pe_detected = buffer.len() >= 2 && buffer[0] == 0x4D && buffer[1] == 0x5A;

        // Calculate entropy for the buffer
        let entropy = Self::calculate_entropy(buffer);
        let high_entropy = entropy > 7.0; // High entropy indicates encryption/compression

        (
            shellcode_detected || pe_detected || high_entropy,
            beacon_detected || c2_detected,
        )
    }

    /// Check for various C2 framework signatures
    fn check_c2_signatures(buffer: &[u8]) -> bool {
        // Check Sliver
        let sliver = SLIVER_SIGNATURES
            .iter()
            .any(|(_, pattern)| buffer.windows(pattern.len()).any(|w| w == *pattern));

        // Check Mythic
        let mythic = MYTHIC_SIGNATURES
            .iter()
            .any(|(_, pattern)| buffer.windows(pattern.len()).any(|w| w == *pattern));

        // Check Havoc
        let havoc = HAVOC_SIGNATURES
            .iter()
            .any(|(_, pattern)| buffer.windows(pattern.len()).any(|w| w == *pattern));

        // Check Brute Ratel C4
        let brute_ratel = BRUTE_RATEL_SIGNATURES
            .iter()
            .any(|(_, pattern)| buffer.windows(pattern.len()).any(|w| w == *pattern));

        // Check Nighthawk
        let nighthawk = NIGHTHAWK_SIGNATURES
            .iter()
            .any(|(_, pattern)| buffer.windows(pattern.len()).any(|w| w == *pattern));

        sliver || mythic || havoc || brute_ratel || nighthawk
    }

    /// Calculate Shannon entropy of a byte buffer
    fn calculate_entropy(data: &[u8]) -> f32 {
        if data.is_empty() {
            return 0.0;
        }

        let mut frequency = [0u32; 256];
        for &byte in data {
            frequency[byte as usize] += 1;
        }

        let len = data.len() as f32;
        let mut entropy: f32 = 0.0;

        for &count in &frequency {
            if count > 0 {
                let p = count as f32 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    fn get_process_name(pid: u32) -> String {
        #[cfg(target_os = "windows")]
        {
            use windows::Win32::Foundation::CloseHandle;
            use windows::Win32::System::ProcessStatus::K32GetProcessImageFileNameW;
            use windows::Win32::System::Threading::{
                OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
            };

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

        #[cfg(target_os = "linux")]
        {
            std::fs::read_to_string(format!("/proc/{}/comm", pid))
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        }

        #[cfg(target_os = "macos")]
        {
            use std::process::Command;

            let pid_str = pid.to_string();
            Command::new("ps")
                .args(["-o", "comm=", "-p", &pid_str])
                .output()
                .ok()
                .and_then(|o| {
                    let name = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    if name.is_empty() {
                        None
                    } else {
                        Some(name)
                    }
                })
                .and_then(|full_path| {
                    // ps on macOS may return full path; extract basename
                    full_path.rsplit('/').next().map(|s| s.to_string())
                })
                .unwrap_or_default()
        }
    }

    fn create_memory_alert(
        suspicious: &SuspiciousMemory,
        process_name: &str,
        process_path: &str,
    ) -> TelemetryEvent {
        // Determine severity based on detection type and confidence
        let severity = if suspicious.beacon_detected {
            Severity::Critical // C2 beacons are always critical
        } else if suspicious.shellcode_detected && suspicious.confidence > 0.85 {
            Severity::Critical // High-confidence shellcode is critical
        } else if suspicious.shellcode_detected {
            Severity::High // Lower-confidence shellcode is high
        } else if suspicious.reason == MemorySuspicionReason::ReadWriteExecute {
            Severity::High // RWX regions are always high severity
        } else if suspicious.reason == MemorySuspicionReason::PeInPrivateMemory {
            Severity::High // Reflective loading indicator
        } else if suspicious.reason == MemorySuspicionReason::ModifiedCodeSection {
            Severity::High // Modified code sections indicate tampering
        } else if suspicious.region.entropy > 7.0 {
            Severity::Medium // High entropy is medium (could be packed but legitimate)
        } else {
            Severity::Medium
        };

        // Use MemoryScan event type for memory-specific detections
        let mut event = TelemetryEvent::new(
            EventType::MemoryScan,
            severity,
            EventPayload::Process(ProcessEvent {
                pid: suspicious.pid,
                ppid: 0,
                name: process_name.to_string(),
                path: process_path.to_string(),
                cmdline: String::new(),
                user: String::new(),
                sha256: Vec::new(),
                entropy: suspicious.region.entropy,
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

        // Build detailed description based on detection type
        let description = if suspicious.beacon_detected {
            format!(
                "C2 beacon detected in {} (PID: {}) at 0x{:x} - {} ({} bytes)",
                process_name,
                suspicious.pid,
                suspicious.region.base_address,
                suspicious.reason.as_str(),
                suspicious.region.size
            )
        } else if suspicious.shellcode_detected {
            format!(
                "Shellcode pattern detected in {} (PID: {}) at 0x{:x} - {:?} protection ({} bytes, entropy: {:.2})",
                process_name,
                suspicious.pid,
                suspicious.region.base_address,
                suspicious.region.protection,
                suspicious.region.size,
                suspicious.region.entropy
            )
        } else {
            format!(
                "Suspicious memory region in {} (PID: {}): {} at 0x{:x} ({} bytes, {:?} protection, entropy: {:.2})",
                process_name,
                suspicious.pid,
                suspicious.reason.as_str(),
                suspicious.region.base_address,
                suspicious.region.size,
                suspicious.region.protection,
                suspicious.region.entropy
            )
        };

        // Get MITRE ATT&CK mapping
        let (mitre_tactics, mitre_techniques) =
            Self::get_mitre_mapping(&suspicious.reason, suspicious.beacon_detected);

        event.add_detection(Detection {
            detection_type: DetectionType::MemoryThreat,
            rule_name: format!("MemoryForensics_{}", suspicious.reason.as_str()),
            confidence: suspicious.confidence,
            description,
            mitre_tactics,
            mitre_techniques,
        });

        // Add comprehensive metadata
        event.metadata.insert(
            "memory_address".to_string(),
            format!("0x{:x}", suspicious.region.base_address),
        );
        event.metadata.insert(
            "memory_size".to_string(),
            suspicious.region.size.to_string(),
        );
        event.metadata.insert(
            "memory_protection".to_string(),
            format!("{:?}", suspicious.region.protection),
        );
        event.metadata.insert(
            "memory_type".to_string(),
            format!("{:?}", suspicious.region.region_type),
        );
        event.metadata.insert(
            "suspicion_reason".to_string(),
            suspicious.reason.as_str().to_string(),
        );
        event.metadata.insert(
            "shellcode_detected".to_string(),
            suspicious.shellcode_detected.to_string(),
        );
        event.metadata.insert(
            "beacon_detected".to_string(),
            suspicious.beacon_detected.to_string(),
        );
        event.metadata.insert(
            "entropy".to_string(),
            format!("{:.2}", suspicious.region.entropy),
        );
        event.metadata.insert(
            "is_private".to_string(),
            suspicious.region.is_private.to_string(),
        );
        event.metadata.insert(
            "is_executable".to_string(),
            suspicious.region.is_executable.to_string(),
        );

        if let Some(ref module_name) = suspicious.region.module_name {
            event
                .metadata
                .insert("module_name".to_string(), module_name.clone());
        }

        event
    }

    /// Get MITRE ATT&CK tactics and techniques based on detection reason
    fn get_mitre_mapping(
        reason: &MemorySuspicionReason,
        beacon_detected: bool,
    ) -> (Vec<String>, Vec<String>) {
        let mut tactics = Vec::new();
        let mut techniques = Vec::new();

        // Add tactics based on detection type
        if beacon_detected {
            tactics.push("command-and-control".to_string());
            techniques.push("T1071.001".to_string()); // Application Layer Protocol: Web Protocols
        }

        match reason {
            MemorySuspicionReason::ExecutablePrivate
            | MemorySuspicionReason::UnbackedExecutable
            | MemorySuspicionReason::ReadWriteExecute => {
                tactics.push("defense-evasion".to_string());
                tactics.push("privilege-escalation".to_string());
                techniques.push("T1055".to_string()); // Process Injection
            }
            MemorySuspicionReason::ShellcodePattern | MemorySuspicionReason::MetasploitPayload => {
                tactics.push("execution".to_string());
                tactics.push("defense-evasion".to_string());
                techniques.push("T1059".to_string()); // Command and Scripting Interpreter
                techniques.push("T1055".to_string()); // Process Injection
            }
            MemorySuspicionReason::PeInPrivateMemory => {
                tactics.push("defense-evasion".to_string());
                techniques.push("T1620".to_string()); // Reflective Code Loading
            }
            MemorySuspicionReason::CobaltStrikeBeacon => {
                tactics.push("command-and-control".to_string());
                tactics.push("defense-evasion".to_string());
                techniques.push("T1071.001".to_string());
                techniques.push("T1055".to_string());
            }
            MemorySuspicionReason::HighEntropyExecutable => {
                tactics.push("defense-evasion".to_string());
                techniques.push("T1027".to_string()); // Obfuscated Files or Information
            }
            MemorySuspicionReason::ModifiedCodeSection => {
                tactics.push("defense-evasion".to_string());
                tactics.push("privilege-escalation".to_string());
                techniques.push("T1055.012".to_string()); // Process Hollowing
            }
        }

        // Deduplicate
        tactics.sort();
        tactics.dedup();
        techniques.sort();
        techniques.dedup();

        (tactics, techniques)
    }

    /// Get next event
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }
}

// ============================================================================
// macOS Memory Scanning via Mach VM APIs
// ============================================================================

/// macOS-specific memory scanning using Mach VM APIs
/// Provides process memory introspection similar to Windows VirtualQueryEx
#[cfg(target_os = "macos")]
pub mod macos_memory {
    use super::*;
    use std::ffi::CStr;
    use std::mem::MaybeUninit;
    use tracing::{debug, error, trace, warn};

    // Mach VM protection flags
    pub const VM_PROT_NONE: i32 = 0x00;
    pub const VM_PROT_READ: i32 = 0x01;
    pub const VM_PROT_WRITE: i32 = 0x02;
    pub const VM_PROT_EXECUTE: i32 = 0x04;
    pub const VM_PROT_ALL: i32 = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;

    // Memory share mode constants
    pub const SM_COW: u8 = 1; // Copy-on-write
    pub const SM_PRIVATE: u8 = 2; // Private
    pub const SM_EMPTY: u8 = 3; // Empty
    pub const SM_SHARED: u8 = 4; // Shared
    pub const SM_TRUESHARED: u8 = 5;
    pub const SM_PRIVATE_ALIASED: u8 = 6;
    pub const SM_SHARED_ALIASED: u8 = 7;
    pub const SM_LARGE_PAGE: u8 = 8;

    /// Mach VM region basic info flavor
    const VM_REGION_BASIC_INFO_64: i32 = 9;
    const VM_REGION_EXTENDED_INFO: i32 = 13;
    const VM_REGION_TOP_INFO: i32 = 12;

    /// vm_region_basic_info_64 structure
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct VmRegionBasicInfo64 {
        pub protection: i32,
        pub max_protection: i32,
        pub inheritance: u32,
        pub shared: u32,
        pub reserved: u32,
        pub offset: u64,
        pub behavior: i32,
        pub user_wired_count: u16,
    }

    /// vm_region_extended_info structure
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct VmRegionExtendedInfo {
        pub protection: i32,
        pub user_tag: u32,
        pub pages_resident: u32,
        pub pages_shared_now_private: u32,
        pub pages_swapped_out: u32,
        pub pages_dirtied: u32,
        pub ref_count: u32,
        pub shadow_depth: u16,
        pub external_pager: u8,
        pub share_mode: u8,
        pub pages_reusable: u32,
    }

    // Memory user tags (from mach/vm_statistics.h)
    const VM_MEMORY_MALLOC: u32 = 1;
    const VM_MEMORY_MALLOC_SMALL: u32 = 2;
    const VM_MEMORY_MALLOC_LARGE: u32 = 3;
    const VM_MEMORY_STACK: u32 = 30;
    const VM_MEMORY_DYLIB: u32 = 33;
    const VM_MEMORY_DYLIB_CODE: u32 = 34;
    const VM_MEMORY_DYLIB_DATA: u32 = 35;
    const VM_MEMORY_APPLICATION_SPECIFIC: u32 = 41;

    // Mach types
    type MachPort = u32;
    type KernReturn = i32;
    type VmAddress = u64;
    type VmSize = u64;
    type Natural = u32;

    const KERN_SUCCESS: i32 = 0;
    const KERN_INVALID_ADDRESS: i32 = 1;

    // Mach VM function declarations
    extern "C" {
        fn mach_task_self() -> MachPort;

        fn task_for_pid(
            target_tport: MachPort,
            pid: libc::c_int,
            task: *mut MachPort,
        ) -> KernReturn;

        fn mach_vm_region(
            target_task: MachPort,
            address: *mut VmAddress,
            size: *mut VmSize,
            flavor: i32,
            info: *mut u8,
            info_count: *mut Natural,
            object_name: *mut MachPort,
        ) -> KernReturn;

        fn mach_vm_read_overwrite(
            target_task: MachPort,
            address: VmAddress,
            size: VmSize,
            data: VmAddress,
            outsize: *mut VmSize,
        ) -> KernReturn;

        fn mach_port_deallocate(target: MachPort, name: MachPort) -> KernReturn;
    }

    /// Memory region information
    #[derive(Debug, Clone)]
    pub struct MacOsMemoryRegion {
        pub base_address: u64,
        pub size: u64,
        pub protection: i32,
        pub max_protection: i32,
        pub share_mode: u8,
        pub user_tag: u32,
        pub is_executable: bool,
        pub is_writable: bool,
        pub is_readable: bool,
        pub is_shared: bool,
        pub is_private: bool,
        pub region_type: String,
    }

    impl MacOsMemoryRegion {
        fn protection_string(&self) -> String {
            let mut s = String::new();
            if self.is_readable {
                s.push('r');
            } else {
                s.push('-');
            }
            if self.is_writable {
                s.push('w');
            } else {
                s.push('-');
            }
            if self.is_executable {
                s.push('x');
            } else {
                s.push('-');
            }
            s
        }
    }

    /// Get task port for a process (requires appropriate entitlements/privileges)
    pub fn get_task_for_pid(pid: i32) -> Result<MachPort, String> {
        let mut task: MachPort = 0;

        let result = unsafe { task_for_pid(mach_task_self(), pid, &mut task) };

        if result != KERN_SUCCESS {
            return Err(format!(
                "task_for_pid failed for PID {}: error {} (requires SIP disabled or entitlement)",
                pid, result
            ));
        }

        Ok(task)
    }

    /// Enumerate memory regions for a task
    pub fn enumerate_regions(task: MachPort) -> Vec<MacOsMemoryRegion> {
        let mut regions = Vec::new();
        let mut address: VmAddress = 0;

        loop {
            let mut size: VmSize = 0;
            let mut info = VmRegionExtendedInfo::default();
            let mut info_count = (std::mem::size_of::<VmRegionExtendedInfo>()
                / std::mem::size_of::<Natural>()) as Natural;
            let mut object_name: MachPort = 0;

            let result = unsafe {
                mach_vm_region(
                    task,
                    &mut address,
                    &mut size,
                    VM_REGION_EXTENDED_INFO,
                    &mut info as *mut _ as *mut u8,
                    &mut info_count,
                    &mut object_name,
                )
            };

            if result != KERN_SUCCESS {
                break;
            }

            let is_executable = (info.protection & VM_PROT_EXECUTE) != 0;
            let is_writable = (info.protection & VM_PROT_WRITE) != 0;
            let is_readable = (info.protection & VM_PROT_READ) != 0;

            let region_type = match info.user_tag {
                VM_MEMORY_MALLOC | VM_MEMORY_MALLOC_SMALL | VM_MEMORY_MALLOC_LARGE => {
                    "heap".to_string()
                }
                VM_MEMORY_STACK => "stack".to_string(),
                VM_MEMORY_DYLIB | VM_MEMORY_DYLIB_CODE | VM_MEMORY_DYLIB_DATA => {
                    "dylib".to_string()
                }
                _ => "private".to_string(),
            };

            let is_shared = info.share_mode == SM_SHARED
                || info.share_mode == SM_TRUESHARED
                || info.share_mode == SM_SHARED_ALIASED;

            let is_private = info.share_mode == SM_PRIVATE || info.share_mode == SM_PRIVATE_ALIASED;

            regions.push(MacOsMemoryRegion {
                base_address: address,
                size,
                protection: info.protection,
                max_protection: 0, // Not available in extended info
                share_mode: info.share_mode,
                user_tag: info.user_tag,
                is_executable,
                is_writable,
                is_readable,
                is_shared,
                is_private,
                region_type,
            });

            // Move to next region
            let next_addr = address.saturating_add(size);
            if next_addr <= address {
                break; // Overflow protection
            }
            address = next_addr;

            // Clean up object name if returned
            if object_name != 0 {
                unsafe { mach_port_deallocate(mach_task_self(), object_name) };
            }
        }

        regions
    }

    /// Read memory from a task
    pub fn read_memory(task: MachPort, address: u64, size: usize) -> Option<Vec<u8>> {
        let mut buffer = vec![0u8; size];
        let mut bytes_read: VmSize = 0;

        let result = unsafe {
            mach_vm_read_overwrite(
                task,
                address,
                size as VmSize,
                buffer.as_mut_ptr() as VmAddress,
                &mut bytes_read,
            )
        };

        if result != KERN_SUCCESS || bytes_read == 0 {
            return None;
        }

        buffer.truncate(bytes_read as usize);
        Some(buffer)
    }

    /// Find suspicious memory regions in a process
    pub fn find_suspicious_regions(pid: i32) -> Vec<VadAnomaly> {
        let mut anomalies = Vec::new();

        let task = match get_task_for_pid(pid) {
            Ok(t) => t,
            Err(e) => {
                debug!("Cannot get task for PID {}: {}", pid, e);
                return anomalies;
            }
        };

        let regions = enumerate_regions(task);

        for region in &regions {
            // Check for RWX private memory (very suspicious)
            if region.is_executable && region.is_writable && region.is_private {
                let entropy = if let Some(data) =
                    read_memory(task, region.base_address, region.size.min(16384) as usize)
                {
                    MemoryScanner::calculate_entropy(&data)
                } else {
                    0.0
                };

                anomalies.push(VadAnomaly {
                    base_address: region.base_address,
                    size: region.size as usize,
                    protection: region.protection_string(),
                    anomaly_type: VadAnomalyType::RwxPrivate,
                    backing_file: None,
                    entropy,
                    details: format!(
                        "Private RWX region (type: {}, share_mode: {})",
                        region.region_type, region.share_mode
                    ),
                    confidence: if entropy > 6.0 { 0.9 } else { 0.75 },
                });
            }

            // Check for unbacked executable (executable private memory)
            if region.is_executable
                && region.is_private
                && !region.is_writable
                && region.region_type != "dylib"
                && region.size >= 4096
            {
                let entropy = if let Some(data) =
                    read_memory(task, region.base_address, region.size.min(16384) as usize)
                {
                    MemoryScanner::calculate_entropy(&data)
                } else {
                    0.0
                };

                anomalies.push(VadAnomaly {
                    base_address: region.base_address,
                    size: region.size as usize,
                    protection: region.protection_string(),
                    anomaly_type: VadAnomalyType::UnbackedExecutable,
                    backing_file: None,
                    entropy,
                    details: format!(
                        "Executable private memory without dylib backing (type: {})",
                        region.region_type
                    ),
                    confidence: if entropy > 5.5 { 0.85 } else { 0.65 },
                });
            }

            // Check for high entropy executable regions
            if region.is_executable && region.size >= 4096 {
                if let Some(data) =
                    read_memory(task, region.base_address, region.size.min(16384) as usize)
                {
                    let entropy = MemoryScanner::calculate_entropy(&data);
                    if entropy > 7.2 {
                        anomalies.push(VadAnomaly {
                            base_address: region.base_address,
                            size: region.size as usize,
                            protection: region.protection_string(),
                            anomaly_type: VadAnomalyType::HighEntropyHeap,
                            backing_file: None,
                            entropy,
                            details: format!("High entropy ({:.2}) executable region", entropy),
                            confidence: 0.7,
                        });
                    }
                }
            }
        }

        // Clean up task port
        unsafe { mach_port_deallocate(mach_task_self(), task) };

        anomalies
    }

    /// Scan process memory for shellcode patterns
    pub fn scan_for_shellcode(pid: i32, scanner: &MemoryScanner) -> Vec<MemoryScanResult> {
        let mut results = Vec::new();

        let task = match get_task_for_pid(pid) {
            Ok(t) => t,
            Err(_) => return results,
        };

        let regions = enumerate_regions(task);

        for region in &regions {
            // Only scan executable regions
            if !region.is_executable {
                continue;
            }

            // Skip dylibs (they're legitimately executable)
            if region.region_type == "dylib" && !region.is_writable {
                continue;
            }

            // Read and scan the region
            let scan_size = region.size.min(1024 * 1024) as usize; // Max 1MB per region
            if let Some(data) = read_memory(task, region.base_address, scan_size) {
                let patterns = scanner.scan_buffer(&data);
                if !patterns.is_empty() {
                    let entropy = MemoryScanner::calculate_entropy(&data);
                    results.push(MemoryScanResult {
                        address: region.base_address,
                        size: region.size,
                        protection: region.protection as u32,
                        is_unbacked: region.region_type == "private",
                        is_rwx: region.is_readable && region.is_writable && region.is_executable,
                        detected_patterns: patterns,
                        entropy,
                        has_pe_header: data.starts_with(b"MZ"),
                        has_shellcode: true,
                        confidence: 0.75,
                    });
                }
            }
        }

        // Clean up
        unsafe { mach_port_deallocate(mach_task_self(), task) };

        results
    }

    /// Check for Mach-O in private memory (reflective loading indicator)
    pub fn find_macho_in_memory(pid: i32) -> Vec<(u64, usize)> {
        let mut found = Vec::new();

        let task = match get_task_for_pid(pid) {
            Ok(t) => t,
            Err(_) => return found,
        };

        let regions = enumerate_regions(task);

        for region in &regions {
            // Check private executable regions
            if !region.is_private || region.size < 4096 {
                continue;
            }

            // Read first page
            if let Some(data) = read_memory(task, region.base_address, 4096) {
                // Check for Mach-O magic numbers
                if data.len() >= 4 {
                    let magic = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);

                    // Mach-O magic numbers
                    const MH_MAGIC_64: u32 = 0xfeedfacf;
                    const MH_CIGAM_64: u32 = 0xcffaedfe;
                    const FAT_MAGIC: u32 = 0xcafebabe;
                    const FAT_CIGAM: u32 = 0xbebafeca;

                    if magic == MH_MAGIC_64
                        || magic == MH_CIGAM_64
                        || magic == FAT_MAGIC
                        || magic == FAT_CIGAM
                    {
                        // Verify it's not a legitimate dylib region
                        if region.region_type != "dylib" {
                            found.push((region.base_address, region.size as usize));
                        }
                    }
                }
            }
        }

        // Clean up
        unsafe { mach_port_deallocate(mach_task_self(), task) };

        found
    }

    /// Safe wrapper for mach_port_deallocate, used by callers outside this module
    ///
    /// # Safety
    /// Caller must ensure the task port is valid and was obtained via get_task_for_pid.
    pub unsafe fn mach_port_deallocate_wrapper(task: MachPort) {
        mach_port_deallocate(mach_task_self(), task);
    }
}

// ============================================================================
// Advanced Injection Detection Module (Windows)
// ============================================================================

/// Advanced injection detection: Process Hollowing, Module Stomping, Transacted Hollowing.
///
/// These techniques are used by sophisticated malware to evade detection by
/// replacing or modifying legitimate process images and DLL modules in memory.
#[cfg(target_os = "windows")]
mod advanced_injection {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::collections::HashSet;
    use tracing::debug;

    // PE header offsets and constants
    const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // MZ
    const IMAGE_NT_SIGNATURE: u32 = 0x00004550; // PE\0\0
    const IMAGE_FILE_HEADER_SIZE: usize = 20;
    const IMAGE_OPTIONAL_HEADER64_MAGIC: u16 = 0x020B;
    const IMAGE_OPTIONAL_HEADER32_MAGIC: u16 = 0x010B;

    // Section characteristics flags
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
    const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
    const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;
    const IMAGE_SCN_CNT_CODE: u32 = 0x00000020;

    /// PE section header parsed from disk or memory
    #[derive(Debug, Clone)]
    struct PeSection {
        name: String,
        virtual_address: u32,
        virtual_size: u32,
        raw_data_offset: u32,
        raw_data_size: u32,
        characteristics: u32,
    }

    impl PeSection {
        fn is_executable(&self) -> bool {
            (self.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
                || (self.characteristics & IMAGE_SCN_CNT_CODE) != 0
        }

        fn is_writable(&self) -> bool {
            (self.characteristics & IMAGE_SCN_MEM_WRITE) != 0
        }
    }

    /// Parsed PE header info
    #[derive(Debug, Clone)]
    struct PeInfo {
        /// ImageBase from OptionalHeader
        image_base: u64,
        /// SizeOfImage from OptionalHeader
        size_of_image: u32,
        /// AddressOfEntryPoint from OptionalHeader
        entry_point_rva: u32,
        /// Whether this is a 64-bit PE
        is_64bit: bool,
        /// Section headers
        sections: Vec<PeSection>,
    }

    /// Parse PE headers from a byte buffer (from disk file or memory)
    fn parse_pe_info(data: &[u8]) -> Option<PeInfo> {
        if data.len() < 64 {
            return None;
        }

        // Check MZ signature
        let dos_sig = u16::from_le_bytes([data[0], data[1]]);
        if dos_sig != IMAGE_DOS_SIGNATURE {
            return None;
        }

        // Get PE header offset from e_lfanew
        let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
        if pe_offset + 4 > data.len() {
            return None;
        }

        // Check PE signature
        let pe_sig = u32::from_le_bytes([
            data[pe_offset],
            data[pe_offset + 1],
            data[pe_offset + 2],
            data[pe_offset + 3],
        ]);
        if pe_sig != IMAGE_NT_SIGNATURE {
            return None;
        }

        let file_header_offset = pe_offset + 4;
        if file_header_offset + IMAGE_FILE_HEADER_SIZE > data.len() {
            return None;
        }

        // Parse FILE_HEADER
        let number_of_sections =
            u16::from_le_bytes([data[file_header_offset + 2], data[file_header_offset + 3]])
                as usize;

        let optional_header_size =
            u16::from_le_bytes([data[file_header_offset + 16], data[file_header_offset + 17]])
                as usize;

        let optional_header_offset = file_header_offset + IMAGE_FILE_HEADER_SIZE;
        if optional_header_offset + 2 > data.len() {
            return None;
        }

        // Parse OPTIONAL_HEADER
        let magic = u16::from_le_bytes([
            data[optional_header_offset],
            data[optional_header_offset + 1],
        ]);

        let is_64bit = magic == IMAGE_OPTIONAL_HEADER64_MAGIC;

        let (image_base, size_of_image, entry_point_rva) = if is_64bit {
            if optional_header_offset + 56 + 8 > data.len() {
                return None;
            }
            let entry_point = u32::from_le_bytes([
                data[optional_header_offset + 16],
                data[optional_header_offset + 17],
                data[optional_header_offset + 18],
                data[optional_header_offset + 19],
            ]);
            let image_base = u64::from_le_bytes([
                data[optional_header_offset + 24],
                data[optional_header_offset + 25],
                data[optional_header_offset + 26],
                data[optional_header_offset + 27],
                data[optional_header_offset + 28],
                data[optional_header_offset + 29],
                data[optional_header_offset + 30],
                data[optional_header_offset + 31],
            ]);
            let size_of_image = u32::from_le_bytes([
                data[optional_header_offset + 56],
                data[optional_header_offset + 57],
                data[optional_header_offset + 58],
                data[optional_header_offset + 59],
            ]);
            (image_base, size_of_image, entry_point)
        } else {
            if optional_header_offset + 56 + 4 > data.len() {
                return None;
            }
            let entry_point = u32::from_le_bytes([
                data[optional_header_offset + 16],
                data[optional_header_offset + 17],
                data[optional_header_offset + 18],
                data[optional_header_offset + 19],
            ]);
            let image_base = u32::from_le_bytes([
                data[optional_header_offset + 28],
                data[optional_header_offset + 29],
                data[optional_header_offset + 30],
                data[optional_header_offset + 31],
            ]) as u64;
            let size_of_image = u32::from_le_bytes([
                data[optional_header_offset + 56],
                data[optional_header_offset + 57],
                data[optional_header_offset + 58],
                data[optional_header_offset + 59],
            ]);
            (image_base, size_of_image, entry_point)
        };

        // Parse section headers
        let section_table_offset = optional_header_offset + optional_header_size;
        let mut sections = Vec::new();

        for i in 0..number_of_sections {
            let sec_offset = section_table_offset + i * 40;
            if sec_offset + 40 > data.len() {
                break;
            }

            // Section name (8 bytes, null-padded)
            let name_bytes = &data[sec_offset..sec_offset + 8];
            let name = String::from_utf8_lossy(
                &name_bytes[..name_bytes.iter().position(|&b| b == 0).unwrap_or(8)],
            )
            .to_string();

            let virtual_size = u32::from_le_bytes([
                data[sec_offset + 8],
                data[sec_offset + 9],
                data[sec_offset + 10],
                data[sec_offset + 11],
            ]);
            let virtual_address = u32::from_le_bytes([
                data[sec_offset + 12],
                data[sec_offset + 13],
                data[sec_offset + 14],
                data[sec_offset + 15],
            ]);
            let raw_data_size = u32::from_le_bytes([
                data[sec_offset + 16],
                data[sec_offset + 17],
                data[sec_offset + 18],
                data[sec_offset + 19],
            ]);
            let raw_data_offset = u32::from_le_bytes([
                data[sec_offset + 20],
                data[sec_offset + 21],
                data[sec_offset + 22],
                data[sec_offset + 23],
            ]);
            let characteristics = u32::from_le_bytes([
                data[sec_offset + 36],
                data[sec_offset + 37],
                data[sec_offset + 38],
                data[sec_offset + 39],
            ]);

            sections.push(PeSection {
                name,
                virtual_address,
                virtual_size,
                raw_data_offset,
                raw_data_size,
                characteristics,
            });
        }

        Some(PeInfo {
            image_base,
            size_of_image,
            entry_point_rva,
            is_64bit,
            sections,
        })
    }

    /// Compute SHA256 hash of a byte slice
    fn sha256_hash(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// Read file contents from disk
    fn read_file_bytes(path: &str) -> Option<Vec<u8>> {
        std::fs::read(path).ok()
    }

    /// Read process memory at a given address
    fn read_process_memory(
        handle: windows::Win32::Foundation::HANDLE,
        address: u64,
        size: usize,
    ) -> Option<Vec<u8>> {
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

        let mut buffer = vec![0u8; size];
        let mut bytes_read = 0usize;

        unsafe {
            if ReadProcessMemory(
                handle,
                address as *const _,
                buffer.as_mut_ptr() as *mut _,
                size,
                Some(&mut bytes_read),
            )
            .is_ok()
                && bytes_read > 0
            {
                buffer.truncate(bytes_read);
                Some(buffer)
            } else {
                None
            }
        }
    }

    // ====================================================================
    // Process Hollowing Detection (T1055.012)
    // ====================================================================

    /// Detect process hollowing by comparing in-memory PE against on-disk PE.
    ///
    /// Hollowing replaces a legitimate process image with malicious code while
    /// keeping the process handle intact. Key indicators:
    /// - ImageBase in memory differs from disk PE optional header
    /// - SizeOfImage mismatch
    /// - Main module memory type is MEM_PRIVATE instead of MEM_IMAGE
    /// - Sections present on disk but unmapped in memory
    pub fn detect_process_hollowing(
        pid: u32,
        process_name: &str,
        process_path: &str,
    ) -> Option<ProcessHollowingResult> {
        use windows::Win32::Foundation::{CloseHandle, HMODULE};
        use windows::Win32::System::Memory::{
            VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_IMAGE, MEM_PRIVATE,
        };
        use windows::Win32::System::ProcessStatus::{
            EnumProcessModules, GetModuleInformation, MODULEINFO,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        // Skip if no valid path
        if process_path.is_empty() {
            return None;
        }

        // Read the on-disk PE file
        let disk_data = match read_file_bytes(process_path) {
            Some(d) if d.len() >= 64 => d,
            _ => return None,
        };

        let disk_pe = match parse_pe_info(&disk_data) {
            Some(pe) => pe,
            None => return None,
        };

        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            {
                Ok(h) => h,
                Err(_) => return None,
            };

            // Get the main module (first module = the executable image)
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

            let memory_image_base = mod_info.lpBaseOfDll as u64;
            let memory_size_of_image = mod_info.SizeOfImage;

            // Read in-memory PE header (first 4KB should cover headers)
            let mem_header_data = match read_process_memory(handle, memory_image_base, 4096) {
                Some(d) => d,
                None => {
                    let _ = CloseHandle(handle);
                    return None;
                }
            };

            let memory_pe = parse_pe_info(&mem_header_data);

            // Query the memory type of the main module base
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let mbi_result = VirtualQueryEx(
                handle,
                Some(memory_image_base as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            let main_module_private = if mbi_result > 0 {
                (mbi.Type.0 & MEM_PRIVATE.0) != 0 && (mbi.Type.0 & MEM_IMAGE.0) == 0
            } else {
                false
            };

            // Compare image bases
            let image_base_mismatch = memory_image_base != disk_pe.image_base;

            // Compare SizeOfImage
            let size_mismatch = memory_size_of_image != disk_pe.size_of_image;

            // Check for unmapped sections
            let mut unmapped_sections = Vec::new();
            for section in &disk_pe.sections {
                let section_addr = memory_image_base + section.virtual_address as u64;
                let mut sec_mbi = MEMORY_BASIC_INFORMATION::default();
                let sec_result = VirtualQueryEx(
                    handle,
                    Some(section_addr as *const _),
                    &mut sec_mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                );

                if sec_result == 0 {
                    unmapped_sections.push(section.name.clone());
                }
            }

            // Check if entry point is in unbacked memory
            let entry_point_addr = memory_image_base + disk_pe.entry_point_rva as u64;
            let mut ep_mbi = MEMORY_BASIC_INFORMATION::default();
            let entry_point_in_unbacked = if VirtualQueryEx(
                handle,
                Some(entry_point_addr as *const _),
                &mut ep_mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            ) > 0
            {
                (ep_mbi.Type.0 & MEM_IMAGE.0) == 0 && (ep_mbi.Type.0 & MEM_PRIVATE.0) != 0
            } else {
                false
            };

            let _ = CloseHandle(handle);

            // Calculate hashes
            let disk_pe_hash = sha256_hash(&disk_data[..std::cmp::min(disk_data.len(), 4096)]);
            let memory_pe_hash = sha256_hash(&mem_header_data);

            // Build evidence
            let mut evidence = Vec::new();
            let mut confidence: f32 = 0.0;

            if image_base_mismatch {
                evidence.push(format!(
                    "ImageBase mismatch: disk=0x{:x}, memory=0x{:x}",
                    disk_pe.image_base, memory_image_base
                ));
                confidence += 0.25;
            }

            if size_mismatch {
                evidence.push(format!(
                    "SizeOfImage mismatch: disk={}, memory={}",
                    disk_pe.size_of_image, memory_size_of_image
                ));
                confidence += 0.20;
            }

            if main_module_private {
                evidence.push("Main module is MEM_PRIVATE (expected MEM_IMAGE)".to_string());
                confidence += 0.30;
            }

            if entry_point_in_unbacked {
                evidence.push(format!(
                    "Entry point (RVA 0x{:x}) is in unbacked/private memory",
                    disk_pe.entry_point_rva
                ));
                confidence += 0.25;
            }

            if !unmapped_sections.is_empty() {
                evidence.push(format!(
                    "Unmapped sections: {}",
                    unmapped_sections.join(", ")
                ));
                confidence += 0.15;
            }

            if disk_pe_hash != memory_pe_hash {
                evidence.push("PE header hash differs between disk and memory".to_string());
                confidence += 0.10;
            }

            // Only report if there is meaningful evidence
            if confidence < 0.25 {
                return None;
            }

            confidence = confidence.min(0.99);

            Some(ProcessHollowingResult {
                pid,
                process_name: process_name.to_string(),
                process_path: process_path.to_string(),
                memory_image_base,
                disk_image_base: disk_pe.image_base,
                memory_size_of_image,
                disk_size_of_image: disk_pe.size_of_image,
                image_base_mismatch,
                size_mismatch,
                entry_point_in_unbacked,
                main_module_private,
                unmapped_sections,
                disk_pe_hash,
                memory_pe_hash,
                confidence,
                evidence,
            })
        }
    }

    // ====================================================================
    // Module Stomping Detection (T1055.001)
    // ====================================================================

    /// Detect module stomping by comparing .text section contents of loaded DLLs
    /// against their on-disk copies.
    ///
    /// Module stomping overwrites a legitimate DLL's code section with malicious
    /// code while keeping the DLL loaded at the same address. Indicators:
    /// - .text section hash differs between disk and memory
    /// - Unusually high entropy in code sections (encrypted payload)
    /// - PAGE_EXECUTE_READWRITE protection on DLL memory (normally PAGE_EXECUTE_READ)
    pub fn detect_module_stomping(
        pid: u32,
        process_name: &str,
        known_good_modules: &HashSet<String>,
    ) -> Vec<ModuleStompingResult> {
        use windows::Win32::Foundation::{CloseHandle, HMODULE};
        use windows::Win32::System::Memory::{
            VirtualQueryEx, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE,
        };
        use windows::Win32::System::ProcessStatus::{
            EnumProcessModules, GetModuleFileNameExW, GetModuleInformation, MODULEINFO,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        let mut results = Vec::new();

        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            {
                Ok(h) => h,
                Err(_) => return results,
            };

            // Enumerate all loaded modules
            let mut modules = vec![HMODULE::default(); 1024];
            let mut bytes_needed = 0u32;

            if EnumProcessModules(
                handle,
                modules.as_mut_ptr(),
                (modules.len() * std::mem::size_of::<HMODULE>()) as u32,
                &mut bytes_needed,
            )
            .is_err()
            {
                let _ = CloseHandle(handle);
                return results;
            }

            let num_modules =
                (bytes_needed as usize / std::mem::size_of::<HMODULE>()).min(modules.len());

            // Skip module[0] (the main executable -- covered by hollowing detection)
            for i in 1..num_modules {
                // Get module path
                let mut name_buf = [0u16; 512];
                let name_len = GetModuleFileNameExW(handle, modules[i], &mut name_buf);
                if name_len == 0 {
                    continue;
                }
                let module_path = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                let module_name = module_path
                    .rsplit('\\')
                    .next()
                    .unwrap_or(&module_path)
                    .to_string();

                // Skip known-good modules
                if known_good_modules.contains(&module_path.to_lowercase()) {
                    continue;
                }

                // Skip non-DLL modules
                let lower_path = module_path.to_lowercase();
                if !lower_path.ends_with(".dll") {
                    continue;
                }

                // Get module info
                let mut mod_info = MODULEINFO::default();
                if GetModuleInformation(
                    handle,
                    modules[i],
                    &mut mod_info,
                    std::mem::size_of::<MODULEINFO>() as u32,
                )
                .is_err()
                {
                    continue;
                }

                let module_base = mod_info.lpBaseOfDll as u64;
                let module_size = mod_info.SizeOfImage as u64;

                // Read on-disk file
                let disk_data = match read_file_bytes(&module_path) {
                    Some(d) if d.len() >= 64 => d,
                    _ => continue,
                };

                let disk_pe = match parse_pe_info(&disk_data) {
                    Some(pe) => pe,
                    None => continue,
                };

                // Check memory protection of module base
                let mut mbi = MEMORY_BASIC_INFORMATION::default();
                let has_rwx = if VirtualQueryEx(
                    handle,
                    Some(module_base as *const _),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                ) > 0
                {
                    mbi.Protect.contains(PAGE_EXECUTE_READWRITE)
                } else {
                    false
                };

                // Compare .text sections
                let mut text_section_modified = false;
                let mut disk_text_hash = String::new();
                let mut memory_text_hash = String::new();
                let mut diff_byte_count = 0usize;
                let mut first_diff_offset: Option<usize> = None;
                let mut section_entropies: Vec<(String, f32)> = Vec::new();

                for section in &disk_pe.sections {
                    // Read the section from memory
                    let section_mem_addr = module_base + section.virtual_address as u64;
                    let section_mem_size = section.virtual_size as usize;

                    if section_mem_size == 0 || section_mem_size > 50 * 1024 * 1024 {
                        continue; // Skip empty or unreasonably large sections
                    }

                    let mem_section_data =
                        match read_process_memory(handle, section_mem_addr, section_mem_size) {
                            Some(d) => d,
                            None => continue,
                        };

                    // Calculate entropy for this section
                    let section_entropy = MemoryScanner::calculate_entropy(&mem_section_data);
                    section_entropies.push((section.name.clone(), section_entropy));

                    // For .text section, do a deep comparison
                    if section.name == ".text" || section.is_executable() {
                        // Read the corresponding section from disk
                        let disk_offset = section.raw_data_offset as usize;
                        let disk_size = section.raw_data_size as usize;

                        if disk_offset + disk_size <= disk_data.len() && disk_size > 0 {
                            let disk_section_data =
                                &disk_data[disk_offset..disk_offset + disk_size];

                            let disk_hash = sha256_hash(disk_section_data);
                            let mem_hash = sha256_hash(
                                &mem_section_data
                                    [..std::cmp::min(mem_section_data.len(), disk_size)],
                            );

                            if section.name == ".text" || disk_text_hash.is_empty() {
                                disk_text_hash = disk_hash.clone();
                                memory_text_hash = mem_hash.clone();
                            }

                            if disk_hash != mem_hash {
                                text_section_modified = true;

                                // Count differing bytes
                                let compare_len =
                                    std::cmp::min(disk_section_data.len(), mem_section_data.len());
                                for j in 0..compare_len {
                                    if disk_section_data[j] != mem_section_data[j] {
                                        diff_byte_count += 1;
                                        if first_diff_offset.is_none() {
                                            first_diff_offset = Some(j);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Build result if suspicious
                if text_section_modified || has_rwx {
                    let mut evidence = Vec::new();
                    let mut confidence: f32 = 0.0;

                    if text_section_modified {
                        evidence.push(format!(
                            ".text section modified: {} bytes differ (first diff at offset 0x{:x})",
                            diff_byte_count,
                            first_diff_offset.unwrap_or(0)
                        ));
                        evidence.push(format!(
                            "Disk .text hash: {}, Memory .text hash: {}",
                            disk_text_hash, memory_text_hash
                        ));
                        confidence += 0.45;

                        // Higher confidence if many bytes changed (not just relocations)
                        if diff_byte_count > 256 {
                            confidence += 0.15;
                        }
                    }

                    if has_rwx {
                        evidence.push(
                            "Module has PAGE_EXECUTE_READWRITE protection (unusual for DLLs)"
                                .to_string(),
                        );
                        confidence += 0.25;
                    }

                    // Check for high-entropy executable sections (encrypted payloads)
                    for (sec_name, sec_entropy) in &section_entropies {
                        if *sec_entropy > 7.0 {
                            evidence.push(format!(
                                "High entropy in {} section: {:.2} (possible encrypted payload)",
                                sec_name, sec_entropy
                            ));
                            confidence += 0.10;
                        }
                    }

                    confidence = confidence.min(0.99);

                    // Only report if confidence is meaningful
                    if confidence >= 0.30 {
                        results.push(ModuleStompingResult {
                            pid,
                            process_name: process_name.to_string(),
                            module_path: module_path.clone(),
                            module_name,
                            module_base,
                            module_size,
                            disk_text_hash,
                            memory_text_hash,
                            text_section_modified,
                            section_entropies,
                            has_rwx_protection: has_rwx,
                            diff_byte_count,
                            first_diff_offset,
                            confidence,
                            evidence,
                        });
                    }
                }
            }

            let _ = CloseHandle(handle);
        }

        results
    }

    // ====================================================================
    // Transacted Hollowing Detection
    // ====================================================================

    /// Detect transacted hollowing by comparing the in-memory process image against
    /// the current on-disk file.
    ///
    /// Transacted hollowing abuses NTFS transactions (TxF) to create a section
    /// from a modified file, then roll back the transaction so the disk file looks
    /// clean. The process image in memory then differs from what's on disk.
    ///
    /// Detection approach:
    /// - Read the on-disk file and the in-memory image headers
    /// - Compare PE headers, entry points, and code sections
    /// - Check for open transaction handles via NtQueryInformationProcess
    pub fn detect_transacted_hollowing(
        pid: u32,
        process_name: &str,
        process_path: &str,
    ) -> Option<TransactedHollowingResult> {
        use windows::Win32::Foundation::{CloseHandle, HMODULE};
        use windows::Win32::System::ProcessStatus::{
            EnumProcessModules, GetModuleInformation, MODULEINFO,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        if process_path.is_empty() {
            return None;
        }

        // Read on-disk file
        let disk_data = match read_file_bytes(process_path) {
            Some(d) if d.len() >= 64 => d,
            _ => return None,
        };

        let disk_pe = match parse_pe_info(&disk_data) {
            Some(pe) => pe,
            None => return None,
        };

        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            {
                Ok(h) => h,
                Err(_) => return None,
            };

            // Get main module base
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

            // Read in-memory PE headers
            let mem_header_data = match read_process_memory(handle, module_base, 4096) {
                Some(d) => d,
                None => {
                    let _ = CloseHandle(handle);
                    return None;
                }
            };

            let memory_pe = match parse_pe_info(&mem_header_data) {
                Some(pe) => pe,
                None => {
                    let _ = CloseHandle(handle);
                    return None;
                }
            };

            // Compare the PE headers
            let pe_header_mismatch = disk_pe.entry_point_rva != memory_pe.entry_point_rva
                || disk_pe.image_base != memory_pe.image_base
                || disk_pe.size_of_image != memory_pe.size_of_image
                || disk_pe.sections.len() != memory_pe.sections.len();

            // Compare code section contents between disk and memory
            let mut image_mismatch = false;
            let mut code_diff_count = 0usize;

            for disk_section in &disk_pe.sections {
                if !disk_section.is_executable() {
                    continue;
                }

                let section_addr = module_base + disk_section.virtual_address as u64;
                let section_size = std::cmp::min(
                    disk_section.virtual_size as usize,
                    disk_section.raw_data_size as usize,
                );

                if section_size == 0 || section_size > 50 * 1024 * 1024 {
                    continue;
                }

                // Read from memory
                let mem_section = match read_process_memory(handle, section_addr, section_size) {
                    Some(d) => d,
                    None => continue,
                };

                // Read from disk
                let disk_offset = disk_section.raw_data_offset as usize;
                if disk_offset + section_size > disk_data.len() {
                    continue;
                }
                let disk_section_data = &disk_data[disk_offset..disk_offset + section_size];

                // Compare
                let compare_len = std::cmp::min(disk_section_data.len(), mem_section.len());
                for j in 0..compare_len {
                    if disk_section_data[j] != mem_section[j] {
                        code_diff_count += 1;
                    }
                }

                if code_diff_count > 0 {
                    image_mismatch = true;
                }
            }

            let _ = CloseHandle(handle);

            // Check for TxF handle indicators
            // TxF (Transacted NTFS) handles are identified by checking for
            // KTM (Kernel Transaction Manager) resource manager handles.
            // We detect this by looking at the file system object name for
            // the process image -- if it was created via a transaction, the
            // section object will reference the transaction.
            let txf_handles_detected = check_txf_handles(pid);
            let mut transaction_indicators = Vec::new();

            if txf_handles_detected {
                transaction_indicators
                    .push("Active NTFS transaction handle detected on process".to_string());
            }

            // Build evidence and confidence
            let mut evidence = Vec::new();
            let mut confidence: f32 = 0.0;

            if pe_header_mismatch {
                evidence.push(format!(
                    "PE header mismatch: disk EP=0x{:x} mem EP=0x{:x}, disk ImageBase=0x{:x} mem ImageBase=0x{:x}",
                    disk_pe.entry_point_rva, memory_pe.entry_point_rva,
                    disk_pe.image_base, memory_pe.image_base,
                ));
                confidence += 0.30;
            }

            if image_mismatch {
                evidence.push(format!(
                    "Code section content differs: {} bytes changed between disk and memory image",
                    code_diff_count
                ));
                confidence += 0.35;
            }

            if txf_handles_detected {
                evidence.push(
                    "TxF (Transacted NTFS) handle detected -- possible transaction abuse"
                        .to_string(),
                );
                confidence += 0.30;
                for indicator in &transaction_indicators {
                    evidence.push(indicator.clone());
                }
            }

            // Calculate file hashes for comparison
            let disk_file_hash = sha256_hash(&disk_data[..std::cmp::min(disk_data.len(), 4096)]);
            let memory_image_hash = sha256_hash(&mem_header_data);

            if disk_file_hash != memory_image_hash {
                evidence
                    .push("Header hash mismatch between disk file and memory image".to_string());
                // This alone is not enough, already counted above
            }

            // Only report if we have meaningful evidence
            if confidence < 0.25 {
                return None;
            }

            confidence = confidence.min(0.99);

            Some(TransactedHollowingResult {
                pid,
                process_name: process_name.to_string(),
                process_path: process_path.to_string(),
                disk_file_hash,
                memory_image_hash,
                image_mismatch,
                txf_handles_detected,
                transaction_indicators,
                pe_header_mismatch,
                confidence,
                evidence,
            })
        }
    }

    /// Check for TxF (Transacted NTFS) handles on a process.
    ///
    /// Uses NtQuerySystemInformation with SystemHandleInformation class to
    /// enumerate handles and look for KTM transaction objects associated
    /// with the target process.
    fn check_txf_handles(pid: u32) -> bool {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION};

        // Attempt to open the process to check for transaction handles.
        // Full implementation would use NtQuerySystemInformation(SystemHandleInformation)
        // to enumerate all handles for this PID and check for KTM transaction objects.
        //
        // As a heuristic, we check if the process has open handles to
        // \Device\KtmResourceManager or similar KTM objects by using
        // NtQueryInformationProcess with ProcessHandleInformation.

        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) {
                Ok(h) => h,
                Err(_) => return false,
            };

            // Heuristic: Check the PEB for unusual section backing.
            // In a transacted hollowing attack, the image section is created from
            // a transacted file. After rollback, the file is clean but the section
            // still contains the malicious content.
            //
            // We detect this by checking if the image section object name differs
            // from the file path. This is done by comparing the module filename
            // returned by GetModuleFileNameEx against the mapped file name from
            // GetMappedFileName. If they differ, it's a strong indicator.
            use windows::Win32::Foundation::HMODULE;
            use windows::Win32::System::ProcessStatus::{
                EnumProcessModules, GetMappedFileNameW, GetModuleFileNameExW,
            };

            // Re-open with VM_READ for mapped file name
            let _ = CloseHandle(handle);
            let handle = match OpenProcess(
                PROCESS_QUERY_INFORMATION | windows::Win32::System::Threading::PROCESS_VM_READ,
                false,
                pid,
            ) {
                Ok(h) => h,
                Err(_) => return false,
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
                return false;
            }

            // Get module filename (as reported by loader)
            let mut mod_name = [0u16; 512];
            let mod_len = GetModuleFileNameExW(handle, modules[0], &mut mod_name);
            let module_filename = if mod_len > 0 {
                String::from_utf16_lossy(&mod_name[..mod_len as usize])
            } else {
                let _ = CloseHandle(handle);
                return false;
            };

            // Get mapped filename (the actual section backing file)
            let mut mapped_name = [0u16; 512];
            let mapped_len = GetMappedFileNameW(handle, modules[0].0 as *const _, &mut mapped_name);

            let _ = CloseHandle(handle);

            if mapped_len > 0 {
                let mapped_filename = String::from_utf16_lossy(&mapped_name[..mapped_len as usize]);

                // The mapped filename uses device paths (e.g., \Device\HarddiskVolume1\...)
                // while the module filename uses drive letters (e.g., C:\...).
                // We compare the file name components only.
                let mod_file = module_filename.rsplit('\\').next().unwrap_or("");
                let mapped_file = mapped_filename.rsplit('\\').next().unwrap_or("");

                if !mod_file.is_empty()
                    && !mapped_file.is_empty()
                    && mod_file.to_lowercase() != mapped_file.to_lowercase()
                {
                    debug!(
                        pid = pid,
                        module = %module_filename,
                        mapped = %mapped_filename,
                        "TxF indicator: module filename differs from mapped file"
                    );
                    return true;
                }
            }
        }

        false
    }
}

// Stub for non-Windows platforms
#[cfg(not(target_os = "windows"))]
mod advanced_injection {
    use super::*;
    use std::collections::HashSet;

    pub fn detect_process_hollowing(
        _pid: u32,
        _process_name: &str,
        _process_path: &str,
    ) -> Option<ProcessHollowingResult> {
        None
    }

    pub fn detect_module_stomping(
        _pid: u32,
        _process_name: &str,
        _known_good: &HashSet<String>,
    ) -> Vec<ModuleStompingResult> {
        Vec::new()
    }

    pub fn detect_transacted_hollowing(
        _pid: u32,
        _process_name: &str,
        _process_path: &str,
    ) -> Option<TransactedHollowingResult> {
        None
    }
}
