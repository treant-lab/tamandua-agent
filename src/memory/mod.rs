//! Advanced Memory Analysis Module
//!
//! Comprehensive memory forensics capabilities for the Tamandua EDR agent:
//! - Memory dump acquisition (full process or specific regions)
//! - YARA scanning of process memory
//! - Suspicious region detection (RWX, injected DLLs, hollowed sections)
//! - VAD tree analysis (Windows)
//! - Import/Export table analysis (IAT/EAT hooking detection)
//! - Memory string extraction with pattern matching
//!
//! Platform Support:
//! - Windows: MiniDumpWriteDump, VirtualQueryEx, ReadProcessMemory
//! - Linux: /proc/[pid]/mem, /proc/[pid]/maps
//! - macOS: mach_vm_read, task_for_pid
//!
//! MITRE ATT&CK:
//! - T1055 (Process Injection)
//! - T1055.012 (Process Hollowing)
//! - T1620 (Reflective Code Loading)
//! - T1574.011 (DLL Side-Loading)
//! - T1027 (Obfuscated Files or Information)

pub mod dump;
pub mod evasion_detector;
pub mod indirect_syscall_detector;
pub mod pe_parser;
pub mod scanner;
pub mod stack_spoofing_detector;
pub mod string_extractor;
pub mod suspicious_detector;

#[cfg(target_os = "windows")]
pub mod vad_parser;

#[cfg(test)]
mod tests;

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Memory region information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    /// Base address of the region
    pub base_address: u64,
    /// Size of the region in bytes
    pub size: u64,
    /// Memory protection flags (PAGE_*)
    pub protection: u32,
    /// Memory type (MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE)
    pub memory_type: MemoryRegionType,
    /// Module name if backed by file
    pub module_name: Option<String>,
    /// Module path if backed by file
    pub module_path: Option<String>,
    /// Is executable (has EXECUTE permission)
    pub is_executable: bool,
    /// Is writable (has WRITE permission)
    pub is_writable: bool,
    /// Is readable (has READ permission)
    pub is_readable: bool,
    /// Is private memory (not backed by file)
    pub is_private: bool,
}

/// Memory region type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryRegionType {
    /// Mapped from executable file (DLL/EXE)
    Image,
    /// Memory-mapped file
    Mapped,
    /// Private allocation (VirtualAlloc)
    Private,
    /// Thread stack
    Stack,
    /// Process heap
    Heap,
    /// Unknown type
    Unknown,
}

/// Suspicious memory detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousRegion {
    /// Process ID
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// Memory region details
    pub region: MemoryRegion,
    /// Suspicion reasons (can have multiple)
    pub reasons: Vec<SuspicionReason>,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// Additional context
    pub details: String,
}

/// Reason for flagging a memory region as suspicious
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuspicionReason {
    /// RWX memory (writable + executable)
    RwxMemory,
    /// Executable private memory (not backed by file)
    ExecutablePrivate,
    /// Injected DLL (LoadLibrary without manifest)
    InjectedDll,
    /// Hollowed section (entry point mismatch)
    HollowedSection,
    /// Memory in non-image region with executable code
    NonImageExecutable,
    /// IAT hook detected
    IatHook,
    /// Inline hook detected (jmp/call redirects)
    InlineHook,
    /// High entropy in executable region
    HighEntropy,
    /// PE header in private memory
    PeInPrivateMemory,
}

impl SuspicionReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RwxMemory => "rwx_memory",
            Self::ExecutablePrivate => "executable_private",
            Self::InjectedDll => "injected_dll",
            Self::HollowedSection => "hollowed_section",
            Self::NonImageExecutable => "non_image_executable",
            Self::IatHook => "iat_hook",
            Self::InlineHook => "inline_hook",
            Self::HighEntropy => "high_entropy",
            Self::PeInPrivateMemory => "pe_in_private_memory",
        }
    }

    pub fn mitre_technique(&self) -> &'static str {
        match self {
            Self::RwxMemory | Self::ExecutablePrivate => "T1055",
            Self::InjectedDll => "T1055.001",
            Self::HollowedSection => "T1055.012",
            Self::NonImageExecutable => "T1620",
            Self::IatHook | Self::InlineHook => "T1055.001",
            Self::HighEntropy => "T1027",
            Self::PeInPrivateMemory => "T1620",
        }
    }
}

/// YARA scan result for memory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryYaraMatch {
    /// Rule name that matched
    pub rule_name: String,
    /// Rule tags
    pub tags: Vec<String>,
    /// Rule metadata
    pub metadata: serde_json::Value,
    /// Match offset in memory region
    pub offset: u64,
    /// Match length
    pub length: usize,
    /// Memory region where match occurred
    pub region: MemoryRegion,
}

/// Memory analysis report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryAnalysisReport {
    /// Process ID
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// Process path
    pub process_path: Option<String>,
    /// Timestamp of analysis
    pub timestamp: u64,
    /// Total memory regions scanned
    pub regions_scanned: usize,
    /// Suspicious regions found
    pub suspicious_regions: Vec<SuspiciousRegion>,
    /// YARA matches
    pub yara_matches: Vec<MemoryYaraMatch>,
    /// IAT hooks detected
    pub iat_hooks: Vec<IatHook>,
    /// Inline hooks detected
    pub inline_hooks: Vec<InlineHook>,
    /// Extracted strings (top N by relevance)
    pub strings: Vec<ExtractedString>,
}

/// IAT hook information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IatHook {
    /// Module name (e.g., "ntdll.dll")
    pub module: String,
    /// Function name (e.g., "NtCreateFile")
    pub function: String,
    /// Expected address
    pub expected_address: u64,
    /// Actual address (hooked)
    pub actual_address: u64,
    /// Hook target module (if resolvable)
    pub hook_target: Option<String>,
}

/// Inline hook information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InlineHook {
    /// Module name
    pub module: String,
    /// Function name
    pub function: String,
    /// Function address
    pub address: u64,
    /// First N bytes (showing jmp/call)
    pub bytes: Vec<u8>,
    /// Disassembled instruction
    pub disassembly: String,
    /// Target address
    pub target_address: u64,
}

/// Extracted string from memory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedString {
    /// String content
    pub content: String,
    /// String type (ascii, unicode, url, ip, path)
    pub string_type: StringType,
    /// Memory address
    pub address: u64,
    /// Memory region
    pub region: MemoryRegion,
    /// Relevance score (0.0 - 1.0)
    pub relevance: f32,
}

/// String type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StringType {
    /// Plain ASCII string
    Ascii,
    /// Unicode (UTF-16) string
    Unicode,
    /// URL pattern
    Url,
    /// IP address
    IpAddress,
    /// File path
    FilePath,
    /// Registry key
    RegistryKey,
    /// Base64 encoded
    Base64,
}

impl StringType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ascii => "ascii",
            Self::Unicode => "unicode",
            Self::Url => "url",
            Self::IpAddress => "ip_address",
            Self::FilePath => "file_path",
            Self::RegistryKey => "registry_key",
            Self::Base64 => "base64",
        }
    }
}

/// Memory dump options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpOptions {
    /// Dump type (full or selective)
    pub dump_type: DumpType,
    /// Compress dump with zstd
    pub compress: bool,
    /// Upload to backend
    pub upload: bool,
    /// Save to disk path (optional)
    pub output_path: Option<String>,
}

/// Memory dump type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DumpType {
    /// Full process memory dump
    Full,
    /// Only RWX regions
    RwxRegions,
    /// Only private executable regions
    PrivateExecutable,
    /// Only suspicious regions
    Suspicious,
}

/// Get memory regions for a process
pub async fn get_memory_regions(pid: u32) -> Result<Vec<MemoryRegion>> {
    #[cfg(target_os = "windows")]
    {
        dump::windows::get_memory_regions_windows(pid).await
    }

    #[cfg(target_os = "linux")]
    {
        dump::linux::get_memory_regions_linux(pid).await
    }

    #[cfg(target_os = "macos")]
    {
        dump::macos::get_memory_regions_macos(pid).await
    }
}

/// Dump process memory
pub async fn dump_process_memory(
    pid: u32,
    regions: Vec<MemoryRegion>,
    options: &DumpOptions,
) -> Result<Vec<u8>> {
    #[cfg(target_os = "windows")]
    {
        dump::windows::dump_process_memory_windows(pid, regions, options).await
    }

    #[cfg(target_os = "linux")]
    {
        dump::linux::dump_process_memory_linux(pid, regions, options).await
    }

    #[cfg(target_os = "macos")]
    {
        dump::macos::dump_process_memory_macos(pid, regions, options).await
    }
}

/// Scan memory with YARA rules
#[cfg(feature = "yara")]
pub async fn scan_memory_yara(
    pid: u32,
    regions: Vec<MemoryRegion>,
    rules_path: &str,
) -> Result<Vec<MemoryYaraMatch>> {
    scanner::scan_memory_yara(pid, regions, rules_path).await
}

/// Detect suspicious memory regions
pub async fn detect_suspicious_regions(pid: u32) -> Result<Vec<SuspiciousRegion>> {
    suspicious_detector::detect_suspicious_regions(pid).await
}

/// Analyze import/export tables for hooks
pub async fn analyze_hooks(pid: u32) -> Result<(Vec<IatHook>, Vec<InlineHook>)> {
    pe_parser::analyze_hooks(pid).await
}

/// Extract strings from memory
pub async fn extract_strings(
    pid: u32,
    regions: Vec<MemoryRegion>,
    min_length: usize,
) -> Result<Vec<ExtractedString>> {
    string_extractor::extract_strings(pid, regions, min_length).await
}

/// Perform full memory analysis
pub async fn analyze_memory(pid: u32, process_name: String) -> Result<MemoryAnalysisReport> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Get memory regions
    let regions = get_memory_regions(pid).await?;
    let regions_scanned = regions.len();

    // Detect suspicious regions
    let suspicious_regions = detect_suspicious_regions(pid).await.unwrap_or_default();

    // Scan with YARA (if available)
    #[cfg(feature = "yara")]
    let yara_matches = scan_memory_yara(pid, regions.clone(), "")
        .await
        .unwrap_or_default();
    #[cfg(not(feature = "yara"))]
    let yara_matches = Vec::new();

    // Analyze hooks
    let (iat_hooks, inline_hooks) = analyze_hooks(pid).await.unwrap_or_default();

    // Extract strings (limit to top 100 most relevant)
    let all_strings = extract_strings(pid, regions.clone(), 4)
        .await
        .unwrap_or_default();
    let mut strings = all_strings;
    strings.sort_by(|a, b| {
        b.relevance
            .partial_cmp(&a.relevance)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    strings.truncate(100);

    Ok(MemoryAnalysisReport {
        pid,
        process_name,
        process_path: None,
        timestamp,
        regions_scanned,
        suspicious_regions,
        yara_matches,
        iat_hooks,
        inline_hooks,
        strings,
    })
}

// Re-export stack spoofing detector types
pub use stack_spoofing_detector::{
    scan_process_for_stack_spoofing, scan_thread_for_stack_spoofing, FrameAnomaly,
    FrameAnomalyType, ModuleInfo, ReturnAddressIssue, SpoofingSeverity, StackFrame, StackInfo,
    StackSpoofingDetection, StackSpoofingDetector, StackSpoofingTechnique, SuspiciousReturnAddress,
};
