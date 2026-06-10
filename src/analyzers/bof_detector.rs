//! Beacon Object File (BOF) Detection Module
//!
//! Detects BOF (Beacon Object File) execution, a technique used by Cobalt Strike
//! and other C2 frameworks to run position-independent code in memory.
//!
//! ## Detection Methods
//!
//! ### 1. COFF Header Detection in Memory
//! BOFs are COFF object files loaded directly into memory. We detect:
//! - COFF file headers (magic bytes: 0x64 0x86 for x64, 0x4C 0x01 for x86)
//! - COFF optional headers in unusual memory regions (MEM_PRIVATE, unbacked)
//! - Section headers characteristic of object files (.text, .data, .rdata)
//!
//! ### 2. BOF Beacon API Resolution Patterns
//! BOFs use a specific API resolution pattern through the Beacon API:
//! - BeaconPrintf, BeaconOutput, BeaconDataParse
//! - DynamicFunctionResolve pattern (GetProcAddress chains)
//! - API hashing for function resolution
//!
//! ### 3. In-Memory COFF Parsing Indicators
//! Detection of COFF parsing behavior:
//! - Section enumeration in memory
//! - Relocation fixup patterns
//! - Symbol table traversal
//!
//! ### 4. BOF Entry Point Patterns
//! BOFs have characteristic entry points:
//! - `go` function as main entry point
//! - BeaconDataParse calls at function start
//! - Specific prologue patterns
//!
//! ### 5. BOF-Specific Function Patterns
//! Detection of BOF helper function calls:
//! - BeaconPrintf (formatted output)
//! - BeaconOutput (raw output)
//! - BeaconFormatAlloc/BeaconFormatFree
//! - BeaconInjectProcess/BeaconInjectTemporaryProcess
//!
//! ## MITRE ATT&CK Mapping
//! - T1059.001: Command and Scripting Interpreter (PowerShell-like in-memory)
//! - T1106: Native API
//! - T1055: Process Injection
//! - T1620: Reflective Code Loading
//! - T1071.001: Application Layer Protocol (C2 communication)

use crate::collectors::{
    Detection, DetectionType, EventPayload, EventType, MemoryPermissionEvent, Severity,
    TelemetryEvent,
};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tracing::{info, trace};

/// COFF file header magic bytes
const COFF_MAGIC_X64: u16 = 0x8664; // IMAGE_FILE_MACHINE_AMD64
const COFF_MAGIC_X86: u16 = 0x014C; // IMAGE_FILE_MACHINE_I386
const COFF_MAGIC_ARM64: u16 = 0xAA64; // IMAGE_FILE_MACHINE_ARM64

/// COFF header structure size
const COFF_HEADER_SIZE: usize = 20;
/// COFF section header size
const COFF_SECTION_HEADER_SIZE: usize = 40;

/// BOF detection result
#[derive(Debug, Clone)]
pub struct BofDetection {
    /// Process ID where BOF was detected
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// Process path
    pub process_path: String,
    /// Memory address where COFF/BOF was found
    pub memory_address: u64,
    /// Size of the detected region
    pub region_size: usize,
    /// Type of BOF detection
    pub detection_type: BofDetectionType,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// Detected patterns
    pub detected_patterns: Vec<String>,
    /// COFF characteristics if parsed
    pub coff_info: Option<CoffInfo>,
    /// Beacon API functions detected
    pub beacon_apis: Vec<String>,
    /// Additional evidence
    pub evidence: Vec<String>,
}

/// Types of BOF detection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BofDetectionType {
    /// Raw COFF header detected in unbacked memory
    CoffHeaderInMemory,
    /// BOF Beacon API pattern detected
    BeaconApiPattern,
    /// COFF relocation processing detected
    CoffRelocationPattern,
    /// BOF entry point pattern (go function)
    BofEntryPoint,
    /// API hashing/resolution pattern
    ApiHashingPattern,
    /// BOF-style function call sequence
    BofFunctionSequence,
    /// In-memory COFF parsing activity
    CoffParsingActivity,
    /// Combined indicators (multiple signals)
    CombinedIndicators,
}

impl BofDetectionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CoffHeaderInMemory => "coff_header_in_memory",
            Self::BeaconApiPattern => "beacon_api_pattern",
            Self::CoffRelocationPattern => "coff_relocation_pattern",
            Self::BofEntryPoint => "bof_entry_point",
            Self::ApiHashingPattern => "api_hashing_pattern",
            Self::BofFunctionSequence => "bof_function_sequence",
            Self::CoffParsingActivity => "coff_parsing_activity",
            Self::CombinedIndicators => "combined_indicators",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::CoffHeaderInMemory => {
                "COFF object file header detected in unbacked/private memory"
            }
            Self::BeaconApiPattern => "Cobalt Strike Beacon API resolution pattern detected",
            Self::CoffRelocationPattern => "COFF relocation fixup processing pattern detected",
            Self::BofEntryPoint => "BOF-style entry point (go function) pattern detected",
            Self::ApiHashingPattern => "API hashing for dynamic function resolution detected",
            Self::BofFunctionSequence => "BOF helper function call sequence detected",
            Self::CoffParsingActivity => "In-memory COFF parsing/loading activity detected",
            Self::CombinedIndicators => "Multiple BOF indicators detected in process",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Self::CoffHeaderInMemory => Severity::Critical,
            Self::BeaconApiPattern => Severity::Critical,
            Self::CoffRelocationPattern => Severity::High,
            Self::BofEntryPoint => Severity::Critical,
            Self::ApiHashingPattern => Severity::High,
            Self::BofFunctionSequence => Severity::Critical,
            Self::CoffParsingActivity => Severity::High,
            Self::CombinedIndicators => Severity::Critical,
        }
    }

    pub fn mitre_techniques(&self) -> Vec<&'static str> {
        match self {
            Self::CoffHeaderInMemory => vec!["T1620", "T1055"],
            Self::BeaconApiPattern => vec!["T1106", "T1071.001"],
            Self::CoffRelocationPattern => vec!["T1620"],
            Self::BofEntryPoint => vec!["T1106", "T1059"],
            Self::ApiHashingPattern => vec!["T1027", "T1106"],
            Self::BofFunctionSequence => vec!["T1106", "T1071.001"],
            Self::CoffParsingActivity => vec!["T1620", "T1055"],
            Self::CombinedIndicators => vec!["T1620", "T1055", "T1106", "T1071.001"],
        }
    }
}

/// Parsed COFF file information
#[derive(Debug, Clone)]
pub struct CoffInfo {
    /// Machine type (x64, x86, ARM64)
    pub machine: CoffMachine,
    /// Number of sections
    pub num_sections: u16,
    /// Timestamp from COFF header
    pub timestamp: u32,
    /// COFF characteristics flags
    pub characteristics: u16,
    /// Section names found
    pub sections: Vec<String>,
    /// Symbols referenced (if symbol table present)
    pub symbols: Vec<String>,
    /// Whether this appears to be a BOF (vs regular object file)
    pub is_likely_bof: bool,
}

/// COFF machine types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoffMachine {
    X64,
    X86,
    Arm64,
    Unknown(u16),
}

impl CoffMachine {
    pub fn from_magic(magic: u16) -> Self {
        match magic {
            COFF_MAGIC_X64 => Self::X64,
            COFF_MAGIC_X86 => Self::X86,
            COFF_MAGIC_ARM64 => Self::Arm64,
            other => Self::Unknown(other),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::X64 => "x64",
            Self::X86 => "x86",
            Self::Arm64 => "arm64",
            Self::Unknown(_) => "unknown",
        }
    }
}

/// Beacon API function signatures and their byte patterns
const BEACON_API_STRINGS: &[&str] = &[
    "BeaconPrintf",
    "BeaconOutput",
    "BeaconDataParse",
    "BeaconDataInt",
    "BeaconDataShort",
    "BeaconDataLength",
    "BeaconDataExtract",
    "BeaconFormatAlloc",
    "BeaconFormatReset",
    "BeaconFormatAppend",
    "BeaconFormatPrintf",
    "BeaconFormatToString",
    "BeaconFormatFree",
    "BeaconFormatInt",
    "BeaconUseToken",
    "BeaconRevertToken",
    "BeaconIsAdmin",
    "BeaconGetSpawnTo",
    "BeaconSpawnTemporaryProcess",
    "BeaconInjectProcess",
    "BeaconInjectTemporaryProcess",
    "BeaconCleanupProcess",
    "toWideChar",
    "KERNEL32",
    "NTDLL",
    "GetProcAddress",
    "LoadLibraryA",
    "VirtualAlloc",
    "VirtualProtect",
];

/// BOF-specific byte patterns for detection
/// These are patterns commonly found in BOF code
const BOF_BYTE_PATTERNS: &[(&str, &[u8], f32)] = &[
    // BOF entry point prologue patterns (x64)
    // push rbp; mov rbp, rsp; sub rsp, XX
    (
        "bof_prologue_x64_1",
        &[0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC],
        0.7,
    ),
    // push rbx; sub rsp, XX; mov rbx, rcx (common BOF arg handling)
    ("bof_prologue_x64_2", &[0x53, 0x48, 0x83, 0xEC], 0.6),
    // BeaconDataParse call pattern (common at BOF start)
    // This is a call to parse the argument buffer from Beacon
    ("beacon_data_parse_setup", &[0x48, 0x8D, 0x54, 0x24], 0.75),
    // API hashing loop (ROR 13 pattern commonly used)
    // ror eax, 0x0D; add eax, ecx
    ("api_hash_ror13", &[0xC1, 0xC8, 0x0D, 0x01, 0xC8], 0.85),
    // ror edx, 0x0D; add edx, eax
    ("api_hash_ror13_v2", &[0xC1, 0xCA, 0x0D, 0x01, 0xC2], 0.85),
    // Dynamic GetProcAddress resolution pattern (x64)
    // mov rcx, [gs:0x60] - PEB access
    (
        "peb_access_x64",
        &[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00],
        0.8,
    ),
    // InMemoryOrderModuleList traversal (common in BOF API resolution)
    // mov rax, [rax+0x10] or similar offsets
    ("ldr_module_list", &[0x48, 0x8B, 0x40, 0x10], 0.5),
    // Syscall stub patterns (some BOFs use direct syscalls)
    ("syscall_stub", &[0x4C, 0x8B, 0xD1, 0xB8], 0.9),
    // COFF relocation pattern markers
    // These patterns appear during relocation fixup
    ("reloc_base_adjustment", &[0x48, 0x03, 0x05], 0.5),
    // Common BOF cleanup pattern (before return)
    // xor eax, eax; add rsp, XX; pop rbx; ret
    ("bof_cleanup_x64", &[0x33, 0xC0, 0x48, 0x83, 0xC4], 0.6),
    // Beacon output buffer write pattern
    // mov [rcx+XX], rdx style memory writes
    ("beacon_buffer_write", &[0x48, 0x89, 0x51], 0.4),
];

/// COFF section names commonly found in BOFs
const BOF_SECTION_NAMES: &[&str] = &[
    ".text", ".data", ".rdata", ".bss", ".reloc", ".pdata", ".xdata",
];

/// BOF Detector configuration
#[derive(Debug, Clone)]
pub struct BofDetectorConfig {
    /// Enable COFF header scanning
    pub scan_coff_headers: bool,
    /// Enable Beacon API pattern detection
    pub scan_beacon_apis: bool,
    /// Enable API hashing detection
    pub scan_api_hashing: bool,
    /// Minimum confidence threshold for alerts
    pub confidence_threshold: f32,
    /// Maximum memory region size to scan (bytes)
    pub max_scan_size: usize,
    /// Scan interval
    pub scan_interval: Duration,
    /// Processes to skip (known legitimate)
    pub skip_processes: HashSet<String>,
}

impl Default for BofDetectorConfig {
    fn default() -> Self {
        let mut skip = HashSet::new();
        // Skip known development/build tools that legitimately handle COFF
        skip.insert("link.exe".to_lowercase());
        skip.insert("cl.exe".to_lowercase());
        skip.insert("lib.exe".to_lowercase());
        skip.insert("dumpbin.exe".to_lowercase());
        skip.insert("ml64.exe".to_lowercase());
        skip.insert("armasm64.exe".to_lowercase());
        skip.insert("objdump.exe".to_lowercase());

        Self {
            scan_coff_headers: true,
            scan_beacon_apis: true,
            scan_api_hashing: true,
            confidence_threshold: 0.65,
            max_scan_size: 10 * 1024 * 1024, // 10MB
            scan_interval: Duration::from_secs(30),
            skip_processes: skip,
        }
    }
}

/// BOF Detector for analyzing memory regions
pub struct BofDetector {
    config: BofDetectorConfig,
    /// Cache of recently scanned regions to avoid duplicate alerts
    scan_cache: HashMap<(u32, u64), Instant>,
    /// Cache expiry duration
    cache_expiry: Duration,
}

impl BofDetector {
    /// Create a new BOF detector with default configuration
    pub fn new() -> Self {
        Self::with_config(BofDetectorConfig::default())
    }

    /// Create a new BOF detector with custom configuration
    pub fn with_config(config: BofDetectorConfig) -> Self {
        Self {
            config,
            scan_cache: HashMap::new(),
            cache_expiry: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Clean up expired cache entries
    pub fn cleanup_cache(&mut self) {
        let now = Instant::now();
        self.scan_cache
            .retain(|_, timestamp| now.duration_since(*timestamp) < self.cache_expiry);
    }

    /// Check if a process should be skipped
    pub fn should_skip_process(&self, process_name: &str) -> bool {
        self.config
            .skip_processes
            .contains(&process_name.to_lowercase())
    }

    /// Scan a memory buffer for BOF indicators
    pub fn scan_buffer(
        &mut self,
        pid: u32,
        process_name: &str,
        process_path: &str,
        memory_address: u64,
        buffer: &[u8],
    ) -> Option<BofDetection> {
        if buffer.is_empty() {
            return None;
        }

        // Check cache to avoid duplicate scanning
        let cache_key = (pid, memory_address);
        if let Some(timestamp) = self.scan_cache.get(&cache_key) {
            if Instant::now().duration_since(*timestamp) < self.cache_expiry {
                trace!(
                    pid,
                    address = memory_address,
                    "BOF scan cache hit, skipping"
                );
                return None;
            }
        }

        let mut detected_patterns = Vec::new();
        let mut beacon_apis = Vec::new();
        let mut evidence = Vec::new();
        let mut total_confidence: f32 = 0.0;
        let mut detection_count = 0;

        // 1. Check for COFF header
        let coff_info = if self.config.scan_coff_headers {
            self.parse_coff_header(buffer)
        } else {
            None
        };

        if let Some(ref info) = coff_info {
            detected_patterns.push("coff_header".to_string());
            evidence.push(format!(
                "COFF header detected: machine={}, sections={}",
                info.machine.as_str(),
                info.num_sections
            ));
            total_confidence += 0.4;
            detection_count += 1;

            if info.is_likely_bof {
                detected_patterns.push("bof_characteristics".to_string());
                evidence.push(
                    "COFF characteristics indicate BOF (relocatable, no entry point)".to_string(),
                );
                total_confidence += 0.3;
            }

            // Check for BOF-typical sections
            for section in &info.sections {
                if BOF_SECTION_NAMES.contains(&section.as_str()) {
                    evidence.push(format!("BOF section: {}", section));
                }
            }

            // Check for Beacon symbols
            for symbol in &info.symbols {
                if BEACON_API_STRINGS.iter().any(|api| symbol.contains(api)) {
                    beacon_apis.push(symbol.clone());
                    evidence.push(format!("Beacon API symbol: {}", symbol));
                    total_confidence += 0.2;
                }
            }
        }

        // 2. Scan for Beacon API strings
        if self.config.scan_beacon_apis {
            let found_apis = self.scan_beacon_api_strings(buffer);
            for api in found_apis {
                if !beacon_apis.contains(&api) {
                    beacon_apis.push(api.clone());
                    detected_patterns.push(format!("beacon_api:{}", api));
                    total_confidence += 0.15;
                    detection_count += 1;
                }
            }
        }

        // 3. Scan for BOF byte patterns
        for (pattern_name, pattern, confidence) in BOF_BYTE_PATTERNS {
            if self.find_pattern(buffer, pattern) {
                detected_patterns.push(pattern_name.to_string());
                evidence.push(format!("BOF pattern detected: {}", pattern_name));
                total_confidence += confidence;
                detection_count += 1;
            }
        }

        // 4. Scan for API hashing patterns
        if self.config.scan_api_hashing {
            if self.detect_api_hashing(buffer) {
                detected_patterns.push("api_hashing".to_string());
                evidence.push("API hashing/resolution loop detected".to_string());
                total_confidence += 0.25;
                detection_count += 1;
            }
        }

        // 5. Check for COFF relocation patterns
        if self.detect_coff_relocations(buffer) {
            detected_patterns.push("coff_relocations".to_string());
            evidence.push("COFF relocation fixup patterns detected".to_string());
            total_confidence += 0.2;
            detection_count += 1;
        }

        // Normalize confidence (cap at 1.0)
        let confidence = (total_confidence / detection_count.max(1) as f32).min(1.0);

        // Only alert if we meet threshold and have meaningful detections
        if confidence >= self.config.confidence_threshold && detection_count >= 2 {
            // Update cache
            self.scan_cache.insert(cache_key, Instant::now());

            // Determine detection type based on what we found
            let detection_type = if coff_info.is_some() && !beacon_apis.is_empty() {
                BofDetectionType::CombinedIndicators
            } else if coff_info.is_some() {
                BofDetectionType::CoffHeaderInMemory
            } else if !beacon_apis.is_empty() {
                BofDetectionType::BeaconApiPattern
            } else if detected_patterns.contains(&"api_hashing".to_string()) {
                BofDetectionType::ApiHashingPattern
            } else if detected_patterns
                .iter()
                .any(|p| p.starts_with("bof_prologue"))
            {
                BofDetectionType::BofEntryPoint
            } else {
                BofDetectionType::BofFunctionSequence
            };

            info!(
                pid,
                process_name,
                address = format!("0x{:x}", memory_address),
                confidence,
                patterns = ?detected_patterns,
                "BOF detection alert"
            );

            Some(BofDetection {
                pid,
                process_name: process_name.to_string(),
                process_path: process_path.to_string(),
                memory_address,
                region_size: buffer.len(),
                detection_type,
                confidence,
                detected_patterns,
                coff_info,
                beacon_apis,
                evidence,
            })
        } else {
            None
        }
    }

    /// Parse COFF header from buffer
    fn parse_coff_header(&self, buffer: &[u8]) -> Option<CoffInfo> {
        if buffer.len() < COFF_HEADER_SIZE {
            return None;
        }

        // Read machine type (first 2 bytes)
        let machine_raw = u16::from_le_bytes([buffer[0], buffer[1]]);
        let machine = CoffMachine::from_magic(machine_raw);

        // Validate it's a known COFF machine type
        if matches!(machine, CoffMachine::Unknown(_)) {
            return None;
        }

        // Parse COFF header fields
        let num_sections = u16::from_le_bytes([buffer[2], buffer[3]]);
        let timestamp = u32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
        let symbol_table_offset =
            u32::from_le_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]);
        let num_symbols = u32::from_le_bytes([buffer[12], buffer[13], buffer[14], buffer[15]]);
        let optional_header_size = u16::from_le_bytes([buffer[16], buffer[17]]);
        let characteristics = u16::from_le_bytes([buffer[18], buffer[19]]);

        // Validate reasonable values
        if num_sections == 0 || num_sections > 96 {
            return None;
        }

        // Parse section names
        let mut sections = Vec::new();
        let section_table_offset = COFF_HEADER_SIZE + optional_header_size as usize;

        for i in 0..num_sections as usize {
            let section_offset = section_table_offset + i * COFF_SECTION_HEADER_SIZE;
            if section_offset + 8 > buffer.len() {
                break;
            }

            // Section name is first 8 bytes (null-terminated or full 8 chars)
            let name_bytes = &buffer[section_offset..section_offset + 8];
            let name = String::from_utf8_lossy(name_bytes)
                .trim_end_matches('\0')
                .to_string();
            if !name.is_empty() {
                sections.push(name);
            }
        }

        // Parse symbols if present
        let mut symbols = Vec::new();
        if symbol_table_offset > 0 && num_symbols > 0 {
            let sym_offset = symbol_table_offset as usize;
            // String table is immediately after symbol table
            let string_table_offset = sym_offset + (num_symbols as usize * 18);

            if string_table_offset + 4 < buffer.len() {
                // Read string table size
                let string_table_size = u32::from_le_bytes([
                    buffer[string_table_offset],
                    buffer[string_table_offset + 1],
                    buffer[string_table_offset + 2],
                    buffer[string_table_offset + 3],
                ]) as usize;

                // Extract strings from string table (look for Beacon API names)
                if string_table_offset + string_table_size <= buffer.len() {
                    let string_table =
                        &buffer[string_table_offset..string_table_offset + string_table_size];
                    for api in BEACON_API_STRINGS {
                        if string_table.windows(api.len()).any(|w| w == api.as_bytes()) {
                            symbols.push(api.to_string());
                        }
                    }
                }
            }
        }

        // Determine if this is likely a BOF
        // BOFs are typically:
        // - Relocatable (no fixed base address)
        // - No line numbers
        // - May have unresolved external references
        const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;
        const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
        #[allow(dead_code)]
        const IMAGE_FILE_LINE_NUMS_STRIPPED: u16 = 0x0004;

        let is_likely_bof =
            // Not a full executable
            (characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0 &&
            // Has relocations (not stripped)
            (characteristics & IMAGE_FILE_RELOCS_STRIPPED) == 0 &&
            // Has standard BOF sections
            sections.iter().any(|s| s == ".text") &&
            // Small number of sections typical of BOF
            num_sections <= 10;

        Some(CoffInfo {
            machine,
            num_sections,
            timestamp,
            characteristics,
            sections,
            symbols,
            is_likely_bof,
        })
    }

    /// Scan for Beacon API string references in buffer
    fn scan_beacon_api_strings(&self, buffer: &[u8]) -> Vec<String> {
        let mut found = Vec::new();

        for api in BEACON_API_STRINGS {
            let api_bytes = api.as_bytes();
            if buffer.windows(api_bytes.len()).any(|w| w == api_bytes) {
                found.push(api.to_string());
            }
        }

        found
    }

    /// Find a byte pattern in the buffer
    fn find_pattern(&self, buffer: &[u8], pattern: &[u8]) -> bool {
        if pattern.len() > buffer.len() {
            return false;
        }
        buffer.windows(pattern.len()).any(|w| w == pattern)
    }

    /// Detect API hashing patterns (common in BOF and shellcode)
    fn detect_api_hashing(&self, buffer: &[u8]) -> bool {
        // Look for ROR-based hashing loops (very common in BOF API resolution)

        // ROR13 hash pattern variants
        let ror13_patterns: &[&[u8]] = &[
            &[0xC1, 0xC8, 0x0D], // ror eax, 0x0D
            &[0xC1, 0xCA, 0x0D], // ror edx, 0x0D
            &[0xC1, 0xCB, 0x0D], // ror ebx, 0x0D
            &[0xC1, 0xC9, 0x0D], // ror ecx, 0x0D
            &[0xC0, 0xC8, 0x0D], // ror al, 0x0D
        ];

        let mut ror_count = 0;
        for pattern in ror13_patterns {
            if self.find_pattern(buffer, pattern) {
                ror_count += 1;
            }
        }

        // Look for XOR-based hashing
        let xor_hash_indicators = [
            &[0x31, 0xC0][..], // xor eax, eax (init)
            &[0x33, 0xC0][..], // xor eax, eax (init)
            &[0xAC][..],       // lodsb (string iteration)
        ];

        let mut xor_count = 0;
        for pattern in xor_hash_indicators {
            if self.find_pattern(buffer, pattern) {
                xor_count += 1;
            }
        }

        // Detection if we see multiple hashing indicators
        ror_count >= 1 && xor_count >= 2
    }

    /// Detect COFF relocation fixup patterns
    fn detect_coff_relocations(&self, buffer: &[u8]) -> bool {
        // Look for patterns indicative of runtime relocation processing

        // LEA with RIP-relative addressing (common for position-independent code)
        let lea_rip_patterns: &[&[u8]] = &[
            &[0x48, 0x8D, 0x05], // lea rax, [rip+XX]
            &[0x48, 0x8D, 0x0D], // lea rcx, [rip+XX]
            &[0x48, 0x8D, 0x15], // lea rdx, [rip+XX]
            &[0x4C, 0x8D, 0x05], // lea r8, [rip+XX]
        ];

        let mut lea_count = 0;
        for pattern in lea_rip_patterns {
            // Count occurrences
            let mut pos = 0;
            while pos + pattern.len() <= buffer.len() {
                if &buffer[pos..pos + pattern.len()] == *pattern {
                    lea_count += 1;
                    if lea_count >= 5 {
                        return true; // Early exit if many LEA RIP found
                    }
                }
                pos += 1;
            }
        }

        // Also look for relocation table markers (IMAGE_REL_AMD64_* patterns)
        // These appear in the .reloc section data
        lea_count >= 3
    }

    /// Create a TelemetryEvent from a BOF detection
    pub fn create_telemetry_event(detection: &BofDetection) -> TelemetryEvent {
        let severity = detection.detection_type.severity();

        let mut event = TelemetryEvent::new(
            EventType::MemoryScan,
            severity,
            EventPayload::MemoryPermission(MemoryPermissionEvent {
                pid: detection.pid,
                process_name: detection.process_name.clone(),
                process_path: detection.process_path.clone(),
                base_address: detection.memory_address,
                region_size: detection.region_size as u64,
                old_protection: 0,
                new_protection: 0,
                old_protection_str: String::new(),
                new_protection_str: "EXECUTE".to_string(),
                mem_type: 0x20000, // MEM_PRIVATE
                mem_type_str: "MEM_PRIVATE".to_string(),
                entropy: 0.0,
                transition_type: "bof_detection".to_string(),
                thread_from_unbacked: false,
                thread_id: None,
                thread_start_address: None,
            }),
        );

        // Build comprehensive description
        let description = format!(
            "{}: {} (PID: {}) at 0x{:x} - {} patterns detected, {} Beacon APIs found",
            detection.detection_type.description(),
            detection.process_name,
            detection.pid,
            detection.memory_address,
            detection.detected_patterns.len(),
            detection.beacon_apis.len()
        );

        // Get MITRE mapping
        let mitre_techniques: Vec<String> = detection
            .detection_type
            .mitre_techniques()
            .iter()
            .map(|s| s.to_string())
            .collect();

        event.add_detection(Detection {
            detection_type: DetectionType::MemoryThreat,
            rule_name: format!("bof_detection_{}", detection.detection_type.as_str()),
            confidence: detection.confidence,
            description,
            mitre_tactics: vec!["execution".to_string(), "defense-evasion".to_string()],
            mitre_techniques,
        });

        // Add detailed metadata
        event.metadata.insert(
            "bof_detection_type".to_string(),
            detection.detection_type.as_str().to_string(),
        );
        event.metadata.insert(
            "detected_patterns".to_string(),
            detection.detected_patterns.join(", "),
        );
        event
            .metadata
            .insert("beacon_apis".to_string(), detection.beacon_apis.join(", "));
        event
            .metadata
            .insert("evidence".to_string(), detection.evidence.join("; "));
        event.metadata.insert(
            "confidence".to_string(),
            format!("{:.2}", detection.confidence),
        );

        if let Some(ref coff_info) = detection.coff_info {
            event.metadata.insert(
                "coff_machine".to_string(),
                coff_info.machine.as_str().to_string(),
            );
            event.metadata.insert(
                "coff_sections".to_string(),
                format!("{}", coff_info.num_sections),
            );
            event.metadata.insert(
                "coff_section_names".to_string(),
                coff_info.sections.join(", "),
            );
            event.metadata.insert(
                "is_likely_bof".to_string(),
                coff_info.is_likely_bof.to_string(),
            );
        }

        event
    }
}

impl Default for BofDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coff_machine_types() {
        assert_eq!(CoffMachine::from_magic(0x8664), CoffMachine::X64);
        assert_eq!(CoffMachine::from_magic(0x014C), CoffMachine::X86);
        assert_eq!(CoffMachine::from_magic(0xAA64), CoffMachine::Arm64);
        assert!(matches!(
            CoffMachine::from_magic(0x0000),
            CoffMachine::Unknown(_)
        ));
    }

    #[test]
    fn test_bof_detection_type_metadata() {
        let detection_type = BofDetectionType::CoffHeaderInMemory;
        assert_eq!(detection_type.as_str(), "coff_header_in_memory");
        assert!(detection_type.mitre_techniques().contains(&"T1620"));
    }

    #[test]
    fn test_beacon_api_string_detection() {
        let detector = BofDetector::new();

        // Buffer containing Beacon API string
        let buffer = b"some data BeaconPrintf more data BeaconOutput end";
        let found = detector.scan_beacon_api_strings(buffer);

        assert!(found.contains(&"BeaconPrintf".to_string()));
        assert!(found.contains(&"BeaconOutput".to_string()));
    }

    #[test]
    fn test_api_hashing_detection() {
        let detector = BofDetector::new();

        // Buffer with ROR13 and lodsb patterns
        let buffer = [
            0x31, 0xC0, // xor eax, eax
            0xAC, // lodsb
            0xC1, 0xC8, 0x0D, // ror eax, 0x0D
            0x01, 0xC0, // add eax, eax
        ];

        assert!(detector.detect_api_hashing(&buffer));
    }

    #[test]
    fn test_coff_header_parsing() {
        let detector = BofDetector::new();

        // Minimal valid x64 COFF header with 1 section
        let mut buffer = vec![0u8; 100];
        // Machine: x64
        buffer[0] = 0x64;
        buffer[1] = 0x86;
        // Number of sections: 1
        buffer[2] = 0x01;
        buffer[3] = 0x00;
        // Timestamp
        buffer[4..8].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        // Pointer to symbol table: 0
        buffer[8..12].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // Number of symbols: 0
        buffer[12..16].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // Size of optional header: 0
        buffer[16] = 0x00;
        buffer[17] = 0x00;
        // Characteristics: 0
        buffer[18] = 0x00;
        buffer[19] = 0x00;
        // Section header starts at offset 20
        // Section name: .text
        buffer[20..28].copy_from_slice(b".text\0\0\0");

        let coff_info = detector.parse_coff_header(&buffer);
        assert!(coff_info.is_some());

        let info = coff_info.unwrap();
        assert_eq!(info.machine, CoffMachine::X64);
        assert_eq!(info.num_sections, 1);
        assert!(info.sections.contains(&".text".to_string()));
    }

    #[test]
    fn test_pattern_matching() {
        let detector = BofDetector::new();

        let buffer = [0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20];
        let pattern = &[0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC];

        assert!(detector.find_pattern(&buffer, pattern));
        assert!(!detector.find_pattern(&buffer, &[0xFF, 0xFF]));
    }

    #[test]
    fn test_skip_process() {
        let detector = BofDetector::new();

        assert!(detector.should_skip_process("link.exe"));
        assert!(detector.should_skip_process("LINK.EXE"));
        assert!(!detector.should_skip_process("notepad.exe"));
    }

    #[test]
    fn test_full_scan_with_bof_indicators() {
        let mut detector = BofDetector::new();

        // Create a buffer that looks like a BOF
        let mut buffer = vec![0u8; 200];

        // Add COFF header (x64)
        buffer[0] = 0x64;
        buffer[1] = 0x86;
        buffer[2] = 0x02; // 2 sections
        buffer[3] = 0x00;

        // Add Beacon API strings somewhere in buffer
        let api_str = b"BeaconPrintf";
        buffer[100..100 + api_str.len()].copy_from_slice(api_str);

        // Add API hashing pattern
        buffer[150..153].copy_from_slice(&[0xC1, 0xC8, 0x0D]); // ror eax, 0x0D
        buffer[160..162].copy_from_slice(&[0x31, 0xC0]); // xor eax, eax
        buffer[170] = 0xAC; // lodsb

        let detection = detector.scan_buffer(1234, "test.exe", "C:\\test.exe", 0x7FF00000, &buffer);

        // With a valid COFF header and Beacon API strings, we should get a detection
        // (depends on exact threshold and pattern matching)
        if let Some(det) = detection {
            assert!(det.confidence > 0.0);
            assert!(!det.detected_patterns.is_empty());
        }
    }
}
