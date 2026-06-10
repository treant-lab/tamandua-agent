//! Heap Spray Detection Module
//!
//! Detects heap spray exploitation attempts, a technique used to prepare memory
//! layout for exploitation by filling heap memory with specific patterns.
//!
//! ## Heap Spray Techniques Detected
//!
//! ### 1. NOP Sled Spraying
//! - Classic 0x90 NOP instructions
//! - Alternative single-byte instructions (0x0c, 0x0d, 0x41)
//! - Wide character variants for JavaScript sprays
//!
//! ### 2. JavaScript/Browser Heap Spray
//! - ArrayBuffer allocations with predictable content
//! - String concatenation spray patterns
//! - TypedArray-based sprays
//!
//! ### 3. Shellcode-laden Sprays
//! - Common shellcode signatures embedded in spray blocks
//! - ROP gadget chains at predictable offsets
//! - Jump trampolines at block boundaries
//!
//! ### 4. Predictable Address Targeting
//! - Allocations targeting specific addresses (0x0c0c0c0c, 0x0d0d0d0d)
//! - Heap feng shui patterns
//! - Memory layout manipulation
//!
//! ## Detection Methods
//!
//! - Track VirtualAlloc/HeapAlloc patterns
//! - Monitor allocation frequencies and sizes
//! - Detect many similar-content allocations
//! - Analyze entropy of allocated regions
//! - Identify shellcode/NOP patterns in allocations
//!
//! ## MITRE ATT&CK Mapping
//! - T1203: Exploitation for Client Execution
//!
//! ## References
//! - https://www.corelan.be/index.php/2011/12/31/exploit-writing-tutorial-part-11-heap-spraying-demystified/
//! - https://attack.mitre.org/techniques/T1203/

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};

use crate::analyzers::calculate_entropy;
use crate::collectors::{
    Detection, DetectionType, EventPayload, EventType, MemoryPermissionEvent, Severity,
    TelemetryEvent,
};
use crate::config::AgentConfig;

// =============================================================================
// CONSTANTS - HEAP SPRAY DETECTION PATTERNS
// =============================================================================

/// Common heap spray NOP-equivalent patterns
/// These patterns are used to create NOP sleds or predictable memory content
pub const NOP_PATTERNS: &[(&str, &[u8])] = &[
    ("x86_nop", &[0x90, 0x90, 0x90, 0x90]),    // x86 NOP
    ("or_al_0c", &[0x0c, 0x0c, 0x0c, 0x0c]),   // OR AL, 0x0C (browser spray)
    ("or_eax_0d", &[0x0d, 0x0d, 0x0d, 0x0d]),  // OR EAX, 0x0D0D0D0D
    ("padding_41", &[0x41, 0x41, 0x41, 0x41]), // 'AAAA' padding
    ("padding_42", &[0x42, 0x42, 0x42, 0x42]), // 'BBBB' padding
    ("padding_43", &[0x43, 0x43, 0x43, 0x43]), // 'CCCC' padding
    ("null_slide", &[0x00, 0x00, 0x00, 0x00]), // NULL slide
    ("x64_nop", &[0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]), // x64 NOP sled
    ("heap_align_0a", &[0x0a, 0x0a, 0x0a, 0x0a]), // OR CL/DL, 0x0A variants
    ("int3_sled", &[0xcc, 0xcc, 0xcc, 0xcc]),  // INT3 breakpoint sled
];

/// Common heap spray target addresses (little-endian representations)
/// These addresses are typically targeted because they're predictable
pub const SPRAY_TARGET_ADDRESSES: &[u64] = &[
    0x0c0c0c0c, // Classic heap spray target
    0x0d0d0d0d, // Alternative heap spray target
    0x0a0a0a0a, // Another common target
    0x04040404, // Low address target
    0x05050505, // Low address target
    0x06060606, // Low address target
    0x07070707, // Low address target
    0x08080808, // Low address target
    0x0b0b0b0b, // Near 0x0c0c0c0c
    0x0e0e0e0e, // Near 0x0d0d0d0d
    0x41414141, // 'AAAA' as address
    0x42424242, // 'BBBB' as address
];

/// Shellcode signature patterns commonly found in heap sprays
/// These are the first bytes of common shellcode stubs
pub const SHELLCODE_PATTERNS: &[(&str, &[u8])] = &[
    // Windows PEB access patterns (used for API resolution)
    ("peb_access_x64", &[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60]),
    ("peb_access_x86_fs", &[0x64, 0xA1, 0x30, 0x00, 0x00, 0x00]),
    ("peb_access_x86_mov", &[0x64, 0x8B, 0x15, 0x30, 0x00, 0x00]),
    // Metasploit-style patterns
    ("msf_shikata", &[0xDA, 0xC1, 0xD9, 0x74, 0x24]), // Shikata Ga Nai encoder
    ("msf_reverse_tcp", &[0xFC, 0xE8, 0x82, 0x00, 0x00]), // Reverse TCP stub
    ("msf_meterpreter", &[0xFC, 0x48, 0x83, 0xE4, 0xF0]), // x64 meterpreter
    // Egg hunter patterns
    ("egg_hunter_ntaccess", &[0x66, 0x81, 0xCA, 0xFF, 0x0F]),
    ("egg_hunter_seh", &[0xEB, 0x21, 0x5F, 0xB9]),
    // Jump trampolines
    ("jmp_esp", &[0xFF, 0xE4]),  // JMP ESP
    ("jmp_eax", &[0xFF, 0xE0]),  // JMP EAX
    ("call_esp", &[0xFF, 0xD4]), // CALL ESP
    ("call_eax", &[0xFF, 0xD0]), // CALL EAX
    ("push_ret", &[0x50, 0xC3]), // PUSH EAX; RET
    // ROP gadget indicators
    ("pop_pop_ret", &[0x5F, 0x5E, 0xC3]), // POP EDI; POP ESI; RET
    ("xchg_eax_esp", &[0x94, 0xC3]),      // XCHG EAX, ESP; RET
    // Cobalt Strike beacon patterns
    ("cs_beacon_start", &[0x4D, 0x5A, 0xE8]), // MZ header with call
    ("cs_shellcode_x64", &[0xFC, 0x48, 0x83, 0xE4]), // x64 shellcode start
    // WinExec/CreateProcess setup
    ("kernel32_hash", &[0x68, 0x8E, 0x4E, 0x0E, 0xEC]), // Push hash for kernel32
    ("winexec_hash", &[0x68, 0xA8, 0xA2, 0x4D, 0xBC]),  // Push hash for WinExec
];

/// Typical heap spray block sizes (in bytes)
/// Heap sprays often use power-of-2 or browser-friendly sizes
pub const COMMON_SPRAY_SIZES: &[usize] = &[
    0x10000,  // 64KB - common spray block
    0x20000,  // 128KB
    0x40000,  // 256KB
    0x80000,  // 512KB
    0x100000, // 1MB
    0x200000, // 2MB
    0x1000,   // 4KB - page size
    0x2000,   // 8KB
    0x4000,   // 16KB
    0x8000,   // 32KB
    0xFFFF0,  // Just under 1MB (JavaScript string)
    0x7FFE0,  // Just under 512KB
];

// =============================================================================
// TYPES AND STRUCTURES
// =============================================================================

/// Heap spray detection result/alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeapSprayAlert {
    /// Process ID where heap spray was detected
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// Process path
    pub process_path: String,
    /// Type of heap spray detected
    pub spray_type: SprayType,
    /// Estimated total sprayed memory size
    pub estimated_size: usize,
    /// Name of the detected pattern
    pub pattern_detected: String,
    /// Affected memory range (start, end)
    pub affected_memory_range: (usize, usize),
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// Number of identical allocations detected
    pub identical_allocation_count: usize,
    /// Detection indicators
    pub indicators: HeapSprayIndicators,
    /// Evidence gathered during detection
    pub evidence: Vec<String>,
    /// MITRE ATT&CK technique ID
    pub mitre_id: &'static str,
    /// Timestamp of detection (milliseconds since UNIX epoch)
    pub timestamp: u64,
}

/// Types of heap spray detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SprayType {
    /// Classic NOP sled spray (0x90909090)
    NopSled,
    /// Browser-specific spray (OR AL patterns)
    BrowserSpray,
    /// JavaScript string/array spray
    JavaScriptSpray,
    /// Shellcode-laden spray
    ShellcodeSpray,
    /// ROP gadget spray
    RopGadgetSpray,
    /// Generic repetitive allocation spray
    GenericSpray,
    /// VBScript-based spray
    VBScriptSpray,
    /// TypedArray-based spray
    TypedArraySpray,
    /// Unknown spray type
    Unknown,
}

impl SprayType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NopSled => "nop_sled",
            Self::BrowserSpray => "browser_spray",
            Self::JavaScriptSpray => "javascript_spray",
            Self::ShellcodeSpray => "shellcode_spray",
            Self::RopGadgetSpray => "rop_gadget_spray",
            Self::GenericSpray => "generic_spray",
            Self::VBScriptSpray => "vbscript_spray",
            Self::TypedArraySpray => "typed_array_spray",
            Self::Unknown => "unknown",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::NopSled => "Classic NOP sled heap spray detected",
            Self::BrowserSpray => "Browser-specific heap spray (OR AL pattern)",
            Self::JavaScriptSpray => "JavaScript string/array heap spray",
            Self::ShellcodeSpray => "Heap spray with embedded shellcode",
            Self::RopGadgetSpray => "ROP gadget chain heap spray",
            Self::GenericSpray => "Generic repetitive allocation spray",
            Self::VBScriptSpray => "VBScript-based heap spray",
            Self::TypedArraySpray => "TypedArray-based heap spray",
            Self::Unknown => "Unknown heap spray type",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Self::ShellcodeSpray | Self::RopGadgetSpray => Severity::Critical,
            Self::NopSled | Self::BrowserSpray | Self::JavaScriptSpray => Severity::High,
            Self::VBScriptSpray | Self::TypedArraySpray | Self::GenericSpray => Severity::High,
            Self::Unknown => Severity::Medium,
        }
    }
}

/// Heap spray detection indicators
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HeapSprayIndicators {
    /// Many allocations with identical content detected
    pub large_identical_allocations: bool,
    /// NOP sled patterns (0x90909090) detected
    pub nop_sled_detected: bool,
    /// Common shellcode signatures found
    pub shellcode_patterns: bool,
    /// Allocations at predictable/targeted addresses
    pub predictable_addresses: bool,
    /// Excessive string allocations (JS/VBS spray indicator)
    pub excessive_string_allocations: bool,
    /// Total estimated spray size in bytes
    pub total_spray_size: usize,
    /// Low entropy detected (highly repetitive content)
    pub low_entropy_detected: bool,
    /// Specific NOP pattern name if detected
    pub nop_pattern_name: Option<String>,
    /// Specific shellcode pattern name if detected
    pub shellcode_pattern_name: Option<String>,
    /// Number of allocations with same content hash
    pub same_content_count: usize,
    /// Allocation size matches common spray sizes
    pub common_spray_size_match: bool,
    /// Rapid successive allocations detected
    pub rapid_allocations: bool,
}

impl HeapSprayIndicators {
    /// Calculate overall confidence based on indicators
    pub fn calculate_confidence(&self) -> f32 {
        let mut confidence: f32 = 0.0;

        if self.large_identical_allocations {
            confidence += 0.25;
        }
        if self.nop_sled_detected {
            confidence += 0.20;
        }
        if self.shellcode_patterns {
            confidence += 0.30;
        }
        if self.predictable_addresses {
            confidence += 0.15;
        }
        if self.excessive_string_allocations {
            confidence += 0.10;
        }
        if self.low_entropy_detected {
            confidence += 0.10;
        }
        if self.common_spray_size_match {
            confidence += 0.05;
        }
        if self.rapid_allocations {
            confidence += 0.10;
        }

        // Scale based on same content count
        if self.same_content_count >= 100 {
            confidence += 0.15;
        } else if self.same_content_count >= 50 {
            confidence += 0.10;
        } else if self.same_content_count >= 20 {
            confidence += 0.05;
        }

        confidence.min(1.0)
    }
}

/// Tracked heap allocation for spray detection
#[derive(Debug, Clone)]
pub struct TrackedAllocation {
    /// Base address of the allocation
    pub address: usize,
    /// Size of the allocation
    pub size: usize,
    /// Content hash (for identifying identical content)
    pub content_hash: u64,
    /// Shannon entropy of the content
    pub entropy: f32,
    /// When the allocation was observed
    pub timestamp: Instant,
    /// Memory protection flags
    pub protection: u32,
}

/// Memory region analysis result
#[derive(Debug, Clone)]
pub struct MemoryAnalysis {
    /// Suspicious regions identified
    pub suspicious_regions: Vec<SuspiciousRegion>,
    /// Total RW memory across all scanned regions
    pub total_rw_memory: usize,
    /// Count of regions with identical content
    pub identical_region_count: usize,
    /// Overall entropy analysis result
    pub entropy_analysis: EntropyResult,
    /// Detected spray patterns
    pub detected_patterns: Vec<DetectedPattern>,
}

/// A suspicious memory region identified during analysis
#[derive(Debug, Clone)]
pub struct SuspiciousRegion {
    /// Base address
    pub address: usize,
    /// Region size
    pub size: usize,
    /// Why this region is suspicious
    pub reason: String,
    /// Detected pattern (if any)
    pub pattern: Option<DetectedPattern>,
    /// Content hash
    pub content_hash: u64,
    /// Entropy of the region
    pub entropy: f32,
}

/// A detected pattern in memory
#[derive(Debug, Clone)]
pub struct DetectedPattern {
    /// Pattern name
    pub name: String,
    /// Pattern type
    pub pattern_type: PatternType,
    /// Offset where pattern was found
    pub offset: usize,
    /// Length of the pattern
    pub length: usize,
}

/// Pattern type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternType {
    NopSled,
    Shellcode,
    JumpTrampoline,
    RopGadget,
    Padding,
}

/// Entropy analysis result
#[derive(Debug, Clone)]
pub struct EntropyResult {
    /// Average entropy across analyzed regions
    pub average_entropy: f32,
    /// Minimum entropy observed
    pub min_entropy: f32,
    /// Maximum entropy observed
    pub max_entropy: f32,
    /// Number of low entropy regions (< 2.0)
    pub low_entropy_count: usize,
}

/// JavaScript heap spray indicator
#[derive(Debug, Clone)]
pub struct JsSprayIndicator {
    /// Allocation pattern detected
    pub pattern: String,
    /// Estimated spray count
    pub spray_count: usize,
    /// Total memory used
    pub total_memory: usize,
    /// Confidence score
    pub confidence: f32,
}

/// Allocation tracking entry with timing
#[derive(Debug, Clone)]
struct AllocationEntry {
    allocation: TrackedAllocation,
    pid: u32,
}

// =============================================================================
// PATTERN MATCHING
// =============================================================================

/// Pattern matcher for heap spray detection
pub struct PatternMatcher {
    /// Compiled NOP patterns
    nop_patterns: Vec<(&'static str, Vec<u8>)>,
    /// Compiled shellcode patterns
    shellcode_patterns: Vec<(&'static str, Vec<u8>)>,
}

impl PatternMatcher {
    /// Create a new pattern matcher
    pub fn new() -> Self {
        let nop_patterns: Vec<_> = NOP_PATTERNS
            .iter()
            .map(|(name, pat)| (*name, pat.to_vec()))
            .collect();

        let shellcode_patterns: Vec<_> = SHELLCODE_PATTERNS
            .iter()
            .map(|(name, pat)| (*name, pat.to_vec()))
            .collect();

        Self {
            nop_patterns,
            shellcode_patterns,
        }
    }

    /// Detect spray patterns in data
    pub fn detect_spray_pattern(&self, data: &[u8]) -> Option<SprayPattern> {
        if data.len() < 16 {
            return None;
        }

        // Check for NOP sled patterns
        if let Some((name, repetitions)) = self.detect_nop_sled(data) {
            return Some(SprayPattern {
                pattern_type: SprayPatternType::NopSled,
                pattern_name: name.to_string(),
                repetition_count: repetitions,
                confidence: calculate_pattern_confidence(repetitions, data.len()),
            });
        }

        // Check for shellcode patterns
        if let Some(name) = self.detect_shellcode(data) {
            return Some(SprayPattern {
                pattern_type: SprayPatternType::Shellcode,
                pattern_name: name.to_string(),
                repetition_count: 1,
                confidence: 0.9,
            });
        }

        // Check for low entropy (highly repetitive content)
        let entropy = calculate_entropy(data);
        if entropy < 1.5 && data.len() >= 1024 {
            // Find the most common 4-byte sequence
            if let Some((pattern_bytes, count)) = find_most_common_sequence(data, 4) {
                let repetitions = count;
                if repetitions > data.len() / 8 {
                    return Some(SprayPattern {
                        pattern_type: SprayPatternType::RepetitiveContent,
                        pattern_name: format!("0x{:08X}", u32::from_le_bytes(pattern_bytes)),
                        repetition_count: repetitions,
                        confidence: calculate_pattern_confidence(repetitions, data.len()),
                    });
                }
            }
        }

        None
    }

    /// Detect NOP sled patterns
    fn detect_nop_sled(&self, data: &[u8]) -> Option<(&str, usize)> {
        for (name, pattern) in &self.nop_patterns {
            let count = count_pattern_occurrences(data, pattern);
            let pattern_bytes = pattern.len();
            let min_threshold = (data.len() / pattern_bytes / 4).max(10); // At least 25% coverage

            if count >= min_threshold {
                return Some((name, count));
            }
        }
        None
    }

    /// Detect shellcode patterns
    fn detect_shellcode(&self, data: &[u8]) -> Option<&str> {
        for (name, pattern) in &self.shellcode_patterns {
            if contains_pattern(data, pattern) {
                return Some(name);
            }
        }
        None
    }

    /// Check if data contains any shellcode signatures
    pub fn contains_shellcode(&self, data: &[u8]) -> Vec<String> {
        let mut found = Vec::new();
        for (name, pattern) in &self.shellcode_patterns {
            if contains_pattern(data, pattern) {
                found.push(name.to_string());
            }
        }
        found
    }
}

impl Default for PatternMatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Spray pattern detection result
#[derive(Debug, Clone)]
pub struct SprayPattern {
    /// Type of pattern detected
    pub pattern_type: SprayPatternType,
    /// Name of the pattern
    pub pattern_name: String,
    /// Number of times pattern repeats
    pub repetition_count: usize,
    /// Confidence score
    pub confidence: f32,
}

/// Spray pattern type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SprayPatternType {
    NopSled,
    Shellcode,
    RepetitiveContent,
    JumpTrampoline,
}

// =============================================================================
// ALLOCATION TRACKER
// =============================================================================

/// Tracks heap allocations to detect spray patterns
pub struct AllocationTracker {
    /// Allocations per process: pid -> list of allocations
    allocations: HashMap<u32, VecDeque<AllocationEntry>>,
    /// Content hash -> count (for detecting identical allocations)
    hash_counts: HashMap<(u32, u64), usize>,
    /// Maximum allocations to track per process
    max_allocations_per_process: usize,
    /// Allocation entry lifetime
    allocation_lifetime: Duration,
}

impl AllocationTracker {
    /// Create a new allocation tracker
    pub fn new() -> Self {
        Self {
            allocations: HashMap::new(),
            hash_counts: HashMap::new(),
            max_allocations_per_process: 10000,
            allocation_lifetime: Duration::from_secs(60),
        }
    }

    /// Track a new allocation
    pub fn track_allocation(
        &mut self,
        pid: u32,
        addr: usize,
        size: usize,
        content_hash: u64,
        entropy: f32,
        protection: u32,
    ) {
        let allocation = TrackedAllocation {
            address: addr,
            size,
            content_hash,
            entropy,
            timestamp: Instant::now(),
            protection,
        };

        let entry = AllocationEntry { allocation, pid };

        // Update hash count
        let hash_key = (pid, content_hash);
        *self.hash_counts.entry(hash_key).or_insert(0) += 1;

        // Add to process allocations
        let allocations = self.allocations.entry(pid).or_insert_with(VecDeque::new);
        allocations.push_back(entry);

        // Enforce max allocations
        while allocations.len() > self.max_allocations_per_process {
            if let Some(old) = allocations.pop_front() {
                let old_key = (old.pid, old.allocation.content_hash);
                if let Some(count) = self.hash_counts.get_mut(&old_key) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        self.hash_counts.remove(&old_key);
                    }
                }
            }
        }
    }

    /// Get allocations for a process
    pub fn get_allocations(&self, pid: u32) -> Vec<&TrackedAllocation> {
        self.allocations
            .get(&pid)
            .map(|entries| entries.iter().map(|e| &e.allocation).collect())
            .unwrap_or_default()
    }

    /// Get count of allocations with specific content hash
    pub fn get_hash_count(&self, pid: u32, content_hash: u64) -> usize {
        self.hash_counts
            .get(&(pid, content_hash))
            .copied()
            .unwrap_or(0)
    }

    /// Get the most common content hash for a process
    pub fn get_most_common_hash(&self, pid: u32) -> Option<(u64, usize)> {
        let mut max_count = 0;
        let mut max_hash = None;

        for ((p, hash), count) in &self.hash_counts {
            if *p == pid && *count > max_count {
                max_count = *count;
                max_hash = Some(*hash);
            }
        }

        max_hash.map(|h| (h, max_count))
    }

    /// Cleanup old allocations
    pub fn cleanup(&mut self) {
        let now = Instant::now();

        for (pid, allocations) in &mut self.allocations {
            while let Some(front) = allocations.front() {
                if now.duration_since(front.allocation.timestamp) > self.allocation_lifetime {
                    if let Some(old) = allocations.pop_front() {
                        let old_key = (*pid, old.allocation.content_hash);
                        if let Some(count) = self.hash_counts.get_mut(&old_key) {
                            *count = count.saturating_sub(1);
                            if *count == 0 {
                                self.hash_counts.remove(&old_key);
                            }
                        }
                    }
                } else {
                    break;
                }
            }
        }

        // Remove empty process entries
        self.allocations.retain(|_, v| !v.is_empty());
    }

    /// Get statistics for a process
    pub fn get_stats(&self, pid: u32) -> AllocationStats {
        let allocations = self.get_allocations(pid);
        let count = allocations.len();

        if count == 0 {
            return AllocationStats::default();
        }

        let total_size: usize = allocations.iter().map(|a| a.size).sum();
        let avg_entropy: f32 = allocations.iter().map(|a| a.entropy).sum::<f32>() / count as f32;

        // Count unique hashes
        let unique_hashes: HashSet<u64> = allocations.iter().map(|a| a.content_hash).collect();

        // Find most common hash count
        let most_common = self.get_most_common_hash(pid);

        AllocationStats {
            allocation_count: count,
            total_size,
            average_entropy: avg_entropy,
            unique_content_count: unique_hashes.len(),
            most_common_hash_count: most_common.map(|(_, c)| c).unwrap_or(0),
        }
    }
}

impl Default for AllocationTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about allocations for a process
#[derive(Debug, Clone, Default)]
pub struct AllocationStats {
    pub allocation_count: usize,
    pub total_size: usize,
    pub average_entropy: f32,
    pub unique_content_count: usize,
    pub most_common_hash_count: usize,
}

// =============================================================================
// HEAP SPRAY DETECTOR
// =============================================================================

/// Configuration for heap spray detection
#[derive(Debug, Clone)]
pub struct HeapSprayConfig {
    /// Minimum number of identical allocations to trigger alert
    pub min_identical_allocations: usize,
    /// Minimum total sprayed size to trigger alert (bytes)
    pub min_spray_size: usize,
    /// Maximum entropy to consider as spray (highly repetitive)
    pub max_spray_entropy: f32,
    /// Minimum confidence to report
    pub min_confidence: f32,
    /// Time window for tracking rapid allocations (seconds)
    pub rapid_allocation_window_secs: u64,
    /// Minimum allocations in window to consider "rapid"
    pub rapid_allocation_threshold: usize,
    /// Enable verbose logging
    pub verbose: bool,
    /// Processes to exclude from monitoring
    pub excluded_processes: HashSet<String>,
}

impl Default for HeapSprayConfig {
    fn default() -> Self {
        let mut excluded = HashSet::new();
        // Some processes legitimately allocate many similar regions
        excluded.insert("chrome.exe".to_lowercase());
        excluded.insert("firefox.exe".to_lowercase());
        excluded.insert("msedge.exe".to_lowercase());
        excluded.insert("sqlservr.exe".to_lowercase());
        excluded.insert("java.exe".to_lowercase());
        excluded.insert("javaw.exe".to_lowercase());

        Self {
            min_identical_allocations: 20,
            min_spray_size: 10 * 1024 * 1024, // 10MB
            max_spray_entropy: 2.5,
            min_confidence: 0.6,
            rapid_allocation_window_secs: 5,
            rapid_allocation_threshold: 50,
            verbose: false,
            excluded_processes: excluded,
        }
    }
}

/// Heap spray detector
pub struct HeapSprayDetector {
    /// Allocation tracker
    allocation_tracker: AllocationTracker,
    /// Pattern matcher
    pattern_matcher: PatternMatcher,
    /// Configuration
    config: HeapSprayConfig,
    /// Known alerts (to avoid duplicates)
    known_alerts: HashSet<(u32, u64)>, // (pid, hash)
    /// Last cleanup time
    last_cleanup: Instant,
}

impl HeapSprayDetector {
    /// Create a new heap spray detector
    pub fn new(config: HeapSprayConfig) -> Self {
        info!("Initializing heap spray detector (T1203)");
        Self {
            allocation_tracker: AllocationTracker::new(),
            pattern_matcher: PatternMatcher::new(),
            config,
            known_alerts: HashSet::new(),
            last_cleanup: Instant::now(),
        }
    }

    /// Track a heap allocation
    pub fn track_allocation(&mut self, pid: u32, addr: usize, size: usize, content_hash: u64) {
        // We don't have content here, so estimate entropy based on hash uniformity
        // Real implementation would read memory and compute actual entropy
        let entropy = estimate_entropy_from_hash(content_hash);

        self.allocation_tracker.track_allocation(
            pid,
            addr,
            size,
            content_hash,
            entropy,
            0, // Protection unknown at this point
        );
    }

    /// Track allocation with full content for analysis
    pub fn track_allocation_with_content(
        &mut self,
        pid: u32,
        addr: usize,
        size: usize,
        content: &[u8],
    ) {
        let content_hash = calculate_content_hash(content);
        let entropy = calculate_entropy(content);

        self.allocation_tracker
            .track_allocation(pid, addr, size, content_hash, entropy, 0);
    }

    /// Analyze a process for heap spray indicators
    pub fn analyze(&self, pid: u32) -> Option<HeapSprayAlert> {
        let stats = self.allocation_tracker.get_stats(pid);

        if stats.allocation_count < self.config.min_identical_allocations {
            return None;
        }

        let allocations = self.allocation_tracker.get_allocations(pid);
        if allocations.is_empty() {
            return None;
        }

        let mut indicators = HeapSprayIndicators::default();

        // Check for many identical allocations
        if stats.most_common_hash_count >= self.config.min_identical_allocations {
            indicators.large_identical_allocations = true;
            indicators.same_content_count = stats.most_common_hash_count;
        }

        // Check for low entropy (spray content is usually very repetitive)
        if stats.average_entropy < self.config.max_spray_entropy {
            indicators.low_entropy_detected = true;
        }

        // Check total size
        if stats.total_size >= self.config.min_spray_size {
            indicators.total_spray_size = stats.total_size;
        }

        // Check for common spray sizes
        for alloc in &allocations {
            if COMMON_SPRAY_SIZES.contains(&alloc.size) {
                indicators.common_spray_size_match = true;
                break;
            }
        }

        // Check for rapid allocations
        let recent_count = allocations
            .iter()
            .filter(|a| {
                a.timestamp.elapsed()
                    < Duration::from_secs(self.config.rapid_allocation_window_secs)
            })
            .count();
        if recent_count >= self.config.rapid_allocation_threshold {
            indicators.rapid_allocations = true;
        }

        // Calculate confidence
        let confidence = indicators.calculate_confidence();

        if confidence < self.config.min_confidence {
            return None;
        }

        // Check if we've already alerted on this
        let (most_common_hash, _) = self.allocation_tracker.get_most_common_hash(pid)?;
        if self.known_alerts.contains(&(pid, most_common_hash)) {
            return None;
        }

        // Determine spray type
        let spray_type = determine_spray_type(&indicators);

        // Build evidence
        let mut evidence = Vec::new();
        if indicators.large_identical_allocations {
            evidence.push(format!(
                "{} allocations with identical content detected",
                indicators.same_content_count
            ));
        }
        if indicators.low_entropy_detected {
            evidence.push(format!(
                "Low average entropy ({:.2}) indicates repetitive content",
                stats.average_entropy
            ));
        }
        if indicators.total_spray_size > 0 {
            evidence.push(format!(
                "Total spray size: {} MB",
                indicators.total_spray_size / (1024 * 1024)
            ));
        }
        if indicators.rapid_allocations {
            evidence.push(format!(
                "{} allocations in {} second window",
                recent_count, self.config.rapid_allocation_window_secs
            ));
        }

        // Calculate affected memory range
        let min_addr = allocations.iter().map(|a| a.address).min().unwrap_or(0);
        let max_addr = allocations
            .iter()
            .map(|a| a.address + a.size)
            .max()
            .unwrap_or(0);

        Some(HeapSprayAlert {
            pid,
            process_name: get_process_name(pid),
            process_path: get_process_path(pid),
            spray_type,
            estimated_size: stats.total_size,
            pattern_detected: spray_type.as_str().to_string(),
            affected_memory_range: (min_addr, max_addr),
            confidence,
            identical_allocation_count: stats.most_common_hash_count,
            indicators,
            evidence,
            mitre_id: "T1203",
            timestamp: current_timestamp(),
        })
    }

    /// Analyze memory content for spray patterns
    pub fn analyze_memory_content(
        &self,
        pid: u32,
        address: usize,
        content: &[u8],
    ) -> Option<HeapSprayAlert> {
        if content.len() < 1024 {
            return None;
        }

        let mut indicators = HeapSprayIndicators::default();
        let mut evidence = Vec::new();

        // Detect spray patterns
        if let Some(pattern) = self.pattern_matcher.detect_spray_pattern(content) {
            match pattern.pattern_type {
                SprayPatternType::NopSled => {
                    indicators.nop_sled_detected = true;
                    indicators.nop_pattern_name = Some(pattern.pattern_name.clone());
                    evidence.push(format!(
                        "NOP sled pattern '{}' detected ({} repetitions)",
                        pattern.pattern_name, pattern.repetition_count
                    ));
                }
                SprayPatternType::Shellcode => {
                    indicators.shellcode_patterns = true;
                    indicators.shellcode_pattern_name = Some(pattern.pattern_name.clone());
                    evidence.push(format!(
                        "Shellcode signature '{}' detected",
                        pattern.pattern_name
                    ));
                }
                SprayPatternType::RepetitiveContent => {
                    indicators.large_identical_allocations = true;
                    evidence.push(format!(
                        "Highly repetitive content pattern {} ({} repetitions)",
                        pattern.pattern_name, pattern.repetition_count
                    ));
                }
                _ => {}
            }
        }

        // Check shellcode patterns specifically
        let shellcode_found = self.pattern_matcher.contains_shellcode(content);
        if !shellcode_found.is_empty() {
            indicators.shellcode_patterns = true;
            indicators.shellcode_pattern_name = Some(shellcode_found[0].clone());
            evidence.push(format!(
                "Shellcode signatures found: {}",
                shellcode_found.join(", ")
            ));
        }

        // Check entropy
        let entropy = calculate_entropy(content);
        if entropy < self.config.max_spray_entropy {
            indicators.low_entropy_detected = true;
            evidence.push(format!(
                "Low entropy ({:.2}) indicates spray content",
                entropy
            ));
        }

        // Check for predictable addresses in content
        for target in SPRAY_TARGET_ADDRESSES {
            let target_bytes = target.to_le_bytes();
            if contains_pattern(content, &target_bytes) {
                indicators.predictable_addresses = true;
                evidence.push(format!(
                    "Spray target address 0x{:08X} found in content",
                    target
                ));
                break;
            }
        }

        indicators.total_spray_size = content.len();

        let confidence = indicators.calculate_confidence();
        if confidence < self.config.min_confidence {
            return None;
        }

        let spray_type = determine_spray_type(&indicators);

        Some(HeapSprayAlert {
            pid,
            process_name: get_process_name(pid),
            process_path: get_process_path(pid),
            spray_type,
            estimated_size: content.len(),
            pattern_detected: indicators
                .shellcode_pattern_name
                .clone()
                .or(indicators.nop_pattern_name.clone())
                .unwrap_or_else(|| spray_type.as_str().to_string()),
            affected_memory_range: (address, address + content.len()),
            confidence,
            identical_allocation_count: 1,
            indicators,
            evidence,
            mitre_id: "T1203",
            timestamp: current_timestamp(),
        })
    }

    /// Mark an alert as known (to avoid duplicates)
    pub fn mark_alert_known(&mut self, pid: u32, content_hash: u64) {
        self.known_alerts.insert((pid, content_hash));
    }

    /// Periodic cleanup
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_cleanup) > Duration::from_secs(30) {
            self.allocation_tracker.cleanup();

            // Clear old alerts (keep last 1000)
            if self.known_alerts.len() > 1000 {
                self.known_alerts.clear();
            }

            self.last_cleanup = now;
        }
    }

    /// Check if process should be monitored
    pub fn should_monitor_process(&self, process_name: &str) -> bool {
        !self
            .config
            .excluded_processes
            .contains(&process_name.to_lowercase())
    }
}

impl Default for HeapSprayDetector {
    fn default() -> Self {
        Self::new(HeapSprayConfig::default())
    }
}

// =============================================================================
// MEMORY ANALYSIS FUNCTIONS
// =============================================================================

/// Analyze memory layout of a process for spray indicators
pub fn analyze_memory_layout(pid: u32) -> MemoryAnalysis {
    let mut suspicious_regions = Vec::new();
    let mut total_rw_memory: usize = 0;
    let mut identical_region_count = 0;
    let mut detected_patterns = Vec::new();
    let mut entropies = Vec::new();

    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Memory::{
            VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_PRIVATE,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            {
                Ok(h) => h,
                Err(_) => {
                    return MemoryAnalysis {
                        suspicious_regions,
                        total_rw_memory,
                        identical_region_count,
                        entropy_analysis: EntropyResult {
                            average_entropy: 0.0,
                            min_entropy: 0.0,
                            max_entropy: 0.0,
                            low_entropy_count: 0,
                        },
                        detected_patterns,
                    };
                }
            };

            let mut address: usize = 0;
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let mut content_hashes: HashMap<u64, usize> = HashMap::new();

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

                // Check for committed private memory (typical for heap)
                const PAGE_READWRITE: u32 = 0x04;
                let is_committed = (mbi.State.0 & MEM_COMMIT.0 as u32) != 0;
                let is_private = (mbi.Type.0 & MEM_PRIVATE.0 as u32) != 0;
                let is_rw = (mbi.Protect.0 & PAGE_READWRITE) != 0;

                if is_committed && is_private && is_rw {
                    total_rw_memory += mbi.RegionSize;

                    // For large regions, compute a quick hash of first bytes
                    if mbi.RegionSize >= 0x10000 {
                        // Read first 4KB for hashing
                        let mut buffer = vec![0u8; 4096.min(mbi.RegionSize)];
                        let mut bytes_read = 0usize;

                        if windows::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                            handle,
                            mbi.BaseAddress,
                            buffer.as_mut_ptr() as *mut _,
                            buffer.len(),
                            Some(&mut bytes_read),
                        )
                        .is_ok()
                            && bytes_read > 0
                        {
                            buffer.truncate(bytes_read);
                            let hash = calculate_content_hash(&buffer);
                            *content_hashes.entry(hash).or_insert(0) += 1;

                            let entropy = calculate_entropy(&buffer);
                            entropies.push(entropy);

                            // Check for suspicious patterns
                            let pattern_matcher = PatternMatcher::new();
                            if let Some(pattern) = pattern_matcher.detect_spray_pattern(&buffer) {
                                suspicious_regions.push(SuspiciousRegion {
                                    address: mbi.BaseAddress as usize,
                                    size: mbi.RegionSize,
                                    reason: format!(
                                        "Spray pattern detected: {} ({}x)",
                                        pattern.pattern_name, pattern.repetition_count
                                    ),
                                    pattern: Some(DetectedPattern {
                                        name: pattern.pattern_name.clone(),
                                        pattern_type: match pattern.pattern_type {
                                            SprayPatternType::NopSled => PatternType::NopSled,
                                            SprayPatternType::Shellcode => PatternType::Shellcode,
                                            _ => PatternType::Padding,
                                        },
                                        offset: 0,
                                        length: 4,
                                    }),
                                    content_hash: hash,
                                    entropy,
                                });

                                detected_patterns.push(DetectedPattern {
                                    name: pattern.pattern_name,
                                    pattern_type: match pattern.pattern_type {
                                        SprayPatternType::NopSled => PatternType::NopSled,
                                        SprayPatternType::Shellcode => PatternType::Shellcode,
                                        _ => PatternType::Padding,
                                    },
                                    offset: mbi.BaseAddress as usize,
                                    length: mbi.RegionSize,
                                });
                            }
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

            // Count identical regions
            for (_, count) in content_hashes {
                if count > 1 {
                    identical_region_count += count;
                }
            }
        }
    }

    // Calculate entropy statistics
    let entropy_analysis = if entropies.is_empty() {
        EntropyResult {
            average_entropy: 0.0,
            min_entropy: 0.0,
            max_entropy: 0.0,
            low_entropy_count: 0,
        }
    } else {
        let sum: f32 = entropies.iter().sum();
        let avg = sum / entropies.len() as f32;
        let min = entropies.iter().cloned().fold(f32::MAX, f32::min);
        let max = entropies.iter().cloned().fold(f32::MIN, f32::max);
        let low_count = entropies.iter().filter(|&&e| e < 2.0).count();

        EntropyResult {
            average_entropy: avg,
            min_entropy: min,
            max_entropy: max,
            low_entropy_count: low_count,
        }
    };

    MemoryAnalysis {
        suspicious_regions,
        total_rw_memory,
        identical_region_count,
        entropy_analysis,
        detected_patterns,
    }
}

/// Detect JavaScript heap spray indicators from allocation patterns
pub fn detect_js_heap_spray(allocations: &[TrackedAllocation]) -> Option<JsSprayIndicator> {
    if allocations.len() < 50 {
        return None;
    }

    // JavaScript sprays typically:
    // - Create many similarly-sized allocations
    // - Use sizes that are multiples of string chunk sizes
    // - Have low entropy content

    let mut size_counts: HashMap<usize, usize> = HashMap::new();
    let mut total_memory = 0;
    let mut low_entropy_count = 0;

    for alloc in allocations {
        *size_counts.entry(alloc.size).or_insert(0) += 1;
        total_memory += alloc.size;
        if alloc.entropy < 2.5 {
            low_entropy_count += 1;
        }
    }

    // Find most common allocation size
    let (most_common_size, common_count) = size_counts
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .unwrap_or((0, 0));

    // JS spray typically uses same-sized blocks
    let size_uniformity = common_count as f32 / allocations.len() as f32;
    let low_entropy_ratio = low_entropy_count as f32 / allocations.len() as f32;

    // Score the likelihood of JS spray
    let mut confidence: f32 = 0.0;

    if size_uniformity > 0.8 {
        confidence += 0.4;
    } else if size_uniformity > 0.5 {
        confidence += 0.2;
    }

    if low_entropy_ratio > 0.8 {
        confidence += 0.3;
    } else if low_entropy_ratio > 0.5 {
        confidence += 0.15;
    }

    // Common JS spray sizes
    let js_spray_sizes = [
        0x10000, 0x20000, 0x40000, 0x80000, // Power of 2
        0xFFFC, 0x1FFFC, 0x3FFFC, // BSTR-friendly
    ];
    if js_spray_sizes.contains(&most_common_size) {
        confidence += 0.2;
    }

    if total_memory > 50 * 1024 * 1024 {
        // > 50MB
        confidence += 0.1;
    }

    if confidence >= 0.6 {
        Some(JsSprayIndicator {
            pattern: format!("JavaScript spray ({}KB blocks)", most_common_size / 1024),
            spray_count: common_count,
            total_memory,
            confidence,
        })
    } else {
        None
    }
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Calculate a hash of content for comparison
fn calculate_content_hash(data: &[u8]) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    hasher.finish()
}

/// Estimate entropy from hash (rough approximation when we don't have content)
fn estimate_entropy_from_hash(hash: u64) -> f32 {
    // Count bit transitions as a rough uniformity measure
    let mut transitions = 0u32;
    let mut prev_bit = hash & 1;
    let mut h = hash >> 1;

    for _ in 0..63 {
        let bit = h & 1;
        if bit != prev_bit {
            transitions += 1;
        }
        prev_bit = bit;
        h >>= 1;
    }

    // Normalize to entropy-like scale (0-8)
    // More transitions = more uniform = higher entropy
    (transitions as f32 / 63.0) * 8.0
}

/// Count occurrences of a pattern in data
fn count_pattern_occurrences(data: &[u8], pattern: &[u8]) -> usize {
    if pattern.is_empty() || data.len() < pattern.len() {
        return 0;
    }

    data.windows(pattern.len())
        .filter(|window| *window == pattern)
        .count()
}

/// Check if data contains a pattern
fn contains_pattern(data: &[u8], pattern: &[u8]) -> bool {
    if pattern.is_empty() || data.len() < pattern.len() {
        return false;
    }

    data.windows(pattern.len()).any(|window| window == pattern)
}

/// Find the most common N-byte sequence in data
fn find_most_common_sequence(data: &[u8], n: usize) -> Option<([u8; 4], usize)> {
    if data.len() < n || n != 4 {
        return None;
    }

    let mut counts: HashMap<[u8; 4], usize> = HashMap::new();

    for window in data.windows(4) {
        let key: [u8; 4] = window.try_into().unwrap();
        *counts.entry(key).or_insert(0) += 1;
    }

    counts
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .map(|(bytes, count)| (bytes, count))
}

/// Calculate pattern confidence based on repetitions
fn calculate_pattern_confidence(repetitions: usize, data_len: usize) -> f32 {
    let coverage = (repetitions * 4) as f32 / data_len as f32;
    (coverage * 1.5).min(1.0)
}

/// Determine spray type from indicators
fn determine_spray_type(indicators: &HeapSprayIndicators) -> SprayType {
    if indicators.shellcode_patterns {
        SprayType::ShellcodeSpray
    } else if indicators.nop_sled_detected {
        if indicators
            .nop_pattern_name
            .as_ref()
            .map(|n| n.contains("0c") || n.contains("0d"))
            .unwrap_or(false)
        {
            SprayType::BrowserSpray
        } else {
            SprayType::NopSled
        }
    } else if indicators.excessive_string_allocations {
        SprayType::JavaScriptSpray
    } else if indicators.large_identical_allocations {
        SprayType::GenericSpray
    } else {
        SprayType::Unknown
    }
}

/// Get current timestamp in milliseconds
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Get process name by PID
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

/// Get process path by PID
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

// =============================================================================
// TELEMETRY INTEGRATION
// =============================================================================

impl HeapSprayDetector {
    /// Create a TelemetryEvent from a HeapSprayAlert
    pub fn create_telemetry_event(alert: &HeapSprayAlert) -> TelemetryEvent {
        let severity = alert.spray_type.severity();

        let mut event = TelemetryEvent::new(
            EventType::MemoryScan,
            severity,
            EventPayload::MemoryPermission(MemoryPermissionEvent {
                pid: alert.pid,
                process_name: alert.process_name.clone(),
                process_path: alert.process_path.clone(),
                base_address: alert.affected_memory_range.0 as u64,
                region_size: (alert.affected_memory_range.1 - alert.affected_memory_range.0) as u64,
                old_protection: 0,
                new_protection: 0x04, // PAGE_READWRITE
                old_protection_str: String::new(),
                new_protection_str: "PAGE_READWRITE".to_string(),
                mem_type: 0x20000, // MEM_PRIVATE
                mem_type_str: "MEM_PRIVATE".to_string(),
                entropy: 0.0,
                transition_type: "heap_spray_detection".to_string(),
                thread_from_unbacked: false,
                thread_id: None,
                thread_start_address: None,
            }),
        );

        // Build description
        let description = format!(
            "{}: {} (PID: {}) - {} identical allocations, {} total",
            alert.spray_type.description(),
            alert.process_name,
            alert.pid,
            alert.identical_allocation_count,
            format_size(alert.estimated_size),
        );

        event.add_detection(Detection {
            detection_type: DetectionType::MemoryThreat,
            rule_name: format!("heap_spray_{}", alert.spray_type.as_str()),
            confidence: alert.confidence,
            description,
            mitre_tactics: vec!["execution".to_string(), "defense-evasion".to_string()],
            mitre_techniques: vec![alert.mitre_id.to_string()],
        });

        // Add metadata
        event.metadata.insert(
            "spray_type".to_string(),
            alert.spray_type.as_str().to_string(),
        );
        event.metadata.insert(
            "estimated_size".to_string(),
            alert.estimated_size.to_string(),
        );
        event.metadata.insert(
            "identical_allocation_count".to_string(),
            alert.identical_allocation_count.to_string(),
        );
        event.metadata.insert(
            "pattern_detected".to_string(),
            alert.pattern_detected.clone(),
        );
        event
            .metadata
            .insert("confidence".to_string(), format!("{:.2}", alert.confidence));
        event
            .metadata
            .insert("mitre_technique".to_string(), alert.mitre_id.to_string());

        // Add indicator flags
        let indicators = &alert.indicators;
        if indicators.nop_sled_detected {
            event
                .metadata
                .insert("nop_sled_detected".to_string(), "true".to_string());
        }
        if indicators.shellcode_patterns {
            event
                .metadata
                .insert("shellcode_detected".to_string(), "true".to_string());
        }
        if indicators.predictable_addresses {
            event
                .metadata
                .insert("predictable_addresses".to_string(), "true".to_string());
        }
        if indicators.rapid_allocations {
            event
                .metadata
                .insert("rapid_allocations".to_string(), "true".to_string());
        }

        // Add evidence
        if !alert.evidence.is_empty() {
            event
                .metadata
                .insert("evidence".to_string(), alert.evidence.join("; "));
        }

        // Add memory range
        event.metadata.insert(
            "memory_range".to_string(),
            format!(
                "0x{:X}-0x{:X}",
                alert.affected_memory_range.0, alert.affected_memory_range.1
            ),
        );

        event
    }
}

/// Format size for human readability
fn format_size(bytes: usize) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

// =============================================================================
// COLLECTOR INTEGRATION
// =============================================================================

/// Heap spray detection collector
pub struct HeapSprayCollector {
    #[allow(dead_code)]
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    #[allow(dead_code)]
    event_tx: mpsc::Sender<TelemetryEvent>,
    #[allow(dead_code)]
    detector: Arc<Mutex<HeapSprayDetector>>,
}

impl HeapSprayCollector {
    /// Create a new heap spray collector
    pub fn new(config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(500);

        let detector = Arc::new(Mutex::new(HeapSprayDetector::new(
            HeapSprayConfig::default(),
        )));

        info!("Initializing heap spray detection collector (T1203)");

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

    #[cfg(target_os = "windows")]
    async fn windows_monitor_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        detector: Arc<Mutex<HeapSprayDetector>>,
        config: AgentConfig,
    ) {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        let mul = config.sub_loop_interval_multiplier;
        info!(multiplier = mul, "Starting heap spray monitor");

        // Scan interval
        let scan_interval_ms = ((5000.0 * mul) as u64).max(2000);
        let cleanup_interval_ms = ((30000.0 * mul) as u64).max(10000);

        let mut scan_interval =
            tokio::time::interval(tokio::time::Duration::from_millis(scan_interval_ms));
        let mut cleanup_timer =
            tokio::time::interval(tokio::time::Duration::from_millis(cleanup_interval_ms));

        // Track which processes we've already analyzed
        let mut analyzed_pids: HashSet<u32> = HashSet::new();

        loop {
            tokio::select! {
                _ = scan_interval.tick() => {
                    // Get list of processes
                    let mut pids_to_analyze = Vec::new();

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
                                            &entry.szExeFile[..entry.szExeFile
                                                .iter()
                                                .position(|&c| c == 0)
                                                .unwrap_or(0)]
                                        );

                                        // Check if process should be monitored
                                        let det = detector.lock().await;
                                        if det.should_monitor_process(&name) && !analyzed_pids.contains(&pid) {
                                            pids_to_analyze.push(pid);
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

                    // Analyze memory layout of interesting processes
                    for pid in pids_to_analyze {
                        let analysis = analyze_memory_layout(pid);

                        // Check for spray indicators
                        if !analysis.suspicious_regions.is_empty()
                            || analysis.identical_region_count >= 10
                            || analysis.entropy_analysis.low_entropy_count >= 5
                        {
                            let mut det = detector.lock().await;

                            // Track allocations from the analysis
                            for region in &analysis.suspicious_regions {
                                det.track_allocation(
                                    pid,
                                    region.address,
                                    region.size,
                                    region.content_hash,
                                );
                            }

                            // Check for alert
                            if let Some(alert) = det.analyze(pid) {
                                let event = HeapSprayDetector::create_telemetry_event(&alert);
                                if tx.send(event).await.is_err() {
                                    warn!("Event channel closed");
                                    return;
                                }

                                // Mark as known
                                if let Some((hash, _)) = det.allocation_tracker.get_most_common_hash(pid) {
                                    det.mark_alert_known(pid, hash);
                                }
                            }

                            analyzed_pids.insert(pid);
                        }
                    }
                }

                _ = cleanup_timer.tick() => {
                    let mut det = detector.lock().await;
                    det.cleanup();

                    // Also clean up analyzed_pids to allow re-analysis of long-running processes
                    if analyzed_pids.len() > 500 {
                        analyzed_pids.clear();
                    }
                }
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
impl HeapSprayCollector {
    async fn windows_monitor_loop(
        _tx: mpsc::Sender<TelemetryEvent>,
        _detector: Arc<Mutex<HeapSprayDetector>>,
        _config: AgentConfig,
    ) {
        // No-op on non-Windows
        std::future::pending::<()>().await;
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spray_type_metadata() {
        assert_eq!(SprayType::NopSled.as_str(), "nop_sled");
        assert_eq!(SprayType::ShellcodeSpray.severity(), Severity::Critical);
        assert_eq!(SprayType::BrowserSpray.severity(), Severity::High);
    }

    #[test]
    fn test_nop_pattern_detection() {
        let matcher = PatternMatcher::new();

        // Create data with NOP sled
        let data = vec![0x90u8; 1024];
        let result = matcher.detect_spray_pattern(&data);

        assert!(result.is_some());
        let pattern = result.unwrap();
        assert_eq!(pattern.pattern_type, SprayPatternType::NopSled);
        assert!(pattern.confidence > 0.5);
    }

    #[test]
    fn test_browser_spray_pattern_detection() {
        let matcher = PatternMatcher::new();

        // Create data with 0x0c pattern (browser spray)
        let data = vec![0x0cu8; 1024];
        let result = matcher.detect_spray_pattern(&data);

        assert!(result.is_some());
        let pattern = result.unwrap();
        assert_eq!(pattern.pattern_type, SprayPatternType::NopSled);
        assert!(pattern.pattern_name.contains("0c"));
    }

    #[test]
    fn test_shellcode_detection() {
        let matcher = PatternMatcher::new();

        // PEB access pattern for x64
        let data = [
            0x65u8, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let found = matcher.contains_shellcode(&data);

        assert!(!found.is_empty());
        assert!(found.iter().any(|s| s.contains("peb")));
    }

    #[test]
    fn test_allocation_tracker() {
        let mut tracker = AllocationTracker::new();

        // Track some allocations with same content
        let hash = 0x12345678u64;
        for i in 0..30 {
            tracker.track_allocation(1234, 0x10000000 + i * 0x10000, 0x10000, hash, 1.5, 0x04);
        }

        let stats = tracker.get_stats(1234);
        assert_eq!(stats.allocation_count, 30);
        assert_eq!(stats.most_common_hash_count, 30);
        assert_eq!(stats.unique_content_count, 1);
    }

    #[test]
    fn test_indicators_confidence() {
        let mut indicators = HeapSprayIndicators::default();

        // Empty indicators should have low confidence
        assert!(indicators.calculate_confidence() < 0.5);

        // Add indicators
        indicators.large_identical_allocations = true;
        indicators.same_content_count = 100;
        indicators.nop_sled_detected = true;
        indicators.low_entropy_detected = true;

        // Now confidence should be high
        assert!(indicators.calculate_confidence() > 0.6);
    }

    #[test]
    fn test_heap_spray_detector() {
        let mut detector = HeapSprayDetector::new(HeapSprayConfig {
            min_identical_allocations: 10,
            min_spray_size: 1024 * 1024,
            min_confidence: 0.5,
            ..Default::default()
        });

        // Track similar allocations
        let hash = 0xABCDEF01u64;
        for i in 0..50 {
            detector.track_allocation(1234, 0x10000000 + i * 0x10000, 0x10000, hash);
        }

        let alert = detector.analyze(1234);
        assert!(alert.is_some());

        let alert = alert.unwrap();
        assert_eq!(alert.pid, 1234);
        assert!(alert.identical_allocation_count >= 10);
        assert!(alert.confidence > 0.5);
    }

    #[test]
    fn test_content_analysis() {
        let detector = HeapSprayDetector::new(HeapSprayConfig {
            min_confidence: 0.25,
            ..Default::default()
        });

        // Create spray-like content
        let content = vec![0x90u8; 4096];
        let alert = detector.analyze_memory_content(1234, 0x10000000, &content);

        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert!(alert.indicators.nop_sled_detected);
    }

    #[test]
    fn test_pattern_confidence() {
        // High repetition should give high confidence
        let confidence = calculate_pattern_confidence(200, 1024);
        assert!(confidence > 0.7);

        // Low repetition should give lower confidence
        let confidence = calculate_pattern_confidence(10, 1024);
        assert!(confidence < 0.1);
    }

    #[test]
    fn test_excluded_processes() {
        let detector = HeapSprayDetector::default();

        // Browser processes should be excluded by default
        assert!(!detector.should_monitor_process("chrome.exe"));
        assert!(!detector.should_monitor_process("CHROME.EXE"));

        // Unknown processes should be monitored
        assert!(detector.should_monitor_process("notepad.exe"));
    }

    #[test]
    fn test_js_spray_detection() {
        let allocations: Vec<TrackedAllocation> = (0..100)
            .map(|i| TrackedAllocation {
                address: 0x10000000 + i * 0x10000,
                size: 0x10000,
                content_hash: 0x12345678,
                entropy: 1.5,
                timestamp: Instant::now(),
                protection: 0x04,
            })
            .collect();

        let result = detect_js_heap_spray(&allocations);
        assert!(result.is_some());

        let indicator = result.unwrap();
        assert!(indicator.confidence > 0.5);
        assert_eq!(indicator.spray_count, 100);
    }

    #[test]
    fn test_telemetry_event_creation() {
        let alert = HeapSprayAlert {
            pid: 1234,
            process_name: "test.exe".to_string(),
            process_path: "C:\\test.exe".to_string(),
            spray_type: SprayType::NopSled,
            estimated_size: 10 * 1024 * 1024,
            pattern_detected: "x86_nop".to_string(),
            affected_memory_range: (0x10000000, 0x20000000),
            confidence: 0.85,
            identical_allocation_count: 50,
            indicators: HeapSprayIndicators {
                nop_sled_detected: true,
                large_identical_allocations: true,
                same_content_count: 50,
                total_spray_size: 10 * 1024 * 1024,
                ..Default::default()
            },
            evidence: vec!["50 identical allocations".to_string()],
            mitre_id: "T1203",
            timestamp: 0,
        };

        let event = HeapSprayDetector::create_telemetry_event(&alert);

        assert_eq!(event.event_type, EventType::MemoryScan);
        assert_eq!(event.severity, Severity::High);
        assert!(!event.detections.is_empty());
        assert!(event.metadata.contains_key("spray_type"));
        assert_eq!(
            event.metadata.get("mitre_technique"),
            Some(&"T1203".to_string())
        );
    }
}
