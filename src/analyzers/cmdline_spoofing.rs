//! Command Line Spoofing Detection (MITRE T1564.010)
//!
//! Detects when processes modify their command line after creation to hide
//! malicious arguments. This is a technique used by advanced threats like
//! Cobalt Strike (argue command), Metasploit, and custom implants.
//!
//! ## Detection Methods
//!
//! 1. **Creation-Time Capture**: Record original command line at process creation
//!    from ETW events, kernel callbacks, or direct API calls.
//!
//! 2. **PEB Validation**: Periodically read current command line from
//!    PEB->ProcessParameters->CommandLine and compare with original.
//!
//! 3. **Memory Write Monitoring**: Detect NtWriteVirtualMemory calls targeting
//!    RTL_USER_PROCESS_PARAMETERS regions (PEB command line buffer).
//!
//! 4. **Pattern Analysis**: Identify suspicious patterns like:
//!    - Command line becoming shorter after creation
//!    - Replacement with spaces or nulls
//!    - Known spoofing tool signatures
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                    Command Line Spoofing Detector                    │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                                                                      │
//! │  ┌─────────────┐    ┌──────────────────┐    ┌───────────────────┐  │
//! │  │   ETW/API   │───>│  Creation Cache  │───>│   PEB Validator   │  │
//! │  │  Listener   │    │  (Original Args) │    │ (Periodic Check)  │  │
//! │  └─────────────┘    └──────────────────┘    └───────────────────┘  │
//! │         │                    │                        │            │
//! │         v                    v                        v            │
//! │  ┌─────────────┐    ┌──────────────────┐    ┌───────────────────┐  │
//! │  │   Memory    │    │    Comparison    │───>│  Alert Generator  │  │
//! │  │   Monitor   │───>│     Engine       │    │                   │  │
//! │  └─────────────┘    └──────────────────┘    └───────────────────┘  │
//! │                                                                      │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## References
//!
//! - MITRE ATT&CK T1564.010: Hide Artifacts: Process Argument Spoofing
//! - Cobalt Strike "argue" command documentation
//! - Windows Internals: PEB and RTL_USER_PROCESS_PARAMETERS structures

// Cmdline-spoofing detector. PEB/RTL fields and cache stats are retained for
// upcoming verification stages.
#![allow(dead_code, unused_variables)]

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, warn};

#[cfg(target_os = "windows")]
use std::ffi::c_void;

/// Alert generated when command line spoofing is detected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmdlineSpoofingAlert {
    /// Process ID where spoofing was detected
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// Process executable path
    pub process_path: String,
    /// Original command line captured at process creation
    pub original_cmdline: String,
    /// Current command line read from PEB
    pub current_cmdline: String,
    /// Original command line length
    pub original_length: usize,
    /// Current command line length
    pub current_length: usize,
    /// Similarity score between original and current (0.0 - 1.0)
    pub similarity_score: f64,
    /// Detection method that triggered the alert
    pub detection_method: DetectionMethod,
    /// Spoofing pattern identified
    pub spoofing_pattern: SpoofingPattern,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Timestamp when spoofing was detected
    pub detected_at_ms: u64,
    /// Additional context about the detection
    pub context: SpoofingContext,
}

/// How the spoofing was detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionMethod {
    /// Periodic PEB validation detected discrepancy
    PebValidation,
    /// Memory write to RTL_USER_PROCESS_PARAMETERS detected
    MemoryWriteMonitor,
    /// ETW reported different args than PEB shows
    EtwComparison,
    /// Kernel callback captured original before modification
    KernelCallback,
    /// Pattern-based heuristic detection
    PatternAnalysis,
}

/// Pattern of command line spoofing detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpoofingPattern {
    /// Command line replaced with spaces
    SpacePadding,
    /// Command line replaced with null bytes
    NullPadding,
    /// Command line truncated significantly
    Truncation,
    /// Arguments replaced with benign-looking ones
    ArgumentSubstitution,
    /// Complete replacement with different command
    CompleteReplacement,
    /// Known malware/tool signature (e.g., Cobalt Strike)
    KnownToolSignature,
    /// Suspicious character patterns
    SuspiciousCharacters,
    /// Generic modification detected
    GenericModification,
}

/// Additional context about the spoofing detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpoofingContext {
    /// Parent process ID
    pub parent_pid: u32,
    /// Parent process name
    pub parent_name: String,
    /// Whether the process is elevated
    pub is_elevated: bool,
    /// Whether the process is signed
    pub is_signed: bool,
    /// Process creation time (ms since UNIX epoch)
    pub process_start_time: u64,
    /// Time between creation and spoofing detection
    pub time_to_detection_ms: u64,
    /// Memory region details if available
    pub memory_region: Option<MemoryRegionInfo>,
}

/// Information about the memory region containing command line
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegionInfo {
    /// Base address of RTL_USER_PROCESS_PARAMETERS
    pub process_parameters_base: u64,
    /// Address of CommandLine buffer
    pub cmdline_buffer_address: u64,
    /// Size of command line buffer
    pub cmdline_buffer_size: usize,
    /// Memory protection flags
    pub protection: u32,
    /// Protection as human-readable string
    pub protection_str: String,
}

/// Cached process information for spoofing detection
#[derive(Debug, Clone)]
struct ProcessCacheEntry {
    /// Process name
    name: String,
    /// Process path
    path: String,
    /// Original command line at creation
    original_cmdline: String,
    /// Time of cache entry creation
    created_at: Instant,
    /// Process creation timestamp (ms since UNIX epoch)
    process_start_time: u64,
    /// Parent process ID
    parent_pid: u32,
    /// Parent process name
    parent_name: String,
    /// Whether this process has been checked for spoofing
    checked: bool,
    /// Number of times this process has been validated
    validation_count: u32,
    /// Last validation time
    last_validated: Instant,
    /// PEB address (Windows only)
    #[cfg(target_os = "windows")]
    peb_address: Option<u64>,
    /// RTL_USER_PROCESS_PARAMETERS address (Windows only)
    #[cfg(target_os = "windows")]
    process_parameters_address: Option<u64>,
}

/// Configuration for the spoofing detector
#[derive(Debug, Clone)]
pub struct SpoofingDetectorConfig {
    /// Maximum number of processes to track
    pub max_cache_size: usize,
    /// Minimum similarity threshold below which we alert (0.0 - 1.0)
    pub similarity_threshold: f64,
    /// Validation interval in milliseconds
    pub validation_interval_ms: u64,
    /// Maximum processes to validate per cycle
    pub max_validations_per_cycle: usize,
    /// Cache entry TTL in seconds (processes older than this are evicted)
    pub cache_ttl_secs: u64,
    /// Excluded process names (case-insensitive)
    pub excluded_processes: HashSet<String>,
    /// Whether to enable memory write monitoring
    pub enable_memory_monitoring: bool,
    /// Minimum command line length change to consider suspicious
    pub min_length_diff: usize,
}

impl Default for SpoofingDetectorConfig {
    fn default() -> Self {
        let mut excluded = HashSet::new();
        // Processes known to legitimately modify their command line
        excluded.insert("java.exe".to_string());
        excluded.insert("javaw.exe".to_string());
        excluded.insert("dotnet.exe".to_string());
        excluded.insert("python.exe".to_string());
        excluded.insert("python3.exe".to_string());
        excluded.insert("node.exe".to_string());
        excluded.insert("pwsh.exe".to_string());
        excluded.insert("powershell.exe".to_string());

        Self {
            max_cache_size: 10000,
            similarity_threshold: 0.70,
            validation_interval_ms: 5000,
            max_validations_per_cycle: 100,
            cache_ttl_secs: 3600, // 1 hour
            excluded_processes: excluded,
            enable_memory_monitoring: true,
            min_length_diff: 10,
        }
    }
}

/// Enhanced command line spoofing detector
///
/// This detector provides comprehensive monitoring for command line
/// manipulation attempts, combining multiple detection strategies.
pub struct EnhancedCmdlineSpoofingDetector {
    /// Configuration
    config: SpoofingDetectorConfig,
    /// Process cache: PID -> CacheEntry
    cache: Arc<RwLock<HashMap<u32, ProcessCacheEntry>>>,
    /// Known spoofing tool signatures for pattern matching
    known_signatures: Vec<SpoofingSignature>,
    /// Statistics
    stats: Arc<RwLock<DetectorStats>>,
}

/// Signature for known spoofing tools
#[derive(Debug, Clone)]
struct SpoofingSignature {
    /// Name of the tool/technique
    name: String,
    /// Pattern to match in original command line
    original_pattern: Option<regex::Regex>,
    /// Pattern to match in spoofed command line
    spoofed_pattern: Option<regex::Regex>,
    /// Associated malware family
    family: Option<String>,
}

/// Detector statistics
#[derive(Debug, Clone, Default)]
struct DetectorStats {
    /// Total processes recorded
    processes_recorded: u64,
    /// Total validations performed
    validations_performed: u64,
    /// Total spoofing alerts generated
    alerts_generated: u64,
    /// Cache hits
    cache_hits: u64,
    /// Cache misses
    cache_misses: u64,
    /// Last GC time
    last_gc: Option<Instant>,
}

impl EnhancedCmdlineSpoofingDetector {
    /// Create a new enhanced spoofing detector with default configuration
    pub fn new() -> Self {
        Self::with_config(SpoofingDetectorConfig::default())
    }

    /// Create a detector with custom configuration
    pub fn with_config(config: SpoofingDetectorConfig) -> Self {
        let known_signatures = Self::build_known_signatures();

        Self {
            config,
            cache: Arc::new(RwLock::new(HashMap::new())),
            known_signatures,
            stats: Arc::new(RwLock::new(DetectorStats::default())),
        }
    }

    /// Build list of known spoofing tool signatures
    fn build_known_signatures() -> Vec<SpoofingSignature> {
        let mut signatures = Vec::new();

        // Cobalt Strike argue command patterns
        if let Ok(re) = regex::Regex::new(r"(?i)beacon|cobaltstrike|\.cna") {
            signatures.push(SpoofingSignature {
                name: "Cobalt Strike Beacon".to_string(),
                original_pattern: Some(re),
                spoofed_pattern: None,
                family: Some("CobaltStrike".to_string()),
            });
        }

        // Common patterns in spoofed args
        if let Ok(re) = regex::Regex::new(r"^\s{10,}$") {
            signatures.push(SpoofingSignature {
                name: "Space Padding".to_string(),
                original_pattern: None,
                spoofed_pattern: Some(re),
                family: None,
            });
        }

        // Metasploit meterpreter patterns
        if let Ok(re) = regex::Regex::new(r"(?i)meterpreter|metsvc|reverse_tcp") {
            signatures.push(SpoofingSignature {
                name: "Metasploit Meterpreter".to_string(),
                original_pattern: Some(re),
                spoofed_pattern: None,
                family: Some("Metasploit".to_string()),
            });
        }

        // Windows LOLBin abuse patterns often spoofed
        if let Ok(re) =
            regex::Regex::new(r"(?i)regsvr32.*scrobj|rundll32.*javascript|mshta.*vbscript")
        {
            signatures.push(SpoofingSignature {
                name: "LOLBin Abuse".to_string(),
                original_pattern: Some(re),
                spoofed_pattern: None,
                family: None,
            });
        }

        // PowerShell encoded command patterns
        if let Ok(re) = regex::Regex::new(r"(?i)-e(nc(odedcommand)?)?[ ]+[A-Za-z0-9+/=]{50,}") {
            signatures.push(SpoofingSignature {
                name: "Encoded PowerShell".to_string(),
                original_pattern: Some(re),
                spoofed_pattern: None,
                family: None,
            });
        }

        signatures
    }

    /// Record a process creation event
    ///
    /// This should be called as early as possible when a new process is detected,
    /// ideally from ETW ProcessStart events or kernel callbacks.
    pub async fn record_creation(
        &self,
        pid: u32,
        name: &str,
        path: &str,
        cmdline: &str,
        parent_pid: u32,
        parent_name: &str,
        process_start_time: u64,
    ) {
        // Check exclusions
        let name_lower = name.to_lowercase();
        if self
            .config
            .excluded_processes
            .iter()
            .any(|e| name_lower.contains(&e.to_lowercase()))
        {
            debug!(
                pid,
                name, "Skipping excluded process for spoofing detection"
            );
            return;
        }

        let mut cache = self.cache.write().await;

        // Evict oldest entries if cache is full
        if cache.len() >= self.config.max_cache_size {
            self.evict_oldest_entries(&mut cache, self.config.max_cache_size / 10);
        }

        let now = Instant::now();
        let entry = ProcessCacheEntry {
            name: name.to_string(),
            path: path.to_string(),
            original_cmdline: cmdline.to_string(),
            created_at: now,
            process_start_time,
            parent_pid,
            parent_name: parent_name.to_string(),
            checked: false,
            validation_count: 0,
            last_validated: now,
            #[cfg(target_os = "windows")]
            peb_address: None,
            #[cfg(target_os = "windows")]
            process_parameters_address: None,
        };

        cache.insert(pid, entry);

        // Update stats
        let mut stats = self.stats.write().await;
        stats.processes_recorded += 1;

        debug!(
            pid,
            name,
            cmdline_len = cmdline.len(),
            "Recorded process for spoofing detection"
        );
    }

    /// Record creation with PEB information (Windows only)
    #[cfg(target_os = "windows")]
    pub async fn record_creation_with_peb(
        &self,
        pid: u32,
        name: &str,
        path: &str,
        cmdline: &str,
        parent_pid: u32,
        parent_name: &str,
        process_start_time: u64,
        peb_address: u64,
        process_parameters_address: u64,
    ) {
        // Check exclusions
        let name_lower = name.to_lowercase();
        if self
            .config
            .excluded_processes
            .iter()
            .any(|e| name_lower.contains(&e.to_lowercase()))
        {
            return;
        }

        let mut cache = self.cache.write().await;

        if cache.len() >= self.config.max_cache_size {
            self.evict_oldest_entries(&mut cache, self.config.max_cache_size / 10);
        }

        let now = Instant::now();
        let entry = ProcessCacheEntry {
            name: name.to_string(),
            path: path.to_string(),
            original_cmdline: cmdline.to_string(),
            created_at: now,
            process_start_time,
            parent_pid,
            parent_name: parent_name.to_string(),
            checked: false,
            validation_count: 0,
            last_validated: now,
            peb_address: Some(peb_address),
            process_parameters_address: Some(process_parameters_address),
        };

        cache.insert(pid, entry);

        let mut stats = self.stats.write().await;
        stats.processes_recorded += 1;
    }

    /// Validate a process's current command line against recorded original
    ///
    /// Returns `Some(CmdlineSpoofingAlert)` if spoofing is detected.
    pub async fn validate_process(&self, pid: u32) -> Option<CmdlineSpoofingAlert> {
        let cache = self.cache.read().await;
        let entry = cache.get(&pid)?;
        let original = entry.original_cmdline.clone();
        let entry_data = entry.clone();
        drop(cache);

        // Read current command line from PEB
        let current = self.read_current_cmdline(pid)?;

        // Update validation stats
        {
            let mut cache = self.cache.write().await;
            if let Some(e) = cache.get_mut(&pid) {
                e.validation_count += 1;
                e.last_validated = Instant::now();
                e.checked = true;
            }

            let mut stats = self.stats.write().await;
            stats.validations_performed += 1;
        }

        // Compare command lines
        self.compare_cmdlines(pid, &entry_data, &original, &current)
            .await
    }

    /// Read current command line from process PEB (Windows implementation)
    #[cfg(target_os = "windows")]
    fn read_current_cmdline(&self, pid: u32) -> Option<String> {
        use crate::collectors::win_compat::ntapi::get_process_command_line;
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(h) => h,
                Err(_) => return None,
            };

            let cmdline = get_process_command_line(std::mem::transmute(handle));
            let _ = CloseHandle(handle);

            cmdline
        }
    }

    /// Read current command line (Linux/macOS stub)
    #[cfg(not(target_os = "windows"))]
    fn read_current_cmdline(&self, pid: u32) -> Option<String> {
        // On Linux, read from /proc/{pid}/cmdline
        #[cfg(target_os = "linux")]
        {
            let cmdline_path = format!("/proc/{}/cmdline", pid);
            if let Ok(data) = std::fs::read(&cmdline_path) {
                // cmdline is null-separated
                let cmdline = data
                    .split(|&b| b == 0)
                    .filter_map(|part| std::str::from_utf8(part).ok())
                    .collect::<Vec<_>>()
                    .join(" ");
                return if cmdline.is_empty() {
                    None
                } else {
                    Some(cmdline)
                };
            }
        }
        None
    }

    /// Compare original and current command lines, detecting spoofing
    async fn compare_cmdlines(
        &self,
        pid: u32,
        entry: &ProcessCacheEntry,
        original: &str,
        current: &str,
    ) -> Option<CmdlineSpoofingAlert> {
        // Normalize for comparison
        let original_normalized = Self::normalize_cmdline(original);
        let current_normalized = Self::normalize_cmdline(current);

        // If identical after normalization, no spoofing
        if original_normalized == current_normalized {
            return None;
        }

        // Calculate similarity
        let similarity = Self::calculate_similarity(&original_normalized, &current_normalized);

        // Check if below threshold
        if similarity >= self.config.similarity_threshold {
            return None;
        }

        // Determine spoofing pattern
        let pattern = self.identify_spoofing_pattern(original, current);

        // Calculate confidence based on various factors
        let confidence = self.calculate_confidence(original, current, similarity, &pattern);

        // Build context
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let context = SpoofingContext {
            parent_pid: entry.parent_pid,
            parent_name: entry.parent_name.clone(),
            is_elevated: self.check_elevation(pid),
            is_signed: self.check_signature(&entry.path),
            process_start_time: entry.process_start_time,
            time_to_detection_ms: now_ms.saturating_sub(entry.process_start_time),
            memory_region: self.get_memory_region_info(pid),
        };

        // Update alert stats
        {
            let mut stats = self.stats.write().await;
            stats.alerts_generated += 1;
        }

        warn!(
            pid,
            process = %entry.name,
            original = %original,
            current = %current,
            similarity = %similarity,
            pattern = ?pattern,
            confidence = %confidence,
            "Command line spoofing detected (T1564.010)"
        );

        Some(CmdlineSpoofingAlert {
            pid,
            process_name: entry.name.clone(),
            process_path: entry.path.clone(),
            original_cmdline: original.to_string(),
            current_cmdline: current.to_string(),
            original_length: original.len(),
            current_length: current.len(),
            similarity_score: similarity,
            detection_method: DetectionMethod::PebValidation,
            spoofing_pattern: pattern,
            confidence,
            detected_at_ms: now_ms,
            context,
        })
    }

    /// Identify the pattern of command line spoofing
    fn identify_spoofing_pattern(&self, original: &str, current: &str) -> SpoofingPattern {
        // Check for space padding
        if current.chars().filter(|c| *c == ' ').count() > current.len() / 2 {
            return SpoofingPattern::SpacePadding;
        }

        // Check for truncation (significant length reduction)
        if original.len() > 20 && current.len() < original.len() / 2 {
            return SpoofingPattern::Truncation;
        }

        // Check for null padding (after conversion, nulls become empty)
        if current.trim().is_empty() && !original.trim().is_empty() {
            return SpoofingPattern::NullPadding;
        }

        // Check for known tool signatures
        for sig in &self.known_signatures {
            if let Some(ref pattern) = sig.original_pattern {
                if pattern.is_match(original) && !pattern.is_match(current) {
                    return SpoofingPattern::KnownToolSignature;
                }
            }
            if let Some(ref pattern) = sig.spoofed_pattern {
                if pattern.is_match(current) {
                    return SpoofingPattern::KnownToolSignature;
                }
            }
        }

        // Check for complete replacement (very different content)
        let original_words: HashSet<&str> = original.split_whitespace().collect();
        let current_words: HashSet<&str> = current.split_whitespace().collect();
        let common_words = original_words.intersection(&current_words).count();

        if common_words == 0 && !original_words.is_empty() && !current_words.is_empty() {
            return SpoofingPattern::CompleteReplacement;
        }

        // Check for argument substitution (some args kept, some changed)
        if common_words > 0 && original_words.len() > current_words.len() {
            return SpoofingPattern::ArgumentSubstitution;
        }

        // Check for suspicious characters
        if current.contains('\0')
            || current
                .chars()
                .any(|c| c.is_control() && c != ' ' && c != '\t')
        {
            return SpoofingPattern::SuspiciousCharacters;
        }

        SpoofingPattern::GenericModification
    }

    /// Calculate confidence score for the detection
    fn calculate_confidence(
        &self,
        original: &str,
        current: &str,
        similarity: f64,
        pattern: &SpoofingPattern,
    ) -> f64 {
        let mut confidence = 1.0 - similarity; // Base confidence from dissimilarity

        // Adjust based on pattern
        match pattern {
            SpoofingPattern::KnownToolSignature => confidence = confidence.max(0.95),
            SpoofingPattern::SpacePadding => confidence = confidence.max(0.90),
            SpoofingPattern::NullPadding => confidence = confidence.max(0.90),
            SpoofingPattern::Truncation => confidence = (confidence + 0.1).min(1.0),
            SpoofingPattern::CompleteReplacement => confidence = (confidence + 0.15).min(1.0),
            _ => {}
        }

        // Higher confidence for larger length differences
        let len_diff = (original.len() as i64 - current.len() as i64).abs() as usize;
        if len_diff > 50 {
            confidence = (confidence + 0.1).min(1.0);
        }

        // Higher confidence if original contained suspicious keywords
        let suspicious_keywords = [
            "invoke",
            "iex",
            "downloadstring",
            "-enc",
            "bypass",
            "hidden",
            "nop",
        ];
        for keyword in suspicious_keywords {
            if original.to_lowercase().contains(keyword) {
                confidence = (confidence + 0.05).min(1.0);
                break;
            }
        }

        confidence.clamp(0.0, 1.0)
    }

    /// Normalize command line for comparison
    fn normalize_cmdline(cmdline: &str) -> String {
        cmdline
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase()
    }

    /// Calculate string similarity using Levenshtein-like ratio
    fn calculate_similarity(s1: &str, s2: &str) -> f64 {
        if s1 == s2 {
            return 1.0;
        }
        if s1.is_empty() || s2.is_empty() {
            return 0.0;
        }

        // Use longest common subsequence ratio
        let lcs_len = Self::longest_common_subsequence_length(s1, s2);
        let max_len = s1.len().max(s2.len());

        lcs_len as f64 / max_len as f64
    }

    /// Calculate length of longest common subsequence
    fn longest_common_subsequence_length(s1: &str, s2: &str) -> usize {
        let s1_chars: Vec<char> = s1.chars().collect();
        let s2_chars: Vec<char> = s2.chars().collect();
        let m = s1_chars.len();
        let n = s2_chars.len();

        // Use space-optimized DP (only need previous row)
        let mut prev = vec![0usize; n + 1];
        let mut curr = vec![0usize; n + 1];

        for i in 1..=m {
            for j in 1..=n {
                if s1_chars[i - 1] == s2_chars[j - 1] {
                    curr[j] = prev[j - 1] + 1;
                } else {
                    curr[j] = prev[j].max(curr[j - 1]);
                }
            }
            std::mem::swap(&mut prev, &mut curr);
            curr.fill(0);
        }

        prev[n]
    }

    /// Check if process is elevated (Windows)
    #[cfg(target_os = "windows")]
    fn check_elevation(&self, pid: u32) -> bool {
        crate::collectors::win_compat::is_process_elevated(pid)
    }

    /// Check if process is elevated (non-Windows)
    #[cfg(not(target_os = "windows"))]
    fn check_elevation(&self, _pid: u32) -> bool {
        false
    }

    /// Check if file is signed
    fn check_signature(&self, _path: &str) -> bool {
        #[cfg(target_os = "windows")]
        {
            crate::collectors::win_compat::is_file_signed(_path)
        }
        #[cfg(not(target_os = "windows"))]
        {
            false
        }
    }

    /// Get memory region info for the command line buffer (Windows)
    #[cfg(target_os = "windows")]
    fn get_memory_region_info(&self, pid: u32) -> Option<MemoryRegionInfo> {
        use crate::collectors::win_compat::ntapi::{
            get_nt_api, ProcessBasicInformation, PROCESS_BASIC_INFORMATION, STATUS_SUCCESS,
        };
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        unsafe {
            let handle =
                OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid).ok()?;

            let api = get_nt_api()?;
            let mut pbi: ProcessBasicInformation = std::mem::zeroed();
            let mut return_length: u32 = 0;

            let status = (api.nt_query_information_process)(
                std::mem::transmute(handle),
                PROCESS_BASIC_INFORMATION,
                &mut pbi as *mut _ as *mut c_void,
                std::mem::size_of::<ProcessBasicInformation>() as u32,
                &mut return_length,
            );

            let _ = CloseHandle(handle);

            if status != STATUS_SUCCESS {
                return None;
            }

            let peb_addr = pbi.peb_base_address as u64;

            // We would need to read the PEB to get ProcessParameters
            // For now, return basic info
            Some(MemoryRegionInfo {
                process_parameters_base: peb_addr,
                cmdline_buffer_address: 0, // Would need PEB read
                cmdline_buffer_size: 0,
                protection: 0,
                protection_str: "Unknown".to_string(),
            })
        }
    }

    /// Get memory region info (non-Windows)
    #[cfg(not(target_os = "windows"))]
    fn get_memory_region_info(&self, _pid: u32) -> Option<MemoryRegionInfo> {
        None
    }

    /// Evict oldest entries from cache
    fn evict_oldest_entries(&self, cache: &mut HashMap<u32, ProcessCacheEntry>, count: usize) {
        let mut entries: Vec<(u32, Instant)> = cache
            .iter()
            .map(|(&pid, entry)| (pid, entry.created_at))
            .collect();

        entries.sort_by_key(|(_, ts)| *ts);

        for (pid, _) in entries.into_iter().take(count) {
            cache.remove(&pid);
        }
    }

    /// Remove a process from tracking
    pub async fn remove_process(&self, pid: u32) {
        let mut cache = self.cache.write().await;
        cache.remove(&pid);
    }

    /// Get count of tracked processes
    pub async fn tracked_count(&self) -> usize {
        self.cache.read().await.len()
    }

    /// Get list of tracked PIDs
    pub async fn tracked_pids(&self) -> Vec<u32> {
        self.cache.read().await.keys().copied().collect()
    }

    /// Garbage collect dead processes
    pub async fn gc_dead_processes(&self, live_pids: &HashSet<u32>) {
        let mut cache = self.cache.write().await;

        let dead_pids: Vec<u32> = cache
            .keys()
            .filter(|pid| !live_pids.contains(pid))
            .copied()
            .collect();

        for pid in dead_pids {
            cache.remove(&pid);
        }

        // Also evict old entries
        let ttl = Duration::from_secs(self.config.cache_ttl_secs);
        let now = Instant::now();

        let expired: Vec<u32> = cache
            .iter()
            .filter(|(_, entry)| now.duration_since(entry.created_at) > ttl)
            .map(|(&pid, _)| pid)
            .collect();

        for pid in expired {
            cache.remove(&pid);
        }
    }

    /// Get detector statistics
    pub async fn get_stats(&self) -> (u64, u64, u64) {
        let stats = self.stats.read().await;
        (
            stats.processes_recorded,
            stats.validations_performed,
            stats.alerts_generated,
        )
    }

    /// Validate multiple processes in batch
    pub async fn validate_batch(&self, pids: Vec<u32>) -> Vec<CmdlineSpoofingAlert> {
        let mut alerts = Vec::new();

        for pid in pids.into_iter().take(self.config.max_validations_per_cycle) {
            if let Some(alert) = self.validate_process(pid).await {
                alerts.push(alert);
            }
        }

        alerts
    }
}

impl Default for EnhancedCmdlineSpoofingDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Monitor for NtWriteVirtualMemory calls targeting PEB regions
///
/// This module provides detection of memory writes to RTL_USER_PROCESS_PARAMETERS
/// which is used by sophisticated spoofing techniques.
#[cfg(target_os = "windows")]
pub mod memory_write_monitor {
    use super::*;

    /// Represents a suspicious memory write event
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SuspiciousMemoryWrite {
        /// Target process ID
        pub target_pid: u32,
        /// Source process ID (the one performing the write)
        pub source_pid: u32,
        /// Source process name
        pub source_process: String,
        /// Target address
        pub target_address: u64,
        /// Size of write
        pub write_size: usize,
        /// Whether this targets RTL_USER_PROCESS_PARAMETERS
        pub targets_process_parameters: bool,
        /// Whether this targets command line buffer specifically
        pub targets_cmdline_buffer: bool,
        /// Timestamp
        pub timestamp_ms: u64,
    }

    /// Check if an address falls within RTL_USER_PROCESS_PARAMETERS
    pub fn is_process_parameters_region(_target_pid: u32, _address: u64, _size: usize) -> bool {
        // This would require:
        // 1. Opening the target process
        // 2. Reading PEB to get ProcessParameters address
        // 3. Checking if the write address overlaps ProcessParameters
        //
        // For now, return false - full implementation requires
        // hooking NtWriteVirtualMemory or ETW TI events

        false
    }

    /// Analyze a memory write for potential spoofing
    pub fn analyze_write(
        target_pid: u32,
        source_pid: u32,
        address: u64,
        size: usize,
    ) -> Option<SuspiciousMemoryWrite> {
        // Cross-process memory writes to user-space are suspicious
        if target_pid == source_pid {
            return None;
        }

        let targets_params = is_process_parameters_region(target_pid, address, size);

        if !targets_params {
            return None;
        }

        let source_process = {
            // Get source process name
            #[cfg(target_os = "windows")]
            {
                use windows::Win32::Foundation::CloseHandle;
                use windows::Win32::System::ProcessStatus::GetModuleBaseNameW;
                use windows::Win32::System::Threading::{
                    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
                };

                unsafe {
                    if let Ok(h) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, source_pid)
                    {
                        let mut name = [0u16; 260];
                        let len = GetModuleBaseNameW(h, None, &mut name);
                        let _ = CloseHandle(h);
                        if len > 0 {
                            String::from_utf16_lossy(&name[..len as usize])
                        } else {
                            format!("Process_{}", source_pid)
                        }
                    } else {
                        format!("Process_{}", source_pid)
                    }
                }
            }
            #[cfg(not(target_os = "windows"))]
            {
                format!("Process_{}", source_pid)
            }
        };

        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Some(SuspiciousMemoryWrite {
            target_pid,
            source_pid,
            source_process,
            target_address: address,
            write_size: size,
            targets_process_parameters: targets_params,
            targets_cmdline_buffer: false, // Would need deeper analysis
            timestamp_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_cmdline() {
        let input = "  powershell.exe   -enc   AAAA   ";
        let expected = "powershell.exe -enc aaaa";
        assert_eq!(
            EnhancedCmdlineSpoofingDetector::normalize_cmdline(input),
            expected
        );
    }

    #[test]
    fn test_calculate_similarity() {
        // Identical strings
        assert!(
            (EnhancedCmdlineSpoofingDetector::calculate_similarity("hello", "hello") - 1.0).abs()
                < 0.001
        );

        // Completely different
        let sim = EnhancedCmdlineSpoofingDetector::calculate_similarity("abc", "xyz");
        assert!(sim < 0.5);

        // Partially similar
        let sim =
            EnhancedCmdlineSpoofingDetector::calculate_similarity("hello world", "hello there");
        assert!(sim > 0.3 && sim < 1.0);

        // Empty string
        assert!(
            (EnhancedCmdlineSpoofingDetector::calculate_similarity("", "test") - 0.0).abs() < 0.001
        );
    }

    #[test]
    fn test_lcs_length() {
        assert_eq!(
            EnhancedCmdlineSpoofingDetector::longest_common_subsequence_length("abc", "abc"),
            3
        );
        assert_eq!(
            EnhancedCmdlineSpoofingDetector::longest_common_subsequence_length("abc", "def"),
            0
        );
        assert_eq!(
            EnhancedCmdlineSpoofingDetector::longest_common_subsequence_length("abcdef", "ace"),
            3
        );
    }

    #[tokio::test]
    async fn test_detector_basic() {
        let detector = EnhancedCmdlineSpoofingDetector::new();

        // Record a process
        detector
            .record_creation(
                1234,
                "test.exe",
                "C:\\test.exe",
                "test.exe --malicious-arg --download http://evil.com",
                1000,
                "parent.exe",
                0,
            )
            .await;

        assert_eq!(detector.tracked_count().await, 1);

        // Remove the process
        detector.remove_process(1234).await;
        assert_eq!(detector.tracked_count().await, 0);
    }

    #[test]
    fn test_spoofing_pattern_detection() {
        let detector = EnhancedCmdlineSpoofingDetector::new();

        // Space padding
        let pattern = detector.identify_spoofing_pattern(
            "malicious.exe --download http://evil.com",
            "                                        ",
        );
        assert_eq!(pattern, SpoofingPattern::SpacePadding);

        // Truncation
        let pattern = detector.identify_spoofing_pattern(
            "powershell.exe -enc VeryLongEncodedStringHere1234567890",
            "powershell.exe",
        );
        assert_eq!(pattern, SpoofingPattern::Truncation);
    }
}
