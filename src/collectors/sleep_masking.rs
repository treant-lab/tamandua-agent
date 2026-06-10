//! Sleep Masking / Sleep Obfuscation Detection Collector
//!
//! Detects advanced evasion techniques where malware encrypts itself in memory during
//! sleep operations to avoid detection by memory scanners.
//!
//! ## Detected Techniques
//!
//! ### Ekko Sleep Masking
//! - Uses timer queue abuse (CreateTimerQueueTimer)
//! - ROP chain to call SystemFunction032/040 for XOR encryption
//! - Avoids detection by encrypting beacon during sleep
//! - Reference: https://github.com/Cracked5pider/Ekko
//!
//! ### Foliage Sleep Masking
//! - Similar to Ekko but uses NtContinue for ROP execution
//! - CreateThreadpoolTimer variant
//! - Uses VEH (Vectored Exception Handler) for control flow
//!
//! ### Deathsleep / Gargoyle
//! - Uses APC injection into the current process
//! - Marks memory as non-executable during sleep
//! - Re-marks as executable via ROP gadgets
//!
//! ### EKKO-like variations
//! - FOLIAGE: Uses NtContinue instead of RtlRestoreContext
//! - Nighthawk: Uses hardware breakpoints
//! - BokuLoader: Abuses loader APIs
//!
//! ## Detection Methods
//!
//! 1. **Memory Permission Cycling Detection**
//!    - Track RW->RX->RW patterns on same memory regions
//!    - Correlate with timing around NtDelayExecution/Sleep calls
//!
//! 2. **Timer Queue Abuse Detection**
//!    - Monitor CreateTimerQueueTimer with callbacks to suspicious addresses
//!    - Track TP_TIMER allocations pointing to encrypted regions
//!
//! 3. **ROP Gadget Setup Detection**
//!    - Detect stack pivoting before sleep calls
//!    - Identify ROP chains targeting crypto functions
//!
//! 4. **VEH Abuse Detection**
//!    - Monitor AddVectoredExceptionHandler calls
//!    - Correlate VEH registration with memory permission changes
//!
//! 5. **NtContinue/RtlRestoreContext Abuse**
//!    - Track unusual CONTEXT structure manipulation
//!    - Detect context pointing to shellcode regions
//!
//! MITRE ATT&CK:
//! - T1027.011 - Obfuscated Files or Information: Fileless Storage
//! - T1055 - Process Injection (related to memory manipulation)
//! - T1497.003 - Virtualization/Sandbox Evasion: Time Based Evasion
//! - T1140 - Deobfuscate/Decode Files or Information

// This collector enumerates known sleep-masking technique families (Ekko,
// Foliage, Gargoyle/Deathsleep, etc.) along with their indicator patterns
// (ROP gadgets, crypto signatures, timer callbacks). Many enum variants,
// pattern tables, and detector helpers are kept exhaustive for future
// dispatch even when not currently consumed by every code path.
#![allow(dead_code, unused_variables)]

use super::{Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent};
use crate::config::AgentConfig;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

// ============================================================================
// Type Definitions
// ============================================================================

/// Types of sleep masking techniques detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SleepMaskingType {
    /// Ekko-style: Timer queue + SystemFunction032/040 encryption
    EkkoTimerQueue,
    /// Foliage-style: NtContinue-based ROP execution
    FoliageNtContinue,
    /// Gargoyle/Deathsleep: APC-based sleep with memory unmarking
    GargoyleApcSleep,
    /// Generic RW->RX->RW memory permission cycling around sleep
    MemoryPermissionCycle,
    /// CreateTimerQueueTimer with suspicious callback
    TimerQueueAbuse,
    /// CreateThreadpoolTimer abuse
    ThreadpoolTimerAbuse,
    /// VEH (Vectored Exception Handler) registered before sleep
    VehAbuse,
    /// NtContinue/RtlRestoreContext pointing to suspicious memory
    ContextManipulation,
    /// ROP chain setup detected before sleep call
    RopChainSetup,
    /// Stack pivot detected (RSP/ESP manipulation)
    StackPivot,
    /// Hardware breakpoint abuse (DR registers)
    HardwareBreakpointAbuse,
    /// Unusual NtDelayExecution patterns (many short sleeps, unusual intervals)
    SleepPatternAnomaly,
    /// Memory decryption detected after sleep resume
    PostSleepDecryption,
    /// Entropy change detection (encrypted during sleep)
    EntropyFluctuation,
    /// Unknown/generic sleep masking behavior
    Unknown,
}

impl SleepMaskingType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EkkoTimerQueue => "ekko_timer_queue",
            Self::FoliageNtContinue => "foliage_nt_continue",
            Self::GargoyleApcSleep => "gargoyle_apc_sleep",
            Self::MemoryPermissionCycle => "memory_permission_cycle",
            Self::TimerQueueAbuse => "timer_queue_abuse",
            Self::ThreadpoolTimerAbuse => "threadpool_timer_abuse",
            Self::VehAbuse => "veh_abuse",
            Self::ContextManipulation => "context_manipulation",
            Self::RopChainSetup => "rop_chain_setup",
            Self::StackPivot => "stack_pivot",
            Self::HardwareBreakpointAbuse => "hardware_breakpoint_abuse",
            Self::SleepPatternAnomaly => "sleep_pattern_anomaly",
            Self::PostSleepDecryption => "post_sleep_decryption",
            Self::EntropyFluctuation => "entropy_fluctuation",
            Self::Unknown => "unknown",
        }
    }

    pub fn mitre_technique(&self) -> &'static str {
        match self {
            Self::EkkoTimerQueue
            | Self::FoliageNtContinue
            | Self::GargoyleApcSleep
            | Self::TimerQueueAbuse
            | Self::ThreadpoolTimerAbuse => "T1027.011",
            Self::MemoryPermissionCycle | Self::PostSleepDecryption | Self::EntropyFluctuation => {
                "T1140"
            }
            Self::VehAbuse | Self::ContextManipulation => "T1055",
            Self::RopChainSetup | Self::StackPivot => "T1055.012",
            Self::HardwareBreakpointAbuse => "T1497.003",
            Self::SleepPatternAnomaly => "T1497.003",
            Self::Unknown => "T1027",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            // Critical: Known malware techniques
            Self::EkkoTimerQueue | Self::FoliageNtContinue | Self::GargoyleApcSleep => {
                Severity::Critical
            }
            // High: Strong indicators
            Self::TimerQueueAbuse
            | Self::ThreadpoolTimerAbuse
            | Self::RopChainSetup
            | Self::ContextManipulation
            | Self::PostSleepDecryption => Severity::High,
            // Medium: Suspicious but could be legitimate
            Self::MemoryPermissionCycle
            | Self::VehAbuse
            | Self::StackPivot
            | Self::HardwareBreakpointAbuse
            | Self::EntropyFluctuation => Severity::Medium,
            // Low: Anomalous patterns
            Self::SleepPatternAnomaly | Self::Unknown => Severity::Low,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::EkkoTimerQueue => "Ekko sleep masking: Timer queue abuse with ROP chain for memory encryption during sleep",
            Self::FoliageNtContinue => "Foliage sleep masking: NtContinue-based execution with memory obfuscation",
            Self::GargoyleApcSleep => "Gargoyle/Deathsleep: APC-based sleep with memory permission toggling",
            Self::MemoryPermissionCycle => "Memory protection cycling (RW->RX->RW) correlated with sleep operations",
            Self::TimerQueueAbuse => "CreateTimerQueueTimer callback pointing to suspicious memory region",
            Self::ThreadpoolTimerAbuse => "Threadpool timer callback targeting encrypted/obfuscated memory",
            Self::VehAbuse => "Vectored Exception Handler registered in correlation with sleep masking patterns",
            Self::ContextManipulation => "Thread context manipulation (NtContinue/RtlRestoreContext) to suspicious address",
            Self::RopChainSetup => "ROP gadget chain setup detected before sleep operation",
            Self::StackPivot => "Stack pivot detected (RSP manipulation) before or during sleep",
            Self::HardwareBreakpointAbuse => "Hardware breakpoint (DR register) abuse for execution control",
            Self::SleepPatternAnomaly => "Unusual NtDelayExecution/Sleep patterns (rapid cycling, unusual intervals)",
            Self::PostSleepDecryption => "Memory region entropy decreased significantly after sleep (decryption indicator)",
            Self::EntropyFluctuation => "Significant entropy fluctuation in executable memory region across sleep cycles",
            Self::Unknown => "Unknown sleep masking behavior detected",
        }
    }
}

/// Sleep masking detection event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SleepMaskingEvent {
    /// Type of sleep masking detected
    pub masking_type: SleepMaskingType,
    /// Process ID
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// Process executable path
    pub process_path: String,
    /// Command line
    pub cmdline: String,
    /// User account
    pub user: String,
    /// Memory region base address (if applicable)
    pub memory_address: Option<u64>,
    /// Memory region size (if applicable)
    pub memory_size: Option<u64>,
    /// Memory protection before
    pub old_protection: Option<u32>,
    /// Memory protection after
    pub new_protection: Option<u32>,
    /// Sleep duration (milliseconds)
    pub sleep_duration_ms: Option<u64>,
    /// Timer callback address (for timer queue abuse)
    pub timer_callback: Option<u64>,
    /// Context RIP/EIP (for context manipulation)
    pub context_rip: Option<u64>,
    /// VEH handler address (for VEH abuse)
    pub veh_handler: Option<u64>,
    /// Entropy before operation
    pub entropy_before: Option<f32>,
    /// Entropy after operation
    pub entropy_after: Option<f32>,
    /// ROP gadget addresses (if detected)
    pub rop_gadgets: Vec<u64>,
    /// Additional evidence details
    pub evidence: Vec<String>,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
}

// ============================================================================
// Memory Region Tracking for Sleep Correlation
// ============================================================================

/// Tracks memory region state for sleep masking detection
#[derive(Debug, Clone)]
struct MemoryRegionSnapshot {
    /// Base address
    pub base_address: u64,
    /// Region size
    pub size: u64,
    /// Current protection flags
    pub protection: u32,
    /// Entropy of the region content
    pub entropy: f32,
    /// When this state was captured
    pub timestamp: Instant,
    /// Whether this region has executable permissions
    pub is_executable: bool,
    /// Memory type (MEM_PRIVATE, MEM_IMAGE, etc.)
    pub mem_type: u32,
}

/// Tracks protection transitions for a single region
#[derive(Debug, Clone)]
struct ProtectionHistory {
    /// Recent protection changes (timestamp, old_prot, new_prot)
    pub transitions: VecDeque<(Instant, u32, u32)>,
    /// Recent entropy measurements (timestamp, entropy)
    pub entropy_history: VecDeque<(Instant, f32)>,
    /// Number of RW->RX transitions
    pub rw_to_rx_count: u32,
    /// Number of RX->RW transitions
    pub rx_to_rw_count: u32,
    /// Last known entropy
    pub last_entropy: f32,
}

impl ProtectionHistory {
    fn new() -> Self {
        Self {
            transitions: VecDeque::with_capacity(20),
            entropy_history: VecDeque::with_capacity(20),
            rw_to_rx_count: 0,
            rx_to_rw_count: 0,
            last_entropy: 0.0,
        }
    }

    fn record_transition(&mut self, old_prot: u32, new_prot: u32) {
        let now = Instant::now();

        // Keep only last 20 transitions
        if self.transitions.len() >= 20 {
            self.transitions.pop_front();
        }
        self.transitions.push_back((now, old_prot, new_prot));

        // Track RW->RX and RX->RW patterns
        let was_rw = is_rw_protection(old_prot);
        let was_rx = is_rx_protection(old_prot);
        let is_rw = is_rw_protection(new_prot);
        let is_rx = is_rx_protection(new_prot);

        if was_rw && is_rx {
            self.rw_to_rx_count += 1;
        }
        if was_rx && is_rw {
            self.rx_to_rw_count += 1;
        }
    }

    fn record_entropy(&mut self, entropy: f32) {
        let now = Instant::now();
        if self.entropy_history.len() >= 20 {
            self.entropy_history.pop_front();
        }
        self.last_entropy = entropy;
        self.entropy_history.push_back((now, entropy));
    }

    /// Check if this region shows permission cycling pattern
    fn has_permission_cycling(&self, window: Duration) -> bool {
        let now = Instant::now();
        let cutoff = now.checked_sub(window).unwrap_or(now);

        // Count cycles (RW->RX followed by RX->RW within window)
        let recent_transitions: Vec<_> = self
            .transitions
            .iter()
            .filter(|(ts, _, _)| *ts >= cutoff)
            .collect();

        if recent_transitions.len() < 2 {
            return false;
        }

        // Look for RW->RX followed by RX->RW
        for i in 0..recent_transitions.len() - 1 {
            let (_, old1, new1) = recent_transitions[i];
            let (_, old2, new2) = recent_transitions[i + 1];

            let first_is_rw_to_rx = is_rw_protection(*old1) && is_rx_protection(*new1);
            let second_is_rx_to_rw = is_rx_protection(*old2) && is_rw_protection(*new2);

            if first_is_rw_to_rx && second_is_rx_to_rw {
                return true;
            }
        }

        false
    }

    /// Check for significant entropy fluctuation (encryption/decryption)
    fn has_entropy_fluctuation(&self, threshold: f32, window: Duration) -> Option<(f32, f32)> {
        let now = Instant::now();
        let cutoff = now.checked_sub(window).unwrap_or(now);

        let recent: Vec<_> = self
            .entropy_history
            .iter()
            .filter(|(ts, _)| *ts >= cutoff)
            .map(|(_, e)| *e)
            .collect();

        if recent.len() < 2 {
            return None;
        }

        let min_entropy = recent.iter().cloned().fold(f32::INFINITY, f32::min);
        let max_entropy = recent.iter().cloned().fold(f32::NEG_INFINITY, f32::max);

        if max_entropy - min_entropy >= threshold {
            Some((min_entropy, max_entropy))
        } else {
            None
        }
    }
}

// ============================================================================
// Sleep Call Tracking
// ============================================================================

/// Tracks sleep/delay calls for pattern analysis
#[derive(Debug, Clone)]
struct SleepCallRecord {
    /// When the sleep was initiated
    pub timestamp: Instant,
    /// Sleep duration requested (milliseconds)
    pub duration_ms: u64,
    /// Thread ID
    pub thread_id: u32,
    /// API used (NtDelayExecution, Sleep, SleepEx, WaitForSingleObject, etc.)
    pub api_name: String,
}

/// Tracks sleep patterns per process
#[derive(Debug)]
struct ProcessSleepTracker {
    /// Recent sleep calls
    pub sleep_calls: VecDeque<SleepCallRecord>,
    /// Memory region snapshots before sleep
    pub pre_sleep_snapshots: HashMap<u64, MemoryRegionSnapshot>,
    /// Timer queue registrations
    pub timer_callbacks: Vec<(Instant, u64, u64)>, // (timestamp, timer_handle, callback_addr)
    /// VEH registrations
    pub veh_handlers: Vec<(Instant, u64)>, // (timestamp, handler_addr)
    /// Detected ROP gadget addresses
    pub rop_gadgets: HashSet<u64>,
    /// Context manipulation events
    pub context_events: VecDeque<(Instant, u64)>, // (timestamp, target_rip)
    /// Protection history per region
    pub protection_history: HashMap<u64, ProtectionHistory>,
}

impl ProcessSleepTracker {
    fn new() -> Self {
        Self {
            sleep_calls: VecDeque::with_capacity(100),
            pre_sleep_snapshots: HashMap::new(),
            timer_callbacks: Vec::new(),
            veh_handlers: Vec::new(),
            rop_gadgets: HashSet::new(),
            context_events: VecDeque::with_capacity(50),
            protection_history: HashMap::new(),
        }
    }

    fn record_sleep(&mut self, duration_ms: u64, thread_id: u32, api_name: &str) {
        if self.sleep_calls.len() >= 100 {
            self.sleep_calls.pop_front();
        }
        self.sleep_calls.push_back(SleepCallRecord {
            timestamp: Instant::now(),
            duration_ms,
            thread_id,
            api_name: api_name.to_string(),
        });
    }

    /// Detect anomalous sleep patterns
    fn detect_sleep_anomaly(&self, window: Duration) -> Option<(u32, u64)> {
        let now = Instant::now();
        let cutoff = now.checked_sub(window).unwrap_or(now);

        let recent: Vec<_> = self
            .sleep_calls
            .iter()
            .filter(|s| s.timestamp >= cutoff)
            .collect();

        if recent.len() < 5 {
            return None;
        }

        // Pattern 1: Many short sleeps (< 100ms) in rapid succession
        let short_sleeps = recent.iter().filter(|s| s.duration_ms < 100).count();
        if short_sleeps > 10 {
            return Some((
                short_sleeps as u32,
                recent.last().map(|s| s.duration_ms).unwrap_or(0),
            ));
        }

        // Pattern 2: Highly regular intervals (exact same duration repeatedly)
        let mut duration_counts: HashMap<u64, u32> = HashMap::new();
        for s in &recent {
            *duration_counts.entry(s.duration_ms).or_insert(0) += 1;
        }
        for (duration, count) in duration_counts {
            if count >= 5 && duration > 1000 {
                // Same sleep duration 5+ times (beacon behavior)
                return Some((count, duration));
            }
        }

        None
    }

    /// GC old data
    fn gc(&mut self, max_age: Duration) {
        let now = Instant::now();
        let cutoff = now.checked_sub(max_age).unwrap_or(now);

        self.sleep_calls.retain(|s| s.timestamp >= cutoff);
        self.timer_callbacks.retain(|(ts, _, _)| *ts >= cutoff);
        self.veh_handlers.retain(|(ts, _)| *ts >= cutoff);
        self.context_events.retain(|(ts, _)| *ts >= cutoff);

        // Clean up protection history (remove old entries)
        for history in self.protection_history.values_mut() {
            history.transitions.retain(|(ts, _, _)| *ts >= cutoff);
            history.entropy_history.retain(|(ts, _)| *ts >= cutoff);
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Windows protection constants
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_WRITECOPY: u32 = 0x08;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

/// Check if protection includes write but not execute
fn is_rw_protection(prot: u32) -> bool {
    ((prot & PAGE_READWRITE) != 0 || (prot & PAGE_WRITECOPY) != 0)
        && (prot & PAGE_EXECUTE) == 0
        && (prot & PAGE_EXECUTE_READ) == 0
        && (prot & PAGE_EXECUTE_READWRITE) == 0
        && (prot & PAGE_EXECUTE_WRITECOPY) == 0
}

/// Check if protection includes execute but not write
fn is_rx_protection(prot: u32) -> bool {
    ((prot & PAGE_EXECUTE) != 0 || (prot & PAGE_EXECUTE_READ) != 0)
        && (prot & PAGE_READWRITE) == 0
        && (prot & PAGE_WRITECOPY) == 0
        && (prot & PAGE_EXECUTE_READWRITE) == 0
        && (prot & PAGE_EXECUTE_WRITECOPY) == 0
}

/// Check if protection is RWX
fn is_rwx_protection(prot: u32) -> bool {
    (prot & PAGE_EXECUTE_READWRITE) != 0 || (prot & PAGE_EXECUTE_WRITECOPY) != 0
}

/// Format protection flags as string
fn format_protection(prot: u32) -> String {
    let mut parts = Vec::new();
    if prot & PAGE_EXECUTE_READWRITE != 0 {
        parts.push("PAGE_EXECUTE_READWRITE");
    }
    if prot & PAGE_EXECUTE_WRITECOPY != 0 {
        parts.push("PAGE_EXECUTE_WRITECOPY");
    }
    if prot & PAGE_EXECUTE_READ != 0 {
        parts.push("PAGE_EXECUTE_READ");
    }
    if prot & PAGE_EXECUTE != 0 {
        parts.push("PAGE_EXECUTE");
    }
    if prot & PAGE_READWRITE != 0 {
        parts.push("PAGE_READWRITE");
    }
    if prot & PAGE_WRITECOPY != 0 {
        parts.push("PAGE_WRITECOPY");
    }
    if prot & PAGE_READONLY != 0 {
        parts.push("PAGE_READONLY");
    }
    if prot & PAGE_NOACCESS != 0 {
        parts.push("PAGE_NOACCESS");
    }
    if parts.is_empty() {
        format!("0x{:x}", prot)
    } else {
        parts.join("|")
    }
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

// ============================================================================
// ROP Gadget Detection
// ============================================================================

/// Known ROP gadget patterns used in sleep masking
static ROP_GADGET_PATTERNS: &[(&str, &[u8])] = &[
    // ret (C3)
    ("ret", &[0xC3]),
    // pop rax; ret
    ("pop_rax_ret", &[0x58, 0xC3]),
    // pop rcx; ret
    ("pop_rcx_ret", &[0x59, 0xC3]),
    // pop rdx; ret
    ("pop_rdx_ret", &[0x5A, 0xC3]),
    // pop rbx; ret
    ("pop_rbx_ret", &[0x5B, 0xC3]),
    // pop rsp; ret (stack pivot)
    ("pop_rsp_ret", &[0x5C, 0xC3]),
    // pop rbp; ret
    ("pop_rbp_ret", &[0x5D, 0xC3]),
    // pop rsi; ret
    ("pop_rsi_ret", &[0x5E, 0xC3]),
    // pop rdi; ret
    ("pop_rdi_ret", &[0x5F, 0xC3]),
    // xchg rax, rsp; ret (stack pivot)
    ("xchg_rax_rsp_ret", &[0x48, 0x94, 0xC3]),
    // mov rsp, rbp; pop rbp; ret (function epilogue abuse)
    ("leave_ret", &[0xC9, 0xC3]),
    // jmp rax
    ("jmp_rax", &[0xFF, 0xE0]),
    // jmp rcx
    ("jmp_rcx", &[0xFF, 0xE1]),
    // call rax
    ("call_rax", &[0xFF, 0xD0]),
    // call rcx
    ("call_rcx", &[0xFF, 0xD1]),
];

/// Known crypto function signatures (SystemFunction032/040, RC4, XOR)
static CRYPTO_SIGNATURES: &[(&str, &[u8])] = &[
    // XOR loop pattern (common in shellcode encryption)
    ("xor_loop", &[0x30, 0x04, 0x08]), // xor byte [rax+rcx], al
    // RC4 key schedule pattern
    ("rc4_sbox", &[0x88, 0x0C, 0x01]), // mov [rcx+rax], cl
    // SystemFunction032 call pattern (advapi32!SystemFunction032)
    // This is RtlEncryptMemory/RtlDecryptMemory under the hood
    ("rtl_encrypt_pattern", &[0x48, 0x89, 0x4C, 0x24]), // mov [rsp+X], rcx (param setup)
];

/// Detects potential ROP gadgets in a memory buffer
fn scan_for_rop_gadgets(buffer: &[u8], base_address: u64) -> Vec<(String, u64)> {
    let mut gadgets = Vec::new();

    for (name, pattern) in ROP_GADGET_PATTERNS {
        if pattern.len() > buffer.len() {
            continue;
        }
        for i in 0..=(buffer.len() - pattern.len()) {
            if &buffer[i..i + pattern.len()] == *pattern {
                gadgets.push((name.to_string(), base_address + i as u64));
            }
        }
    }

    gadgets
}

// ============================================================================
// Timer Queue and Callback Monitoring Patterns
// ============================================================================

/// Suspicious timer callback indicators
#[derive(Debug, Clone)]
struct SuspiciousTimerCallback {
    pub timer_handle: u64,
    pub callback_address: u64,
    pub period_ms: u32,
    pub is_callback_unbacked: bool,
    pub callback_in_rwx: bool,
    pub callback_entropy: f32,
}

// ============================================================================
// Main Detector Implementation
// ============================================================================

/// Sleep masking detection collector
pub struct SleepMaskingDetector {
    /// Configuration
    #[allow(dead_code)]
    config: AgentConfig,
    /// Event sender
    event_tx: mpsc::Sender<TelemetryEvent>,
    /// Event receiver
    event_rx: mpsc::Receiver<TelemetryEvent>,
    /// Per-process tracking state
    process_trackers: Arc<RwLock<HashMap<u32, ProcessSleepTracker>>>,
    /// Set of already reported (pid, base_address) to avoid duplicates
    reported: Arc<RwLock<HashSet<(u32, u64)>>>,
}

impl SleepMaskingDetector {
    /// Create a new sleep masking detector
    pub fn new(config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(500);

        let detector = Self {
            config: config.clone(),
            event_tx: tx.clone(),
            event_rx: rx,
            process_trackers: Arc::new(RwLock::new(HashMap::new())),
            reported: Arc::new(RwLock::new(HashSet::new())),
        };

        // Start platform-specific monitoring
        #[cfg(target_os = "windows")]
        {
            let tx_clone = tx.clone();
            let trackers = detector.process_trackers.clone();
            let reported = detector.reported.clone();
            tokio::spawn(async move {
                Self::windows_monitor_loop(tx_clone, trackers, reported).await;
            });
        }

        #[cfg(target_os = "linux")]
        {
            let tx_clone = tx.clone();
            let trackers = detector.process_trackers.clone();
            let reported = detector.reported.clone();
            tokio::spawn(async move {
                Self::linux_monitor_loop(tx_clone, trackers, reported).await;
            });
        }

        detector
    }

    /// Get next event from collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }

    /// Record a sleep call from external monitoring
    pub fn record_sleep_call(&self, pid: u32, duration_ms: u64, thread_id: u32, api_name: &str) {
        let mut trackers = self.process_trackers.write();
        let tracker = trackers.entry(pid).or_insert_with(ProcessSleepTracker::new);
        tracker.record_sleep(duration_ms, thread_id, api_name);
    }

    /// Record a memory protection change
    pub fn record_protection_change(
        &self,
        pid: u32,
        base_address: u64,
        old_prot: u32,
        new_prot: u32,
        entropy: f32,
    ) {
        let mut trackers = self.process_trackers.write();
        let tracker = trackers.entry(pid).or_insert_with(ProcessSleepTracker::new);

        let history = tracker
            .protection_history
            .entry(base_address)
            .or_insert_with(ProtectionHistory::new);

        history.record_transition(old_prot, new_prot);
        history.record_entropy(entropy);
    }

    /// Record a timer queue registration
    pub fn record_timer_callback(&self, pid: u32, timer_handle: u64, callback_address: u64) {
        let mut trackers = self.process_trackers.write();
        let tracker = trackers.entry(pid).or_insert_with(ProcessSleepTracker::new);
        tracker
            .timer_callbacks
            .push((Instant::now(), timer_handle, callback_address));
    }

    /// Record a VEH registration
    pub fn record_veh_handler(&self, pid: u32, handler_address: u64) {
        let mut trackers = self.process_trackers.write();
        let tracker = trackers.entry(pid).or_insert_with(ProcessSleepTracker::new);
        tracker.veh_handlers.push((Instant::now(), handler_address));
    }

    /// Record context manipulation (NtContinue, RtlRestoreContext, etc.)
    pub fn record_context_event(&self, pid: u32, target_rip: u64) {
        let mut trackers = self.process_trackers.write();
        let tracker = trackers.entry(pid).or_insert_with(ProcessSleepTracker::new);
        if tracker.context_events.len() >= 50 {
            tracker.context_events.pop_front();
        }
        tracker
            .context_events
            .push_back((Instant::now(), target_rip));
    }

    /// Analyze a process for sleep masking indicators
    pub fn analyze_process(&self, pid: u32) -> Vec<SleepMaskingEvent> {
        let trackers = self.process_trackers.read();
        let tracker = match trackers.get(&pid) {
            Some(t) => t,
            None => return Vec::new(),
        };

        let mut events = Vec::new();
        let process_name = Self::get_process_name(pid);
        let process_path = Self::get_process_path(pid);
        let cmdline = Self::get_process_cmdline(pid);
        let user = Self::get_process_user(pid);

        // Detection 1: Memory permission cycling
        for (base_addr, history) in &tracker.protection_history {
            if history.has_permission_cycling(Duration::from_secs(60)) {
                let mut evidence = vec![
                    format!("RW->RX transitions: {}", history.rw_to_rx_count),
                    format!("RX->RW transitions: {}", history.rx_to_rw_count),
                ];

                // Check for entropy fluctuation
                let (entropy_before, entropy_after) = if let Some((min, max)) =
                    history.has_entropy_fluctuation(2.0, Duration::from_secs(60))
                {
                    evidence.push(format!("Entropy fluctuation: {:.2} -> {:.2}", min, max));
                    (Some(min), Some(max))
                } else {
                    (None, None)
                };

                events.push(SleepMaskingEvent {
                    masking_type: SleepMaskingType::MemoryPermissionCycle,
                    pid,
                    process_name: process_name.clone(),
                    process_path: process_path.clone(),
                    cmdline: cmdline.clone(),
                    user: user.clone(),
                    memory_address: Some(*base_addr),
                    memory_size: None,
                    old_protection: None,
                    new_protection: None,
                    sleep_duration_ms: None,
                    timer_callback: None,
                    context_rip: None,
                    veh_handler: None,
                    entropy_before,
                    entropy_after,
                    rop_gadgets: Vec::new(),
                    evidence,
                    confidence: 0.85,
                });
            }
        }

        // Detection 2: Sleep pattern anomaly
        if let Some((count, duration)) = tracker.detect_sleep_anomaly(Duration::from_secs(300)) {
            events.push(SleepMaskingEvent {
                masking_type: SleepMaskingType::SleepPatternAnomaly,
                pid,
                process_name: process_name.clone(),
                process_path: process_path.clone(),
                cmdline: cmdline.clone(),
                user: user.clone(),
                memory_address: None,
                memory_size: None,
                old_protection: None,
                new_protection: None,
                sleep_duration_ms: Some(duration),
                timer_callback: None,
                context_rip: None,
                veh_handler: None,
                entropy_before: None,
                entropy_after: None,
                rop_gadgets: Vec::new(),
                evidence: vec![format!(
                    "{} sleep calls with duration {}ms in 5 minutes",
                    count, duration
                )],
                confidence: 0.6,
            });
        }

        // Detection 3: Timer queue abuse with correlation to permission cycling
        for (ts, _handle, callback) in &tracker.timer_callbacks {
            // Check if callback is in a region that shows permission cycling
            if tracker
                .protection_history
                .values()
                .any(|h| h.has_permission_cycling(Duration::from_secs(60)))
            {
                events.push(SleepMaskingEvent {
                    masking_type: SleepMaskingType::TimerQueueAbuse,
                    pid,
                    process_name: process_name.clone(),
                    process_path: process_path.clone(),
                    cmdline: cmdline.clone(),
                    user: user.clone(),
                    memory_address: None,
                    memory_size: None,
                    old_protection: None,
                    new_protection: None,
                    sleep_duration_ms: None,
                    timer_callback: Some(*callback),
                    context_rip: None,
                    veh_handler: None,
                    entropy_before: None,
                    entropy_after: None,
                    rop_gadgets: Vec::new(),
                    evidence: vec![format!(
                        "Timer callback 0x{:016x} registered {:?} ago",
                        callback,
                        ts.elapsed()
                    )],
                    confidence: 0.75,
                });
                break; // Only report once per process
            }
        }

        // Detection 4: VEH abuse correlation
        if !tracker.veh_handlers.is_empty()
            && tracker
                .protection_history
                .values()
                .any(|h| h.has_permission_cycling(Duration::from_secs(60)))
        {
            let (_, handler_addr) = tracker.veh_handlers.last().unwrap();
            events.push(SleepMaskingEvent {
                masking_type: SleepMaskingType::VehAbuse,
                pid,
                process_name: process_name.clone(),
                process_path: process_path.clone(),
                cmdline: cmdline.clone(),
                user: user.clone(),
                memory_address: None,
                memory_size: None,
                old_protection: None,
                new_protection: None,
                sleep_duration_ms: None,
                timer_callback: None,
                context_rip: None,
                veh_handler: Some(*handler_addr),
                entropy_before: None,
                entropy_after: None,
                rop_gadgets: Vec::new(),
                evidence: vec![format!(
                    "VEH handler 0x{:016x} with permission cycling detected",
                    handler_addr
                )],
                confidence: 0.8,
            });
        }

        // Detection 5: Context manipulation to suspicious address
        for (_, target_rip) in &tracker.context_events {
            // Check if target RIP is in a region that shows permission cycling
            for (base, history) in &tracker.protection_history {
                if history.has_permission_cycling(Duration::from_secs(60)) {
                    events.push(SleepMaskingEvent {
                        masking_type: SleepMaskingType::ContextManipulation,
                        pid,
                        process_name: process_name.clone(),
                        process_path: process_path.clone(),
                        cmdline: cmdline.clone(),
                        user: user.clone(),
                        memory_address: Some(*base),
                        memory_size: None,
                        old_protection: None,
                        new_protection: None,
                        sleep_duration_ms: None,
                        timer_callback: None,
                        context_rip: Some(*target_rip),
                        veh_handler: None,
                        entropy_before: None,
                        entropy_after: None,
                        rop_gadgets: Vec::new(),
                        evidence: vec![format!(
                            "Context RIP 0x{:016x} targeting cycling region 0x{:016x}",
                            target_rip, base
                        )],
                        confidence: 0.9,
                    });
                    break;
                }
            }
        }

        events
    }

    /// Create telemetry event from detection
    fn create_event(event: &SleepMaskingEvent) -> TelemetryEvent {
        let mut telemetry = TelemetryEvent::new(
            EventType::DefenseEvasion,
            event.masking_type.severity(),
            EventPayload::Generic(serde_json::json!({
                "event_type": "sleep_masking",
                "masking_type": event.masking_type.as_str(),
                "pid": event.pid,
                "process_name": event.process_name,
                "process_path": event.process_path,
                "cmdline": event.cmdline,
                "user": event.user,
                "memory_address": event.memory_address,
                "memory_size": event.memory_size,
                "old_protection": event.old_protection,
                "new_protection": event.new_protection,
                "sleep_duration_ms": event.sleep_duration_ms,
                "timer_callback": event.timer_callback,
                "context_rip": event.context_rip,
                "veh_handler": event.veh_handler,
                "entropy_before": event.entropy_before,
                "entropy_after": event.entropy_after,
                "rop_gadgets": event.rop_gadgets,
                "evidence": event.evidence,
            })),
        );

        telemetry.add_detection(Detection {
            detection_type: DetectionType::DefenseEvasion,
            rule_name: format!("sleep_masking_{}", event.masking_type.as_str()),
            confidence: event.confidence,
            description: event.masking_type.description().to_string(),
            mitre_tactics: vec!["Defense Evasion".to_string()],
            mitre_techniques: vec![event.masking_type.mitre_technique().to_string()],
        });

        telemetry
    }

    // Platform-specific helper functions
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
                .unwrap_or_default()
        }
    }

    fn get_process_path(pid: u32) -> String {
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
                        return String::from_utf16_lossy(&buffer[..len as usize]);
                    }
                }
            }
            String::new()
        }

        #[cfg(target_os = "linux")]
        {
            std::fs::read_link(format!("/proc/{}/exe", pid))
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default()
        }

        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            let pid_str = pid.to_string();
            Command::new("ps")
                .args(["-o", "command=", "-p", &pid_str])
                .output()
                .ok()
                .and_then(|o| {
                    let cmd = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    if cmd.is_empty() {
                        None
                    } else {
                        cmd.split_whitespace().next().map(|s| s.to_string())
                    }
                })
                .unwrap_or_default()
        }
    }

    fn get_process_cmdline(pid: u32) -> String {
        #[cfg(target_os = "windows")]
        {
            // Getting command line on Windows requires more complex logic
            // For now, return empty string
            String::new()
        }

        #[cfg(target_os = "linux")]
        {
            std::fs::read_to_string(format!("/proc/{}/cmdline", pid))
                .map(|s| s.replace('\0', " ").trim().to_string())
                .unwrap_or_default()
        }

        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            let pid_str = pid.to_string();
            Command::new("ps")
                .args(["-o", "command=", "-p", &pid_str])
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default()
        }
    }

    fn get_process_user(pid: u32) -> String {
        #[cfg(target_os = "windows")]
        {
            // Getting user on Windows requires token query
            String::new()
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            use std::process::Command;
            let pid_str = pid.to_string();
            Command::new("ps")
                .args(["-o", "user=", "-p", &pid_str])
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default()
        }
    }

    // ========================================================================
    // Windows Monitoring Implementation
    // ========================================================================

    #[cfg(target_os = "windows")]
    async fn windows_monitor_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        trackers: Arc<RwLock<HashMap<u32, ProcessSleepTracker>>>,
        reported: Arc<RwLock<HashSet<(u32, u64)>>>,
    ) {
        use std::ffi::c_void;
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows::Win32::System::Memory::{
            VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE,
            PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
        };
        use windows::Win32::System::ProcessStatus::K32EnumProcesses;
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        let mut interval = tokio::time::interval(Duration::from_secs(5));
        let mut last_gc = Instant::now();

        loop {
            interval.tick().await;

            // GC old data periodically
            if last_gc.elapsed() > Duration::from_secs(60) {
                let mut t = trackers.write();
                for tracker in t.values_mut() {
                    tracker.gc(Duration::from_secs(300));
                }

                // Clean up reported set
                let mut r = reported.write();
                if r.len() > 10000 {
                    r.clear();
                }
                last_gc = Instant::now();
            }

            // Enumerate processes
            let mut pids = vec![0u32; 4096];
            let mut bytes_returned = 0u32;

            unsafe {
                if !K32EnumProcesses(
                    pids.as_mut_ptr(),
                    (pids.len() * std::mem::size_of::<u32>()) as u32,
                    &mut bytes_returned,
                )
                .as_bool()
                {
                    warn!("Failed to enumerate processes for sleep masking detection");
                    continue;
                }
            }

            let count = bytes_returned as usize / std::mem::size_of::<u32>();
            let pids = &pids[..count];

            for &pid in pids {
                if pid == 0 {
                    continue;
                }

                // Skip our own process
                if pid == std::process::id() {
                    continue;
                }

                let mut pending_events = Vec::new();

                {
                    // Open process for memory scanning
                    let handle = match unsafe {
                        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
                    } {
                        Ok(h) => h,
                        Err(_) => continue,
                    };

                    // Scan memory regions for permission patterns
                    let mut address: usize = 0;
                    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };

                    while unsafe {
                        VirtualQueryEx(
                            handle,
                            Some(address as *const c_void),
                            &mut mbi,
                            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                        )
                    } > 0
                    {
                        let base = mbi.BaseAddress as u64;
                        let size = mbi.RegionSize as u64;
                        let prot = mbi.Protect.0;
                        let state = mbi.State;
                        let mem_type = mbi.Type.0;

                        // Only interested in committed private memory
                        if state == MEM_COMMIT && mem_type == MEM_PRIVATE.0 {
                            // Read memory to calculate entropy
                            let is_executable = (prot & PAGE_EXECUTE.0) != 0
                                || (prot & PAGE_EXECUTE_READ.0) != 0
                                || (prot & PAGE_EXECUTE_READWRITE.0) != 0
                                || (prot & PAGE_EXECUTE_WRITECOPY.0) != 0;

                            if is_executable && size > 0 && size < 10 * 1024 * 1024 {
                                let read_size = size.min(4096) as usize;
                                let mut buffer = vec![0u8; read_size];
                                let mut bytes_read = 0usize;

                                let entropy = if unsafe {
                                    ReadProcessMemory(
                                        handle,
                                        base as *const c_void,
                                        buffer.as_mut_ptr() as *mut c_void,
                                        read_size,
                                        Some(&mut bytes_read),
                                    )
                                }
                                .is_ok()
                                    && bytes_read > 0
                                {
                                    calculate_entropy(&buffer[..bytes_read])
                                } else {
                                    0.0
                                };

                                // Update tracking
                                {
                                    let mut t = trackers.write();
                                    let tracker =
                                        t.entry(pid).or_insert_with(ProcessSleepTracker::new);

                                    let history = tracker
                                        .protection_history
                                        .entry(base)
                                        .or_insert_with(ProtectionHistory::new);

                                    // Check for protection change
                                    let last_transitions = history.transitions.back();
                                    if let Some((_, _, last_prot)) = last_transitions {
                                        if *last_prot != prot {
                                            history.record_transition(*last_prot, prot);
                                        }
                                    } else {
                                        // First observation - record initial state
                                        history.record_transition(0, prot);
                                    }

                                    history.record_entropy(entropy);

                                    // Detect permission cycling
                                    if history.has_permission_cycling(Duration::from_secs(60)) {
                                        let key = (pid, base);
                                        let mut r = reported.write();
                                        if !r.contains(&key) {
                                            r.insert(key);

                                            let process_name = Self::get_process_name(pid);
                                            let process_path = Self::get_process_path(pid);

                                            let event = SleepMaskingEvent {
                                                masking_type:
                                                    SleepMaskingType::MemoryPermissionCycle,
                                                pid,
                                                process_name,
                                                process_path,
                                                cmdline: Self::get_process_cmdline(pid),
                                                user: Self::get_process_user(pid),
                                                memory_address: Some(base),
                                                memory_size: Some(size),
                                                old_protection: None,
                                                new_protection: Some(prot),
                                                sleep_duration_ms: None,
                                                timer_callback: None,
                                                context_rip: None,
                                                veh_handler: None,
                                                entropy_before: None,
                                                entropy_after: Some(entropy),
                                                rop_gadgets: Vec::new(),
                                                evidence: vec![
                                                    format!(
                                                        "Permission cycling detected at 0x{:016x}",
                                                        base
                                                    ),
                                                    format!(
                                                        "Current protection: {}",
                                                        format_protection(prot)
                                                    ),
                                                    format!("Region entropy: {:.2}", entropy),
                                                ],
                                                confidence: 0.85,
                                            };

                                            let telemetry = Self::create_event(&event);
                                            pending_events.push(telemetry);

                                            info!(
                                                pid = pid,
                                                addr = format!("0x{:016x}", base),
                                                "Sleep masking detected: permission cycling"
                                            );
                                        }
                                    }

                                    // Detect entropy fluctuation
                                    if let Some((min_e, max_e)) = history
                                        .has_entropy_fluctuation(2.0, Duration::from_secs(60))
                                    {
                                        let key = (pid, base | 0x8000000000000000); // Different key for entropy detection
                                        let mut r = reported.write();
                                        if !r.contains(&key) {
                                            r.insert(key);

                                            let process_name = Self::get_process_name(pid);
                                            let process_path = Self::get_process_path(pid);

                                            let event = SleepMaskingEvent {
                                                masking_type: SleepMaskingType::EntropyFluctuation,
                                                pid,
                                                process_name,
                                                process_path,
                                                cmdline: Self::get_process_cmdline(pid),
                                                user: Self::get_process_user(pid),
                                                memory_address: Some(base),
                                                memory_size: Some(size),
                                                old_protection: None,
                                                new_protection: Some(prot),
                                                sleep_duration_ms: None,
                                                timer_callback: None,
                                                context_rip: None,
                                                veh_handler: None,
                                                entropy_before: Some(min_e),
                                                entropy_after: Some(max_e),
                                                rop_gadgets: Vec::new(),
                                                evidence: vec![
                                                    format!(
                                                        "Entropy fluctuation: {:.2} -> {:.2}",
                                                        min_e, max_e
                                                    ),
                                                    format!("Region: 0x{:016x}", base),
                                                    "Possible encryption/decryption during sleep"
                                                        .to_string(),
                                                ],
                                                confidence: 0.75,
                                            };

                                            let telemetry = Self::create_event(&event);
                                            pending_events.push(telemetry);

                                            info!(
                                                pid = pid,
                                                addr = format!("0x{:016x}", base),
                                                min_entropy = min_e,
                                                max_entropy = max_e,
                                                "Sleep masking detected: entropy fluctuation"
                                            );
                                        }
                                    }
                                }
                            }
                        }

                        address = (mbi.BaseAddress as usize) + mbi.RegionSize;
                        if address == 0 {
                            break;
                        }
                    }

                    unsafe {
                        let _ = CloseHandle(handle);
                    }
                }

                for telemetry in pending_events {
                    if tx.send(telemetry).await.is_err() {
                        error!("Failed to send sleep masking event");
                        return;
                    }
                }
            }
        }
    }

    // ========================================================================
    // Linux Monitoring Implementation
    // ========================================================================

    #[cfg(target_os = "linux")]
    async fn linux_monitor_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        trackers: Arc<RwLock<HashMap<u32, ProcessSleepTracker>>>,
        reported: Arc<RwLock<HashSet<(u32, u64)>>>,
    ) {
        use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};

        let mut interval = tokio::time::interval(Duration::from_secs(5));
        let mut last_gc = Instant::now();

        loop {
            interval.tick().await;

            // GC old data periodically
            if last_gc.elapsed() > Duration::from_secs(60) {
                let mut t = trackers.write();
                for tracker in t.values_mut() {
                    tracker.gc(Duration::from_secs(300));
                }

                let mut r = reported.write();
                if r.len() > 10000 {
                    r.clear();
                }
                last_gc = Instant::now();
            }

            // Enumerate processes from /proc
            let proc_dir = match std::fs::read_dir("/proc") {
                Ok(d) => d,
                Err(e) => {
                    warn!(error = %e, "Failed to read /proc for sleep masking detection");
                    continue;
                }
            };

            for entry in proc_dir.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();

                // Skip non-PID entries
                let pid: u32 = match name_str.parse() {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                // Skip our own process
                if pid == std::process::id() {
                    continue;
                }

                // Parse /proc/[pid]/maps for memory regions
                let maps_path = format!("/proc/{}/maps", pid);
                let maps_file = match std::fs::File::open(&maps_path) {
                    Ok(f) => f,
                    Err(_) => continue,
                };

                let reader = BufReader::new(maps_file);
                let mem_path = format!("/proc/{}/mem", pid);
                let mut mem_file = std::fs::File::open(&mem_path).ok();

                for line in reader.lines().flatten() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() < 2 {
                        continue;
                    }

                    // Parse address range
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
                    let size = end - start;

                    // Parse permissions
                    let perms = parts[1];
                    let is_read = perms.contains('r');
                    let is_write = perms.contains('w');
                    let is_exec = perms.contains('x');
                    let is_private = perms.contains('p');

                    // Convert to Windows-style protection flags for consistency
                    let prot = if is_read && is_write && is_exec {
                        PAGE_EXECUTE_READWRITE
                    } else if is_read && is_exec {
                        PAGE_EXECUTE_READ
                    } else if is_exec {
                        PAGE_EXECUTE
                    } else if is_read && is_write {
                        PAGE_READWRITE
                    } else if is_read {
                        PAGE_READONLY
                    } else {
                        PAGE_NOACCESS
                    };

                    // Only interested in private executable regions (anonymous)
                    let pathname = if parts.len() >= 6 { parts[5] } else { "" };
                    if !is_exec || !is_private || !pathname.is_empty() {
                        continue;
                    }

                    // Try to read memory and calculate entropy
                    let entropy = if let Some(ref mut mem) = mem_file {
                        if size > 0 && size < 10 * 1024 * 1024 {
                            let read_size = size.min(4096) as usize;
                            if mem.seek(SeekFrom::Start(start)).is_ok() {
                                let mut buffer = vec![0u8; read_size];
                                if let Ok(bytes_read) = mem.read(&mut buffer) {
                                    if bytes_read > 0 {
                                        calculate_entropy(&buffer[..bytes_read])
                                    } else {
                                        0.0
                                    }
                                } else {
                                    0.0
                                }
                            } else {
                                0.0
                            }
                        } else {
                            0.0
                        }
                    } else {
                        0.0
                    };

                    // Update tracking
                    {
                        let mut t = trackers.write();
                        let tracker = t.entry(pid).or_insert_with(ProcessSleepTracker::new);

                        let history = tracker
                            .protection_history
                            .entry(start)
                            .or_insert_with(ProtectionHistory::new);

                        // Check for protection change
                        let last_transitions = history.transitions.back();
                        if let Some((_, _, last_prot)) = last_transitions {
                            if *last_prot != prot {
                                history.record_transition(*last_prot, prot);
                            }
                        } else {
                            history.record_transition(0, prot);
                        }

                        history.record_entropy(entropy);

                        // Detect permission cycling
                        if history.has_permission_cycling(Duration::from_secs(60)) {
                            let key = (pid, start);
                            let mut r = reported.write();
                            if !r.contains(&key) {
                                r.insert(key);
                                drop(r);
                                drop(t);

                                let process_name = Self::get_process_name(pid);
                                let process_path = Self::get_process_path(pid);

                                let event = SleepMaskingEvent {
                                    masking_type: SleepMaskingType::MemoryPermissionCycle,
                                    pid,
                                    process_name,
                                    process_path,
                                    cmdline: Self::get_process_cmdline(pid),
                                    user: Self::get_process_user(pid),
                                    memory_address: Some(start),
                                    memory_size: Some(size),
                                    old_protection: None,
                                    new_protection: Some(prot),
                                    sleep_duration_ms: None,
                                    timer_callback: None,
                                    context_rip: None,
                                    veh_handler: None,
                                    entropy_before: None,
                                    entropy_after: Some(entropy),
                                    rop_gadgets: Vec::new(),
                                    evidence: vec![
                                        format!("Permission cycling detected at 0x{:016x}", start),
                                        format!("Current protection: {}", format_protection(prot)),
                                        format!("Region entropy: {:.2}", entropy),
                                    ],
                                    confidence: 0.85,
                                };

                                let telemetry = Self::create_event(&event);
                                if tx.blocking_send(telemetry).is_err() {
                                    error!("Failed to send sleep masking event");
                                    return;
                                }

                                info!(
                                    pid = pid,
                                    addr = format!("0x{:016x}", start),
                                    "Sleep masking detected: permission cycling"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    async fn linux_monitor_loop(
        _tx: mpsc::Sender<TelemetryEvent>,
        _trackers: Arc<RwLock<HashMap<u32, ProcessSleepTracker>>>,
        _reported: Arc<RwLock<HashSet<(u32, u64)>>>,
    ) {
        // macOS implementation placeholder
        // Would use Mach APIs similar to memory.rs
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protection_flags() {
        assert!(is_rw_protection(PAGE_READWRITE));
        assert!(!is_rw_protection(PAGE_EXECUTE_READWRITE));
        assert!(is_rx_protection(PAGE_EXECUTE_READ));
        assert!(!is_rx_protection(PAGE_EXECUTE_READWRITE));
        assert!(is_rwx_protection(PAGE_EXECUTE_READWRITE));
    }

    #[test]
    fn test_protection_history_cycling() {
        let mut history = ProtectionHistory::new();

        // Simulate RW -> RX -> RW cycle
        history.record_transition(PAGE_READWRITE, PAGE_EXECUTE_READ);
        history.record_transition(PAGE_EXECUTE_READ, PAGE_READWRITE);

        assert!(history.has_permission_cycling(Duration::from_secs(60)));
        assert_eq!(history.rw_to_rx_count, 1);
        assert_eq!(history.rx_to_rw_count, 1);
    }

    #[test]
    fn test_entropy_fluctuation() {
        let mut history = ProtectionHistory::new();

        // Simulate entropy fluctuation (encryption/decryption)
        history.record_entropy(7.8); // High entropy (encrypted)
        history.record_entropy(4.5); // Low entropy (decrypted)
        history.record_entropy(7.9); // High again

        let fluctuation = history.has_entropy_fluctuation(2.0, Duration::from_secs(60));
        assert!(fluctuation.is_some());

        let (min, max) = fluctuation.unwrap();
        assert!(max - min >= 2.0);
    }

    #[test]
    fn test_sleep_masking_type_properties() {
        let ekko = SleepMaskingType::EkkoTimerQueue;
        assert_eq!(ekko.as_str(), "ekko_timer_queue");
        assert_eq!(ekko.mitre_technique(), "T1027.011");
        assert_eq!(ekko.severity(), Severity::Critical);
    }

    #[test]
    fn test_entropy_calculation() {
        // Random-ish data should have high entropy
        let high_entropy_data: Vec<u8> = (0..=255).collect();
        let entropy = calculate_entropy(&high_entropy_data);
        assert!(entropy > 7.0);

        // Uniform data should have low entropy
        let low_entropy_data = vec![0u8; 256];
        let entropy = calculate_entropy(&low_entropy_data);
        assert!(entropy < 0.1);
    }

    #[test]
    fn test_rop_gadget_detection() {
        // Buffer containing ret gadget
        let buffer = vec![0x90, 0x90, 0xC3, 0x90]; // nop nop ret nop
        let gadgets = scan_for_rop_gadgets(&buffer, 0x1000);
        assert!(!gadgets.is_empty());
        assert!(gadgets
            .iter()
            .any(|(name, addr)| name == "ret" && *addr == 0x1002));
    }

    #[test]
    fn test_process_sleep_tracker() {
        let mut tracker = ProcessSleepTracker::new();

        // Record regular beacon-like sleep calls (same duration > 1000ms repeated 5+ times)
        tracker.record_sleep(5000, 1234, "Sleep");
        tracker.record_sleep(5000, 1234, "Sleep");
        tracker.record_sleep(5000, 1234, "Sleep");
        tracker.record_sleep(5000, 1234, "Sleep");
        tracker.record_sleep(5000, 1234, "Sleep");

        // Should detect regular sleep pattern (beacon behavior)
        let anomaly = tracker.detect_sleep_anomaly(Duration::from_secs(300));
        assert!(anomaly.is_some());
        let (count, duration) = anomaly.unwrap();
        assert_eq!(count, 5);
        assert_eq!(duration, 5000);
    }
}
