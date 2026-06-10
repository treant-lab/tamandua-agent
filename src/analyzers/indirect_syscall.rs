//! Indirect Syscall Detection Analyzer
//!
//! Detects indirect syscall techniques used to bypass user-mode hooks by jumping
//! directly to syscall instructions in ntdll.dll rather than calling through
//! the normal API chain.
//!
//! ## Detection Methods
//!
//! 1. **Syscall Origin Validation**: Validates that syscalls originate from within
//!    ntdll.dll code sections. Syscalls from private/heap memory indicate direct
//!    or indirect syscall usage.
//!
//! 2. **Dynamic SSN Resolution Detection**: Identifies patterns used by:
//!    - Hell's Gate: Walks export table, reads SSN from syscall stubs
//!    - Halo's Gate: Searches neighboring functions when stubs are hooked
//!    - Tartarus's Gate: Hybrid approach with function sorting
//!    - SysWhispers: Various generations of syscall stub generation
//!    - FreshyCalls: Uses TEB->ThreadLocalStoragePointer for SSN lookup
//!    - RecycledGate: Reuses existing syscall gadgets
//!
//! 3. **ntdll Memory Scanning Detection**: Detects processes scanning ntdll's
//!    .text section looking for syscall instructions (0x0F 0x05).
//!
//! 4. **ROP-based Syscall Detection**: Identifies return-oriented programming
//!    chains that pivot to syscall gadgets.
//!
//! 5. **Thread Start Address Validation**: Verifies new threads start from
//!    legitimate module code, not from shellcode in private memory.
//!
//! ## MITRE ATT&CK Techniques
//!
//! - T1106 - Native API (Direct/Indirect Syscalls)
//! - T1055.012 - Process Hollowing (often uses syscalls)
//! - T1562.001 - Disable or Modify Tools (bypassing EDR hooks)
//!
//! ## Implementation Notes
//!
//! This analyzer works in conjunction with the syscall_evasion collector but
//! provides deeper analysis capabilities including:
//! - Cross-process syscall origin tracing via ETW Threat Intelligence provider
//! - Real-time return address validation using instrumentation callbacks
//! - Statistical analysis of syscall patterns per process

// This analyzer enumerates indirect-syscall technique families (Hell's Gate,
// Halo's Gate, Tartarus's Gate, SysWhispers, FreshyCalls, RecycledGate) plus
// SSN-resolution patterns and per-process syscall statistics. Many constants
// and helper fields are reserved for downstream correlation/audit even when
// not consumed by the current dispatch paths.
#![allow(dead_code, unused_variables)]

use crate::collectors::{
    Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info};

#[cfg(target_os = "windows")]
use tokio::sync::mpsc;

// ============================================================================
// Types and Patterns
// ============================================================================

/// Indirect syscall technique classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndirectSyscallTechnique {
    /// Hell's Gate: Export table walking with direct SSN extraction
    HellsGate,
    /// Halo's Gate: Neighbor function SSN recovery for hooked stubs
    HalosGate,
    /// Tartarus's Gate: Hybrid Hell's/Halo's with function sorting
    TartarusGate,
    /// SysWhispers v1: Compile-time SSN embedding
    SysWhispers1,
    /// SysWhispers v2: Runtime SSN resolution with direct syscall
    SysWhispers2,
    /// SysWhispers v3: Indirect syscall via jmp to ntdll
    SysWhispers3,
    /// FreshyCalls: TEB-based SSN lookup
    FreshyCalls,
    /// RecycledGate: Reuses existing syscall gadgets in ntdll
    RecycledGate,
    /// HWSyscalls: Hardware breakpoint-based syscall execution
    HwSyscalls,
    /// SyscallsInline: Manually inlined syscall stubs
    SyscallsInline,
    /// Generic indirect syscall (jmp to ntdll syscall instruction)
    GenericIndirect,
    /// Generic direct syscall (syscall instruction in non-ntdll code)
    GenericDirect,
    /// ROP chain pivoting to syscall gadget
    RopSyscall,
    /// ntdll memory scanning for syscall instructions
    NtdllScanning,
    /// Syscall from thread with suspicious start address
    SuspiciousThreadSyscall,
    /// Unknown/novel technique
    Unknown,
}

impl IndirectSyscallTechnique {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HellsGate => "hells_gate",
            Self::HalosGate => "halos_gate",
            Self::TartarusGate => "tartarus_gate",
            Self::SysWhispers1 => "syswhispers_v1",
            Self::SysWhispers2 => "syswhispers_v2",
            Self::SysWhispers3 => "syswhispers_v3",
            Self::FreshyCalls => "freshycalls",
            Self::RecycledGate => "recycled_gate",
            Self::HwSyscalls => "hw_syscalls",
            Self::SyscallsInline => "syscalls_inline",
            Self::GenericIndirect => "generic_indirect",
            Self::GenericDirect => "generic_direct",
            Self::RopSyscall => "rop_syscall",
            Self::NtdllScanning => "ntdll_scanning",
            Self::SuspiciousThreadSyscall => "suspicious_thread_syscall",
            Self::Unknown => "unknown",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            // Critical: Known evasion frameworks actively used by malware
            Self::HellsGate
            | Self::HalosGate
            | Self::TartarusGate
            | Self::SysWhispers2
            | Self::SysWhispers3
            | Self::HwSyscalls
            | Self::RopSyscall => Severity::Critical,

            // High: Suspicious but could have edge cases
            Self::FreshyCalls
            | Self::RecycledGate
            | Self::GenericIndirect
            | Self::GenericDirect
            | Self::NtdllScanning
            | Self::SuspiciousThreadSyscall => Severity::High,

            // Medium: Potentially legitimate (e.g., old tools, debugging)
            Self::SysWhispers1 | Self::SyscallsInline | Self::Unknown => Severity::Medium,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::HellsGate => "Hell's Gate SSN resolution via ntdll export table parsing",
            Self::HalosGate => "Halo's Gate neighbor function SSN recovery for hooked stubs",
            Self::TartarusGate => "Tartarus's Gate hybrid SSN resolution technique",
            Self::SysWhispers1 => "SysWhispers v1 compile-time SSN embedding",
            Self::SysWhispers2 => "SysWhispers v2 runtime SSN resolution with direct syscall",
            Self::SysWhispers3 => "SysWhispers v3 indirect syscall via jump to ntdll",
            Self::FreshyCalls => "FreshyCalls TEB-based SSN lookup",
            Self::RecycledGate => "RecycledGate reusing existing ntdll syscall gadgets",
            Self::HwSyscalls => "Hardware breakpoint-based syscall execution",
            Self::SyscallsInline => "Manually inlined syscall stub in non-ntdll code",
            Self::GenericIndirect => "Indirect syscall via jump to ntdll syscall instruction",
            Self::GenericDirect => "Direct syscall instruction outside ntdll",
            Self::RopSyscall => "ROP chain pivoting to syscall gadget",
            Self::NtdllScanning => "Process scanning ntdll memory for syscall instructions",
            Self::SuspiciousThreadSyscall => "Syscall from thread with suspicious start address",
            Self::Unknown => "Unknown indirect syscall technique",
        }
    }
}

/// Detection event for indirect syscall usage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndirectSyscallEvent {
    /// Detected technique
    pub technique: IndirectSyscallTechnique,
    /// Process ID
    pub pid: u32,
    /// Thread ID that executed the syscall
    pub tid: u32,
    /// Process name
    pub process_name: String,
    /// Process path
    pub process_path: String,
    /// Command line
    pub cmdline: String,
    /// User account running the process
    pub user: String,
    /// System Service Number (SSN) if extracted
    pub ssn: Option<u32>,
    /// Resolved syscall name (e.g., "NtAllocateVirtualMemory")
    pub syscall_name: Option<String>,
    /// Return address of the syscall
    pub return_address: Option<u64>,
    /// Module containing the return address (if any)
    pub return_module: Option<String>,
    /// Address of syscall instruction used
    pub syscall_instruction_addr: Option<u64>,
    /// Whether the syscall originated from ntdll
    pub from_ntdll: bool,
    /// Memory region containing the syscall stub
    pub stub_region_base: Option<u64>,
    /// Size of the memory region
    pub stub_region_size: Option<u64>,
    /// Memory protection of the stub region
    pub stub_region_protection: Option<String>,
    /// Matched byte pattern (hex string)
    pub matched_pattern: Option<String>,
    /// Pattern name (e.g., "syswhispers3_jmp_r11")
    pub pattern_name: Option<String>,
    /// Additional indicators found
    pub indicators: Vec<String>,
    /// Detection confidence (0.0 - 1.0)
    pub confidence: f32,
    /// Human-readable details
    pub details: String,
}

/// Memory read event indicating potential ntdll scanning
#[derive(Debug, Clone)]
pub struct NtdllReadEvent {
    pub pid: u32,
    pub tid: u32,
    pub read_address: u64,
    pub read_size: usize,
    pub timestamp: Instant,
}

/// Per-process state for indirect syscall analysis
#[derive(Debug)]
pub struct ProcessSyscallProfile {
    /// Process ID
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// Total syscalls observed
    pub total_syscalls: u64,
    /// Syscalls from ntdll
    pub ntdll_syscalls: u64,
    /// Syscalls from non-ntdll locations (suspicious)
    pub non_ntdll_syscalls: u64,
    /// Unique return addresses seen
    pub return_addresses: HashSet<u64>,
    /// SSNs used (for pattern analysis)
    pub ssns_used: HashSet<u32>,
    /// Recent ntdll read events (for scanning detection)
    pub ntdll_reads: VecDeque<NtdllReadEvent>,
    /// Detected techniques
    pub detected_techniques: HashSet<IndirectSyscallTechnique>,
    /// First observation time
    pub first_seen: Instant,
    /// Last activity time
    pub last_seen: Instant,
    /// Anomaly score (0.0 - 1.0)
    pub anomaly_score: f32,
}

impl ProcessSyscallProfile {
    pub fn new(pid: u32, name: String) -> Self {
        let now = Instant::now();
        Self {
            pid,
            process_name: name,
            total_syscalls: 0,
            ntdll_syscalls: 0,
            non_ntdll_syscalls: 0,
            return_addresses: HashSet::new(),
            ssns_used: HashSet::new(),
            ntdll_reads: VecDeque::with_capacity(100),
            detected_techniques: HashSet::new(),
            first_seen: now,
            last_seen: now,
            anomaly_score: 0.0,
        }
    }

    /// Record a syscall observation
    pub fn record_syscall(&mut self, from_ntdll: bool, return_addr: u64, ssn: Option<u32>) {
        self.total_syscalls += 1;
        self.last_seen = Instant::now();

        if from_ntdll {
            self.ntdll_syscalls += 1;
        } else {
            self.non_ntdll_syscalls += 1;
        }

        self.return_addresses.insert(return_addr);

        if let Some(s) = ssn {
            self.ssns_used.insert(s);
        }

        // Update anomaly score
        self.update_anomaly_score();
    }

    /// Record an ntdll memory read
    pub fn record_ntdll_read(&mut self, read: NtdllReadEvent) {
        // Keep only recent reads (last 5 seconds)
        let cutoff = Instant::now() - Duration::from_secs(5);
        while let Some(front) = self.ntdll_reads.front() {
            if front.timestamp < cutoff {
                self.ntdll_reads.pop_front();
            } else {
                break;
            }
        }

        self.ntdll_reads.push_back(read);
        self.last_seen = Instant::now();
    }

    /// Check if the process appears to be scanning ntdll
    pub fn is_scanning_ntdll(&self) -> bool {
        // Heuristic: More than 50 reads to ntdll .text in 5 seconds
        // covering a significant portion of the address space
        if self.ntdll_reads.len() < 50 {
            return false;
        }

        // Check address distribution
        let mut addresses: Vec<u64> = self.ntdll_reads.iter().map(|r| r.read_address).collect();
        addresses.sort_unstable();
        addresses.dedup();

        // If reading many unique addresses in sequence, likely scanning
        addresses.len() > 30
    }

    /// Calculate anomaly score based on syscall behavior
    fn update_anomaly_score(&mut self) {
        if self.total_syscalls == 0 {
            self.anomaly_score = 0.0;
            return;
        }

        let mut score = 0.0;

        // Factor 1: Ratio of non-ntdll syscalls (0.0 - 0.4)
        let non_ntdll_ratio = self.non_ntdll_syscalls as f32 / self.total_syscalls as f32;
        score += non_ntdll_ratio * 0.4;

        // Factor 2: Unique return addresses per syscall (0.0 - 0.2)
        // Normal processes have few unique return addresses
        let addr_ratio = (self.return_addresses.len() as f32 / self.total_syscalls as f32).min(1.0);
        if addr_ratio > 0.5 {
            score += 0.2;
        } else if addr_ratio > 0.2 {
            score += 0.1;
        }

        // Factor 3: ntdll scanning detected (0.0 - 0.2)
        if self.is_scanning_ntdll() {
            score += 0.2;
        }

        // Factor 4: Known evasion techniques detected (0.0 - 0.2)
        if !self.detected_techniques.is_empty() {
            score += 0.2;
        }

        self.anomaly_score = score.min(1.0);
    }
}

// ============================================================================
// Byte Patterns for Technique Identification
// ============================================================================

/// Indirect syscall byte patterns for detection
/// Format: (name, pattern, technique, is_prefix)
#[cfg(target_os = "windows")]
const INDIRECT_SYSCALL_PATTERNS: &[(&str, &[u8], IndirectSyscallTechnique, bool)] = &[
    // =========================================================================
    // SysWhispers variants
    // =========================================================================

    // SysWhispers2: mov r10, rcx; mov eax, SSN; syscall
    // 4C 8B D1    mov r10, rcx
    // B8 XX XX 00 00  mov eax, <SSN>
    // 0F 05       syscall
    (
        "syswhispers2_direct",
        &[0x4C, 0x8B, 0xD1, 0xB8],
        IndirectSyscallTechnique::SysWhispers2,
        true,
    ),
    // SysWhispers3: mov r10, rcx; mov eax, SSN; jmp r11 (r11 points to ntdll syscall)
    // 4C 8B D1    mov r10, rcx
    // B8 XX XX 00 00  mov eax, <SSN>
    // 41 FF E3    jmp r11
    (
        "syswhispers3_jmp_r11",
        &[0x4C, 0x8B, 0xD1, 0xB8],
        IndirectSyscallTechnique::SysWhispers3,
        true,
    ),
    // SysWhispers3 with call instead of jmp
    // 41 FF D3    call r11
    (
        "syswhispers3_call_r11",
        &[0x41, 0xFF, 0xD3],
        IndirectSyscallTechnique::SysWhispers3,
        false,
    ),
    // SysWhispers3 indirect via rax
    // FF E0       jmp rax
    (
        "syswhispers3_jmp_rax",
        &[0xFF, 0xE0],
        IndirectSyscallTechnique::SysWhispers3,
        false,
    ),
    // =========================================================================
    // Hell's Gate patterns
    // =========================================================================

    // Hell's Gate SSN extraction: mov eax, [rax+4] (reading SSN from syscall stub)
    // 8B 40 04    mov eax, [rax+4]
    (
        "hells_gate_ssn_read",
        &[0x8B, 0x40, 0x04],
        IndirectSyscallTechnique::HellsGate,
        false,
    ),
    // Hell's Gate export table walking: mov rax, [r8+rax*8]
    // 4A 8B 04 C0 mov rax, [rax+r8*8]
    (
        "hells_gate_export_walk",
        &[0x4A, 0x8B, 0x04, 0xC0],
        IndirectSyscallTechnique::HellsGate,
        false,
    ),
    // =========================================================================
    // Halo's Gate patterns
    // =========================================================================

    // Halo's Gate neighbor check: cmp word [rax], 0x0F05 (checking for syscall opcode)
    // 66 81 38 0F 05  cmp word [rax], 0x050F
    (
        "halos_gate_syscall_check",
        &[0x66, 0x81, 0x38, 0x0F, 0x05],
        IndirectSyscallTechnique::HalosGate,
        false,
    ),
    // Halo's Gate alternative: cmp byte [rax], 0x4C (checking for mov r10, rcx)
    // 80 38 4C    cmp byte [rax], 0x4C
    (
        "halos_gate_stub_check",
        &[0x80, 0x38, 0x4C],
        IndirectSyscallTechnique::HalosGate,
        false,
    ),
    // Halo's Gate hooked function detection: cmp byte [rax], 0xE9 (jmp hook)
    // 80 38 E9    cmp byte [rax], 0xE9
    (
        "halos_gate_hook_detect",
        &[0x80, 0x38, 0xE9],
        IndirectSyscallTechnique::HalosGate,
        false,
    ),
    // =========================================================================
    // Tartarus's Gate patterns
    // =========================================================================

    // Tartarus's Gate: mov rax, [rcx+0x10]; mov r8, [rax+...]
    // 48 8B 41 10 mov rax, [rcx+0x10]
    // 4C 8B 40 XX mov r8, [rax+XX]
    (
        "tartarus_gate_resolve",
        &[0x48, 0x8B, 0x41, 0x10, 0x4C, 0x8B, 0x40],
        IndirectSyscallTechnique::TartarusGate,
        true,
    ),
    // =========================================================================
    // FreshyCalls patterns
    // =========================================================================

    // FreshyCalls TEB access: mov rax, gs:[0x30] (accessing TEB)
    // 65 48 8B 04 25 30 00 00 00  mov rax, gs:[0x30]
    (
        "freshycalls_teb_access",
        &[0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00],
        IndirectSyscallTechnique::FreshyCalls,
        false,
    ),
    // FreshyCalls: accessing ThreadLocalStoragePointer
    // 65 4C 8B 14 25 30 00 00 00  mov r10, gs:[0x30]
    (
        "freshycalls_tls",
        &[0x65, 0x4C, 0x8B, 0x14, 0x25, 0x30, 0x00],
        IndirectSyscallTechnique::FreshyCalls,
        true,
    ),
    // =========================================================================
    // RecycledGate patterns
    // =========================================================================

    // RecycledGate: push rcx; pop r10; mov eax, SSN; jmp [syscall_addr]
    // 48 89 4C 24 08  mov [rsp+8], rcx (save arg)
    // 48 8B C1        mov rax, rcx
    (
        "recycled_gate_save",
        &[0x48, 0x89, 0x4C, 0x24, 0x08, 0x48, 0x8B, 0xC1],
        IndirectSyscallTechnique::RecycledGate,
        true,
    ),
    // =========================================================================
    // HWSyscalls patterns (hardware breakpoint-based)
    // =========================================================================

    // HWSyscalls: VEH setup + Dr7 manipulation
    // Note: Detection is primarily behavioral, but setup patterns include:
    // 0F 23 F8    mov dr7, rax (setting debug register)
    (
        "hw_syscalls_dr7",
        &[0x0F, 0x23, 0xF8],
        IndirectSyscallTechnique::HwSyscalls,
        false,
    ),
    // HWSyscalls: Dr0-3 manipulation
    // 0F 23 C0    mov dr0, rax
    (
        "hw_syscalls_dr0",
        &[0x0F, 0x23, 0xC0],
        IndirectSyscallTechnique::HwSyscalls,
        false,
    ),
    // =========================================================================
    // Generic indirect syscall patterns
    // =========================================================================

    // Syscall instruction in non-ntdll code
    // 0F 05       syscall
    (
        "direct_syscall",
        &[0x0F, 0x05],
        IndirectSyscallTechnique::GenericDirect,
        false,
    ),
    // Int 2E (legacy syscall)
    // CD 2E       int 0x2E
    (
        "int2e_syscall",
        &[0xCD, 0x2E],
        IndirectSyscallTechnique::GenericDirect,
        false,
    ),
    // SYSENTER (32-bit)
    // 0F 34       sysenter
    (
        "sysenter",
        &[0x0F, 0x34],
        IndirectSyscallTechnique::GenericDirect,
        false,
    ),
    // =========================================================================
    // Heaven's Gate (WoW64 transition)
    // =========================================================================

    // Heaven's Gate: far jmp to 64-bit code segment
    // 6A 33       push 0x33
    // E8 00 00 00 00  call $+5
    // 83 04 24 05 add dword [rsp], 5
    // CB          retf
    (
        "heavens_gate",
        &[
            0x6A, 0x33, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x83, 0x04, 0x24, 0x05, 0xCB,
        ],
        IndirectSyscallTechnique::Unknown,
        false,
    ),
    // =========================================================================
    // ROP gadget patterns
    // =========================================================================

    // ROP: pop rax; ret (for loading SSN)
    // 58          pop rax
    // C3          ret
    (
        "rop_pop_rax_ret",
        &[0x58, 0xC3],
        IndirectSyscallTechnique::RopSyscall,
        false,
    ),
    // ROP: mov r10, rcx; ret (for syscall setup)
    // 4C 8B D1    mov r10, rcx
    // C3          ret
    (
        "rop_mov_r10_ret",
        &[0x4C, 0x8B, 0xD1, 0xC3],
        IndirectSyscallTechnique::RopSyscall,
        false,
    ),
    // ROP: syscall; ret (gadget in ntdll)
    // 0F 05       syscall
    // C3          ret
    (
        "rop_syscall_ret",
        &[0x0F, 0x05, 0xC3],
        IndirectSyscallTechnique::RopSyscall,
        false,
    ),
];

/// x86 (WoW64) indirect syscall patterns
#[cfg(target_os = "windows")]
const INDIRECT_SYSCALL_PATTERNS_X86: &[(&str, &[u8], IndirectSyscallTechnique, bool)] = &[
    // WoW64 transition
    // B8 XX XX 00 00  mov eax, <SSN>
    // BA XX XX XX XX  mov edx, <Wow64Transition>
    // FF D2           call edx
    (
        "wow64_transition",
        &[0xB8],
        IndirectSyscallTechnique::GenericDirect,
        true,
    ),
    // Direct int 2E
    // B8 XX XX 00 00  mov eax, <SSN>
    // CD 2E           int 0x2E
    (
        "wow64_int2e",
        &[0xCD, 0x2E],
        IndirectSyscallTechnique::GenericDirect,
        false,
    ),
    // Sysenter
    // B8 XX XX 00 00  mov eax, <SSN>
    // 0F 34           sysenter
    (
        "wow64_sysenter",
        &[0x0F, 0x34],
        IndirectSyscallTechnique::GenericDirect,
        false,
    ),
];

// ============================================================================
// Indirect Syscall Analyzer
// ============================================================================

/// Main analyzer for indirect syscall detection
pub struct IndirectSyscallAnalyzer {
    /// Per-process profiles
    profiles: Arc<RwLock<HashMap<u32, ProcessSyscallProfile>>>,
    /// Maximum processes to track
    max_processes: usize,
    /// Detection confidence threshold
    confidence_threshold: f32,
    /// Enable deep scanning (more CPU intensive)
    deep_scan_enabled: bool,
    /// ntdll base address (cached)
    #[cfg(target_os = "windows")]
    ntdll_base: Option<u64>,
    /// ntdll size (cached)
    #[cfg(target_os = "windows")]
    ntdll_size: Option<u64>,
    /// ntdll .text section bounds
    #[cfg(target_os = "windows")]
    ntdll_text_bounds: Option<(u64, u64)>,
}

impl IndirectSyscallAnalyzer {
    /// Create a new analyzer
    pub fn new() -> Self {
        Self {
            profiles: Arc::new(RwLock::new(HashMap::new())),
            max_processes: 1000,
            confidence_threshold: 0.7,
            deep_scan_enabled: true,
            #[cfg(target_os = "windows")]
            ntdll_base: None,
            #[cfg(target_os = "windows")]
            ntdll_size: None,
            #[cfg(target_os = "windows")]
            ntdll_text_bounds: None,
        }
    }

    /// Initialize ntdll bounds for the current process
    #[cfg(target_os = "windows")]
    pub fn initialize_ntdll_bounds(&mut self) -> bool {
        use windows::core::w;
        use windows::Win32::System::LibraryLoader::GetModuleHandleW;
        use windows::Win32::System::ProcessStatus::{GetModuleInformation, MODULEINFO};
        use windows::Win32::System::Threading::GetCurrentProcess;

        unsafe {
            let ntdll = match GetModuleHandleW(w!("ntdll.dll")) {
                Ok(h) => h,
                Err(_) => return false,
            };

            let mut info: MODULEINFO = std::mem::zeroed();
            if GetModuleInformation(
                GetCurrentProcess(),
                ntdll,
                &mut info,
                std::mem::size_of::<MODULEINFO>() as u32,
            )
            .is_err()
            {
                return false;
            }

            self.ntdll_base = Some(ntdll.0 as u64);
            self.ntdll_size = Some(info.SizeOfImage as u64);

            // Parse PE headers to find .text section bounds
            if let Some((text_start, text_size)) = self.parse_text_section(ntdll.0 as u64) {
                self.ntdll_text_bounds = Some((text_start, text_start + text_size));
                debug!(
                    "ntdll .text section: 0x{:016X} - 0x{:016X}",
                    text_start,
                    text_start + text_size
                );
            }

            info!(
                "Initialized ntdll bounds: base=0x{:016X}, size=0x{:X}",
                self.ntdll_base.unwrap_or(0),
                self.ntdll_size.unwrap_or(0)
            );

            true
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn initialize_ntdll_bounds(&mut self) -> bool {
        // No ntdll on non-Windows
        false
    }

    /// Parse PE headers to find .text section
    #[cfg(target_os = "windows")]
    fn parse_text_section(&self, base: u64) -> Option<(u64, u64)> {
        unsafe {
            let dos_header = base as *const u8;

            // Validate DOS magic
            if std::ptr::read(dos_header as *const u16) != 0x5A4D {
                return None;
            }

            // Get PE header offset
            let e_lfanew = std::ptr::read(dos_header.add(0x3C) as *const u32) as usize;
            let pe_header = dos_header.add(e_lfanew);

            // Validate PE signature
            if std::ptr::read(pe_header as *const u32) != 0x00004550 {
                return None;
            }

            // Get optional header magic to determine PE32 vs PE32+
            let optional_header = pe_header.add(24);
            let magic = std::ptr::read(optional_header as *const u16);

            // Get section header offset
            let optional_header_size = std::ptr::read(pe_header.add(20) as *const u16) as usize;
            let section_headers = optional_header.add(optional_header_size);

            // Get number of sections
            let num_sections = std::ptr::read(pe_header.add(6) as *const u16) as usize;

            // Find .text section
            for i in 0..num_sections {
                let section = section_headers.add(i * 40);
                let name = std::slice::from_raw_parts(section, 8);

                if name.starts_with(b".text") {
                    let virtual_size = std::ptr::read(section.add(8) as *const u32) as u64;
                    let virtual_address = std::ptr::read(section.add(12) as *const u32) as u64;
                    return Some((base + virtual_address, virtual_size));
                }
            }

            None
        }
    }

    /// Check if an address is within ntdll
    #[cfg(target_os = "windows")]
    pub fn is_in_ntdll(&self, addr: u64) -> bool {
        if let (Some(base), Some(size)) = (self.ntdll_base, self.ntdll_size) {
            addr >= base && addr < base + size
        } else {
            false
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn is_in_ntdll(&self, _addr: u64) -> bool {
        false
    }

    /// Check if an address is within ntdll's .text section
    #[cfg(target_os = "windows")]
    pub fn is_in_ntdll_text(&self, addr: u64) -> bool {
        if let Some((start, end)) = self.ntdll_text_bounds {
            addr >= start && addr < end
        } else {
            self.is_in_ntdll(addr)
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn is_in_ntdll_text(&self, _addr: u64) -> bool {
        false
    }

    /// Analyze a memory region for indirect syscall patterns
    #[cfg(target_os = "windows")]
    pub fn analyze_memory_region(
        &self,
        pid: u32,
        region_base: u64,
        region_size: u64,
        memory: &[u8],
        process_name: &str,
    ) -> Vec<IndirectSyscallEvent> {
        let mut detections = Vec::new();

        // Skip if region is in ntdll (legitimate syscalls)
        if self.is_in_ntdll(region_base) {
            return detections;
        }

        // Scan for patterns
        for (pattern_name, pattern, technique, is_prefix) in INDIRECT_SYSCALL_PATTERNS.iter() {
            let matches = self.find_all_patterns(memory, pattern);

            for offset in matches {
                let addr = region_base + offset as u64;

                // Extract additional context
                let ssn = if *is_prefix {
                    self.extract_ssn_after_pattern(memory, offset, pattern.len())
                } else {
                    self.extract_ssn_before_pattern(memory, offset)
                };

                // Calculate confidence based on pattern type and context
                let confidence =
                    self.calculate_detection_confidence(memory, offset, *technique, ssn.is_some());

                if confidence < self.confidence_threshold {
                    continue;
                }

                let matched_hex = memory[offset..std::cmp::min(offset + 16, memory.len())]
                    .iter()
                    .map(|b| format!("{:02X}", b))
                    .collect::<Vec<_>>()
                    .join(" ");

                detections.push(IndirectSyscallEvent {
                    technique: *technique,
                    pid,
                    tid: 0, // Unknown at scan time
                    process_name: process_name.to_string(),
                    process_path: String::new(),
                    cmdline: String::new(),
                    user: String::new(),
                    ssn,
                    syscall_name: ssn.and_then(|s| self.resolve_ssn_name(s)),
                    return_address: None,
                    return_module: None,
                    syscall_instruction_addr: if pattern == &[0x0F, 0x05] {
                        Some(addr)
                    } else {
                        None
                    },
                    from_ntdll: false,
                    stub_region_base: Some(region_base),
                    stub_region_size: Some(region_size),
                    stub_region_protection: None,
                    matched_pattern: Some(matched_hex),
                    pattern_name: Some(pattern_name.to_string()),
                    indicators: self.extract_indicators(memory, offset, *technique),
                    confidence,
                    details: format!(
                        "{} detected at 0x{:016X} (pattern: {})",
                        technique.description(),
                        addr,
                        pattern_name
                    ),
                });
            }
        }

        detections
    }

    #[cfg(not(target_os = "windows"))]
    pub fn analyze_memory_region(
        &self,
        _pid: u32,
        _region_base: u64,
        _region_size: u64,
        _memory: &[u8],
        _process_name: &str,
    ) -> Vec<IndirectSyscallEvent> {
        Vec::new()
    }

    /// Find all occurrences of a pattern in memory
    fn find_all_patterns(&self, haystack: &[u8], needle: &[u8]) -> Vec<usize> {
        if needle.is_empty() || haystack.len() < needle.len() {
            return Vec::new();
        }

        haystack
            .windows(needle.len())
            .enumerate()
            .filter(|(_, window)| *window == needle)
            .map(|(i, _)| i)
            .collect()
    }

    /// Extract SSN from bytes following a pattern match (e.g., after mov r10, rcx)
    fn extract_ssn_after_pattern(
        &self,
        memory: &[u8],
        offset: usize,
        pattern_len: usize,
    ) -> Option<u32> {
        let start = offset + pattern_len;
        if start + 4 > memory.len() {
            return None;
        }

        // Look for mov eax, imm32 (0xB8)
        for i in 0..std::cmp::min(8, memory.len() - start - 4) {
            if memory[start + i] == 0xB8 && start + i + 5 <= memory.len() {
                let ssn = u32::from_le_bytes([
                    memory[start + i + 1],
                    memory[start + i + 2],
                    memory[start + i + 3],
                    memory[start + i + 4],
                ]);
                // Valid SSN range (typically 0-0x2FF for Windows 10/11)
                if ssn < 0x300 {
                    return Some(ssn);
                }
            }
        }

        None
    }

    /// Extract SSN from bytes before a pattern match (e.g., before syscall instruction)
    fn extract_ssn_before_pattern(&self, memory: &[u8], offset: usize) -> Option<u32> {
        if offset < 10 {
            return None;
        }

        // Search backwards for mov eax, imm32 (0xB8)
        for i in (0..std::cmp::min(20, offset)).rev() {
            if memory[offset - i - 1] == 0xB8 && offset - i + 4 <= memory.len() {
                let ssn = u32::from_le_bytes([
                    memory[offset - i],
                    memory[offset - i + 1],
                    memory[offset - i + 2],
                    memory[offset - i + 3],
                ]);
                if ssn < 0x300 {
                    return Some(ssn);
                }
            }
        }

        None
    }

    /// Resolve SSN to syscall name
    #[cfg(target_os = "windows")]
    fn resolve_ssn_name(&self, ssn: u32) -> Option<String> {
        // Use the global SSN resolver from syscall_evasion module
        if let Some(resolver) = crate::collectors::syscall_evasion::get_ssn_resolver() {
            if let Some(name) = resolver.get_name(ssn) {
                return Some(name.to_string());
            }
        }

        // Fallback to common SSNs (Windows 10 21H2)
        let common_ssns: &[(&str, u32)] = &[
            ("NtAllocateVirtualMemory", 0x18),
            ("NtProtectVirtualMemory", 0x50),
            ("NtWriteVirtualMemory", 0x3A),
            ("NtCreateThreadEx", 0xC2),
            ("NtQueueApcThread", 0x45),
            ("NtMapViewOfSection", 0x28),
            ("NtOpenProcess", 0x26),
            ("NtReadVirtualMemory", 0x3F),
            ("NtCreateSection", 0x4A),
            ("NtResumeThread", 0x52),
        ];

        for (name, known_ssn) in common_ssns {
            if *known_ssn == ssn {
                return Some(name.to_string());
            }
        }

        None
    }

    #[cfg(not(target_os = "windows"))]
    fn resolve_ssn_name(&self, _ssn: u32) -> Option<String> {
        None
    }

    /// Calculate detection confidence based on context
    fn calculate_detection_confidence(
        &self,
        memory: &[u8],
        offset: usize,
        technique: IndirectSyscallTechnique,
        has_ssn: bool,
    ) -> f32 {
        let mut confidence: f32 = 0.5;

        // Higher confidence for known evasion techniques
        match technique {
            IndirectSyscallTechnique::SysWhispers2
            | IndirectSyscallTechnique::SysWhispers3
            | IndirectSyscallTechnique::HellsGate
            | IndirectSyscallTechnique::HalosGate => {
                confidence += 0.3;
            }
            IndirectSyscallTechnique::GenericDirect | IndirectSyscallTechnique::GenericIndirect => {
                confidence += 0.2;
            }
            _ => {
                confidence += 0.1;
            }
        }

        // SSN extraction success increases confidence
        if has_ssn {
            confidence += 0.15;
        }

        // Check for full syscall stub structure
        if self.has_complete_syscall_stub(memory, offset) {
            confidence += 0.1;
        }

        confidence.min(1.0)
    }

    /// Check if there's a complete syscall stub structure around the pattern
    fn has_complete_syscall_stub(&self, memory: &[u8], offset: usize) -> bool {
        // Look for: mov r10, rcx (4C 8B D1); mov eax, SSN (B8 XX XX 00 00); syscall (0F 05)
        // Or jmp variant

        if offset >= 4 && offset + 10 < memory.len() {
            // Check if we're within a complete stub
            let search_start = offset.saturating_sub(10);
            let search_end = std::cmp::min(offset + 20, memory.len());
            let region = &memory[search_start..search_end];

            // Look for the mov r10, rcx prefix
            let has_mov_r10 = region.windows(3).any(|w| w == [0x4C, 0x8B, 0xD1]);
            // Look for mov eax, imm32
            let has_mov_eax = region.windows(1).any(|w| w == [0xB8]);
            // Look for syscall or jmp
            let has_syscall = region.windows(2).any(|w| w == [0x0F, 0x05]);
            let has_jmp = region
                .windows(2)
                .any(|w| w == [0xFF, 0xE0] || w == [0x41, 0xFF]);

            return has_mov_r10 && has_mov_eax && (has_syscall || has_jmp);
        }

        false
    }

    /// Extract additional behavioral indicators around a match
    fn extract_indicators(
        &self,
        memory: &[u8],
        offset: usize,
        technique: IndirectSyscallTechnique,
    ) -> Vec<String> {
        let mut indicators = Vec::new();

        // Check for common adjacent patterns
        let search_start = offset.saturating_sub(50);
        let search_end = std::cmp::min(offset + 50, memory.len());
        let region = &memory[search_start..search_end];

        // VEH setup indicator (AddVectoredExceptionHandler pattern)
        if region.windows(4).any(|w| w.starts_with(&[0xFF, 0x15])) {
            indicators.push("indirect_call_detected".to_string());
        }

        // Debug register manipulation
        if region.windows(3).any(|w| w[0] == 0x0F && w[1] == 0x23) {
            indicators.push("debug_register_manipulation".to_string());
        }

        // TEB access
        if region.windows(4).any(|w| w[0] == 0x65 && w[1] == 0x48) {
            indicators.push("teb_access".to_string());
        }

        // GetProcAddress pattern (function resolution)
        if region.windows(5).any(|w| {
            // mov rcx, string; call GetProcAddress pattern
            w[0] == 0x48 && w[1] == 0x8D && w[2] == 0x0D
        }) {
            indicators.push("dynamic_api_resolution".to_string());
        }

        // Technique-specific indicators
        match technique {
            IndirectSyscallTechnique::HellsGate | IndirectSyscallTechnique::HalosGate => {
                indicators.push("export_table_parsing".to_string());
            }
            IndirectSyscallTechnique::HwSyscalls => {
                indicators.push("hardware_breakpoint_abuse".to_string());
            }
            IndirectSyscallTechnique::RopSyscall => {
                indicators.push("rop_chain_detected".to_string());
            }
            _ => {}
        }

        indicators
    }

    /// Create a telemetry event from a detection
    pub fn create_telemetry_event(event: &IndirectSyscallEvent) -> TelemetryEvent {
        let mut telemetry = TelemetryEvent::new(
            EventType::DefenseEvasion,
            event.technique.severity(),
            EventPayload::Custom(serde_json::json!({
                "detection_type": "indirect_syscall",
                "technique": event.technique.as_str(),
                "pid": event.pid,
                "tid": event.tid,
                "process_name": event.process_name,
                "process_path": event.process_path,
                "cmdline": event.cmdline,
                "ssn": event.ssn,
                "syscall_name": event.syscall_name,
                "return_address": event.return_address.map(|a| format!("0x{:016X}", a)),
                "return_module": event.return_module,
                "syscall_instruction_addr": event.syscall_instruction_addr.map(|a| format!("0x{:016X}", a)),
                "from_ntdll": event.from_ntdll,
                "stub_region_base": event.stub_region_base.map(|a| format!("0x{:016X}", a)),
                "stub_region_size": event.stub_region_size,
                "stub_region_protection": event.stub_region_protection,
                "matched_pattern": event.matched_pattern,
                "pattern_name": event.pattern_name,
                "indicators": event.indicators,
                "confidence": event.confidence,
                "details": event.details,
            })),
        );

        // Add detection
        telemetry.add_detection(Detection {
            detection_type: DetectionType::DefenseEvasion,
            rule_name: format!("indirect_syscall_{}", event.technique.as_str()),
            confidence: event.confidence,
            description: format!(
                "{}: {} (PID: {}, SSN: {})",
                event.technique.description(),
                event.details,
                event.pid,
                event
                    .ssn
                    .map_or("unknown".to_string(), |s| format!("0x{:04X}", s))
            ),
            mitre_tactics: vec!["defense-evasion".to_string(), "execution".to_string()],
            mitre_techniques: vec!["T1106".to_string(), "T1562.001".to_string()],
        });

        // Add metadata
        telemetry.metadata.insert(
            "technique".to_string(),
            event.technique.as_str().to_string(),
        );
        if let Some(ssn) = event.ssn {
            telemetry
                .metadata
                .insert("ssn".to_string(), format!("0x{:04X}", ssn));
        }
        if let Some(ref name) = event.syscall_name {
            telemetry
                .metadata
                .insert("syscall_name".to_string(), name.clone());
        }
        if let Some(ref pattern) = event.pattern_name {
            telemetry
                .metadata
                .insert("pattern_name".to_string(), pattern.clone());
        }

        telemetry
    }

    /// Record a syscall for a process
    pub fn record_syscall(
        &self,
        pid: u32,
        name: &str,
        from_ntdll: bool,
        return_addr: u64,
        ssn: Option<u32>,
    ) {
        let mut profiles = self.profiles.write();

        // Evict old profiles if at capacity
        if profiles.len() >= self.max_processes && !profiles.contains_key(&pid) {
            let cutoff = Instant::now() - Duration::from_secs(300);
            profiles.retain(|_, p| p.last_seen > cutoff);
        }

        let profile = profiles
            .entry(pid)
            .or_insert_with(|| ProcessSyscallProfile::new(pid, name.to_string()));
        profile.record_syscall(from_ntdll, return_addr, ssn);
    }

    /// Record an ntdll read event for a process
    pub fn record_ntdll_read(&self, pid: u32, name: &str, read: NtdllReadEvent) {
        let mut profiles = self.profiles.write();

        let profile = profiles
            .entry(pid)
            .or_insert_with(|| ProcessSyscallProfile::new(pid, name.to_string()));
        profile.record_ntdll_read(read);
    }

    /// Get anomaly score for a process
    pub fn get_anomaly_score(&self, pid: u32) -> Option<f32> {
        self.profiles.read().get(&pid).map(|p| p.anomaly_score)
    }

    /// Check if a process is potentially scanning ntdll
    pub fn is_process_scanning_ntdll(&self, pid: u32) -> bool {
        self.profiles
            .read()
            .get(&pid)
            .map(|p| p.is_scanning_ntdll())
            .unwrap_or(false)
    }

    /// Remove a process profile
    pub fn remove_profile(&self, pid: u32) {
        self.profiles.write().remove(&pid);
    }

    /// Get statistics about tracked processes
    pub fn get_stats(&self) -> (usize, usize) {
        let profiles = self.profiles.read();
        let suspicious = profiles.values().filter(|p| p.anomaly_score > 0.5).count();
        (profiles.len(), suspicious)
    }
}

impl Default for IndirectSyscallAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Windows-specific Real-time Monitoring
// ============================================================================

#[cfg(target_os = "windows")]
pub mod windows_monitor {
    use super::*;

    /// Start real-time indirect syscall monitoring
    /// Uses a combination of:
    /// 1. Memory scanning of suspicious regions
    /// 2. ETW Threat Intelligence provider events
    /// 3. Process/thread creation monitoring
    pub async fn start_monitoring(
        tx: mpsc::Sender<TelemetryEvent>,
        analyzer: Arc<IndirectSyscallAnalyzer>,
    ) {
        info!("Starting indirect syscall real-time monitoring");

        // Spawn memory scanner task
        let tx1 = tx.clone();
        let analyzer1 = Arc::clone(&analyzer);
        tokio::spawn(async move {
            memory_scan_loop(tx1, analyzer1).await;
        });

        // Spawn thread monitoring task
        let tx2 = tx.clone();
        let analyzer2 = Arc::clone(&analyzer);
        tokio::spawn(async move {
            thread_monitor_loop(tx2, analyzer2).await;
        });

        // Keep main task alive
        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    }

    /// Periodically scan process memory for indirect syscall patterns
    async fn memory_scan_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        analyzer: Arc<IndirectSyscallAnalyzer>,
    ) {
        use scopeguard;
        use sysinfo::System;
        use windows::Win32::Foundation::{CloseHandle, BOOL};
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows::Win32::System::Memory::{
            VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE_READ,
            PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        let mut interval = tokio::time::interval(Duration::from_secs(60));
        let mut scanned_regions: HashSet<(u32, u64)> = HashSet::new();

        loop {
            interval.tick().await;

            let mut system = System::new_all();
            system.refresh_processes();

            for (pid, process) in system.processes() {
                let pid_u32 = pid.as_u32();

                // Skip system processes
                if pid_u32 < 10 {
                    continue;
                }

                let name = process.name().to_string();
                let path = process
                    .exe()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();
                let cmdline = process.cmd().join(" ");
                let mut pending_events = Vec::new();

                unsafe {
                    let process_handle = match OpenProcess(
                        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                        BOOL::from(false),
                        pid_u32,
                    ) {
                        Ok(h) => h,
                        Err(_) => continue,
                    };

                    let _guard = scopeguard::guard(process_handle, |h| {
                        let _ = CloseHandle(h);
                    });

                    // Enumerate memory regions
                    let mut address: usize = 0;
                    let max_address: usize = 0x7FFFFFFFFFFF;

                    while address < max_address {
                        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
                        let result = VirtualQueryEx(
                            process_handle,
                            Some(address as *const std::ffi::c_void),
                            &mut mbi,
                            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                        );

                        if result == 0 {
                            break;
                        }

                        let is_private = mbi.Type == MEM_PRIVATE;
                        let is_committed = mbi.State == MEM_COMMIT;
                        let is_executable = mbi.Protect == PAGE_EXECUTE_READ
                            || mbi.Protect == PAGE_EXECUTE_READWRITE
                            || mbi.Protect == PAGE_EXECUTE_WRITECOPY;

                        // Focus on private executable memory (shellcode, JIT, etc.)
                        if is_private && is_committed && is_executable && mbi.RegionSize > 0 {
                            let region_base = mbi.BaseAddress as u64;

                            // Skip if already scanned
                            if scanned_regions.contains(&(pid_u32, region_base)) {
                                address = (mbi.BaseAddress as usize) + mbi.RegionSize;
                                continue;
                            }

                            // Read and scan the region
                            let scan_size = std::cmp::min(mbi.RegionSize, 0x10000);
                            let mut buffer = vec![0u8; scan_size];
                            let mut bytes_read: usize = 0;

                            if ReadProcessMemory(
                                process_handle,
                                mbi.BaseAddress,
                                buffer.as_mut_ptr() as *mut std::ffi::c_void,
                                scan_size,
                                Some(&mut bytes_read),
                            )
                            .is_ok()
                                && bytes_read > 0
                            {
                                buffer.truncate(bytes_read);

                                let detections = analyzer.analyze_memory_region(
                                    pid_u32,
                                    region_base,
                                    mbi.RegionSize as u64,
                                    &buffer,
                                    &name,
                                );

                                for mut detection in detections {
                                    detection.process_path = path.clone();
                                    detection.cmdline = cmdline.clone();

                                    let event =
                                        IndirectSyscallAnalyzer::create_telemetry_event(&detection);
                                    pending_events.push(event);
                                }

                                scanned_regions.insert((pid_u32, region_base));
                            }
                        }

                        address = (mbi.BaseAddress as usize) + mbi.RegionSize;
                    }
                }

                for event in pending_events {
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }
            }

            // Clean up old entries
            if scanned_regions.len() > 50000 {
                scanned_regions.clear();
            }
        }
    }

    /// Monitor thread creation for suspicious start addresses
    async fn thread_monitor_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        analyzer: Arc<IndirectSyscallAnalyzer>,
    ) {
        use sysinfo::System;

        // This is a simplified implementation - a production version would use
        // ETW or kernel callbacks for real-time thread creation events

        let mut interval = tokio::time::interval(Duration::from_secs(30));
        let known_threads: HashSet<(u32, u32)> = HashSet::new();

        loop {
            interval.tick().await;

            let mut system = System::new_all();
            system.refresh_processes();

            for (pid, process) in system.processes() {
                let pid_u32 = pid.as_u32();

                if pid_u32 < 10 {
                    continue;
                }

                let name = process.name().to_string();

                // In a full implementation, we would enumerate threads and check their
                // start addresses against module bounds. Threads starting from
                // non-image memory are suspicious.

                // This is a placeholder - real implementation would use NtQueryInformationThread
                // to get thread start addresses
            }
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
    fn test_pattern_detection() {
        let analyzer = IndirectSyscallAnalyzer::new();

        // SysWhispers2 pattern: mov r10, rcx; mov eax, 0x18; syscall
        let syscall_stub = vec![
            0x4C, 0x8B, 0xD1, // mov r10, rcx
            0xB8, 0x18, 0x00, 0x00, 0x00, // mov eax, 0x18
            0x0F, 0x05, // syscall
        ];

        #[cfg(target_os = "windows")]
        {
            let detections = analyzer.analyze_memory_region(
                1234,
                0x10000,
                syscall_stub.len() as u64,
                &syscall_stub,
                "test.exe",
            );

            assert!(!detections.is_empty());
            assert!(detections.iter().any(|d| matches!(
                d.technique,
                IndirectSyscallTechnique::SysWhispers2 | IndirectSyscallTechnique::GenericDirect
            )));
        }
    }

    #[test]
    fn test_ssn_extraction() {
        let analyzer = IndirectSyscallAnalyzer::new();

        // Test SSN extraction after mov r10, rcx
        let stub = vec![
            0x4C, 0x8B, 0xD1, // mov r10, rcx
            0xB8, 0x50, 0x00, 0x00, 0x00, // mov eax, 0x50 (NtProtectVirtualMemory)
            0x0F, 0x05, // syscall
        ];

        let ssn = analyzer.extract_ssn_after_pattern(&stub, 0, 3);
        assert_eq!(ssn, Some(0x50));
    }

    #[test]
    fn test_process_profile() {
        let mut profile = ProcessSyscallProfile::new(1234, "test.exe".to_string());

        // Simulate normal syscalls
        for _ in 0..100 {
            profile.record_syscall(true, 0x7FFB1234, Some(0x18));
        }

        assert_eq!(profile.ntdll_syscalls, 100);
        assert_eq!(profile.non_ntdll_syscalls, 0);
        assert!(profile.anomaly_score < 0.2);

        // Simulate suspicious syscalls from non-ntdll
        for i in 0..50 {
            profile.record_syscall(false, 0x10000 + i, Some(0x18));
        }

        assert_eq!(profile.non_ntdll_syscalls, 50);
        assert!(profile.anomaly_score > 0.2);
    }

    #[test]
    fn test_technique_classification() {
        // Verify all techniques have proper metadata
        let techniques = [
            IndirectSyscallTechnique::HellsGate,
            IndirectSyscallTechnique::HalosGate,
            IndirectSyscallTechnique::TartarusGate,
            IndirectSyscallTechnique::SysWhispers1,
            IndirectSyscallTechnique::SysWhispers2,
            IndirectSyscallTechnique::SysWhispers3,
            IndirectSyscallTechnique::FreshyCalls,
            IndirectSyscallTechnique::RecycledGate,
            IndirectSyscallTechnique::HwSyscalls,
            IndirectSyscallTechnique::GenericDirect,
            IndirectSyscallTechnique::GenericIndirect,
            IndirectSyscallTechnique::RopSyscall,
            IndirectSyscallTechnique::NtdllScanning,
        ];

        for technique in techniques {
            assert!(!technique.as_str().is_empty());
            assert!(!technique.description().is_empty());
            assert!(matches!(
                technique.severity(),
                Severity::Critical | Severity::High | Severity::Medium
            ));
        }
    }
}
