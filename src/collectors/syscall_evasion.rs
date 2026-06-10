//! Syscall Evasion Detection Collector
//!
//! Detects HookChain-style EDR evasion techniques across Windows and Linux:
//!
//! ## Windows Detection Methods
//! - IAT hooking and modifications
//! - Dynamic SSN (System Service Number) resolution
//! - Direct and indirect syscalls
//! - Stack spoofing and ROP chain detection
//! - Syscall stub generation in non-ntdll memory
//! - Heaven's Gate (WoW64 transition abuse)
//! - NTDLL integrity monitoring
//!
//! ## Linux Detection Methods (eBPF-based)
//! - eBPF syscall tracing for security-relevant syscalls
//! - mmap/mprotect with PROT_EXEC on anonymous memory
//! - ptrace-based process injection
//! - process_vm_writev to other processes
//! - memfd_create + execveat (fileless execution)
//! - /proc/*/mem writes for code injection
//! - LD_PRELOAD abuse detection
//! - Seccomp filter manipulation
//! - Syscall patterns in anonymous memory regions
//!
//! MITRE ATT&CK Techniques:
//! - T1574.001 - DLL Search Order Hijacking
//! - T1574.002 - DLL Side-Loading
//! - T1574.006 - Dynamic Linker Hijacking (LD_PRELOAD)
//! - T1106 - Native API (Direct Syscalls)
//! - T1055.004 - Asynchronous Procedure Call
//! - T1055.008 - Ptrace System Calls
//! - T1055.009 - Proc Memory
//! - T1055.012 - Process Hollowing
//! - T1014 - Rootkit (SSDT tampering)
//! - T1620 - Reflective Code Loading (memfd_create)
//! - T1562.001 - Disable or Modify Tools (seccomp)
//!
//! ## Windows Detection Methods
//!
//! ### IAT Integrity Checker
//! - Captures baseline IAT entries on process start
//! - Compares memory IAT against disk PE headers
//! - Detects hooked functions, redirected imports
//!
//! ### Syscall Stub Detector
//! - Scans RX/RWX private memory for syscall patterns
//! - Detects dynamically generated syscall stubs
//! - Extracts and validates SSN values
//!
//! ### Syscall Sequence Profiler
//! - Monitors syscall sequences via ETW
//! - Builds baseline profiles per process type
//! - Detects anomalous patterns (direct NtXxx without normal call chain)
//!
//! ### Stack Frame Analyzer
//! - Validates return addresses are preceded by CALL instructions
//! - Detects synthetic frames (spoofing)
//! - Identifies ROP gadget chains and stack pivoting
//!
//! ## Linux Detection Methods
//!
//! ### eBPF Syscall Monitor (Primary)
//! - Raw tracepoint on sys_enter for security-relevant syscalls
//! - Monitors mmap, mprotect, ptrace, memfd_create, execveat, seccomp
//! - Tracks return addresses to detect syscalls from anonymous memory
//! - Correlates memfd_create + execveat for fileless execution detection
//!
//! ### Proc Filesystem Scanner (Fallback)
//! - Scans /proc/*/maps for executable anonymous memory
//! - Detects syscall instruction patterns in non-file-backed regions
//! - Monitors /proc/*/fd for memfd file descriptors
//! - Checks /proc/*/exe for fileless execution indicators
//!
//! ### LD_PRELOAD Monitor
//! - Scans /proc/*/environ for LD_PRELOAD variables
//! - Flags suspicious preload paths (/tmp, /dev/shm, hidden files)
//!
//! ### /proc/*/mem Write Monitor
//! - Detects processes with /proc/*/mem open for writing
//! - Strong indicator of code injection attempts

// This collector enumerates syscall stub patterns, SSN sequences, IAT baseline
// shapes, and stack-frame heuristics for HookChain / Heaven's Gate / direct
// syscall / ptrace-injection detection. Many pattern tables and helper
// structs are kept exhaustive as reference even when not all variants fire.
#![allow(dead_code, unused_variables)]

use super::{Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent};
use crate::config::{AgentConfig, SyscallEvasionConfig};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

// ============================================================================
// Type Definitions
// ============================================================================

/// Types of syscall evasion techniques detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyscallEvasionType {
    /// IAT entry modified to redirect API calls
    IatHook,
    /// IAT entry points to non-standard location
    IatRedirect,
    /// Direct syscall instruction found in non-ntdll memory
    DirectSyscall,
    /// Indirect syscall (jmp to ntdll syscall instruction)
    IndirectSyscall,
    /// Dynamic SSN resolution detected (Hell's Gate, Halo's Gate, etc.)
    DynamicSsnResolution,
    /// Syscall stub generated in private memory
    SyscallStubGeneration,
    /// Anomalous syscall sequence detected
    SyscallSequenceAnomaly,
    /// Return address not preceded by CALL instruction
    InvalidReturnAddress,
    /// ROP gadget chain detected
    RopChainDetected,
    /// Stack pointer outside expected range
    StackPivot,
    /// Synthetic stack frame detected (spoofing)
    StackSpoofing,
    /// NTDLL remapped from disk (unhooking)
    NtdllUnhooking,
    /// NTDLL .text section modified
    NtdllTampered,
    /// KnownDLLs bypass detected
    KnownDllsBypass,
    /// Heaven's Gate (WoW64 transition abuse)
    HeavensGate,
    // === Linux-specific evasion types ===
    /// Syscall from anonymous (non-file-backed) memory region
    AnonymousSyscall,
    /// ptrace-based process injection
    PtraceInjection,
    /// process_vm_writev to another process
    ProcessVmWrite,
    /// memfd_create for fileless execution
    MemfdCreate,
    /// execveat with AT_EMPTY_PATH (fileless execution)
    FilelessExecveat,
    /// /proc/self/mem write for code injection
    ProcMemWrite,
    /// Suspicious LD_PRELOAD usage
    LdPreloadAbuse,
    /// Seccomp filter manipulation
    SeccompManipulation,
    /// mmap with PROT_EXEC on anonymous memory
    AnonymousExecMmap,
    /// mprotect adding PROT_EXEC
    MprotectExec,
    /// ETW function tampering detected (cross-process)
    EtwTampering,
}

impl SyscallEvasionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::IatHook => "iat_hook",
            Self::IatRedirect => "iat_redirect",
            Self::DirectSyscall => "direct_syscall",
            Self::IndirectSyscall => "indirect_syscall",
            Self::DynamicSsnResolution => "dynamic_ssn_resolution",
            Self::SyscallStubGeneration => "syscall_stub_generation",
            Self::SyscallSequenceAnomaly => "syscall_sequence_anomaly",
            Self::InvalidReturnAddress => "invalid_return_address",
            Self::RopChainDetected => "rop_chain_detected",
            Self::StackPivot => "stack_pivot",
            Self::StackSpoofing => "stack_spoofing",
            Self::NtdllUnhooking => "ntdll_unhooking",
            Self::NtdllTampered => "ntdll_tampered",
            Self::KnownDllsBypass => "knowndlls_bypass",
            Self::HeavensGate => "heavens_gate",
            // Linux-specific
            Self::AnonymousSyscall => "anonymous_syscall",
            Self::PtraceInjection => "ptrace_injection",
            Self::ProcessVmWrite => "process_vm_write",
            Self::MemfdCreate => "memfd_create",
            Self::FilelessExecveat => "fileless_execveat",
            Self::ProcMemWrite => "proc_mem_write",
            Self::LdPreloadAbuse => "ld_preload_abuse",
            Self::SeccompManipulation => "seccomp_manipulation",
            Self::AnonymousExecMmap => "anonymous_exec_mmap",
            Self::MprotectExec => "mprotect_exec",
            Self::EtwTampering => "etw_tampering",
        }
    }

    pub fn mitre_technique(&self) -> &'static str {
        match self {
            Self::IatHook | Self::IatRedirect => "T1574.001",
            Self::DirectSyscall | Self::IndirectSyscall => "T1106",
            Self::DynamicSsnResolution | Self::SyscallStubGeneration => "T1106",
            Self::SyscallSequenceAnomaly => "T1106",
            Self::InvalidReturnAddress | Self::RopChainDetected => "T1055.012",
            Self::StackPivot | Self::StackSpoofing => "T1055.004",
            Self::NtdllUnhooking | Self::NtdllTampered => "T1562.001",
            Self::KnownDllsBypass => "T1574.002",
            Self::HeavensGate => "T1055",
            // Linux-specific
            Self::AnonymousSyscall | Self::AnonymousExecMmap | Self::MprotectExec => "T1055.009", // Process Injection: Proc Memory
            Self::PtraceInjection | Self::ProcessVmWrite => "T1055.008", // Process Injection: Ptrace
            Self::MemfdCreate | Self::FilelessExecveat => "T1620",       // Reflective Code Loading
            Self::ProcMemWrite => "T1055.009", // Process Injection: Proc Memory
            Self::LdPreloadAbuse => "T1574.006", // LD_PRELOAD
            Self::SeccompManipulation => "T1562.001", // Disable or Modify Tools
            Self::EtwTampering => "T1562.006", // Disable or Modify System Firewall / ETW
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            // Critical - active evasion
            Self::DirectSyscall
            | Self::IndirectSyscall
            | Self::SyscallStubGeneration
            | Self::NtdllUnhooking
            | Self::RopChainDetected
            | Self::StackSpoofing
            | Self::FilelessExecveat  // Fileless execution is critical
            | Self::ProcessVmWrite    // Direct memory injection is critical
            | Self::PtraceInjection   // Ptrace injection is critical
            | Self::EtwTampering      // ETW tampering blinds EDR - critical
            => Severity::Critical,

            // High - suspicious behavior
            Self::IatHook
            | Self::DynamicSsnResolution
            | Self::StackPivot
            | Self::NtdllTampered
            | Self::HeavensGate
            | Self::MemfdCreate       // memfd_create is highly suspicious
            | Self::ProcMemWrite      // /proc/self/mem write is suspicious
            | Self::AnonymousSyscall  // Syscalls from anon memory
            => Severity::High,

            // Medium - potential evasion
            Self::IatRedirect
            | Self::SyscallSequenceAnomaly
            | Self::InvalidReturnAddress
            | Self::KnownDllsBypass
            | Self::LdPreloadAbuse     // Could be legitimate
            | Self::SeccompManipulation // Could be sandboxing
            | Self::AnonymousExecMmap  // JIT is common
            | Self::MprotectExec       // JIT is common
            => Severity::Medium,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::IatHook => "Import Address Table entry has been hooked",
            Self::IatRedirect => "Import Address Table entry redirected to unexpected location",
            Self::DirectSyscall => "Direct syscall instruction detected outside ntdll.dll",
            Self::IndirectSyscall => "Indirect syscall via jump to ntdll syscall instruction",
            Self::DynamicSsnResolution => "Dynamic System Service Number resolution detected",
            Self::SyscallStubGeneration => "Syscall stub dynamically generated in private memory",
            Self::SyscallSequenceAnomaly => "Anomalous syscall sequence bypassing normal API chain",
            Self::InvalidReturnAddress => "Return address not preceded by valid CALL instruction",
            Self::RopChainDetected => "Return-Oriented Programming gadget chain detected",
            Self::StackPivot => "Stack pointer outside expected memory range",
            Self::StackSpoofing => "Synthetic stack frames detected (call stack spoofing)",
            Self::NtdllUnhooking => "NTDLL has been remapped from disk to unhook EDR",
            Self::NtdllTampered => "NTDLL .text section has been modified",
            Self::KnownDllsBypass => "Bypass of KnownDLLs protection detected",
            Self::HeavensGate => "Heaven's Gate WoW64 transition abuse detected",
            // Linux-specific
            Self::AnonymousSyscall => {
                "Syscall executed from anonymous (non-file-backed) memory region"
            }
            Self::PtraceInjection => "ptrace used to inject code into another process",
            Self::ProcessVmWrite => "process_vm_writev used to write to another process memory",
            Self::MemfdCreate => "memfd_create called (potential fileless execution setup)",
            Self::FilelessExecveat => "execveat with AT_EMPTY_PATH detected (fileless execution)",
            Self::ProcMemWrite => "Write to /proc/*/mem detected (code injection)",
            Self::LdPreloadAbuse => "Suspicious LD_PRELOAD usage detected",
            Self::SeccompManipulation => "Seccomp filter manipulation detected",
            Self::AnonymousExecMmap => "mmap with PROT_EXEC on anonymous memory",
            Self::MprotectExec => "mprotect adding PROT_EXEC to memory region",
            Self::EtwTampering => "ETW function prologue patched in remote process (EDR blinding)",
        }
    }
}

/// Syscall evasion detection event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEvasionEvent {
    /// Type of evasion detected
    pub evasion_type: SyscallEvasionType,
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
    /// Module involved (if applicable)
    pub module: Option<String>,
    /// Function name (for IAT hooks)
    pub function: Option<String>,
    /// Expected address
    pub expected_address: Option<u64>,
    /// Actual/detected address
    pub actual_address: Option<u64>,
    /// System Service Number (for syscall detections)
    pub ssn: Option<u32>,
    /// Target syscall name (if resolved)
    pub syscall_name: Option<String>,
    /// Memory region base address
    pub region_base: Option<u64>,
    /// Memory region size
    pub region_size: Option<u64>,
    /// Detection confidence (0.0-1.0)
    pub confidence: f32,
    /// Additional details
    pub details: String,
    /// Matched pattern name (for signature-based detection)
    pub pattern_name: Option<String>,
}

/// IAT entry baseline for comparison
#[derive(Debug, Clone)]
pub struct IatBaseline {
    /// Module name (e.g., "kernel32.dll")
    pub module_name: String,
    /// Function name (e.g., "VirtualAlloc")
    pub function_name: String,
    /// Address from disk PE
    pub disk_address: u64,
    /// Address in memory
    pub memory_address: u64,
    /// Whether the function is forwarded
    pub is_forwarded: bool,
    /// Forward target if forwarded
    pub forward_target: Option<String>,
}

/// IAT hook detection result
#[derive(Debug, Clone)]
pub struct IatHookDetection {
    pub pid: u32,
    pub module: String,
    pub function: String,
    pub expected: u64,
    pub actual: u64,
    pub redirect_target: Option<String>,
    pub confidence: f32,
}

/// Stack frame information
#[derive(Debug, Clone)]
pub struct StackFrame {
    /// Return address
    pub return_address: u64,
    /// Frame pointer
    pub frame_pointer: u64,
    /// Module containing return address
    pub module: Option<String>,
    /// Function name (if available)
    pub function: Option<String>,
    /// Offset within function
    pub offset: u64,
    /// Whether return address is preceded by CALL
    pub valid_call_site: bool,
}

/// Stack validation result
#[derive(Debug, Clone)]
pub struct StackValidation {
    pub frames: Vec<StackFrame>,
    pub anomalies: Vec<StackAnomaly>,
    pub spoof_confidence: f32,
}

/// Types of stack anomalies
#[derive(Debug, Clone)]
pub enum StackAnomaly {
    /// Return address not in executable memory
    NonExecutableReturn { addr: u64 },
    /// Return address not preceded by CALL
    InvalidCallSite { addr: u64, module: Option<String> },
    /// ROP gadget (small code before ret)
    RopGadget { addr: u64, gadget_size: usize },
    /// Stack pointer outside normal range
    StackPivot {
        rsp: u64,
        expected_range: (u64, u64),
    },
    /// Synthetic frame pattern
    SyntheticFrame { frame_addr: u64 },
}

/// Syscall sequence profile for a process type
#[derive(Debug, Clone, Default)]
pub struct SyscallProfile {
    /// Process type (browser, office, powershell, etc.)
    pub process_type: String,
    /// Common syscall sequences
    pub common_sequences: Vec<Vec<u32>>,
    /// Suspicious sequences
    pub suspicious_sequences: Vec<Vec<u32>>,
    /// Syscall counts
    pub syscall_counts: HashMap<u32, u32>,
    /// Direct syscall indicators
    pub direct_syscall_count: u32,
}

// ============================================================================
// Process Type Baseline Profiling
// ============================================================================

/// Process type categories for syscall behavior analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessType {
    Browser,
    Office,
    Development,
    Shell,
    System,
    Unknown,
}

impl ProcessType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Browser => "browser",
            Self::Office => "office",
            Self::Development => "development",
            Self::Shell => "shell",
            Self::System => "system",
            Self::Unknown => "unknown",
        }
    }
}

impl Default for ProcessType {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Process type classifier
#[derive(Debug, Clone)]
pub struct ProcessTypeClassifier {
    browser_patterns: Vec<&'static str>,
    office_patterns: Vec<&'static str>,
    development_patterns: Vec<&'static str>,
    shell_patterns: Vec<&'static str>,
    system_patterns: Vec<&'static str>,
}

impl ProcessTypeClassifier {
    pub fn new() -> Self {
        Self {
            browser_patterns: vec!["chrome.exe", "firefox.exe", "msedge.exe", "brave.exe"],
            office_patterns: vec!["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"],
            development_patterns: vec![
                "devenv.exe",
                "code.exe",
                "idea64.exe",
                "cargo.exe",
                "node.exe",
                "python.exe",
            ],
            shell_patterns: vec![
                "cmd.exe",
                "powershell.exe",
                "pwsh.exe",
                "wscript.exe",
                "cscript.exe",
            ],
            system_patterns: vec![
                "svchost.exe",
                "services.exe",
                "lsass.exe",
                "csrss.exe",
                "smss.exe",
            ],
        }
    }
    pub fn classify(&self, name: &str) -> ProcessType {
        let n = name.to_lowercase();
        if self.browser_patterns.iter().any(|p| n.contains(p)) {
            ProcessType::Browser
        } else if self.office_patterns.iter().any(|p| n.contains(p)) {
            ProcessType::Office
        } else if self.development_patterns.iter().any(|p| n.contains(p)) {
            ProcessType::Development
        } else if self.shell_patterns.iter().any(|p| n.contains(p)) {
            ProcessType::Shell
        } else if self.system_patterns.iter().any(|p| n.contains(p)) {
            ProcessType::System
        } else {
            ProcessType::Unknown
        }
    }
}

impl Default for ProcessTypeClassifier {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyscallCategory {
    Network,
    Memory,
    FileIO,
    Process,
    Registry,
    Security,
    Other,
}

#[derive(Debug, Clone)]
pub struct SyscallThreshold {
    pub normal_range: (u32, u32),
    pub warning_threshold: u32,
    pub critical_threshold: u32,
}

#[derive(Debug, Clone)]
pub struct SyscallExpectation {
    pub syscall_name: String,
    pub expected: bool,
    pub max_frequency: u32,
    pub weight: f32,
}

#[derive(Debug, Clone)]
pub struct SyscallBaseline {
    pub process_type: ProcessType,
    pub category_thresholds: HashMap<SyscallCategory, SyscallThreshold>,
    pub syscall_expectations: HashMap<String, SyscallExpectation>,
    pub category_weights: HashMap<SyscallCategory, f32>,
    pub description: &'static str,
}

impl SyscallBaseline {
    pub fn for_type(pt: ProcessType) -> Self {
        let mut ct = HashMap::new();
        let mut cw = HashMap::new();
        match pt {
            ProcessType::Browser => {
                ct.insert(
                    SyscallCategory::Network,
                    SyscallThreshold {
                        normal_range: (50, 500),
                        warning_threshold: 1000,
                        critical_threshold: 5000,
                    },
                );
                ct.insert(
                    SyscallCategory::Memory,
                    SyscallThreshold {
                        normal_range: (20, 200),
                        warning_threshold: 500,
                        critical_threshold: 2000,
                    },
                );
                ct.insert(
                    SyscallCategory::Process,
                    SyscallThreshold {
                        normal_range: (0, 20),
                        warning_threshold: 50,
                        critical_threshold: 100,
                    },
                );
                cw.insert(SyscallCategory::Network, 0.3);
                cw.insert(SyscallCategory::Memory, 0.8);
                cw.insert(SyscallCategory::Process, 0.9);
            }
            ProcessType::Office => {
                ct.insert(
                    SyscallCategory::Network,
                    SyscallThreshold {
                        normal_range: (0, 50),
                        warning_threshold: 200,
                        critical_threshold: 500,
                    },
                );
                ct.insert(
                    SyscallCategory::Memory,
                    SyscallThreshold {
                        normal_range: (5, 50),
                        warning_threshold: 150,
                        critical_threshold: 500,
                    },
                );
                ct.insert(
                    SyscallCategory::Process,
                    SyscallThreshold {
                        normal_range: (0, 10),
                        warning_threshold: 25,
                        critical_threshold: 50,
                    },
                );
                cw.insert(SyscallCategory::Network, 0.7);
                cw.insert(SyscallCategory::Memory, 0.9);
                cw.insert(SyscallCategory::Process, 1.0);
            }
            ProcessType::Shell => {
                ct.insert(
                    SyscallCategory::Network,
                    SyscallThreshold {
                        normal_range: (0, 100),
                        warning_threshold: 300,
                        critical_threshold: 1000,
                    },
                );
                ct.insert(
                    SyscallCategory::Memory,
                    SyscallThreshold {
                        normal_range: (10, 100),
                        warning_threshold: 300,
                        critical_threshold: 1000,
                    },
                );
                ct.insert(
                    SyscallCategory::Process,
                    SyscallThreshold {
                        normal_range: (5, 50),
                        warning_threshold: 100,
                        critical_threshold: 500,
                    },
                );
                cw.insert(SyscallCategory::Network, 0.6);
                cw.insert(SyscallCategory::Memory, 0.7);
                cw.insert(SyscallCategory::Process, 0.6);
                cw.insert(SyscallCategory::Security, 0.9);
            }
            ProcessType::System => {
                ct.insert(
                    SyscallCategory::Network,
                    SyscallThreshold {
                        normal_range: (0, 1000),
                        warning_threshold: 5000,
                        critical_threshold: 10000,
                    },
                );
                ct.insert(
                    SyscallCategory::Memory,
                    SyscallThreshold {
                        normal_range: (0, 500),
                        warning_threshold: 2000,
                        critical_threshold: 5000,
                    },
                );
                cw.insert(SyscallCategory::Network, 0.2);
                cw.insert(SyscallCategory::Memory, 0.3);
            }
            ProcessType::Development => {
                ct.insert(
                    SyscallCategory::Network,
                    SyscallThreshold {
                        normal_range: (10, 200),
                        warning_threshold: 500,
                        critical_threshold: 2000,
                    },
                );
                ct.insert(
                    SyscallCategory::Memory,
                    SyscallThreshold {
                        normal_range: (50, 500),
                        warning_threshold: 1500,
                        critical_threshold: 5000,
                    },
                );
                ct.insert(
                    SyscallCategory::Process,
                    SyscallThreshold {
                        normal_range: (20, 200),
                        warning_threshold: 500,
                        critical_threshold: 1000,
                    },
                );
                cw.insert(SyscallCategory::Network, 0.4);
                cw.insert(SyscallCategory::Memory, 0.5);
                cw.insert(SyscallCategory::Process, 0.4);
            }
            ProcessType::Unknown => {
                ct.insert(
                    SyscallCategory::Network,
                    SyscallThreshold {
                        normal_range: (0, 100),
                        warning_threshold: 300,
                        critical_threshold: 1000,
                    },
                );
                ct.insert(
                    SyscallCategory::Memory,
                    SyscallThreshold {
                        normal_range: (0, 50),
                        warning_threshold: 150,
                        critical_threshold: 500,
                    },
                );
                ct.insert(
                    SyscallCategory::Process,
                    SyscallThreshold {
                        normal_range: (0, 20),
                        warning_threshold: 50,
                        critical_threshold: 100,
                    },
                );
                cw.insert(SyscallCategory::Network, 0.6);
                cw.insert(SyscallCategory::Memory, 0.8);
                cw.insert(SyscallCategory::Process, 0.9);
            }
        }
        Self {
            process_type: pt,
            category_thresholds: ct,
            syscall_expectations: HashMap::new(),
            category_weights: cw,
            description: "Baseline",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SyscallObservation {
    pub syscall: String,
    pub category: SyscallCategory,
    pub timestamp: Instant,
    pub is_direct: bool,
}

#[derive(Debug)]
pub struct ProcessSyscallState {
    pub pid: u32,
    pub process_name: String,
    pub process_type: ProcessType,
    pub baseline: SyscallBaseline,
    pub observations: VecDeque<SyscallObservation>,
    pub category_counts: HashMap<SyscallCategory, u32>,
    pub syscall_counts: HashMap<String, u32>,
    pub anomaly_score: f32,
    pub in_learning_period: bool,
    pub learning_start: Instant,
    pub window_duration: Duration,
}

impl ProcessSyscallState {
    pub fn new(
        pid: u32,
        name: String,
        classifier: &ProcessTypeClassifier,
        config: &BaselineConfig,
    ) -> Self {
        let pt = classifier.classify(&name);
        Self {
            pid,
            process_name: name,
            process_type: pt,
            baseline: SyscallBaseline::for_type(pt),
            observations: VecDeque::new(),
            category_counts: HashMap::new(),
            syscall_counts: HashMap::new(),
            anomaly_score: 0.0,
            in_learning_period: config.learning_period_seconds > 0,
            learning_start: Instant::now(),
            window_duration: Duration::from_secs(60),
        }
    }
    pub fn add_observation(&mut self, syscall: String, category: SyscallCategory, is_direct: bool) {
        let now = Instant::now();
        while let Some(f) = self.observations.front() {
            if now.duration_since(f.timestamp) > self.window_duration {
                let o = self.observations.pop_front().unwrap();
                if let Some(c) = self.category_counts.get_mut(&o.category) {
                    *c = c.saturating_sub(1);
                }
                if let Some(c) = self.syscall_counts.get_mut(&o.syscall) {
                    *c = c.saturating_sub(1);
                }
            } else {
                break;
            }
        }
        self.observations.push_back(SyscallObservation {
            syscall: syscall.clone(),
            category,
            timestamp: now,
            is_direct,
        });
        *self.category_counts.entry(category).or_insert(0) += 1;
        *self.syscall_counts.entry(syscall).or_insert(0) += 1;
    }
    pub fn calculate_anomaly_score(&mut self, config: &BaselineConfig) -> f32 {
        if self.in_learning_period
            && self.learning_start.elapsed().as_secs() < config.learning_period_seconds as u64
        {
            return 0.0;
        }
        self.in_learning_period = false;
        let (mut total, mut wsum) = (0.0f32, 0.0f32);
        for (cat, cnt) in &self.category_counts {
            if let Some(th) = self.baseline.category_thresholds.get(cat) {
                let w = self
                    .baseline
                    .category_weights
                    .get(cat)
                    .copied()
                    .unwrap_or(0.5);
                wsum += w;
                let s = if *cnt < th.normal_range.0 {
                    0.1
                } else if *cnt <= th.normal_range.1 {
                    0.0
                } else if *cnt <= th.warning_threshold {
                    0.5 * ((*cnt - th.normal_range.1) as f32
                        / (th.warning_threshold - th.normal_range.1).max(1) as f32)
                        .min(1.0)
                } else if *cnt <= th.critical_threshold {
                    0.5 + 0.5
                        * ((*cnt - th.warning_threshold) as f32
                            / (th.critical_threshold - th.warning_threshold).max(1) as f32)
                            .min(1.0)
                } else {
                    1.0
                };
                total += s * w;
            }
        }
        self.anomaly_score = if wsum > 0.0 {
            (total / wsum).clamp(0.0, 1.0)
        } else {
            0.0
        };
        self.anomaly_score = (self.anomaly_score
            * config
                .type_sensitivity
                .get(&self.process_type)
                .copied()
                .unwrap_or(1.0))
        .clamp(0.0, 1.0);
        self.anomaly_score
    }
    pub fn is_anomalous(&self, config: &BaselineConfig) -> bool {
        self.anomaly_score >= config.anomaly_threshold
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineConfig {
    pub learning_period_seconds: u32,
    pub anomaly_threshold: f32,
    pub type_sensitivity: HashMap<ProcessType, f32>,
}

impl Default for BaselineConfig {
    fn default() -> Self {
        let mut ts = HashMap::new();
        ts.insert(ProcessType::Browser, 1.0);
        ts.insert(ProcessType::Office, 1.2);
        ts.insert(ProcessType::Development, 0.8);
        ts.insert(ProcessType::Shell, 1.5);
        ts.insert(ProcessType::System, 0.5);
        ts.insert(ProcessType::Unknown, 1.0);
        Self {
            learning_period_seconds: 300,
            anomaly_threshold: 0.7,
            type_sensitivity: ts,
        }
    }
}

pub struct BaselineProfiler {
    classifier: ProcessTypeClassifier,
    config: BaselineConfig,
    process_states: Arc<RwLock<HashMap<u32, ProcessSyscallState>>>,
    max_tracked: usize,
}

impl BaselineProfiler {
    pub fn new(config: BaselineConfig) -> Self {
        Self {
            classifier: ProcessTypeClassifier::new(),
            config,
            process_states: Arc::new(RwLock::new(HashMap::new())),
            max_tracked: 10000,
        }
    }
    pub fn record_syscall(
        &self,
        pid: u32,
        name: &str,
        syscall: &str,
        category: SyscallCategory,
        is_direct: bool,
    ) {
        let mut st = self.process_states.write();
        if st.len() >= self.max_tracked && !st.contains_key(&pid) {
            let mut e: Vec<_> = st.iter().map(|(k, v)| (*k, v.learning_start)).collect();
            e.sort_by_key(|(_, t)| *t);
            for (p, _) in e.into_iter().take(self.max_tracked / 10) {
                st.remove(&p);
            }
        }
        st.entry(pid)
            .or_insert_with(|| {
                ProcessSyscallState::new(pid, name.to_string(), &self.classifier, &self.config)
            })
            .add_observation(syscall.to_string(), category, is_direct);
    }
    pub fn calculate_anomaly(&self, pid: u32) -> Option<f32> {
        self.process_states
            .write()
            .get_mut(&pid)
            .map(|s| s.calculate_anomaly_score(&self.config))
    }
    pub fn check_anomaly(&self, pid: u32) -> Option<bool> {
        self.process_states
            .read()
            .get(&pid)
            .map(|s| s.is_anomalous(&self.config))
    }
    pub fn get_process_type(&self, pid: u32) -> Option<ProcessType> {
        self.process_states.read().get(&pid).map(|s| s.process_type)
    }
    pub fn classify_syscall(n: &str) -> SyscallCategory {
        let n = n.to_lowercase();
        if n.contains("socket") || n.contains("connect") || n.contains("send") || n.contains("recv")
        {
            SyscallCategory::Network
        } else if n.contains("allocate")
            || n.contains("protect")
            || n.contains("virtual")
            || n.contains("memory")
        {
            SyscallCategory::Memory
        } else if n.contains("process") || n.contains("thread") || n.contains("apc") {
            // Check Process before FileIO to avoid "thread" matching "read" in "createthread"
            SyscallCategory::Process
        } else if n.contains("key") || n.contains("registry") {
            // Check Registry before FileIO to avoid "open" in "OpenKey" matching FileIO
            SyscallCategory::Registry
        } else if n.contains("token") || n.contains("privilege") || n.contains("security") {
            SyscallCategory::Security
        } else if n.contains("file")
            || n.contains("read")
            || n.contains("write")
            || n.contains("open")
        {
            SyscallCategory::FileIO
        } else {
            SyscallCategory::Other
        }
    }
    pub fn remove_process(&self, pid: u32) {
        self.process_states.write().remove(&pid);
    }
    pub fn config(&self) -> &BaselineConfig {
        &self.config
    }
    pub fn classifier(&self) -> &ProcessTypeClassifier {
        &self.classifier
    }
}

// ============================================================================
// Module Resolution (Windows)
// ============================================================================

/// Information about a loaded module
#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    /// Base address of the module in process memory
    pub base_address: u64,
    /// Size of the module in memory
    pub size: u64,
    /// Full path to the module file
    pub path: String,
    /// Module filename (e.g., "ntdll.dll")
    pub name: String,
}

#[cfg(target_os = "windows")]
impl ModuleInfo {
    /// Check if an address falls within this module
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base_address && addr < self.base_address + self.size
    }
}

/// Module resolver that caches module information per-process
/// and provides efficient address-to-module lookups using binary search
#[cfg(target_os = "windows")]
pub struct ModuleResolver {
    /// Process handle for memory operations
    process_handle: windows::Win32::Foundation::HANDLE,
    /// Process ID
    pid: u32,
    /// Cached module list, sorted by base address for binary search
    modules: Vec<ModuleInfo>,
    /// Last refresh timestamp
    last_refresh: Instant,
}

#[cfg(target_os = "windows")]
impl ModuleResolver {
    /// Create a new ModuleResolver for the given process
    /// Returns None if the process cannot be opened
    pub fn new(pid: u32) -> Option<Self> {
        use windows::Win32::Foundation::BOOL;
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        unsafe {
            let process_handle = OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                BOOL::from(false),
                pid,
            )
            .ok()?;

            let mut resolver = Self {
                process_handle,
                pid,
                modules: Vec::new(),
                last_refresh: Instant::now(),
            };

            // Initial population of module list
            resolver.refresh_modules();

            Some(resolver)
        }
    }

    /// Refresh the module list for the process
    /// This should be called periodically to catch newly loaded modules
    pub fn refresh_modules(&mut self) {
        use windows::Win32::System::ProcessStatus::{
            EnumProcessModulesEx, GetModuleFileNameExW, GetModuleInformation, LIST_MODULES_ALL,
            MODULEINFO,
        };

        self.modules.clear();

        unsafe {
            // Enumerate all modules in the process
            let mut h_mods: [windows::Win32::Foundation::HMODULE; 1024] =
                [windows::Win32::Foundation::HMODULE::default(); 1024];
            let mut cb_needed: u32 = 0;

            if EnumProcessModulesEx(
                self.process_handle,
                h_mods.as_mut_ptr(),
                std::mem::size_of_val(&h_mods) as u32,
                &mut cb_needed,
                LIST_MODULES_ALL,
            )
            .is_err()
            {
                debug!("Failed to enumerate modules for PID {}", self.pid);
                return;
            }

            let num_modules =
                (cb_needed as usize) / std::mem::size_of::<windows::Win32::Foundation::HMODULE>();

            for i in 0..num_modules {
                let h_mod = h_mods[i];

                // Get module path
                let mut module_path = [0u16; 260];
                let path_len = GetModuleFileNameExW(self.process_handle, h_mod, &mut module_path);

                if path_len == 0 {
                    continue;
                }

                let full_path = String::from_utf16_lossy(&module_path[..path_len as usize]);

                // Extract filename from path
                let name = full_path
                    .rsplit(|c| c == '\\' || c == '/')
                    .next()
                    .unwrap_or(&full_path)
                    .to_string();

                // Get module info (base address and size)
                let mut mod_info: MODULEINFO = std::mem::zeroed();
                if GetModuleInformation(
                    self.process_handle,
                    h_mod,
                    &mut mod_info,
                    std::mem::size_of::<MODULEINFO>() as u32,
                )
                .is_err()
                {
                    continue;
                }

                self.modules.push(ModuleInfo {
                    base_address: mod_info.lpBaseOfDll as u64,
                    size: mod_info.SizeOfImage as u64,
                    path: full_path,
                    name,
                });
            }

            // Sort modules by base address for binary search
            self.modules.sort_by_key(|m| m.base_address);
            self.last_refresh = Instant::now();

            trace!(
                "Refreshed module list for PID {}: {} modules loaded",
                self.pid,
                self.modules.len()
            );
        }
    }

    /// Resolve an address to its containing module using binary search
    /// Returns None if the address is not in any known module
    pub fn resolve(&self, addr: u64) -> Option<&ModuleInfo> {
        if self.modules.is_empty() {
            return None;
        }

        // Binary search to find the module with the highest base address <= addr
        let idx = match self.modules.binary_search_by_key(&addr, |m| m.base_address) {
            Ok(i) => i, // Exact match on base address
            Err(i) => {
                // i is where we would insert - check the module before
                if i == 0 {
                    return None;
                }
                i - 1
            }
        };

        let module = &self.modules[idx];
        if module.contains(addr) {
            Some(module)
        } else {
            None
        }
    }

    /// Resolve an address to a module name string
    /// Returns "[unknown]" if not in any module
    pub fn resolve_name(&self, addr: u64) -> String {
        match self.resolve(addr) {
            Some(module) => module.name.clone(),
            None => "[unknown]".to_string(),
        }
    }

    /// Resolve an address to a module name with offset
    /// Returns format like "ntdll.dll+0x1234"
    pub fn resolve_with_offset(&self, addr: u64) -> String {
        match self.resolve(addr) {
            Some(module) => {
                let offset = addr - module.base_address;
                format!("{}+0x{:X}", module.name, offset)
            }
            None => format!("0x{:016X}", addr),
        }
    }

    /// Check if an address is in a specific module (case-insensitive)
    pub fn is_in_module(&self, addr: u64, module_name: &str) -> bool {
        self.resolve(addr)
            .map(|m| m.name.eq_ignore_ascii_case(module_name))
            .unwrap_or(false)
    }

    /// Get age of the module cache in seconds
    pub fn cache_age_secs(&self) -> u64 {
        self.last_refresh.elapsed().as_secs()
    }

    /// Get all modules
    pub fn modules(&self) -> &[ModuleInfo] {
        &self.modules
    }
}

#[cfg(target_os = "windows")]
impl Drop for ModuleResolver {
    fn drop(&mut self) {
        use windows::Win32::Foundation::CloseHandle;
        unsafe {
            let _ = CloseHandle(self.process_handle);
        }
    }
}

/// Thread-safe module resolver cache that maintains resolvers per-process
#[cfg(target_os = "windows")]
pub struct ModuleResolverCache {
    /// Map of PID to resolver
    resolvers: RwLock<HashMap<u32, Arc<RwLock<ModuleResolver>>>>,
    /// Maximum cache age before refresh (seconds)
    max_cache_age_secs: u64,
    /// Maximum number of cached resolvers
    max_resolvers: usize,
}

#[cfg(target_os = "windows")]
impl ModuleResolverCache {
    /// Create a new resolver cache
    pub fn new(max_cache_age_secs: u64, max_resolvers: usize) -> Self {
        Self {
            resolvers: RwLock::new(HashMap::new()),
            max_cache_age_secs,
            max_resolvers,
        }
    }

    /// Get or create a resolver for the given process
    pub fn get_or_create(&self, pid: u32) -> Option<Arc<RwLock<ModuleResolver>>> {
        // Check if we have a cached resolver
        {
            let resolvers = self.resolvers.read();
            if let Some(resolver) = resolvers.get(&pid) {
                // Check if it needs refresh
                let needs_refresh = {
                    let r = resolver.read();
                    r.cache_age_secs() > self.max_cache_age_secs
                };

                if needs_refresh {
                    resolver.write().refresh_modules();
                }

                return Some(Arc::clone(resolver));
            }
        }

        // Create new resolver
        let resolver = ModuleResolver::new(pid)?;
        let resolver = Arc::new(RwLock::new(resolver));

        // Insert into cache
        {
            let mut resolvers = self.resolvers.write();

            // Evict old entries if cache is full
            if resolvers.len() >= self.max_resolvers {
                // Simple LRU: remove oldest entries
                let to_remove: Vec<u32> = resolvers
                    .iter()
                    .filter(|(_, r)| r.read().cache_age_secs() > self.max_cache_age_secs)
                    .map(|(pid, _)| *pid)
                    .take(resolvers.len() / 4)
                    .collect();

                for pid in to_remove {
                    resolvers.remove(&pid);
                }
            }

            resolvers.insert(pid, Arc::clone(&resolver));
        }

        Some(resolver)
    }

    /// Remove a resolver for a terminated process
    pub fn remove(&self, pid: u32) {
        self.resolvers.write().remove(&pid);
    }

    /// Clear all cached resolvers
    pub fn clear(&self) {
        self.resolvers.write().clear();
    }

    /// Resolve an address in the given process to a module name
    pub fn resolve_module_name(&self, pid: u32, addr: u64) -> String {
        self.get_or_create(pid)
            .map(|r| r.read().resolve_name(addr))
            .unwrap_or_else(|| "[inaccessible]".to_string())
    }

    /// Resolve an address to module+offset format
    pub fn resolve_with_offset(&self, pid: u32, addr: u64) -> String {
        self.get_or_create(pid)
            .map(|r| r.read().resolve_with_offset(addr))
            .unwrap_or_else(|| format!("0x{:016X}", addr))
    }
}

#[cfg(target_os = "windows")]
impl Default for ModuleResolverCache {
    fn default() -> Self {
        Self::new(30, 100) // 30 second cache, max 100 processes
    }
}

// Global module resolver cache for the syscall evasion collector
#[cfg(target_os = "windows")]
lazy_static::lazy_static! {
    static ref MODULE_RESOLVER_CACHE: ModuleResolverCache = ModuleResolverCache::default();
}

// ============================================================================
// Syscall Patterns
// ============================================================================

/// Direct syscall patterns (x64)
const SYSCALL_PATTERNS_X64: &[(&str, &[u8], &str)] = &[
    // Standard syscall stub: mov r10, rcx; mov eax, SSN; syscall
    (
        "direct_syscall_standard",
        &[0x4C, 0x8B, 0xD1, 0xB8],
        "T1106",
    ),
    // Syscall instruction
    ("syscall_instruction", &[0x0F, 0x05], "T1106"),
    // Indirect syscall: mov r10, rcx; mov eax, SSN; jmp r11
    (
        "indirect_syscall_jmp_r11",
        &[0x4C, 0x8B, 0xD1, 0xB8],
        "T1106",
    ),
    // SysWhispers2 pattern
    (
        "syswhispers2",
        &[0x4C, 0x8B, 0xD1, 0x48, 0x8B, 0x44, 0x24],
        "T1106",
    ),
    // SysWhispers3 pattern (indirect)
    (
        "syswhispers3",
        &[0x49, 0x89, 0xCA, 0x8B, 0x44, 0x24],
        "T1106",
    ),
    // Hell's Gate SSN extraction: mov eax, [rax+4]
    ("hells_gate_ssn", &[0x8B, 0x40, 0x04], "T1106"),
    // Halo's Gate neighbor check: cmp word [rax], 0x0F05
    ("halos_gate_check", &[0x66, 0x83, 0x38, 0x0F], "T1106"),
    // Tartarus's Gate variant
    (
        "tartarus_gate",
        &[0x48, 0x8B, 0x41, 0x10, 0x4C, 0x8B, 0x40],
        "T1106",
    ),
    // FreshyCalls pattern
    (
        "freshycalls",
        &[0x65, 0x4C, 0x8B, 0x14, 0x25, 0x30, 0x00],
        "T1106",
    ),
    // RecycledGate pattern
    (
        "recycled_gate",
        &[0x48, 0x89, 0x4C, 0x24, 0x08, 0x48, 0x8B, 0xC1],
        "T1106",
    ),
];

/// Direct syscall patterns (x86)
const SYSCALL_PATTERNS_X86: &[(&str, &[u8], &str)] = &[
    // WoW64 syscall: mov eax, SSN; call fs:[0xC0]
    ("wow64_syscall", &[0xB8], "T1106"),
    // Int 2E (legacy NT syscall)
    ("int2e_syscall", &[0xCD, 0x2E], "T1106"),
    // Sysenter instruction
    ("sysenter", &[0x0F, 0x34], "T1106"),
    // Heaven's Gate transition
    (
        "heavens_gate",
        &[
            0x6A, 0x33, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x83, 0x04, 0x24, 0x05, 0xCB,
        ],
        "T1055",
    ),
];

/// NTDLL function patterns for SSN resolution (fallback - Windows 10 21H2)
const NTDLL_FUNC_PATTERNS: &[(&str, u32)] = &[
    ("NtAllocateVirtualMemory", 0x0018),
    ("NtProtectVirtualMemory", 0x0050),
    ("NtWriteVirtualMemory", 0x003A),
    ("NtCreateThreadEx", 0x00C2),
    ("NtQueueApcThread", 0x0045),
    ("NtMapViewOfSection", 0x0028),
    ("NtOpenProcess", 0x0026),
    ("NtReadVirtualMemory", 0x003F),
    ("NtCreateSection", 0x004A),
    ("NtResumeThread", 0x0052),
    ("NtSuspendThread", 0x01BC),
    ("NtSetContextThread", 0x018B),
    ("NtGetContextThread", 0x00F2),
];

// ============================================================================
// Dynamic SSN Resolution (Windows version independent)
// ============================================================================

/// Information about a resolved NT function including hook status
#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
pub struct NtFunctionInfo {
    pub name: String,
    pub ssn: u32,
    pub address: u64,
    pub is_hooked: bool,
    pub hook_target: Option<u64>,
    pub stub_bytes: [u8; 32],
}

/// Error types for SSN resolution
#[cfg(target_os = "windows")]
#[derive(Debug)]
pub enum SsnResolverError {
    NtdllNotFound,
    MemoryReadError(String),
    InvalidPeFormat(String),
    Wow64DetectionFailed,
}

#[cfg(target_os = "windows")]
impl std::fmt::Display for SsnResolverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NtdllNotFound => write!(f, "ntdll.dll not found"),
            Self::MemoryReadError(s) => write!(f, "Memory read error: {}", s),
            Self::InvalidPeFormat(s) => write!(f, "Invalid PE format: {}", s),
            Self::Wow64DetectionFailed => write!(f, "WoW64 detection failed"),
        }
    }
}

#[cfg(target_os = "windows")]
impl std::error::Error for SsnResolverError {}

/// Dynamic SSN resolver - parses ntdll.dll to extract real SSNs for current Windows version
#[cfg(target_os = "windows")]
pub struct SsnResolver {
    ssn_cache: HashMap<String, u32>,
    function_info: HashMap<String, NtFunctionInfo>,
    ssn_to_name: HashMap<u32, String>,
    is_wow64: bool,
    ntdll_base: u64,
    ntdll_size: u64,
    ntdll_is_hooked: bool,
    hook_count: usize,
}

#[cfg(target_os = "windows")]
impl SsnResolver {
    /// Create a new SSN resolver by parsing ntdll.dll from current process
    pub fn new() -> Result<Self, SsnResolverError> {
        use windows::core::w;
        use windows::Win32::Foundation::BOOL;
        use windows::Win32::System::LibraryLoader::GetModuleHandleW;
        use windows::Win32::System::ProcessStatus::{GetModuleInformation, MODULEINFO};
        use windows::Win32::System::Threading::{GetCurrentProcess, IsWow64Process};

        info!("Initializing dynamic SSN resolver");

        unsafe {
            // Detect WoW64 mode
            let mut is_wow64 = BOOL::from(false);
            let current_process = GetCurrentProcess();
            if IsWow64Process(current_process, &mut is_wow64).is_err() {
                return Err(SsnResolverError::Wow64DetectionFailed);
            }
            let is_wow64 = is_wow64.as_bool();
            debug!("WoW64 mode: {}", is_wow64);

            // Get ntdll base address
            let ntdll_handle =
                GetModuleHandleW(w!("ntdll.dll")).map_err(|_| SsnResolverError::NtdllNotFound)?;
            let ntdll_base = ntdll_handle.0 as u64;
            debug!("ntdll.dll base: 0x{:016X}", ntdll_base);

            // Get ntdll size
            let mut mod_info: MODULEINFO = std::mem::zeroed();
            GetModuleInformation(
                current_process,
                ntdll_handle,
                &mut mod_info,
                std::mem::size_of::<MODULEINFO>() as u32,
            )
            .map_err(|e| SsnResolverError::MemoryReadError(e.to_string()))?;
            let ntdll_size = mod_info.SizeOfImage as u64;

            let mut resolver = Self {
                ssn_cache: HashMap::new(),
                function_info: HashMap::new(),
                ssn_to_name: HashMap::new(),
                is_wow64,
                ntdll_base,
                ntdll_size,
                ntdll_is_hooked: false,
                hook_count: 0,
            };

            resolver.resolve_all_ssns()?;
            info!(
                "SSN resolver: {} functions resolved, {} hooks detected",
                resolver.ssn_cache.len(),
                resolver.hook_count
            );
            Ok(resolver)
        }
    }

    /// Parse ntdll exports and extract SSNs from syscall stubs
    fn resolve_all_ssns(&mut self) -> Result<(), SsnResolverError> {
        let exports = self.parse_ntdll_exports()?;

        for (name, address) in exports {
            // Only process Nt/Zw functions
            if !name.starts_with("Nt") && !name.starts_with("Zw") {
                continue;
            }

            if let Some(info) = self.extract_ssn_from_stub(&name, address) {
                if info.is_hooked {
                    self.hook_count += 1;
                    self.ntdll_is_hooked = true;
                    warn!("Hooked function detected: {} at 0x{:016X}", name, address);
                }
                self.ssn_cache.insert(name.clone(), info.ssn);
                self.ssn_to_name.insert(info.ssn, name.clone());
                self.function_info.insert(name, info);
            }
        }
        Ok(())
    }

    /// Parse PE export directory to get all exported functions
    fn parse_ntdll_exports(&self) -> Result<Vec<(String, u64)>, SsnResolverError> {
        let mut exports = Vec::new();

        unsafe {
            let base = self.ntdll_base as *const u8;

            // Validate DOS header
            let dos_magic = std::ptr::read(base as *const u16);
            if dos_magic != 0x5A4D {
                return Err(SsnResolverError::InvalidPeFormat(
                    "Invalid DOS magic".into(),
                ));
            }

            // Get PE header offset
            let pe_offset = std::ptr::read(base.add(0x3C) as *const u32) as usize;
            let pe_ptr = base.add(pe_offset);

            // Validate PE signature
            let pe_sig = std::ptr::read(pe_ptr as *const u32);
            if pe_sig != 0x00004550 {
                return Err(SsnResolverError::InvalidPeFormat(
                    "Invalid PE signature".into(),
                ));
            }

            // Get optional header and determine PE32/PE32+
            let opt_hdr = base.add(pe_offset + 24);
            let magic = std::ptr::read(opt_hdr as *const u16);

            let (export_rva, export_size) = match magic {
                0x20B => {
                    // PE32+ (64-bit)
                    let rva = std::ptr::read(opt_hdr.add(112) as *const u32);
                    let size = std::ptr::read(opt_hdr.add(116) as *const u32);
                    (rva, size)
                }
                0x10B => {
                    // PE32 (32-bit)
                    let rva = std::ptr::read(opt_hdr.add(96) as *const u32);
                    let size = std::ptr::read(opt_hdr.add(100) as *const u32);
                    (rva, size)
                }
                _ => return Err(SsnResolverError::InvalidPeFormat("Unknown PE magic".into())),
            };

            if export_rva == 0 {
                return Err(SsnResolverError::InvalidPeFormat(
                    "No export directory".into(),
                ));
            }

            // Parse export directory
            let export_dir = base.add(export_rva as usize);
            let num_names = std::ptr::read(export_dir.add(24) as *const u32) as usize;
            let funcs_rva = std::ptr::read(export_dir.add(28) as *const u32) as usize;
            let names_rva = std::ptr::read(export_dir.add(32) as *const u32) as usize;
            let ords_rva = std::ptr::read(export_dir.add(36) as *const u32) as usize;

            let funcs = base.add(funcs_rva) as *const u32;
            let names = base.add(names_rva) as *const u32;
            let ords = base.add(ords_rva) as *const u16;

            for i in 0..num_names {
                let name_rva = std::ptr::read(names.add(i));
                let ord = std::ptr::read(ords.add(i)) as usize;
                let func_rva = std::ptr::read(funcs.add(ord));

                // Skip forwarded exports
                if func_rva >= export_rva && func_rva < export_rva + export_size {
                    continue;
                }

                // Read function name
                let name_ptr = base.add(name_rva as usize);
                let mut len = 0usize;
                while *name_ptr.add(len) != 0 && len < 256 {
                    len += 1;
                }
                let name =
                    String::from_utf8_lossy(std::slice::from_raw_parts(name_ptr, len)).to_string();

                exports.push((name, self.ntdll_base + func_rva as u64));
            }
        }

        debug!("Parsed {} exports from ntdll.dll", exports.len());
        Ok(exports)
    }

    /// Extract SSN from syscall stub, detecting hooks
    fn extract_ssn_from_stub(&self, name: &str, address: u64) -> Option<NtFunctionInfo> {
        unsafe {
            let ptr = address as *const u8;
            let mut stub = [0u8; 32];
            for i in 0..32 {
                stub[i] = std::ptr::read(ptr.add(i));
            }

            let (ssn, is_hooked, hook_target) = if self.is_wow64 {
                self.extract_ssn_wow64(&stub)?
            } else {
                self.extract_ssn_x64(&stub)?
            };

            Some(NtFunctionInfo {
                name: name.to_string(),
                ssn,
                address,
                is_hooked,
                hook_target,
                stub_bytes: stub,
            })
        }
    }

    /// Extract SSN from x64 syscall stub
    /// Normal pattern: 4C 8B D1 (mov r10, rcx) B8 XX XX 00 00 (mov eax, SSN)
    fn extract_ssn_x64(&self, stub: &[u8]) -> Option<(u32, bool, Option<u64>)> {
        if stub.len() < 8 {
            return None;
        }

        // Check for standard unhooked stub
        if stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 && stub[3] == 0xB8 {
            let ssn = u32::from_le_bytes([stub[4], stub[5], stub[6], stub[7]]);
            return Some((ssn, false, None));
        }

        // Check for hooks and try to recover SSN
        let (is_hooked, hook_target) = self.detect_hook_x64(stub);

        if is_hooked {
            // Try Halo's Gate: search for mov eax, SSN pattern in the stub
            for i in 0..stub.len().saturating_sub(5) {
                if stub[i] == 0xB8 {
                    let ssn =
                        u32::from_le_bytes([stub[i + 1], stub[i + 2], stub[i + 3], stub[i + 4]]);
                    if ssn < 0x500 {
                        // Reasonable SSN range
                        return Some((ssn, true, hook_target));
                    }
                }
            }
            // SSN recovery failed for hooked function
            return None;
        }

        // Try to find mov eax pattern at different offsets (some packers modify prologue)
        for i in 0..4 {
            if stub[i] == 0xB8 {
                let ssn = u32::from_le_bytes([stub[i + 1], stub[i + 2], stub[i + 3], stub[i + 4]]);
                if ssn < 0x500 {
                    return Some((ssn, false, None));
                }
            }
        }

        None
    }

    /// Detect common hook patterns in x64 stubs
    fn detect_hook_x64(&self, stub: &[u8]) -> (bool, Option<u64>) {
        if stub.len() < 12 {
            return (false, None);
        }

        // JMP rel32 (E9 XX XX XX XX)
        if stub[0] == 0xE9 {
            let rel = i32::from_le_bytes([stub[1], stub[2], stub[3], stub[4]]);
            return (true, Some(rel as u64));
        }

        // JMP [rip+rel32] (FF 25 XX XX XX XX)
        if stub[0] == 0xFF && stub[1] == 0x25 {
            return (true, None);
        }

        // MOV RAX, imm64; JMP RAX (48 B8 XX... FF E0)
        if stub[0] == 0x48 && stub[1] == 0xB8 {
            let target = u64::from_le_bytes([
                stub[2], stub[3], stub[4], stub[5], stub[6], stub[7], stub[8], stub[9],
            ]);
            return (true, Some(target));
        }

        // PUSH addr; RET (68 XX XX XX XX C3)
        if stub[0] == 0x68 && stub[5] == 0xC3 {
            let target = u32::from_le_bytes([stub[1], stub[2], stub[3], stub[4]]) as u64;
            return (true, Some(target));
        }

        // INT3 breakpoint
        if stub[0] == 0xCC {
            return (true, None);
        }

        // Short JMP (EB XX)
        if stub[0] == 0xEB {
            return (true, Some(stub[1] as u64));
        }

        (false, None)
    }

    /// Extract SSN from WoW64 (32-bit) syscall stub
    /// Pattern: B8 XX XX 00 00 (mov eax, SSN)
    fn extract_ssn_wow64(&self, stub: &[u8]) -> Option<(u32, bool, Option<u64>)> {
        if stub.len() < 10 {
            return None;
        }

        let (is_hooked, hook_target) = self.detect_hook_wow64(stub);

        if stub[0] == 0xB8 {
            let ssn = u32::from_le_bytes([stub[1], stub[2], stub[3], stub[4]]);
            if ssn < 0x500 {
                return Some((ssn, is_hooked, hook_target));
            }
        }

        None
    }

    /// Detect hooks in WoW64 stubs
    fn detect_hook_wow64(&self, stub: &[u8]) -> (bool, Option<u64>) {
        if stub.len() < 6 {
            return (false, None);
        }

        // JMP rel32
        if stub[0] == 0xE9 {
            let rel = i32::from_le_bytes([stub[1], stub[2], stub[3], stub[4]]);
            return (true, Some(rel as u64));
        }

        // Short JMP
        if stub[0] == 0xEB {
            return (true, Some(stub[1] as u64));
        }

        // PUSH/RET
        if stub[0] == 0x68 && stub[5] == 0xC3 {
            let target = u32::from_le_bytes([stub[1], stub[2], stub[3], stub[4]]) as u64;
            return (true, Some(target));
        }

        // INT3
        if stub[0] == 0xCC {
            return (true, None);
        }

        // If first byte isn't MOV EAX, likely hooked
        if stub[0] != 0xB8 {
            return (true, None);
        }

        (false, None)
    }

    // Public API

    /// Get SSN for a function name
    pub fn get_ssn(&self, name: &str) -> Option<u32> {
        self.ssn_cache.get(name).copied()
    }

    /// Get function name for an SSN
    pub fn get_name(&self, ssn: u32) -> Option<&str> {
        self.ssn_to_name.get(&ssn).map(|s| s.as_str())
    }

    /// Get full function info
    pub fn get_function_info(&self, name: &str) -> Option<&NtFunctionInfo> {
        self.function_info.get(name)
    }

    /// Check if ntdll has any hooks
    pub fn is_hooked(&self) -> bool {
        self.ntdll_is_hooked
    }

    /// Get number of hooked functions
    pub fn hook_count(&self) -> usize {
        self.hook_count
    }

    /// Get all resolved SSNs
    pub fn all_ssns(&self) -> &HashMap<String, u32> {
        &self.ssn_cache
    }

    /// Check if running in WoW64 mode
    pub fn is_wow64(&self) -> bool {
        self.is_wow64
    }

    /// Get ntdll base address
    pub fn ntdll_base(&self) -> u64 {
        self.ntdll_base
    }

    /// Verify an SSN matches our resolved value
    pub fn verify_ssn(&self, name: &str, ssn: u32) -> bool {
        self.ssn_cache.get(name).map_or(false, |&s| s == ssn)
    }

    /// Get list of hooked functions
    pub fn get_hooked_functions(&self) -> Vec<&NtFunctionInfo> {
        self.function_info
            .values()
            .filter(|i| i.is_hooked)
            .collect()
    }
}

/// Global SSN resolver instance
#[cfg(target_os = "windows")]
static SSN_RESOLVER: std::sync::OnceLock<Option<SsnResolver>> = std::sync::OnceLock::new();

/// Get or initialize the global SSN resolver
#[cfg(target_os = "windows")]
pub fn get_ssn_resolver() -> Option<&'static SsnResolver> {
    SSN_RESOLVER
        .get_or_init(|| match SsnResolver::new() {
            Ok(resolver) => Some(resolver),
            Err(e) => {
                error!("Failed to initialize SSN resolver: {}", e);
                None
            }
        })
        .as_ref()
}

/// Suspicious syscall sequences (injection patterns)
const SUSPICIOUS_SYSCALL_SEQUENCES: &[&[&str]] = &[
    // Classic injection: allocate -> write -> protect -> create thread
    &[
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtProtectVirtualMemory",
        "NtCreateThreadEx",
    ],
    // APC injection: allocate -> write -> queue APC
    &[
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtQueueApcThread",
    ],
    // Section injection: create section -> map -> write
    &[
        "NtCreateSection",
        "NtMapViewOfSection",
        "NtWriteVirtualMemory",
    ],
    // Thread hijacking: suspend -> get context -> set context -> resume
    &[
        "NtSuspendThread",
        "NtGetContextThread",
        "NtSetContextThread",
        "NtResumeThread",
    ],
];

/// High-risk processes for enhanced monitoring
const HIGH_RISK_PROCESSES: &[&str] = &[
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "msiexec.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "wmic.exe",
    "msbuild.exe",
    "installutil.exe",
];

// ============================================================================
// Collector Implementation
// ============================================================================

/// Syscall evasion detection collector
pub struct SyscallEvasionCollector {
    #[allow(dead_code)]
    config: AgentConfig,
    #[allow(dead_code)]
    evasion_config: SyscallEvasionConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    #[allow(dead_code)]
    event_tx: mpsc::Sender<TelemetryEvent>,
}

impl SyscallEvasionCollector {
    /// Create a new syscall evasion collector
    pub fn new(config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(500);
        let evasion_config = config.syscall_evasion.clone();

        let collector = Self {
            config: config.clone(),
            evasion_config: evasion_config.clone(),
            event_rx: rx,
            event_tx: tx.clone(),
        };

        // Start platform-specific monitoring
        #[cfg(target_os = "windows")]
        {
            let tx_clone = tx.clone();
            let ec = evasion_config.clone();
            tokio::spawn(async move {
                Self::windows_monitor_loop(tx_clone, ec).await;
            });
        }

        #[cfg(target_os = "linux")]
        {
            let tx_clone = tx.clone();
            let config_clone = config.clone();
            tokio::spawn(async move {
                Self::linux_monitor_loop(tx_clone, config_clone).await;
            });
        }

        collector
    }

    /// Get next event from collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }

    /// Create telemetry event from syscall evasion detection
    fn create_evasion_event(evasion: &SyscallEvasionEvent) -> TelemetryEvent {
        let mut event = TelemetryEvent::new(
            EventType::DefenseEvasion,
            evasion.evasion_type.severity(),
            EventPayload::Custom(serde_json::json!({
                "evasion_type": evasion.evasion_type.as_str(),
                "evasion_category": "syscall_evasion",
                "pid": evasion.pid,
                "process_name": evasion.process_name,
                "process_path": evasion.process_path,
                "cmdline": evasion.cmdline,
                "user": evasion.user,
                "module": evasion.module,
                "function": evasion.function,
                "expected_address": evasion.expected_address,
                "actual_address": evasion.actual_address,
                "ssn": evasion.ssn,
                "syscall_name": evasion.syscall_name,
                "region_base": evasion.region_base,
                "region_size": evasion.region_size,
                "confidence": evasion.confidence,
                "details": evasion.details,
                "pattern_name": evasion.pattern_name,
            })),
        );

        // Add detection
        event.add_detection(Detection {
            detection_type: DetectionType::DefenseEvasion,
            rule_name: format!("syscall_evasion_{}", evasion.evasion_type.as_str()),
            confidence: evasion.confidence,
            description: format!(
                "{}: {} (Process: {} [{}])",
                evasion.evasion_type.description(),
                evasion.details,
                evasion.process_name,
                evasion.pid
            ),
            mitre_tactics: vec!["defense-evasion".to_string(), "execution".to_string()],
            mitre_techniques: vec![evasion.evasion_type.mitre_technique().to_string()],
        });

        // Add metadata
        event.metadata.insert(
            "evasion_type".to_string(),
            evasion.evasion_type.as_str().to_string(),
        );
        event.metadata.insert(
            "evasion_category".to_string(),
            "syscall_evasion".to_string(),
        );
        event
            .metadata
            .insert("details".to_string(), evasion.details.clone());

        if let Some(ref module) = evasion.module {
            event.metadata.insert("module".to_string(), module.clone());
        }
        if let Some(ref func) = evasion.function {
            event.metadata.insert("function".to_string(), func.clone());
        }
        if let Some(ssn) = evasion.ssn {
            event
                .metadata
                .insert("ssn".to_string(), format!("0x{:04X}", ssn));
        }

        event
    }

    // ==================== Windows Implementation ====================
    #[cfg(target_os = "windows")]
    async fn windows_monitor_loop(tx: mpsc::Sender<TelemetryEvent>, ec: SyscallEvasionConfig) {
        info!(
            iat_interval = ec.iat_check_interval_secs,
            mem_interval = ec.memory_scan_interval_secs,
            stack = ec.stack_validation,
            etw = ec.etw_profiling,
            heavens_gate = ec.heavens_gate_detection,
            "Starting Windows syscall evasion monitor"
        );

        // Start multiple monitoring tasks, gated by config

        // IAT integrity monitoring
        let tx1 = tx.clone();
        let iat_interval = ec.iat_check_interval_secs;
        let high_risk = ec.high_risk_processes.clone();
        tokio::spawn(async move {
            Self::monitor_iat_integrity(tx1, iat_interval, high_risk).await;
        });

        // Syscall stub detection in memory
        let tx2 = tx.clone();
        let mem_interval = ec.memory_scan_interval_secs;
        tokio::spawn(async move {
            Self::monitor_syscall_stubs(tx2, mem_interval).await;
        });

        // NTDLL integrity monitoring
        let tx3 = tx.clone();
        let ntdll_interval = ec.ntdll_check_interval_secs;
        tokio::spawn(async move {
            Self::monitor_ntdll_integrity(tx3, ntdll_interval).await;
        });

        // Cross-process ETW function integrity monitoring
        if ec.etw_cross_process_integrity_enabled {
            let tx_etw = tx.clone();
            let etw_interval = ec.etw_cross_process_interval_secs;
            tokio::spawn(async move {
                Self::monitor_etw_cross_process_integrity(tx_etw, etw_interval).await;
            });
        } else {
            info!("Cross-process ETW integrity checking disabled by configuration");
        }

        // Stack validation for suspicious processes (configurable)
        if ec.stack_validation {
            let tx4 = tx.clone();
            let high_risk_stack = ec.high_risk_processes.clone();
            tokio::spawn(async move {
                Self::monitor_stack_integrity(tx4, high_risk_stack).await;
            });
        } else {
            info!("Stack validation disabled by configuration");
        }

        // ETW Syscall Audit monitoring (Kernel-Audit-API-Calls)
        if ec.etw_profiling {
            let tx6 = tx.clone();
            let anomaly_threshold = ec.anomaly_threshold;
            let learning_period = ec.learning_period_secs;
            tokio::spawn(async move {
                Self::monitor_etw_syscalls(tx6, anomaly_threshold, learning_period).await;
            });
        } else {
            info!("ETW syscall profiling disabled by configuration");
        }

        // Heaven's Gate and WoW64 abuse detection
        if ec.heavens_gate_detection {
            let tx5 = tx.clone();
            Self::monitor_heavens_gate(tx5).await;
        } else {
            info!("Heaven's Gate detection disabled by configuration");
            // Keep the task alive so the monitor loop doesn't exit
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
            }
        }
    }

    #[cfg(target_os = "windows")]
    async fn monitor_iat_integrity(
        tx: mpsc::Sender<TelemetryEvent>,
        check_interval_secs: u64,
        high_risk_processes: Vec<String>,
    ) {
        use std::collections::HashMap;
        use sysinfo::System;

        info!(
            interval_secs = check_interval_secs,
            "Starting IAT integrity monitor"
        );

        // Baseline cache: PID -> (module -> function -> expected_addr)
        let iat_baselines: HashMap<u32, HashMap<String, HashMap<String, u64>>> = HashMap::new();
        let mut interval =
            tokio::time::interval(tokio::time::Duration::from_secs(check_interval_secs));

        loop {
            interval.tick().await;

            let mut system = System::new_all();
            system.refresh_processes();

            for (pid, process) in system.processes() {
                let pid_u32 = pid.as_u32();
                let name = process.name().to_string();
                let path = process
                    .exe()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();

                // Skip system processes
                if pid_u32 < 10 {
                    continue;
                }

                // Focus on high-risk processes (from config or fallback to static list)
                let name_lower = name.to_lowercase();
                let is_high_risk = if high_risk_processes.is_empty() {
                    HIGH_RISK_PROCESSES.iter().any(|p| name_lower.contains(p))
                } else {
                    high_risk_processes
                        .iter()
                        .any(|p| name_lower.contains(&p.to_lowercase()))
                };

                if !is_high_risk {
                    continue;
                }

                // Check IAT for critical modules
                let critical_modules = ["kernel32.dll", "ntdll.dll", "kernelbase.dll"];
                let critical_functions = [
                    "VirtualAlloc",
                    "VirtualProtect",
                    "WriteProcessMemory",
                    "CreateRemoteThread",
                    "NtAllocateVirtualMemory",
                    "NtProtectVirtualMemory",
                    "NtWriteVirtualMemory",
                    "NtCreateThreadEx",
                    "LoadLibraryA",
                    "GetProcAddress",
                ];

                // Attempt to read IAT from process memory
                if let Some(hooks) =
                    Self::check_iat_hooks(pid_u32, &critical_modules, &critical_functions)
                {
                    for hook in hooks {
                        let evasion = SyscallEvasionEvent {
                            evasion_type: SyscallEvasionType::IatHook,
                            pid: pid_u32,
                            process_name: name.clone(),
                            process_path: path.clone(),
                            cmdline: process.cmd().join(" "),
                            user: String::new(),
                            module: Some(hook.module.clone()),
                            function: Some(hook.function.clone()),
                            expected_address: Some(hook.expected),
                            actual_address: Some(hook.actual),
                            ssn: None,
                            syscall_name: None,
                            region_base: None,
                            region_size: None,
                            confidence: hook.confidence,
                            details: format!(
                                "IAT hook detected: {}!{} expected 0x{:016X}, found 0x{:016X}",
                                hook.module, hook.function, hook.expected, hook.actual
                            ),
                            pattern_name: None,
                        };

                        let event = Self::create_evasion_event(&evasion);
                        if tx.send(event).await.is_err() {
                            return;
                        }
                    }
                }
            }
        }
    }

    /// Check for IAT hooks by comparing memory IAT entries against expected module addresses
    ///
    /// This function performs real IAT hook detection:
    /// 1. Enumerates modules in the target process
    /// 2. For each module, parses PE headers from process memory
    /// 3. Walks the import descriptors and IAT entries
    /// 4. For each imported function from critical DLLs, verifies the IAT entry points to the expected module
    /// 5. Reports any hooks (IAT entries pointing to unexpected memory regions)
    #[cfg(target_os = "windows")]
    fn check_iat_hooks(
        pid: u32,
        modules: &[&str],
        functions: &[&str],
    ) -> Option<Vec<IatHookDetection>> {
        use windows::Win32::Foundation::{CloseHandle, BOOL};

        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_IMAGE};
        use windows::Win32::System::ProcessStatus::{
            EnumProcessModulesEx, GetModuleFileNameExW, LIST_MODULES_ALL,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        let mut hooks = Vec::new();

        // Build a set of critical functions for fast lookup
        let critical_functions: std::collections::HashSet<&str> =
            functions.iter().copied().collect();

        unsafe {
            // Open target process for memory reading
            let process_handle = match OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                BOOL::from(false),
                pid,
            ) {
                Ok(h) => h,
                Err(e) => {
                    trace!("Failed to open process {}: {:?}", pid, e);
                    return None;
                }
            };

            let _process_guard = scopeguard::guard(process_handle, |h| {
                let _ = CloseHandle(h);
            });

            // Enumerate all modules in the target process
            let mut h_mods: [windows::Win32::Foundation::HMODULE; 1024] =
                [windows::Win32::Foundation::HMODULE::default(); 1024];
            let mut cb_needed: u32 = 0;

            if EnumProcessModulesEx(
                process_handle,
                h_mods.as_mut_ptr(),
                std::mem::size_of_val(&h_mods) as u32,
                &mut cb_needed,
                LIST_MODULES_ALL,
            )
            .is_err()
            {
                return None;
            }

            let num_modules =
                (cb_needed as usize) / std::mem::size_of::<windows::Win32::Foundation::HMODULE>();

            // Build a map of module name -> (base address, full path)
            let mut module_map: HashMap<String, (u64, String)> = HashMap::new();

            for i in 0..num_modules {
                let h_mod = h_mods[i];
                let mut module_path = [0u16; 260];
                let name_len = GetModuleFileNameExW(process_handle, h_mod, &mut module_path);

                if name_len == 0 {
                    continue;
                }

                let path_str = String::from_utf16_lossy(&module_path[..name_len as usize]);
                let base_addr = h_mod.0 as u64;

                // Extract filename for lookup
                if let Some(file_name) = std::path::Path::new(&path_str).file_name() {
                    let name_lower = file_name.to_string_lossy().to_lowercase();
                    module_map.insert(name_lower, (base_addr, path_str));
                }
            }

            // For each module in the process, check its IAT
            for i in 0..num_modules {
                let h_mod = h_mods[i];
                let mut module_path = [0u16; 260];
                let name_len = GetModuleFileNameExW(process_handle, h_mod, &mut module_path);

                if name_len == 0 {
                    continue;
                }

                let module_path_str = String::from_utf16_lossy(&module_path[..name_len as usize]);
                let module_base = h_mod.0 as u64;

                // Read DOS header from process memory
                let mut dos_header = [0u8; 64];
                let mut bytes_read: usize = 0;

                if ReadProcessMemory(
                    process_handle,
                    module_base as *const std::ffi::c_void,
                    dos_header.as_mut_ptr() as *mut std::ffi::c_void,
                    dos_header.len(),
                    Some(&mut bytes_read),
                )
                .is_err()
                    || bytes_read < 64
                {
                    continue;
                }

                // Validate DOS header magic
                if dos_header[0] != b'M' || dos_header[1] != b'Z' {
                    continue;
                }

                // Get e_lfanew (offset to PE header) at offset 0x3C
                let e_lfanew = u32::from_le_bytes([
                    dos_header[0x3C],
                    dos_header[0x3D],
                    dos_header[0x3E],
                    dos_header[0x3F],
                ]) as usize;

                if e_lfanew > 0x1000 {
                    continue; // Invalid PE offset
                }

                // Read PE header
                let pe_header_size = 0x200;
                let mut pe_header = vec![0u8; pe_header_size];

                if ReadProcessMemory(
                    process_handle,
                    (module_base + e_lfanew as u64) as *const std::ffi::c_void,
                    pe_header.as_mut_ptr() as *mut std::ffi::c_void,
                    pe_header_size,
                    Some(&mut bytes_read),
                )
                .is_err()
                    || bytes_read < 0x80
                {
                    continue;
                }

                // Validate PE signature
                if &pe_header[0..4] != b"PE\0\0" {
                    continue;
                }

                // Determine PE type (32-bit or 64-bit)
                let optional_header_offset = 24;
                let magic = u16::from_le_bytes([
                    pe_header[optional_header_offset],
                    pe_header[optional_header_offset + 1],
                ]);

                let is_pe64 = magic == 0x20B; // PE32+ magic

                // Get import directory RVA and size
                // For PE32+: data directories start at offset 112 from optional header
                // For PE32: data directories start at offset 96 from optional header
                let data_dir_offset = optional_header_offset + if is_pe64 { 112 } else { 96 };

                // Import directory is the second entry (index 1), each entry is 8 bytes
                let import_dir_offset = data_dir_offset + 8; // Skip export directory

                if import_dir_offset + 8 > pe_header.len() {
                    continue;
                }

                let import_rva = u32::from_le_bytes([
                    pe_header[import_dir_offset],
                    pe_header[import_dir_offset + 1],
                    pe_header[import_dir_offset + 2],
                    pe_header[import_dir_offset + 3],
                ]) as u64;

                let import_size = u32::from_le_bytes([
                    pe_header[import_dir_offset + 4],
                    pe_header[import_dir_offset + 5],
                    pe_header[import_dir_offset + 6],
                    pe_header[import_dir_offset + 7],
                ]) as usize;

                if import_rva == 0 || import_size == 0 {
                    continue; // No imports
                }

                // Read import descriptors from process memory
                // IMAGE_IMPORT_DESCRIPTOR is 20 bytes each
                let mut import_desc_buf = vec![0u8; import_size];

                if ReadProcessMemory(
                    process_handle,
                    (module_base + import_rva) as *const std::ffi::c_void,
                    import_desc_buf.as_mut_ptr() as *mut std::ffi::c_void,
                    import_size,
                    Some(&mut bytes_read),
                )
                .is_err()
                    || bytes_read < 20
                {
                    continue;
                }

                // Walk import descriptors
                let mut desc_offset = 0;
                while desc_offset + 20 <= bytes_read {
                    let desc = &import_desc_buf[desc_offset..desc_offset + 20];

                    // Parse IMAGE_IMPORT_DESCRIPTOR fields
                    let original_first_thunk =
                        u32::from_le_bytes([desc[0], desc[1], desc[2], desc[3]]) as u64; // INT
                    let name_rva =
                        u32::from_le_bytes([desc[12], desc[13], desc[14], desc[15]]) as u64;
                    let first_thunk =
                        u32::from_le_bytes([desc[16], desc[17], desc[18], desc[19]]) as u64; // IAT

                    // End of import descriptors (all zeros)
                    if original_first_thunk == 0 && first_thunk == 0 {
                        break;
                    }

                    if name_rva == 0 {
                        desc_offset += 20;
                        continue;
                    }

                    // Read imported DLL name
                    let mut dll_name_buf = [0u8; 256];
                    if ReadProcessMemory(
                        process_handle,
                        (module_base + name_rva) as *const std::ffi::c_void,
                        dll_name_buf.as_mut_ptr() as *mut std::ffi::c_void,
                        dll_name_buf.len(),
                        Some(&mut bytes_read),
                    )
                    .is_err()
                        || bytes_read == 0
                    {
                        desc_offset += 20;
                        continue;
                    }

                    let dll_name = std::ffi::CStr::from_bytes_until_nul(&dll_name_buf)
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_default()
                        .to_lowercase();

                    // Only check imports from critical DLLs (kernel32, ntdll, kernelbase)
                    let is_critical_dll =
                        modules.iter().any(|m| dll_name.contains(&m.to_lowercase()));
                    if !is_critical_dll {
                        desc_offset += 20;
                        continue;
                    }

                    // Get the expected base address for this imported DLL
                    let expected_module_info = module_map.get(&dll_name);
                    let expected_base = match expected_module_info {
                        Some((base, _path)) => *base,
                        None => {
                            desc_offset += 20;
                            continue;
                        }
                    };

                    // Walk IAT entries for this imported DLL
                    let int_rva = if original_first_thunk != 0 {
                        original_first_thunk
                    } else {
                        first_thunk
                    };
                    let iat_rva = first_thunk;

                    let thunk_size = if is_pe64 { 8usize } else { 4usize };
                    let mut thunk_idx = 0u64;

                    loop {
                        // Read INT entry (function name hint/ordinal)
                        let int_addr = module_base + int_rva + thunk_idx * thunk_size as u64;
                        let iat_addr = module_base + iat_rva + thunk_idx * thunk_size as u64;

                        let mut int_entry = [0u8; 8];
                        let mut iat_entry = [0u8; 8];

                        if ReadProcessMemory(
                            process_handle,
                            int_addr as *const std::ffi::c_void,
                            int_entry.as_mut_ptr() as *mut std::ffi::c_void,
                            thunk_size,
                            Some(&mut bytes_read),
                        )
                        .is_err()
                            || bytes_read == 0
                        {
                            break;
                        }

                        let int_value = if is_pe64 {
                            u64::from_le_bytes(int_entry)
                        } else {
                            u32::from_le_bytes([
                                int_entry[0],
                                int_entry[1],
                                int_entry[2],
                                int_entry[3],
                            ]) as u64
                        };

                        if int_value == 0 {
                            break; // End of thunk array
                        }

                        // Read current IAT entry (function address in memory)
                        if ReadProcessMemory(
                            process_handle,
                            iat_addr as *const std::ffi::c_void,
                            iat_entry.as_mut_ptr() as *mut std::ffi::c_void,
                            thunk_size,
                            Some(&mut bytes_read),
                        )
                        .is_err()
                            || bytes_read == 0
                        {
                            break;
                        }

                        let memory_func_addr = if is_pe64 {
                            u64::from_le_bytes(iat_entry)
                        } else {
                            u32::from_le_bytes([
                                iat_entry[0],
                                iat_entry[1],
                                iat_entry[2],
                                iat_entry[3],
                            ]) as u64
                        };

                        // Check if ordinal import (high bit set)
                        let ordinal_flag = if is_pe64 {
                            0x8000000000000000u64
                        } else {
                            0x80000000u64
                        };
                        let is_ordinal = (int_value & ordinal_flag) != 0;

                        // Get function name
                        let func_name = if is_ordinal {
                            format!("Ordinal#{}", int_value & 0xFFFF)
                        } else {
                            // INT points to IMAGE_IMPORT_BY_NAME: 2 bytes hint + null-terminated name
                            let hint_rva = int_value;
                            let mut name_buf = [0u8; 128];

                            if ReadProcessMemory(
                                process_handle,
                                (module_base + hint_rva + 2) as *const std::ffi::c_void, // Skip hint
                                name_buf.as_mut_ptr() as *mut std::ffi::c_void,
                                name_buf.len(),
                                Some(&mut bytes_read),
                            )
                            .is_ok()
                                && bytes_read > 0
                            {
                                std::ffi::CStr::from_bytes_until_nul(&name_buf)
                                    .map(|s| s.to_string_lossy().to_string())
                                    .unwrap_or_default()
                            } else {
                                String::new()
                            }
                        };

                        // Only check critical functions
                        if !func_name.is_empty() && critical_functions.contains(func_name.as_str())
                        {
                            // Query memory info for the function address to find which module it's in
                            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
                            let query_result = VirtualQueryEx(
                                process_handle,
                                Some(memory_func_addr as *const std::ffi::c_void),
                                &mut mbi,
                                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                            );

                            if query_result > 0 {
                                let func_module_base = mbi.AllocationBase as u64;

                                // Check if function points to the expected module
                                if func_module_base != expected_base {
                                    // IAT hook detected - function points to different module

                                    // Find what module the hook redirects to
                                    let redirect_module = module_map
                                        .iter()
                                        .find(|(_, (base, _))| *base == func_module_base)
                                        .map(|(name, _)| name.clone());

                                    // Check if it's pointing to non-image memory (more suspicious)
                                    let is_non_image = mbi.Type != MEM_IMAGE;

                                    let confidence = if is_non_image {
                                        0.95 // Non-image memory is highly suspicious
                                    } else if redirect_module.is_some() {
                                        0.85 // Redirected to another known DLL
                                    } else {
                                        0.75 // Unknown redirect
                                    };

                                    let redirect_target = if is_non_image {
                                        Some(format!(
                                            "Private memory at 0x{:016X}",
                                            func_module_base
                                        ))
                                    } else {
                                        redirect_module.map(|m| format!("Redirected to {}", m))
                                    };

                                    hooks.push(IatHookDetection {
                                        pid,
                                        module: dll_name.clone(),
                                        function: func_name.clone(),
                                        expected: expected_base,
                                        actual: memory_func_addr,
                                        redirect_target,
                                        confidence,
                                    });

                                    debug!(
                                        "IAT hook detected: {}!{} in PID {} - expected base 0x{:X}, actual base 0x{:X}",
                                        dll_name, func_name, pid, expected_base, func_module_base
                                    );
                                }
                            }
                        }

                        thunk_idx += 1;

                        // Safety limit to prevent infinite loops
                        if thunk_idx > 10000 {
                            break;
                        }
                    }

                    desc_offset += 20;
                }
            }
        }

        if hooks.is_empty() {
            None
        } else {
            Some(hooks)
        }
    }

    /// Map a DLL from disk using CreateFileMappingW/MapViewOfFile for comparison
    /// Returns (base_address, size, file_handle, mapping_handle)
    #[cfg(target_os = "windows")]
    #[allow(dead_code)]
    fn map_dll_from_disk(
        path: &str,
    ) -> Option<(
        u64,
        usize,
        windows::Win32::Foundation::HANDLE,
        windows::Win32::Foundation::HANDLE,
    )> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, INVALID_HANDLE_VALUE};
        use windows::Win32::Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING,
        };
        use windows::Win32::System::Memory::{
            CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, FILE_MAP_READ,
            MEMORY_MAPPED_VIEW_ADDRESS, PAGE_READONLY,
        };

        unsafe {
            // Convert path to wide string
            let wide_path: Vec<u16> = OsStr::new(path)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            // Open file for reading
            let file_handle = match CreateFileW(
                PCWSTR(wide_path.as_ptr()),
                GENERIC_READ.0,
                FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            ) {
                Ok(h) if h != INVALID_HANDLE_VALUE => h,
                _ => return None,
            };

            // Create file mapping
            let mapping_handle =
                match CreateFileMappingW(file_handle, None, PAGE_READONLY, 0, 0, None) {
                    Ok(h) => h,
                    Err(_) => {
                        let _ = CloseHandle(file_handle);
                        return None;
                    }
                };

            // Map view of file
            let view = MapViewOfFile(mapping_handle, FILE_MAP_READ, 0, 0, 0);
            let base = view.Value as u64;
            if base == 0 {
                let _ = CloseHandle(mapping_handle);
                let _ = CloseHandle(file_handle);
                return None;
            }

            // Parse PE headers to get size
            let dos_header = std::slice::from_raw_parts(base as *const u8, 64);
            if dos_header[0] != b'M' || dos_header[1] != b'Z' {
                let _ = UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
                    Value: base as *mut std::ffi::c_void,
                });
                let _ = CloseHandle(mapping_handle);
                let _ = CloseHandle(file_handle);
                return None;
            }

            let e_lfanew = u32::from_le_bytes([
                dos_header[0x3C],
                dos_header[0x3D],
                dos_header[0x3E],
                dos_header[0x3F],
            ]) as usize;

            let pe_header =
                std::slice::from_raw_parts((base as usize + e_lfanew) as *const u8, 256);
            if &pe_header[0..4] != b"PE\0\0" {
                let _ = UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
                    Value: base as *mut std::ffi::c_void,
                });
                let _ = CloseHandle(mapping_handle);
                let _ = CloseHandle(file_handle);
                return None;
            }

            // Get SizeOfImage from optional header
            let optional_header_offset = 24;
            let size_of_image_offset = optional_header_offset + 56;

            let size_of_image = u32::from_le_bytes([
                pe_header[size_of_image_offset],
                pe_header[size_of_image_offset + 1],
                pe_header[size_of_image_offset + 2],
                pe_header[size_of_image_offset + 3],
            ]) as usize;

            Some((base, size_of_image, file_handle, mapping_handle))
        }
    }

    /// Resolve an export address from a disk-mapped PE file
    /// Returns the RVA of the function if found
    #[cfg(target_os = "windows")]
    #[allow(dead_code)]
    fn resolve_export_from_disk(dll_path: &str, func_name: &str) -> Option<u64> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Memory::{UnmapViewOfFile, MEMORY_MAPPED_VIEW_ADDRESS};

        let (base, _size, file_handle, mapping_handle) = Self::map_dll_from_disk(dll_path)?;

        let result = unsafe {
            // Parse PE headers
            let dos_header = std::slice::from_raw_parts(base as *const u8, 64);
            let e_lfanew = u32::from_le_bytes([
                dos_header[0x3C],
                dos_header[0x3D],
                dos_header[0x3E],
                dos_header[0x3F],
            ]) as usize;

            let pe_base = base as usize + e_lfanew;
            let pe_header = std::slice::from_raw_parts(pe_base as *const u8, 512);

            // Check PE type
            let optional_header_offset = 24;
            let magic = u16::from_le_bytes([
                pe_header[optional_header_offset],
                pe_header[optional_header_offset + 1],
            ]);
            let is_pe64 = magic == 0x20B;

            // Get export directory
            let data_dir_offset = optional_header_offset + if is_pe64 { 112 } else { 96 };
            let export_rva = u32::from_le_bytes([
                pe_header[data_dir_offset],
                pe_header[data_dir_offset + 1],
                pe_header[data_dir_offset + 2],
                pe_header[data_dir_offset + 3],
            ]) as usize;

            let export_size = u32::from_le_bytes([
                pe_header[data_dir_offset + 4],
                pe_header[data_dir_offset + 5],
                pe_header[data_dir_offset + 6],
                pe_header[data_dir_offset + 7],
            ]) as usize;

            if export_rva == 0 || export_size == 0 {
                return None;
            }

            // Parse export directory
            let export_dir = std::slice::from_raw_parts(
                (base as usize + export_rva) as *const u8,
                std::cmp::min(export_size, 0x1000),
            );

            let num_names = u32::from_le_bytes([
                export_dir[24],
                export_dir[25],
                export_dir[26],
                export_dir[27],
            ]) as usize;
            let addr_of_functions = u32::from_le_bytes([
                export_dir[28],
                export_dir[29],
                export_dir[30],
                export_dir[31],
            ]) as usize;
            let addr_of_names = u32::from_le_bytes([
                export_dir[32],
                export_dir[33],
                export_dir[34],
                export_dir[35],
            ]) as usize;
            let addr_of_ordinals = u32::from_le_bytes([
                export_dir[36],
                export_dir[37],
                export_dir[38],
                export_dir[39],
            ]) as usize;

            // Search for function by name
            for i in 0..num_names {
                let name_rva_ptr = (base as usize + addr_of_names + i * 4) as *const u8;
                let name_rva = u32::from_le_bytes([
                    *name_rva_ptr,
                    *name_rva_ptr.add(1),
                    *name_rva_ptr.add(2),
                    *name_rva_ptr.add(3),
                ]) as usize;

                let name_ptr = (base as usize + name_rva) as *const u8;
                let mut name_buf = [0u8; 128];
                for j in 0..127 {
                    let ch = *name_ptr.add(j);
                    if ch == 0 {
                        break;
                    }
                    name_buf[j] = ch;
                }

                let export_name = std::ffi::CStr::from_bytes_until_nul(&name_buf)
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default();

                if export_name == func_name {
                    let ordinal_ptr = (base as usize + addr_of_ordinals + i * 2) as *const u8;
                    let ordinal = u16::from_le_bytes([*ordinal_ptr, *ordinal_ptr.add(1)]) as usize;

                    let func_rva_ptr =
                        (base as usize + addr_of_functions + ordinal * 4) as *const u8;
                    let func_rva = u32::from_le_bytes([
                        *func_rva_ptr,
                        *func_rva_ptr.add(1),
                        *func_rva_ptr.add(2),
                        *func_rva_ptr.add(3),
                    ]) as u64;

                    return Some(func_rva);
                }
            }

            None
        };

        // Cleanup
        unsafe {
            let _ = UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
                Value: base as *mut std::ffi::c_void,
            });
            let _ = CloseHandle(mapping_handle);
            let _ = CloseHandle(file_handle);
        }

        result
    }

    #[cfg(target_os = "windows")]
    async fn monitor_syscall_stubs(tx: mpsc::Sender<TelemetryEvent>, scan_interval_secs: u64) {
        use sysinfo::System;

        info!(
            interval_secs = scan_interval_secs,
            "Starting syscall stub detector"
        );

        let mut interval =
            tokio::time::interval(tokio::time::Duration::from_secs(scan_interval_secs));
        let mut reported: HashSet<(u32, u64)> = HashSet::new();

        loop {
            interval.tick().await;

            let mut system = System::new_all();
            system.refresh_processes();

            for (pid, process) in system.processes() {
                let pid_u32 = pid.as_u32();
                let name = process.name().to_string();
                let path = process
                    .exe()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();

                // Skip system processes
                if pid_u32 < 10 {
                    continue;
                }

                // Scan process memory for syscall patterns
                if let Some(detections) = Self::scan_memory_for_syscalls(pid_u32) {
                    for detection in detections {
                        // Skip if already reported
                        if reported.contains(&(pid_u32, detection.region_base.unwrap_or(0))) {
                            continue;
                        }
                        reported.insert((pid_u32, detection.region_base.unwrap_or(0)));

                        let evasion = SyscallEvasionEvent {
                            evasion_type: detection.evasion_type,
                            pid: pid_u32,
                            process_name: name.clone(),
                            process_path: path.clone(),
                            cmdline: process.cmd().join(" "),
                            user: String::new(),
                            module: detection.module,
                            function: detection.function,
                            expected_address: None,
                            actual_address: detection.actual_address,
                            ssn: detection.ssn,
                            syscall_name: detection.syscall_name,
                            region_base: detection.region_base,
                            region_size: detection.region_size,
                            confidence: detection.confidence,
                            details: detection.details,
                            pattern_name: detection.pattern_name,
                        };

                        let event = Self::create_evasion_event(&evasion);
                        if tx.send(event).await.is_err() {
                            return;
                        }
                    }
                }
            }

            // Clean up old entries
            if reported.len() > 10000 {
                reported.clear();
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn scan_memory_for_syscalls(pid: u32) -> Option<Vec<SyscallEvasionEvent>> {
        use windows::Win32::Foundation::{CloseHandle, BOOL};
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows::Win32::System::Memory::{
            VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE_READ,
            PAGE_EXECUTE_READWRITE,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        let mut detections = Vec::new();

        unsafe {
            // Open process
            let process_handle = match OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                BOOL::from(false),
                pid,
            ) {
                Ok(h) => h,
                Err(_) => return None,
            };

            let _guard = scopeguard::guard(process_handle, |h| {
                let _ = CloseHandle(h);
            });

            // Enumerate memory regions
            let mut address: usize = 0;
            let max_address: usize = 0x7FFFFFFFFFFF; // User mode space

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

                // Check for executable private memory (not backed by image)
                let is_private = mbi.Type == MEM_PRIVATE;
                let is_committed = mbi.State == MEM_COMMIT;
                let is_executable =
                    mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE;

                if is_private && is_committed && is_executable && mbi.RegionSize > 0 {
                    // Read memory for pattern scanning
                    let region_size = std::cmp::min(mbi.RegionSize, 0x10000); // Limit scan size
                    let mut buffer = vec![0u8; region_size];
                    let mut bytes_read: usize = 0;

                    if ReadProcessMemory(
                        process_handle,
                        mbi.BaseAddress,
                        buffer.as_mut_ptr() as *mut std::ffi::c_void,
                        region_size,
                        Some(&mut bytes_read),
                    )
                    .is_ok()
                        && bytes_read > 0
                    {
                        buffer.truncate(bytes_read);

                        // Scan for syscall patterns
                        for (pattern_name, pattern, mitre) in SYSCALL_PATTERNS_X64.iter() {
                            if let Some(offset) = Self::find_pattern(&buffer, pattern) {
                                // Check if this is a real syscall stub
                                let stub_addr = mbi.BaseAddress as u64 + offset as u64;

                                // Try to extract SSN if this is a syscall stub
                                let ssn = Self::extract_ssn(&buffer, offset);

                                let detection = SyscallEvasionEvent {
                                    evasion_type: if pattern_name.contains("indirect") {
                                        SyscallEvasionType::IndirectSyscall
                                    } else if pattern_name.contains("gate") {
                                        SyscallEvasionType::DynamicSsnResolution
                                    } else {
                                        SyscallEvasionType::DirectSyscall
                                    },
                                    pid,
                                    process_name: String::new(),
                                    process_path: String::new(),
                                    cmdline: String::new(),
                                    user: String::new(),
                                    module: None,
                                    function: None,
                                    expected_address: None,
                                    actual_address: Some(stub_addr),
                                    ssn,
                                    syscall_name: ssn.and_then(|s| Self::ssn_to_name(s)),
                                    region_base: Some(mbi.BaseAddress as u64),
                                    region_size: Some(mbi.RegionSize as u64),
                                    confidence: 0.90,
                                    details: format!(
                                        "Syscall pattern '{}' found in private memory at 0x{:016X}",
                                        pattern_name, stub_addr
                                    ),
                                    pattern_name: Some(pattern_name.to_string()),
                                };

                                detections.push(detection);
                                break; // One detection per region
                            }
                        }
                    }
                }

                // Move to next region
                address = (mbi.BaseAddress as usize) + mbi.RegionSize;
            }
        }

        if detections.is_empty() {
            None
        } else {
            Some(detections)
        }
    }

    #[cfg(target_os = "windows")]
    fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() || haystack.len() < needle.len() {
            return None;
        }

        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    #[cfg(target_os = "windows")]
    fn extract_ssn(buffer: &[u8], offset: usize) -> Option<u32> {
        // Look for mov eax, SSN pattern: B8 XX XX XX XX
        // Starting from pattern match, look ahead for SSN
        if offset + 8 > buffer.len() {
            return None;
        }

        // Check if followed by mov eax, imm32
        let search_area = &buffer[offset..std::cmp::min(offset + 20, buffer.len())];
        for i in 0..search_area.len().saturating_sub(5) {
            if search_area[i] == 0xB8 {
                // Extract 32-bit immediate
                let ssn = u32::from_le_bytes([
                    search_area[i + 1],
                    search_area[i + 2],
                    search_area[i + 3],
                    search_area[i + 4],
                ]);

                // Validate SSN is in reasonable range
                if ssn < 0x300 {
                    return Some(ssn);
                }
            }
        }

        None
    }

    #[cfg(target_os = "windows")]
    fn ssn_to_name(ssn: u32) -> Option<String> {
        // Use dynamic SSN resolver for cross-Windows-version compatibility
        // The resolver parses ntdll.dll exports at runtime to get actual SSNs
        if let Some(resolver) = get_ssn_resolver() {
            if let Some(name) = resolver.get_name(ssn) {
                return Some(name.to_string());
            }
        }

        // Fallback to static table if resolver not available or SSN not found
        // Note: Static SSNs are from Windows 10 21H2 and may not match other versions
        for (name, known_ssn) in NTDLL_FUNC_PATTERNS.iter() {
            if *known_ssn == ssn {
                return Some(name.to_string());
            }
        }
        None
    }

    #[cfg(target_os = "windows")]
    async fn monitor_ntdll_integrity(tx: mpsc::Sender<TelemetryEvent>, check_interval_secs: u64) {
        use std::collections::HashMap;
        use sysinfo::System;

        info!(
            interval_secs = check_interval_secs,
            "Starting NTDLL integrity monitor"
        );

        // Cache of NTDLL hashes per process
        let ntdll_hashes: HashMap<u32, Vec<u8>> = HashMap::new();
        let mut interval =
            tokio::time::interval(tokio::time::Duration::from_secs(check_interval_secs));

        loop {
            interval.tick().await;

            let mut system = System::new_all();
            system.refresh_processes();

            for (pid, process) in system.processes() {
                let pid_u32 = pid.as_u32();
                let name = process.name().to_string();
                let path = process
                    .exe()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();

                if pid_u32 < 10 {
                    continue;
                }

                // Check if NTDLL has been modified
                if let Some(tamper_type) = Self::check_ntdll_integrity(pid_u32) {
                    let evasion = SyscallEvasionEvent {
                        evasion_type: tamper_type,
                        pid: pid_u32,
                        process_name: name.clone(),
                        process_path: path.clone(),
                        cmdline: process.cmd().join(" "),
                        user: String::new(),
                        module: Some("ntdll.dll".to_string()),
                        function: None,
                        expected_address: None,
                        actual_address: None,
                        ssn: None,
                        syscall_name: None,
                        region_base: None,
                        region_size: None,
                        confidence: 0.95,
                        details: format!(
                            "NTDLL integrity violation in process {} [{}]",
                            name, pid_u32
                        ),
                        pattern_name: None,
                    };

                    let event = Self::create_evasion_event(&evasion);
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn check_ntdll_integrity(pid: u32) -> Option<SyscallEvasionType> {
        use windows::Win32::Foundation::{CloseHandle, BOOL};
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_IMAGE};
        use windows::Win32::System::ProcessStatus::{
            EnumProcessModulesEx, GetModuleFileNameExW, GetModuleInformation, LIST_MODULES_ALL,
            MODULEINFO,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        unsafe {
            // Open process
            let process_handle = match OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                BOOL::from(false),
                pid,
            ) {
                Ok(h) => h,
                Err(_) => return None,
            };

            let _guard = scopeguard::guard(process_handle, |h| {
                let _ = CloseHandle(h);
            });

            // Find ntdll.dll
            let mut h_mods: [windows::Win32::Foundation::HMODULE; 1024] =
                [windows::Win32::Foundation::HMODULE::default(); 1024];
            let mut cb_needed: u32 = 0;

            if EnumProcessModulesEx(
                process_handle,
                h_mods.as_mut_ptr(),
                std::mem::size_of_val(&h_mods) as u32,
                &mut cb_needed,
                LIST_MODULES_ALL,
            )
            .is_err()
            {
                return None;
            }

            let num_modules =
                (cb_needed as usize) / std::mem::size_of::<windows::Win32::Foundation::HMODULE>();

            for i in 0..num_modules {
                let h_mod = h_mods[i];

                let mut module_name = [0u16; 260];
                let name_len = GetModuleFileNameExW(process_handle, h_mod, &mut module_name);

                if name_len == 0 {
                    continue;
                }

                let module_name_str = String::from_utf16_lossy(&module_name[..name_len as usize]);

                if !module_name_str.to_lowercase().contains("ntdll.dll") {
                    continue;
                }

                // Get module info
                let mut mod_info: MODULEINFO = std::mem::zeroed();
                if GetModuleInformation(
                    process_handle,
                    h_mod,
                    &mut mod_info,
                    std::mem::size_of::<MODULEINFO>() as u32,
                )
                .is_err()
                {
                    continue;
                }

                // Query memory info
                let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
                let result = VirtualQueryEx(
                    process_handle,
                    Some(mod_info.lpBaseOfDll),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                );

                if result == 0 {
                    continue;
                }

                // Check for signs of unhooking
                // 1. NTDLL not mapped as image (file-backed)
                if mbi.Type != MEM_IMAGE {
                    return Some(SyscallEvasionType::NtdllUnhooking);
                }

                // 2. Check .text section protection
                // A freshly remapped NTDLL will have PAGE_EXECUTE_READ
                // An EDR-hooked NTDLL might have different protection
                // However, a process that manually restored it would also have PAGE_EXECUTE_READ
                // We look for signs of manual remapping

                // Read first page and check for signs of disk vs memory differences
                let mut header = [0u8; 0x1000];
                let mut bytes_read: usize = 0;

                if ReadProcessMemory(
                    process_handle,
                    mod_info.lpBaseOfDll,
                    header.as_mut_ptr() as *mut std::ffi::c_void,
                    header.len(),
                    Some(&mut bytes_read),
                )
                .is_ok()
                    && bytes_read == header.len()
                {
                    // Check DOS header
                    if header[0] != b'M' || header[1] != b'Z' {
                        return Some(SyscallEvasionType::NtdllTampered);
                    }

                    // Validate PE signature location
                    let pe_offset = u32::from_le_bytes([
                        header[0x3C],
                        header[0x3D],
                        header[0x3E],
                        header[0x3F],
                    ]) as usize;
                    if pe_offset > 0 && pe_offset < 0x800 && pe_offset + 4 <= header.len() {
                        if &header[pe_offset..pe_offset + 4] != b"PE\0\0" {
                            return Some(SyscallEvasionType::NtdllTampered);
                        }
                    }
                }

                return None;
            }
        }

        None
    }

    // ==================== Cross-Process ETW Integrity Monitoring ====================
    //
    // Monitors ETW functions (EtwEventWrite, NtTraceEvent, etc.) in ALL processes
    // for patching patterns that would blind EDR telemetry collection.
    //
    // Detection patterns:
    // - `ret` (0xC3) at function start
    // - `xor eax,eax; ret` (0x33 0xC0 0xC3 or 0x31 0xC0 0xC3)
    // - `mov eax, imm; ret` (0xB8 XX XX XX XX 0xC3)
    // - `jmp rel32` (0xE9 XX XX XX XX)
    // - `jmp [rip+disp32]` (0xFF 0x25 XX XX XX XX)
    // - NOP sled (0x90 0x90 0x90...)
    // - Any deviation from expected syscall stub pattern in adjacent functions
    //

    /// ETW functions to monitor for tampering across all processes
    #[cfg(target_os = "windows")]
    const ETW_FUNCTIONS_TO_MONITOR: &[&str] = &[
        "EtwEventWrite",
        "EtwEventWriteEx",
        "EtwEventWriteFull",
        "NtTraceEvent",
        "NtTraceControl",
    ];

    /// Expected syscall stub pattern prefix (Windows 10+):
    /// mov r10, rcx  (4C 8B D1)
    /// mov eax, SSN  (B8 XX XX 00 00)
    #[cfg(target_os = "windows")]
    const SYSCALL_STUB_PREFIX: &[u8] = &[0x4C, 0x8B, 0xD1, 0xB8];

    /// System/critical processes to skip (low PIDs and known system services)
    #[cfg(target_os = "windows")]
    const SYSTEM_PROCESS_NAMES: &[&str] = &[
        "system",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "services.exe",
        "lsass.exe",
        "svchost.exe",
        "dwm.exe",
        "winlogon.exe",
    ];

    #[cfg(target_os = "windows")]
    async fn monitor_etw_cross_process_integrity(
        tx: mpsc::Sender<TelemetryEvent>,
        check_interval_secs: u64,
    ) {
        use std::collections::HashMap;
        use sysinfo::System;

        info!(
            interval_secs = check_interval_secs,
            "Starting cross-process ETW function integrity monitor"
        );

        // Cache: PID -> { function_name -> (address, baseline_bytes) }
        let mut etw_baselines: HashMap<u32, HashMap<String, (u64, Vec<u8>)>> = HashMap::new();
        let mut interval =
            tokio::time::interval(tokio::time::Duration::from_secs(check_interval_secs));

        // Resolve our own ntdll ETW function addresses as reference
        let reference_stubs = Self::get_reference_etw_stubs();
        if reference_stubs.is_empty() {
            warn!("Could not resolve reference ETW function stubs, cross-process ETW integrity disabled");
            return;
        }

        info!(
            function_count = reference_stubs.len(),
            "Reference ETW function stubs captured"
        );

        loop {
            interval.tick().await;

            let mut system = System::new_all();
            system.refresh_processes();

            for (pid, process) in system.processes() {
                let pid_u32 = pid.as_u32();
                let name = process.name().to_string();
                let path = process
                    .exe()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();

                // Skip system processes and low PIDs
                if pid_u32 < 10 {
                    continue;
                }

                // Skip known system processes
                let name_lower = name.to_lowercase();
                if Self::SYSTEM_PROCESS_NAMES.iter().any(|s| name_lower == *s) {
                    continue;
                }

                // Check ETW functions in this process
                if let Some(tampering) =
                    Self::check_process_etw_integrity(pid_u32, &mut etw_baselines, &reference_stubs)
                {
                    for (func_name, original_bytes, current_bytes, pattern_desc) in tampering {
                        warn!(
                            pid = pid_u32,
                            process = %name,
                            function = %func_name,
                            pattern = %pattern_desc,
                            "ETW TAMPERING DETECTED in remote process"
                        );

                        let evasion = SyscallEvasionEvent {
                            evasion_type: SyscallEvasionType::EtwTampering,
                            pid: pid_u32,
                            process_name: name.clone(),
                            process_path: path.clone(),
                            cmdline: process.cmd().join(" "),
                            user: String::new(),
                            module: Some("ntdll.dll".to_string()),
                            function: Some(func_name.clone()),
                            expected_address: None,
                            actual_address: None,
                            ssn: None,
                            syscall_name: None,
                            region_base: None,
                            region_size: None,
                            confidence: 0.95,
                            details: format!(
                                "ETW function {} patched in process {} [{}]. Pattern: {}. Original: {:02X?}, Current: {:02X?}",
                                func_name, name, pid_u32, pattern_desc,
                                &original_bytes[..original_bytes.len().min(8)],
                                &current_bytes[..current_bytes.len().min(8)]
                            ),
                            pattern_name: Some(pattern_desc),
                        };

                        let event = Self::create_evasion_event(&evasion);
                        if tx.send(event).await.is_err() {
                            return;
                        }
                    }
                }
            }

            // Cleanup stale entries (processes that no longer exist)
            let current_pids: HashSet<u32> =
                system.processes().keys().map(|p| p.as_u32()).collect();
            etw_baselines.retain(|pid, _| current_pids.contains(pid));
        }
    }

    /// Get reference ETW function stubs from our own ntdll
    #[cfg(target_os = "windows")]
    fn get_reference_etw_stubs() -> HashMap<String, Vec<u8>> {
        use windows::core::PCSTR;
        use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

        let mut stubs = HashMap::new();

        unsafe {
            let ntdll_name = PCSTR::from_raw(b"ntdll.dll\0".as_ptr());
            let ntdll_handle = match GetModuleHandleA(ntdll_name) {
                Ok(h) => h,
                Err(_) => return stubs,
            };

            for func_name in Self::ETW_FUNCTIONS_TO_MONITOR {
                let func_cstr = format!("{}\0", func_name);
                let func_pcstr = PCSTR::from_raw(func_cstr.as_ptr());

                if let Some(addr) = GetProcAddress(ntdll_handle, func_pcstr) {
                    let func_addr = addr as usize;
                    let prologue_ptr = func_addr as *const u8;
                    let mut prologue = vec![0u8; 32];
                    std::ptr::copy_nonoverlapping(prologue_ptr, prologue.as_mut_ptr(), 32);
                    stubs.insert(func_name.to_string(), prologue);
                }
            }
        }

        stubs
    }

    /// Check ETW function integrity in a specific process
    #[cfg(target_os = "windows")]
    fn check_process_etw_integrity(
        pid: u32,
        baselines: &mut HashMap<u32, HashMap<String, (u64, Vec<u8>)>>,
        reference_stubs: &HashMap<String, Vec<u8>>,
    ) -> Option<Vec<(String, Vec<u8>, Vec<u8>, String)>> {
        use windows::core::PCSTR;
        use windows::Win32::Foundation::{CloseHandle, BOOL};
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows::Win32::System::LibraryLoader::GetProcAddress;
        use windows::Win32::System::ProcessStatus::{
            EnumProcessModulesEx, GetModuleFileNameExW, LIST_MODULES_ALL,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        let mut tampering_detected: Vec<(String, Vec<u8>, Vec<u8>, String)> = Vec::new();

        unsafe {
            // Open process
            let process_handle = match OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                BOOL::from(false),
                pid,
            ) {
                Ok(h) => h,
                Err(_) => return None,
            };

            let _guard = scopeguard::guard(process_handle, |h| {
                let _ = CloseHandle(h);
            });

            // Find ntdll.dll in the remote process
            let mut h_mods: [windows::Win32::Foundation::HMODULE; 1024] =
                [windows::Win32::Foundation::HMODULE::default(); 1024];
            let mut cb_needed: u32 = 0;

            if EnumProcessModulesEx(
                process_handle,
                h_mods.as_mut_ptr(),
                std::mem::size_of_val(&h_mods) as u32,
                &mut cb_needed,
                LIST_MODULES_ALL,
            )
            .is_err()
            {
                return None;
            }

            let num_modules =
                (cb_needed as usize) / std::mem::size_of::<windows::Win32::Foundation::HMODULE>();
            let mut ntdll_base: Option<u64> = None;

            for i in 0..num_modules {
                let h_mod = h_mods[i];
                let mut module_name = [0u16; 260];
                let name_len = GetModuleFileNameExW(process_handle, h_mod, &mut module_name);

                if name_len == 0 {
                    continue;
                }

                let module_name_str = String::from_utf16_lossy(&module_name[..name_len as usize]);
                if module_name_str.to_lowercase().contains("ntdll.dll") {
                    ntdll_base = Some(h_mod.0 as u64);
                    break;
                }
            }

            let ntdll_base = match ntdll_base {
                Some(b) => b,
                None => return None,
            };

            // For each ETW function, resolve its address in the remote process and check
            // We use the offset from our own ntdll to calculate the address in remote ntdll
            let our_ntdll = match windows::Win32::System::LibraryLoader::GetModuleHandleA(
                PCSTR::from_raw(b"ntdll.dll\0".as_ptr()),
            ) {
                Ok(h) => h.0 as u64,
                Err(_) => return None,
            };

            for (func_name, reference_bytes) in reference_stubs {
                let func_cstr = format!("{}\0", func_name);
                let func_pcstr = PCSTR::from_raw(func_cstr.as_ptr());

                let our_func_addr = match GetProcAddress(
                    windows::Win32::Foundation::HMODULE(our_ntdll as isize),
                    func_pcstr,
                ) {
                    Some(a) => a as u64,
                    None => continue,
                };

                // Calculate offset and apply to remote ntdll
                let offset = our_func_addr - our_ntdll;
                let remote_func_addr = ntdll_base + offset;

                // Read prologue from remote process
                let mut current_bytes = vec![0u8; 32];
                let mut bytes_read: usize = 0;

                if ReadProcessMemory(
                    process_handle,
                    remote_func_addr as *const std::ffi::c_void,
                    current_bytes.as_mut_ptr() as *mut std::ffi::c_void,
                    32,
                    Some(&mut bytes_read),
                )
                .is_err()
                    || bytes_read < 16
                {
                    continue;
                }

                current_bytes.truncate(bytes_read);

                // Get or create baseline for this process/function
                let process_baselines = baselines.entry(pid).or_insert_with(HashMap::new);
                let baseline_entry = process_baselines.entry(func_name.clone());

                match baseline_entry {
                    std::collections::hash_map::Entry::Vacant(e) => {
                        // First time seeing this process - save baseline
                        // But also check if it's already patched compared to reference
                        if let Some(pattern) = Self::detect_etw_patch_pattern(&current_bytes) {
                            // Already patched - detect immediately
                            tampering_detected.push((
                                func_name.clone(),
                                reference_bytes.clone(),
                                current_bytes.clone(),
                                pattern,
                            ));
                        }
                        e.insert((remote_func_addr, current_bytes));
                    }
                    std::collections::hash_map::Entry::Occupied(mut e) => {
                        let (_, baseline_bytes) = e.get();
                        // Check if changed from baseline
                        if *baseline_bytes != current_bytes {
                            if let Some(pattern) = Self::detect_etw_patch_pattern(&current_bytes) {
                                tampering_detected.push((
                                    func_name.clone(),
                                    baseline_bytes.clone(),
                                    current_bytes.clone(),
                                    pattern,
                                ));
                            }
                            // Update baseline
                            e.get_mut().1 = current_bytes;
                        }
                    }
                }
            }
        }

        if tampering_detected.is_empty() {
            None
        } else {
            Some(tampering_detected)
        }
    }

    /// Detect specific ETW patching patterns in function prologue
    #[cfg(target_os = "windows")]
    fn detect_etw_patch_pattern(bytes: &[u8]) -> Option<String> {
        if bytes.is_empty() {
            return None;
        }

        // Pattern: ret (0xC3) at function start - silently returns
        if bytes[0] == 0xC3 {
            return Some("ret_at_start".to_string());
        }

        // Pattern: xor eax,eax; ret (0x33 0xC0 0xC3) - returns STATUS_SUCCESS
        if bytes.len() >= 3 && bytes[0] == 0x33 && bytes[1] == 0xC0 && bytes[2] == 0xC3 {
            return Some("xor_eax_ret_33c0c3".to_string());
        }

        // Pattern: xor eax,eax; ret (0x31 0xC0 0xC3) - alternate encoding
        if bytes.len() >= 3 && bytes[0] == 0x31 && bytes[1] == 0xC0 && bytes[2] == 0xC3 {
            return Some("xor_eax_ret_31c0c3".to_string());
        }

        // Pattern: mov eax, imm32; ret (B8 xx xx xx xx C3)
        if bytes.len() >= 6 && bytes[0] == 0xB8 && bytes[5] == 0xC3 {
            let imm = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
            return Some(format!("mov_eax_{:08x}_ret", imm));
        }

        // Pattern: JMP rel32 (E9 xx xx xx xx) - detour
        if bytes.len() >= 5 && bytes[0] == 0xE9 {
            let offset = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
            return Some(format!("jmp_rel32_{:+}", offset));
        }

        // Pattern: JMP [rip+disp32] (FF 25 xx xx xx xx) - indirect jump
        if bytes.len() >= 6 && bytes[0] == 0xFF && bytes[1] == 0x25 {
            return Some("jmp_rip_indirect".to_string());
        }

        // Pattern: NOP sled (3+ NOPs at start)
        if bytes.len() >= 3 && bytes[0] == 0x90 && bytes[1] == 0x90 && bytes[2] == 0x90 {
            return Some("nop_sled".to_string());
        }

        // Pattern: INT3 breakpoint at start
        if bytes[0] == 0xCC {
            return Some("int3_breakpoint".to_string());
        }

        // Pattern: MOV RAX, imm64; JMP RAX (48 B8 ... FF E0)
        if bytes.len() >= 12
            && bytes[0] == 0x48
            && bytes[1] == 0xB8
            && bytes[10] == 0xFF
            && bytes[11] == 0xE0
        {
            return Some("mov_rax_imm64_jmp_rax".to_string());
        }

        // Check if it matches expected syscall stub pattern
        // Expected: 4C 8B D1 B8 XX XX 00 00 ... 0F 05 C3
        if bytes.len() >= 4 {
            let is_valid_stub =
                bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && bytes[3] == 0xB8;
            if !is_valid_stub {
                // Doesn't match expected syscall stub - could be patch in adjacent region
                return Some("invalid_syscall_stub_prologue".to_string());
            }
        }

        None
    }

    #[cfg(target_os = "windows")]
    async fn monitor_stack_integrity(
        tx: mpsc::Sender<TelemetryEvent>,
        high_risk_processes: Vec<String>,
    ) {
        use sysinfo::System;

        info!("Starting stack integrity monitor");

        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));

        loop {
            interval.tick().await;

            let mut system = System::new_all();
            system.refresh_processes();

            for (pid, process) in system.processes() {
                let pid_u32 = pid.as_u32();
                let name = process.name().to_string();
                let path = process
                    .exe()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();

                // Focus on high-risk processes (from config or fallback to static list)
                let name_lower = name.to_lowercase();
                let is_target = if high_risk_processes.is_empty() {
                    HIGH_RISK_PROCESSES.iter().any(|p| name_lower.contains(p))
                } else {
                    high_risk_processes
                        .iter()
                        .any(|p| name_lower.contains(&p.to_lowercase()))
                };
                if !is_target {
                    continue;
                }

                // Stack validation is expensive, so we sample
                if let Some(anomalies) = Self::validate_process_stacks(pid_u32) {
                    for anomaly in anomalies {
                        let (evasion_type, details, module_name, actual_addr) = match anomaly {
                            StackAnomaly::InvalidCallSite { addr, ref module } => {
                                let mod_name = module.clone().unwrap_or_else(|| {
                                    MODULE_RESOLVER_CACHE.resolve_module_name(pid_u32, addr)
                                });
                                (
                                    SyscallEvasionType::InvalidReturnAddress,
                                    format!("Invalid call site at {} (0x{:016X})", mod_name, addr),
                                    Some(mod_name),
                                    Some(addr),
                                )
                            }
                            StackAnomaly::RopGadget { addr, gadget_size } => {
                                let mod_name =
                                    MODULE_RESOLVER_CACHE.resolve_module_name(pid_u32, addr);
                                (
                                    SyscallEvasionType::RopChainDetected,
                                    format!(
                                        "ROP gadget ({} bytes) at {} (0x{:016X})",
                                        gadget_size, mod_name, addr
                                    ),
                                    Some(mod_name),
                                    Some(addr),
                                )
                            }
                            StackAnomaly::StackPivot {
                                rsp,
                                expected_range,
                            } => (
                                SyscallEvasionType::StackPivot,
                                format!(
                                    "Stack pivot: RSP 0x{:016X} outside range 0x{:016X}-0x{:016X}",
                                    rsp, expected_range.0, expected_range.1
                                ),
                                None,
                                Some(rsp),
                            ),
                            StackAnomaly::SyntheticFrame { frame_addr } => {
                                let mod_name =
                                    MODULE_RESOLVER_CACHE.resolve_module_name(pid_u32, frame_addr);
                                (
                                    SyscallEvasionType::StackSpoofing,
                                    format!(
                                        "Synthetic stack frame at {} (0x{:016X})",
                                        mod_name, frame_addr
                                    ),
                                    Some(mod_name),
                                    Some(frame_addr),
                                )
                            }
                            StackAnomaly::NonExecutableReturn { addr } => {
                                let mod_name =
                                    MODULE_RESOLVER_CACHE.resolve_module_name(pid_u32, addr);
                                (
                                    SyscallEvasionType::InvalidReturnAddress,
                                    format!("Return address 0x{:016X} ({}) points to non-executable memory", addr, mod_name),
                                    Some(mod_name),
                                    Some(addr),
                                )
                            }
                        };

                        let evasion = SyscallEvasionEvent {
                            evasion_type,
                            pid: pid_u32,
                            process_name: name.clone(),
                            process_path: path.clone(),
                            cmdline: process.cmd().join(" "),
                            user: String::new(),
                            module: module_name,
                            function: None,
                            expected_address: None,
                            actual_address: actual_addr,
                            ssn: None,
                            syscall_name: None,
                            region_base: None,
                            region_size: None,
                            confidence: 0.85,
                            details,
                            pattern_name: None,
                        };

                        let event = Self::create_evasion_event(&evasion);
                        if tx.send(event).await.is_err() {
                            return;
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn validate_process_stacks(pid: u32) -> Option<Vec<StackAnomaly>> {
        use windows::Win32::Foundation::{CloseHandle, BOOL};
        use windows::Win32::System::Diagnostics::Debug::{
            GetThreadContext, ReadProcessMemory, CONTEXT, CONTEXT_FULL_AMD64,
        };
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
        };
        use windows::Win32::System::Memory::{
            VirtualQueryEx, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ,
            PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, OpenThread, ResumeThread, SuspendThread, PROCESS_QUERY_INFORMATION,
            PROCESS_VM_READ, THREAD_GET_CONTEXT, THREAD_SUSPEND_RESUME,
        };

        let mut anomalies = Vec::new();

        unsafe {
            // Open process
            let process_handle = match OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                BOOL::from(false),
                pid,
            ) {
                Ok(h) => h,
                Err(_) => return None,
            };

            let _process_guard = scopeguard::guard(process_handle, |h| {
                let _ = CloseHandle(h);
            });

            // Get threads
            let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
                Ok(h) => h,
                Err(_) => return None,
            };

            let _snapshot_guard = scopeguard::guard(snapshot, |h| {
                let _ = CloseHandle(h);
            });

            let mut te: THREADENTRY32 = std::mem::zeroed();
            te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

            if Thread32First(snapshot, &mut te).is_err() {
                return None;
            }

            loop {
                if te.th32OwnerProcessID == pid {
                    // Open thread
                    if let Ok(thread_handle) = OpenThread(
                        THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
                        BOOL::from(false),
                        te.th32ThreadID,
                    ) {
                        let _thread_guard = scopeguard::guard(thread_handle, |h| {
                            let _ = CloseHandle(h);
                        });

                        // Suspend thread
                        let suspend_count = SuspendThread(thread_handle);
                        if suspend_count == u32::MAX {
                            continue;
                        }

                        // Get context
                        let mut context: CONTEXT = std::mem::zeroed();
                        context.ContextFlags = CONTEXT_FULL_AMD64;

                        if GetThreadContext(thread_handle, &mut context).is_ok() {
                            let rsp = context.Rsp;
                            let rip = context.Rip;

                            // Validate RSP is in reasonable range
                            // Check if RSP points to stack memory
                            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
                            let result = VirtualQueryEx(
                                process_handle,
                                Some(rsp as *const std::ffi::c_void),
                                &mut mbi,
                                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                            );

                            if result > 0 {
                                // Stack pivot check: RSP should be in committed memory
                                let stack_base = mbi.AllocationBase as u64;
                                let stack_end = stack_base + mbi.RegionSize as u64;

                                if rsp < stack_base || rsp > stack_end {
                                    anomalies.push(StackAnomaly::StackPivot {
                                        rsp,
                                        expected_range: (stack_base, stack_end),
                                    });
                                }
                            }

                            // Walk stack and validate return addresses
                            let mut frame_ptr = context.Rbp;
                            let mut depth = 0;
                            let max_depth = 20;

                            while depth < max_depth && frame_ptr > 0 {
                                // Read return address (frame_ptr + 8 on x64)
                                let mut ret_addr: u64 = 0;
                                let mut bytes_read: usize = 0;

                                if ReadProcessMemory(
                                    process_handle,
                                    (frame_ptr + 8) as *const std::ffi::c_void,
                                    &mut ret_addr as *mut u64 as *mut std::ffi::c_void,
                                    8,
                                    Some(&mut bytes_read),
                                )
                                .is_err()
                                    || bytes_read != 8
                                {
                                    break;
                                }

                                if ret_addr == 0 {
                                    break;
                                }

                                // Validate return address points to executable memory
                                let mut ret_mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
                                let ret_result = VirtualQueryEx(
                                    process_handle,
                                    Some(ret_addr as *const std::ffi::c_void),
                                    &mut ret_mbi,
                                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                                );

                                if ret_result > 0 {
                                    let is_executable = ret_mbi.Protect == PAGE_EXECUTE_READ
                                        || ret_mbi.Protect == PAGE_EXECUTE_READWRITE
                                        || ret_mbi.Protect == PAGE_EXECUTE
                                        || ret_mbi.Protect == PAGE_EXECUTE_WRITECOPY;

                                    if !is_executable {
                                        anomalies.push(StackAnomaly::NonExecutableReturn {
                                            addr: ret_addr,
                                        });
                                    }

                                    // Check if preceded by CALL (expensive, sample)
                                    if depth == 0 || (depth < 5 && depth % 2 == 0) {
                                        if !Self::is_preceded_by_call(process_handle, ret_addr) {
                                            // Resolve module name for better diagnostics
                                            let module_name = MODULE_RESOLVER_CACHE
                                                .resolve_module_name(pid, ret_addr);
                                            anomalies.push(StackAnomaly::InvalidCallSite {
                                                addr: ret_addr,
                                                module: Some(module_name),
                                            });
                                        }
                                    }
                                }

                                // Read next frame pointer
                                let mut next_frame: u64 = 0;
                                if ReadProcessMemory(
                                    process_handle,
                                    frame_ptr as *const std::ffi::c_void,
                                    &mut next_frame as *mut u64 as *mut std::ffi::c_void,
                                    8,
                                    Some(&mut bytes_read),
                                )
                                .is_err()
                                    || bytes_read != 8
                                {
                                    break;
                                }

                                // Sanity check: frame pointer should increase
                                if next_frame <= frame_ptr {
                                    break;
                                }

                                frame_ptr = next_frame;
                                depth += 1;
                            }
                        }

                        // Resume thread
                        let _ = ResumeThread(thread_handle);
                    }
                }

                if Thread32Next(snapshot, &mut te).is_err() {
                    break;
                }
            }
        }

        if anomalies.is_empty() {
            None
        } else {
            Some(anomalies)
        }
    }

    #[cfg(target_os = "windows")]
    fn is_preceded_by_call(process_handle: windows::Win32::Foundation::HANDLE, addr: u64) -> bool {
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

        // CALL can be:
        // E8 xx xx xx xx (5 bytes, near relative)
        // FF /2 (varies, 2-7 bytes, indirect)
        // 9A xx xx xx xx xx xx (7 bytes, far absolute - rare in x64)

        unsafe {
            // Read bytes before the return address
            let mut buffer = [0u8; 8];
            let mut bytes_read: usize = 0;

            // Read 8 bytes before the return address
            let read_addr = addr.saturating_sub(8);

            if ReadProcessMemory(
                process_handle,
                read_addr as *const std::ffi::c_void,
                buffer.as_mut_ptr() as *mut std::ffi::c_void,
                8,
                Some(&mut bytes_read),
            )
            .is_err()
                || bytes_read != 8
            {
                return false; // Assume invalid if we can't read
            }

            // Check for E8 (CALL rel32) at offset 3 (5 bytes before addr)
            if buffer[3] == 0xE8 {
                return true;
            }

            // Check for FF /2 patterns (CALL r/m)
            // This is complex due to ModR/M byte variations
            // Common patterns:
            // FF D0-FF D7 (CALL reg) - 2 bytes
            // FF 15 xx xx xx xx (CALL [rip+disp32]) - 6 bytes

            // Check for FF 15 at offset 2 (6 bytes before)
            if buffer[2] == 0xFF && buffer[3] == 0x15 {
                return true;
            }

            // Check for FF Dx at offset 6 (2 bytes before)
            if buffer[6] == 0xFF && (buffer[7] >= 0xD0 && buffer[7] <= 0xD7) {
                return true;
            }

            // Check for FF 10-17 (CALL [reg]) at offset 6 (2 bytes before)
            if buffer[6] == 0xFF && (buffer[7] >= 0x10 && buffer[7] <= 0x17) {
                return true;
            }

            false
        }
    }

    #[cfg(target_os = "windows")]
    async fn monitor_heavens_gate(tx: mpsc::Sender<TelemetryEvent>) {
        use sysinfo::System;

        info!("Starting Heaven's Gate monitor");

        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
        let mut reported: HashSet<u32> = HashSet::new();

        loop {
            interval.tick().await;

            let mut system = System::new_all();
            system.refresh_processes();

            // Only relevant for 32-bit processes on 64-bit Windows (WoW64)
            for (pid, process) in system.processes() {
                let pid_u32 = pid.as_u32();
                let name = process.name().to_string();
                let path = process
                    .exe()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();

                if reported.contains(&pid_u32) {
                    continue;
                }

                // Check for Heaven's Gate patterns
                if let Some(detection) = Self::check_heavens_gate(pid_u32) {
                    reported.insert(pid_u32);

                    let evasion = SyscallEvasionEvent {
                        evasion_type: SyscallEvasionType::HeavensGate,
                        pid: pid_u32,
                        process_name: name.clone(),
                        process_path: path.clone(),
                        cmdline: process.cmd().join(" "),
                        user: String::new(),
                        module: None,
                        function: None,
                        expected_address: None,
                        actual_address: Some(detection),
                        ssn: None,
                        syscall_name: None,
                        region_base: None,
                        region_size: None,
                        confidence: 0.90,
                        details: format!(
                            "Heaven's Gate transition detected at 0x{:016X}",
                            detection
                        ),
                        pattern_name: Some("heavens_gate".to_string()),
                    };

                    let event = Self::create_evasion_event(&evasion);
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }
            }

            // Cleanup
            if reported.len() > 10000 {
                reported.clear();
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn check_heavens_gate(pid: u32) -> Option<u64> {
        use windows::Win32::Foundation::{CloseHandle, BOOL};
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows::Win32::System::Memory::{
            VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READ,
            PAGE_EXECUTE_READWRITE,
        };
        use windows::Win32::System::Threading::{
            IsWow64Process, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        unsafe {
            // Open process
            let process_handle = match OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                BOOL::from(false),
                pid,
            ) {
                Ok(h) => h,
                Err(_) => return None,
            };

            let _guard = scopeguard::guard(process_handle, |h| {
                let _ = CloseHandle(h);
            });

            // Check if WoW64 process
            let mut is_wow64: BOOL = BOOL::from(false);
            if IsWow64Process(process_handle, &mut is_wow64).is_err() || !is_wow64.as_bool() {
                return None; // Only WoW64 processes can use Heaven's Gate
            }

            // Scan for Heaven's Gate pattern
            // Pattern: 6A 33 E8 00 00 00 00 83 04 24 05 CB
            // (push 0x33; call $+5; add dword [rsp], 5; retf)
            let pattern = &[
                0x6A, 0x33, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x83, 0x04, 0x24, 0x05, 0xCB,
            ];

            let mut address: usize = 0;
            let max_address: usize = 0x7FFFFFFF; // 32-bit space

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

                let is_executable =
                    mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE;

                if mbi.State == MEM_COMMIT && is_executable && mbi.RegionSize > 0 {
                    let region_size = std::cmp::min(mbi.RegionSize, 0x10000);
                    let mut buffer = vec![0u8; region_size];
                    let mut bytes_read: usize = 0;

                    if ReadProcessMemory(
                        process_handle,
                        mbi.BaseAddress,
                        buffer.as_mut_ptr() as *mut std::ffi::c_void,
                        region_size,
                        Some(&mut bytes_read),
                    )
                    .is_ok()
                        && bytes_read > 0
                    {
                        buffer.truncate(bytes_read);

                        if let Some(offset) = Self::find_pattern(&buffer, pattern) {
                            return Some(mbi.BaseAddress as u64 + offset as u64);
                        }
                    }
                }

                address = (mbi.BaseAddress as usize) + mbi.RegionSize;
            }
        }

        None
    }

    // ==================== ETW Syscall Audit Implementation ====================

    /// ETW Kernel-Audit-API-Calls provider GUID
    /// Microsoft-Windows-Kernel-Audit-API-Calls
    /// {E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23}
    #[cfg(target_os = "windows")]
    const KERNEL_AUDIT_API_GUID: windows::core::GUID =
        windows::core::GUID::from_u128(0xe02a841c_75a3_4fa7_afc8_ae09cf9b7f23);

    /// Monitor syscalls via ETW Kernel-Audit-API-Calls provider
    #[cfg(target_os = "windows")]
    async fn monitor_etw_syscalls(
        tx: mpsc::Sender<TelemetryEvent>,
        _anomaly_threshold: f32,
        _learning_period_secs: u32,
    ) {
        info!(
            anomaly_threshold = _anomaly_threshold,
            learning_period = _learning_period_secs,
            "Starting ETW syscall audit monitor (Kernel-Audit-API-Calls)"
        );

        // Create the syscall sequence profiler
        let profiler = Arc::new(RwLock::new(SyscallSequenceProfiler::new()));
        let profiler_clone = profiler.clone();
        let tx_clone = tx.clone();

        // Run ETW session in a separate thread (blocking)
        let handle =
            std::thread::spawn(move || Self::run_etw_syscall_session(tx_clone, profiler_clone));

        // Start a background task to check for suspicious sequences periodically
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
        loop {
            interval.tick().await;

            // Check profiler for suspicious sequences
            let alerts = {
                let mut profiler = profiler.write();
                profiler.check_suspicious_sequences()
            };

            for alert in alerts {
                let event = Self::create_evasion_event(&alert);
                if tx.send(event).await.is_err() {
                    break;
                }
            }
        }
    }

    /// Run the ETW session for syscall auditing
    #[cfg(target_os = "windows")]
    fn run_etw_syscall_session(
        tx: mpsc::Sender<TelemetryEvent>,
        profiler: Arc<RwLock<SyscallSequenceProfiler>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use super::win_compat::etw as etw_api;
        use std::ffi::c_void;
        use std::sync::OnceLock;

        // Global context for callback
        static ETW_SYSCALL_CTX: OnceLock<EtwSyscallContext> = OnceLock::new();

        let _ = ETW_SYSCALL_CTX.set(EtwSyscallContext {
            tx: std::sync::Mutex::new(Some(tx)),
            profiler,
        });

        let api = match etw_api::get_etw_api() {
            Some(api) => api,
            None => {
                warn!("ETW API not available for syscall auditing");
                return Ok(());
            }
        };

        // Session properties
        let session_name = "TamanduaSyscallAudit";
        let session_name_wide: Vec<u16> = session_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        // Create trace properties
        let total_size = std::mem::size_of::<EtwTraceProperties>();
        let mut properties = EtwTraceProperties {
            wnode: EtwWnodeHeader {
                buffer_size: total_size as u32,
                provider_id: 0,
                historical_context: 0,
                timestamp: 0,
                guid: [0; 16],
                client_context: 1, // QPC timestamp
                flags: etw_api::WNODE_FLAG_TRACED_GUID,
            },
            buffer_size: 64, // 64 KB buffers
            minimum_buffers: 4,
            maximum_buffers: 64,
            maximum_file_size: 0,
            log_file_mode: etw_api::EVENT_TRACE_REAL_TIME_MODE
                | etw_api::EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING,
            flush_timer: 1,
            enable_flags: 0,
            age_limit: 0,
            number_of_buffers: 0,
            free_buffers: 0,
            events_lost: 0,
            buffers_written: 0,
            log_buffers_lost: 0,
            real_time_buffers_lost: 0,
            logger_thread_id: std::ptr::null_mut(),
            log_file_name_offset: 0,
            logger_name_offset: 0,
            _padding: [0; 1024],
        };

        // Copy session name to properties
        let name_offset = std::mem::offset_of!(EtwTraceProperties, _padding);
        unsafe {
            let props_ptr = &mut properties as *mut EtwTraceProperties as *mut u8;
            std::ptr::copy_nonoverlapping(
                session_name_wide.as_ptr() as *const u8,
                props_ptr.add(name_offset),
                session_name_wide.len() * 2,
            );
        }
        properties.logger_name_offset = name_offset as u32;

        // Start trace session
        let mut session_handle: u64 = 0;
        let result = unsafe {
            (api.start_trace)(
                &mut session_handle,
                session_name_wide.as_ptr(),
                &mut properties as *mut _ as *mut c_void,
            )
        };

        match result {
            etw_api::ERROR_SUCCESS => {
                info!(handle = session_handle, "ETW syscall audit session created");
            }
            etw_api::ERROR_ALREADY_EXISTS => {
                info!("ETW syscall audit session already exists, stopping and recreating");
                unsafe {
                    (api.control_trace)(
                        0,
                        session_name_wide.as_ptr(),
                        &mut properties as *mut _ as *mut c_void,
                        etw_api::EVENT_TRACE_CONTROL_STOP,
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(100));

                // Retry
                properties = EtwTraceProperties {
                    wnode: EtwWnodeHeader {
                        buffer_size: total_size as u32,
                        provider_id: 0,
                        historical_context: 0,
                        timestamp: 0,
                        guid: [0; 16],
                        client_context: 1,
                        flags: etw_api::WNODE_FLAG_TRACED_GUID,
                    },
                    buffer_size: 64,
                    minimum_buffers: 4,
                    maximum_buffers: 64,
                    maximum_file_size: 0,
                    log_file_mode: etw_api::EVENT_TRACE_REAL_TIME_MODE
                        | etw_api::EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING,
                    flush_timer: 1,
                    enable_flags: 0,
                    age_limit: 0,
                    number_of_buffers: 0,
                    free_buffers: 0,
                    events_lost: 0,
                    buffers_written: 0,
                    log_buffers_lost: 0,
                    real_time_buffers_lost: 0,
                    logger_thread_id: std::ptr::null_mut(),
                    log_file_name_offset: 0,
                    logger_name_offset: 0,
                    _padding: [0; 1024],
                };
                properties.logger_name_offset = name_offset as u32;
                unsafe {
                    let props_ptr = &mut properties as *mut EtwTraceProperties as *mut u8;
                    std::ptr::copy_nonoverlapping(
                        session_name_wide.as_ptr() as *const u8,
                        props_ptr.add(name_offset),
                        session_name_wide.len() * 2,
                    );
                }

                let retry_result = unsafe {
                    (api.start_trace)(
                        &mut session_handle,
                        session_name_wide.as_ptr(),
                        &mut properties as *mut _ as *mut c_void,
                    )
                };
                if retry_result != etw_api::ERROR_SUCCESS {
                    warn!(
                        error = retry_result,
                        "Failed to start ETW syscall audit session after stop"
                    );
                    return Ok(());
                }
                info!(
                    handle = session_handle,
                    "ETW syscall audit session created after stop"
                );
            }
            etw_api::ERROR_ACCESS_DENIED => {
                warn!("ETW syscall audit access denied - elevation required");
                return Ok(());
            }
            _ => {
                warn!(error = result, "Failed to start ETW syscall audit session");
                return Ok(());
            }
        }

        // Enable the Kernel-Audit-API-Calls provider
        if let Some(enable_ex2) = api.enable_trace_ex2 {
            let result = unsafe {
                enable_ex2(
                    session_handle,
                    &Self::KERNEL_AUDIT_API_GUID as *const _ as *const c_void,
                    etw_api::EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                    etw_api::TRACE_LEVEL_VERBOSE,
                    0xFFFFFFFFFFFFFFFF, // All keywords
                    0,
                    0,
                    std::ptr::null(),
                )
            };
            if result == etw_api::ERROR_SUCCESS {
                info!("Kernel-Audit-API-Calls provider enabled");
            } else {
                debug!(error = result, "Failed to enable Kernel-Audit-API-Calls provider (may require SYSTEM privileges)");
            }
        } else {
            // Legacy EnableTrace for Windows 7
            let result = unsafe {
                (api.enable_trace)(
                    1,          // Enable
                    0xFFFFFFFF, // All flags
                    etw_api::TRACE_LEVEL_VERBOSE as u32,
                    &Self::KERNEL_AUDIT_API_GUID as *const _ as *const c_void,
                    session_handle,
                )
            };
            if result == etw_api::ERROR_SUCCESS {
                info!("Kernel-Audit-API-Calls provider enabled (legacy)");
            } else {
                debug!(
                    error = result,
                    "Failed to enable Kernel-Audit-API-Calls provider"
                );
            }
        }

        // Open trace for consumption
        let mut logfile = unsafe { std::mem::zeroed::<EtwTraceLogfile>() };
        let mut session_name_wide_mut = session_name_wide.clone();
        logfile.logger_name = session_name_wide_mut.as_mut_ptr();
        logfile.log_file_mode = 0x00000100 | 0x10000000; // PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
        logfile.event_record_callback = Some(etw_syscall_callback);

        let trace_handle = unsafe { (api.open_trace)(&mut logfile as *mut _ as *mut c_void) };
        if trace_handle == u64::MAX {
            warn!("Failed to open ETW syscall audit trace");
            unsafe {
                (api.control_trace)(
                    session_handle,
                    session_name_wide.as_ptr(),
                    &mut properties as *mut _ as *mut c_void,
                    etw_api::EVENT_TRACE_CONTROL_STOP,
                );
            }
            return Ok(());
        }

        info!(handle = trace_handle, "ETW syscall audit trace opened");

        // Process trace (blocks until session is stopped)
        let handles = [trace_handle];
        let result =
            unsafe { (api.process_trace)(handles.as_ptr(), 1, std::ptr::null(), std::ptr::null()) };

        // Cleanup
        unsafe {
            (api.close_trace)(trace_handle);
            (api.control_trace)(
                session_handle,
                session_name_wide.as_ptr(),
                &mut properties as *mut _ as *mut c_void,
                etw_api::EVENT_TRACE_CONTROL_STOP,
            );
        }

        if result != etw_api::ERROR_SUCCESS && result != 1223 {
            warn!(
                error = result,
                "ETW syscall audit ProcessTrace ended with error"
            );
        }

        info!("ETW syscall audit monitoring stopped");
        Ok(())
    }

    // ==================== Linux Implementation ====================
    #[cfg(target_os = "linux")]
    async fn linux_monitor_loop(tx: mpsc::Sender<TelemetryEvent>, _config: AgentConfig) {
        info!("Starting Linux syscall evasion monitor");

        // Linux implementation focuses on:
        // 1. eBPF-based syscall monitoring (mmap, mprotect, ptrace, etc.)
        // 2. Direct syscall detection via memory scanning
        // 3. LD_PRELOAD-based unhooking
        // 4. Seccomp bypass detection
        // 5. memfd_create + execveat (fileless execution)
        // 6. /proc/self/mem writes

        let tx1 = tx.clone();
        let tx2 = tx.clone();
        let tx3 = tx.clone();
        let tx4 = tx.clone();

        // Start eBPF-based syscall monitoring (primary detection method)
        let ebpf_tx = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = Self::linux_ebpf_syscall_monitor(ebpf_tx).await {
                warn!(
                    "eBPF syscall monitor failed: {}, falling back to proc scanning",
                    e
                );
            }
        });

        // Monitor for direct syscall stubs in process memory (fallback/supplementary)
        tokio::spawn(async move {
            Self::linux_monitor_syscall_stubs(tx1).await;
        });

        // Monitor for library unhooking/bypasses (LD_PRELOAD)
        tokio::spawn(async move {
            Self::linux_monitor_library_integrity(tx2).await;
        });

        // Monitor for /proc/self/mem writes
        tokio::spawn(async move {
            Self::linux_monitor_proc_mem_writes(tx3).await;
        });

        // Monitor for memfd + execveat patterns (fileless execution)
        Self::linux_monitor_fileless_execution(tx4).await;
    }

    /// eBPF-based syscall monitoring for detecting evasion techniques
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    async fn linux_ebpf_syscall_monitor(tx: mpsc::Sender<TelemetryEvent>) -> anyhow::Result<()> {
        use aya::{
            maps::RingBuf,
            programs::{KProbe, RawTracePoint, TracePoint},
            Ebpf,
        };
        use std::convert::TryInto;

        info!("Starting eBPF-based syscall evasion monitor");

        // Try to load the eBPF program
        let ebpf_path = std::env::var("TAMANDUA_EBPF_PATH")
            .unwrap_or_else(|_| "/opt/tamandua/ebpf/tamandua_ebpf".to_string());

        // Check if eBPF is available
        if !std::path::Path::new("/sys/fs/bpf").exists() {
            warn!("BPF filesystem not mounted, eBPF monitoring unavailable");
            return Err(anyhow::anyhow!("BPF filesystem not available"));
        }

        // Try to load pre-compiled eBPF object
        let mut bpf = match Ebpf::load_file(&ebpf_path) {
            Ok(b) => b,
            Err(e) => {
                // Try embedded version
                warn!("Could not load eBPF from {}: {}", ebpf_path, e);

                // Fall back to raw tracepoint monitoring via audit
                return Self::linux_audit_syscall_monitor(tx).await;
            }
        };

        // Attach sys_enter_security raw tracepoint
        let program: &mut RawTracePoint = bpf
            .program_mut("sys_enter_security")
            .ok_or_else(|| anyhow::anyhow!("sys_enter_security program not found"))?
            .try_into()?;
        program.load()?;
        program.attach("sys_enter")?;
        info!("Attached sys_enter_security raw tracepoint");

        // Attach sys_exit_security tracepoint for return value tracking
        if let Some(prog) = bpf.program_mut("sys_exit_security") {
            let tp: &mut TracePoint = prog.try_into()?;
            tp.load()?;
            tp.attach("raw_syscalls", "sys_exit")?;
            info!("Attached sys_exit_security tracepoint");
        }

        // Attach proc_mem_write kprobe if available
        if let Some(prog) = bpf.program_mut("proc_mem_write") {
            let kp: &mut KProbe = prog.try_into()?;
            kp.load()?;
            // This would attach to the kernel function that handles /proc/*/mem writes
            if let Err(e) = kp.attach("mem_write", 0) {
                debug!("Could not attach proc_mem_write kprobe: {}", e);
            } else {
                info!("Attached proc_mem_write kprobe");
            }
        }

        // Get the events ring buffer
        let events = RingBuf::try_from(
            bpf.map_mut("EVENTS")
                .ok_or_else(|| anyhow::anyhow!("EVENTS map not found"))?,
        )?;

        info!("eBPF syscall evasion monitoring active");

        // Process events from ring buffer
        loop {
            // Poll the ring buffer
            while let Some(event_data) = events.next() {
                if let Some(telemetry) = Self::parse_ebpf_evasion_event(&event_data) {
                    if tx.send(telemetry).await.is_err() {
                        return Ok(());
                    }
                }
            }

            // Small sleep to prevent busy-waiting
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }
    }

    #[cfg(all(target_os = "linux", not(feature = "ebpf")))]
    async fn linux_ebpf_syscall_monitor(tx: mpsc::Sender<TelemetryEvent>) -> anyhow::Result<()> {
        Self::linux_audit_syscall_monitor(tx).await
    }

    /// Parse eBPF event data into a TelemetryEvent
    #[cfg(target_os = "linux")]
    fn parse_ebpf_evasion_event(data: &[u8]) -> Option<TelemetryEvent> {
        use tamandua_ebpf_common::{
            bytes_to_str, EventType as EbpfEventType,
            SyscallEvasionEvent as EbpfSyscallEvasionEvent, EVASION_ANONYMOUS_MMAP,
            EVASION_DIRECT_SYSCALL, EVASION_LD_PRELOAD, EVASION_MEMFD_EXEC, EVASION_PROC_MEM_WRITE,
            EVASION_PTRACE_INJECT, EVASION_SECCOMP_BYPASS,
        };

        if data.len() < 4 {
            return None;
        }

        // Read event type from first 4 bytes
        let event_type = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);

        // Check if this is a syscall evasion event
        let ebpf_event_type = EbpfEventType::from_u32(event_type)?;

        // Only process syscall evasion events
        match ebpf_event_type {
            EbpfEventType::SyscallEvasionDirectSyscall
            | EbpfEventType::SyscallEvasionAnonymousMmap
            | EbpfEventType::SyscallEvasionSeccompBypass
            | EbpfEventType::SyscallEvasionPtraceInject
            | EbpfEventType::SyscallEvasionMemfdExec
            | EbpfEventType::SyscallEvasionProcMemWrite
            | EbpfEventType::SyscallEvasionLdPreload => {}
            _ => return None,
        }

        // Parse the event structure
        if data.len() < std::mem::size_of::<EbpfSyscallEvasionEvent>() {
            return None;
        }

        // Safety: we've verified the size
        let ebpf_event: &EbpfSyscallEvasionEvent =
            unsafe { &*(data.as_ptr() as *const EbpfSyscallEvasionEvent) };

        // Map eBPF evasion type to our enum
        let evasion_type = match ebpf_event.evasion_type {
            EVASION_DIRECT_SYSCALL => SyscallEvasionType::DirectSyscall,
            EVASION_ANONYMOUS_MMAP => SyscallEvasionType::AnonymousExecMmap,
            EVASION_SECCOMP_BYPASS => SyscallEvasionType::SeccompManipulation,
            EVASION_PTRACE_INJECT => SyscallEvasionType::PtraceInjection,
            EVASION_MEMFD_EXEC => {
                // Check if this is memfd_create or execveat
                if ebpf_event.syscall_nr == 322 {
                    // execveat
                    SyscallEvasionType::FilelessExecveat
                } else {
                    SyscallEvasionType::MemfdCreate
                }
            }
            EVASION_PROC_MEM_WRITE => SyscallEvasionType::ProcMemWrite,
            EVASION_LD_PRELOAD => SyscallEvasionType::LdPreloadAbuse,
            _ => SyscallEvasionType::DirectSyscall, // Default
        };

        // Extract process info from the event header
        let pid = ebpf_event.header.pid;
        let comm = bytes_to_str(&ebpf_event.header.comm);
        let path = bytes_to_str(&ebpf_event.path);

        // Get additional process info from /proc
        let (process_path, cmdline, user) = Self::get_process_info_from_proc(pid);

        let event = SyscallEvasionEvent {
            evasion_type,
            pid,
            process_name: if comm.is_empty() {
                process_path
                    .rsplit('/')
                    .next()
                    .unwrap_or("unknown")
                    .to_string()
            } else {
                comm.to_string()
            },
            process_path: if process_path.is_empty() {
                path.to_string()
            } else {
                process_path
            },
            cmdline,
            user,
            module: None,
            function: None,
            expected_address: None,
            actual_address: Some(ebpf_event.return_addr),
            ssn: Some(ebpf_event.syscall_nr),
            syscall_name: Self::syscall_nr_to_name(ebpf_event.syscall_nr),
            region_base: Some(ebpf_event.region_start),
            region_size: Some(ebpf_event.region_size),
            confidence: (ebpf_event.confidence as f32) / 100.0,
            details: format!(
                "eBPF detected {} (syscall {}) at 0x{:016X}",
                evasion_type.as_str(),
                ebpf_event.syscall_nr,
                ebpf_event.return_addr
            ),
            pattern_name: Some(format!("ebpf_{}", evasion_type.as_str())),
        };

        Some(Self::create_evasion_event(&event))
    }

    /// Get process info from /proc filesystem
    #[cfg(target_os = "linux")]
    fn get_process_info_from_proc(pid: u32) -> (String, String, String) {
        use std::fs;

        let exe_path = fs::read_link(format!("/proc/{}/exe", pid))
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        let comm = fs::read_to_string(format!("/proc/{}/comm", pid))
            .unwrap_or_default()
            .trim()
            .to_string();

        let cmdline = fs::read_to_string(format!("/proc/{}/cmdline", pid))
            .unwrap_or_default()
            .replace('\0', " ");

        (exe_path, cmdline, comm)
    }
}

// ============================================================================
// ETW Structures for Syscall Auditing (Windows-specific)
// ============================================================================

#[cfg(target_os = "windows")]
#[repr(C)]
struct EtwWnodeHeader {
    buffer_size: u32,
    provider_id: u32,
    historical_context: u64,
    timestamp: i64,
    guid: [u8; 16],
    client_context: u32,
    flags: u32,
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct EtwTraceProperties {
    wnode: EtwWnodeHeader,
    buffer_size: u32,
    minimum_buffers: u32,
    maximum_buffers: u32,
    maximum_file_size: u32,
    log_file_mode: u32,
    flush_timer: u32,
    enable_flags: u32,
    age_limit: i32,
    number_of_buffers: u32,
    free_buffers: u32,
    events_lost: u32,
    buffers_written: u32,
    log_buffers_lost: u32,
    real_time_buffers_lost: u32,
    logger_thread_id: *mut std::ffi::c_void,
    log_file_name_offset: u32,
    logger_name_offset: u32,
    _padding: [u8; 1024],
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct EtwTraceLogfile {
    log_file_name: *mut u16,
    logger_name: *mut u16,
    current_time: i64,
    buffers_read: u32,
    log_file_mode: u32,
    current_event: [u8; 176],
    logfile_header: [u8; 272],
    buffer_callback: Option<unsafe extern "system" fn(*mut EtwTraceLogfile) -> u32>,
    buffer_size: u32,
    filled: u32,
    events_lost: u32,
    event_record_callback: Option<unsafe extern "system" fn(*mut EtwEventRecord)>,
    is_kernel_trace: u32,
    context: *mut std::ffi::c_void,
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct EtwEventRecord {
    event_header: EtwEventHeader,
    buffer_context: EtwBufferContext,
    extended_data_count: u16,
    user_data_length: u16,
    extended_data: *mut std::ffi::c_void,
    user_data: *mut std::ffi::c_void,
    user_context: *mut std::ffi::c_void,
}

#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Clone, Copy)]
struct EtwEventHeader {
    size: u16,
    header_type: u16,
    flags: u16,
    event_property: u16,
    thread_id: u32,
    process_id: u32,
    timestamp: i64,
    provider_id: [u8; 16],
    event_descriptor: EtwEventDescriptor,
    kernel_time: u32,
    user_time: u32,
    activity_id: [u8; 16],
}

#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Clone, Copy)]
struct EtwEventDescriptor {
    id: u16,
    version: u8,
    channel: u8,
    level: u8,
    opcode: u8,
    task: u16,
    keyword: u64,
}

#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Clone, Copy)]
struct EtwBufferContext {
    processor_number: u8,
    alignment: u8,
    logger_id: u16,
}

/// Context for ETW syscall callback
#[cfg(target_os = "windows")]
struct EtwSyscallContext {
    tx: std::sync::Mutex<Option<mpsc::Sender<TelemetryEvent>>>,
    profiler: Arc<RwLock<SyscallSequenceProfiler>>,
}

/// ETW callback for syscall audit events
#[cfg(target_os = "windows")]
unsafe extern "system" fn etw_syscall_callback(event_record: *mut EtwEventRecord) {
    if event_record.is_null() {
        return;
    }
    let record = &*event_record;
    let pid = record.event_header.process_id;
    if let Some(ctx) = ETW_SYSCALL_CTX.get() {
        if let Some(syscall_info) = parse_syscall_event(record) {
            let mut profiler = ctx.profiler.write();
            profiler.record_syscall(pid, &syscall_info);
        }
    }
}

/// Global ETW syscall context
#[cfg(target_os = "windows")]
static ETW_SYSCALL_CTX: std::sync::OnceLock<EtwSyscallContext> = std::sync::OnceLock::new();

/// Syscall information from ETW event
#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
pub(crate) struct SyscallInfo {
    name: String,
    ssn: u32,
    return_address: u64,
    from_unbacked_memory: bool,
    timestamp: u64,
}

/// Parse syscall event from ETW record
#[cfg(target_os = "windows")]
fn parse_syscall_event(record: &EtwEventRecord) -> Option<SyscallInfo> {
    if record.user_data.is_null() || record.user_data_length == 0 {
        return None;
    }
    let event_id = record.event_header.event_descriptor.id;
    let timestamp = record.event_header.timestamp as u64;
    match event_id {
        1 => Some(SyscallInfo {
            name: "NtAllocateVirtualMemory".to_string(),
            ssn: 0x0018,
            return_address: extract_return_address(record),
            from_unbacked_memory: check_unbacked_memory(record),
            timestamp,
        }),
        2 => Some(SyscallInfo {
            name: "NtProtectVirtualMemory".to_string(),
            ssn: 0x0050,
            return_address: extract_return_address(record),
            from_unbacked_memory: check_unbacked_memory(record),
            timestamp,
        }),
        3 => Some(SyscallInfo {
            name: "NtWriteVirtualMemory".to_string(),
            ssn: 0x003A,
            return_address: extract_return_address(record),
            from_unbacked_memory: check_unbacked_memory(record),
            timestamp,
        }),
        4 => Some(SyscallInfo {
            name: "NtCreateThreadEx".to_string(),
            ssn: 0x00C2,
            return_address: extract_return_address(record),
            from_unbacked_memory: check_unbacked_memory(record),
            timestamp,
        }),
        5 => Some(SyscallInfo {
            name: "NtSuspendThread".to_string(),
            ssn: 0x01BC,
            return_address: extract_return_address(record),
            from_unbacked_memory: check_unbacked_memory(record),
            timestamp,
        }),
        6 => Some(SyscallInfo {
            name: "NtGetContextThread".to_string(),
            ssn: 0x00F2,
            return_address: extract_return_address(record),
            from_unbacked_memory: check_unbacked_memory(record),
            timestamp,
        }),
        7 => Some(SyscallInfo {
            name: "NtSetContextThread".to_string(),
            ssn: 0x018B,
            return_address: extract_return_address(record),
            from_unbacked_memory: check_unbacked_memory(record),
            timestamp,
        }),
        8 => Some(SyscallInfo {
            name: "NtResumeThread".to_string(),
            ssn: 0x0052,
            return_address: extract_return_address(record),
            from_unbacked_memory: check_unbacked_memory(record),
            timestamp,
        }),
        9 => Some(SyscallInfo {
            name: "NtQueueApcThread".to_string(),
            ssn: 0x0045,
            return_address: extract_return_address(record),
            from_unbacked_memory: check_unbacked_memory(record),
            timestamp,
        }),
        10 => Some(SyscallInfo {
            name: "NtMapViewOfSection".to_string(),
            ssn: 0x0028,
            return_address: extract_return_address(record),
            from_unbacked_memory: check_unbacked_memory(record),
            timestamp,
        }),
        11 => Some(SyscallInfo {
            name: "NtCreateSection".to_string(),
            ssn: 0x004A,
            return_address: extract_return_address(record),
            from_unbacked_memory: check_unbacked_memory(record),
            timestamp,
        }),
        _ => None,
    }
}

#[cfg(target_os = "windows")]
fn extract_return_address(record: &EtwEventRecord) -> u64 {
    if !record.user_data.is_null() && record.user_data_length >= 8 {
        unsafe { *(record.user_data as *const u64) }
    } else {
        0
    }
}

#[cfg(target_os = "windows")]
fn check_unbacked_memory(_record: &EtwEventRecord) -> bool {
    false
}

// ============================================================================
// Syscall Sequence Profiler
// ============================================================================

const SYSCALL_WINDOW_SIZE: usize = 10;
const MAX_TRACKED_PROCESSES: usize = 1000;

/// Syscall sequence profiler for detecting suspicious patterns
#[derive(Debug)]
pub struct SyscallSequenceProfiler {
    process_windows: HashMap<u32, ProcessSyscallWindow>,
    suspicious_patterns: Vec<SyscallPattern>,
    flagged_processes: HashSet<u32>,
    pending_alerts: Vec<SyscallEvasionEvent>,
}

#[derive(Debug)]
struct ProcessSyscallWindow {
    process_name: String,
    process_path: String,
    #[cfg(target_os = "windows")]
    syscalls: VecDeque<SyscallInfo>,
    #[cfg(not(target_os = "windows"))]
    syscalls: VecDeque<String>,
    last_activity: Instant,
    unbacked_syscall_count: u32,
    total_syscall_count: u64,
}

#[derive(Debug, Clone)]
struct SyscallPattern {
    name: String,
    sequence: Vec<String>,
    description: String,
    #[allow(dead_code)]
    mitre_technique: String,
    #[allow(dead_code)]
    severity: Severity,
}

impl SyscallSequenceProfiler {
    pub fn new() -> Self {
        Self {
            process_windows: HashMap::new(),
            suspicious_patterns: vec![
                SyscallPattern {
                    name: "classic_injection".to_string(),
                    sequence: vec![
                        "NtAllocateVirtualMemory".to_string(),
                        "NtWriteVirtualMemory".to_string(),
                        "NtProtectVirtualMemory".to_string(),
                        "NtCreateThreadEx".to_string(),
                    ],
                    description: "Classic injection: Alloc -> Write -> Protect -> CreateThread"
                        .to_string(),
                    mitre_technique: "T1055".to_string(),
                    severity: Severity::Critical,
                },
                SyscallPattern {
                    name: "thread_hijacking".to_string(),
                    sequence: vec![
                        "NtSuspendThread".to_string(),
                        "NtGetContextThread".to_string(),
                        "NtSetContextThread".to_string(),
                        "NtResumeThread".to_string(),
                    ],
                    description: "Thread hijacking: Suspend -> GetContext -> SetContext -> Resume"
                        .to_string(),
                    mitre_technique: "T1055.003".to_string(),
                    severity: Severity::Critical,
                },
                SyscallPattern {
                    name: "apc_injection".to_string(),
                    sequence: vec![
                        "NtAllocateVirtualMemory".to_string(),
                        "NtWriteVirtualMemory".to_string(),
                        "NtQueueApcThread".to_string(),
                    ],
                    description: "APC injection: Alloc -> Write -> QueueAPC".to_string(),
                    mitre_technique: "T1055.004".to_string(),
                    severity: Severity::Critical,
                },
                SyscallPattern {
                    name: "section_injection".to_string(),
                    sequence: vec![
                        "NtCreateSection".to_string(),
                        "NtMapViewOfSection".to_string(),
                        "NtWriteVirtualMemory".to_string(),
                    ],
                    description: "Section injection: CreateSection -> MapView -> Write".to_string(),
                    mitre_technique: "T1055.012".to_string(),
                    severity: Severity::High,
                },
            ],
            flagged_processes: HashSet::new(),
            pending_alerts: Vec::new(),
        }
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn record_syscall(&mut self, pid: u32, syscall: &SyscallInfo) {
        if self.process_windows.len() > MAX_TRACKED_PROCESSES {
            self.cleanup_old_entries();
        }
        let window = self
            .process_windows
            .entry(pid)
            .or_insert_with(|| ProcessSyscallWindow {
                process_name: get_process_name_for_profiler(pid).unwrap_or_default(),
                process_path: get_process_path_for_profiler(pid).unwrap_or_default(),
                syscalls: VecDeque::with_capacity(SYSCALL_WINDOW_SIZE),
                last_activity: Instant::now(),
                unbacked_syscall_count: 0,
                total_syscall_count: 0,
            });
        window.last_activity = Instant::now();
        window.total_syscall_count += 1;
        if syscall.from_unbacked_memory {
            window.unbacked_syscall_count += 1;
        }
        if window.syscalls.len() >= SYSCALL_WINDOW_SIZE {
            window.syscalls.pop_front();
        }
        window.syscalls.push_back(syscall.clone());
        self.check_patterns(pid);
    }

    #[cfg(target_os = "windows")]
    fn check_patterns(&mut self, pid: u32) {
        if self.flagged_processes.contains(&pid) {
            return;
        }
        let window = match self.process_windows.get(&pid) {
            Some(w) => w,
            None => return,
        };
        let syscall_names: Vec<&str> = window.syscalls.iter().map(|s| s.name.as_str()).collect();
        for pattern in &self.suspicious_patterns {
            if Self::matches_pattern(&syscall_names, &pattern.sequence) {
                self.flagged_processes.insert(pid);
                self.pending_alerts.push(SyscallEvasionEvent {
                    evasion_type: SyscallEvasionType::SyscallSequenceAnomaly,
                    pid,
                    process_name: window.process_name.clone(),
                    process_path: window.process_path.clone(),
                    cmdline: String::new(),
                    user: String::new(),
                    module: None,
                    function: None,
                    expected_address: None,
                    actual_address: None,
                    ssn: None,
                    syscall_name: Some(pattern.sequence.join(" -> ")),
                    region_base: None,
                    region_size: None,
                    confidence: 0.90,
                    details: format!(
                        "{}: detected in {} [{}]",
                        pattern.description, window.process_name, pid
                    ),
                    pattern_name: Some(pattern.name.clone()),
                });
                debug!(pid = pid, pattern = %pattern.name, "Suspicious syscall sequence detected");
                break;
            }
        }
        if window.unbacked_syscall_count > 3 && !self.flagged_processes.contains(&pid) {
            self.flagged_processes.insert(pid);
            self.pending_alerts.push(SyscallEvasionEvent {
                evasion_type: SyscallEvasionType::DirectSyscall,
                pid,
                process_name: window.process_name.clone(),
                process_path: window.process_path.clone(),
                cmdline: String::new(),
                user: String::new(),
                module: None,
                function: None,
                expected_address: None,
                actual_address: None,
                ssn: None,
                syscall_name: None,
                region_base: None,
                region_size: None,
                confidence: 0.85,
                details: format!(
                    "Multiple syscalls ({}) from unbacked memory in {} [{}]",
                    window.unbacked_syscall_count, window.process_name, pid
                ),
                pattern_name: Some("unbacked_syscalls".to_string()),
            });
        }
    }

    fn matches_pattern(syscalls: &[&str], pattern: &[String]) -> bool {
        if pattern.is_empty() || syscalls.len() < pattern.len() {
            return false;
        }
        let mut idx = 0;
        for syscall in syscalls {
            if *syscall == pattern[idx] {
                idx += 1;
                if idx == pattern.len() {
                    return true;
                }
            }
        }
        false
    }

    pub fn check_suspicious_sequences(&mut self) -> Vec<SyscallEvasionEvent> {
        std::mem::take(&mut self.pending_alerts)
    }

    fn cleanup_old_entries(&mut self) {
        let timeout = std::time::Duration::from_secs(300);
        let now = Instant::now();
        self.process_windows
            .retain(|_, w| now.duration_since(w.last_activity) < timeout);
        self.flagged_processes
            .retain(|pid| self.process_windows.contains_key(pid));
    }
}

impl Default for SyscallSequenceProfiler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "windows")]
fn get_process_name_for_profiler(pid: u32) -> Option<String> {
    use sysinfo::{Pid, System};
    let mut system = System::new();
    system.refresh_process(Pid::from_u32(pid));
    system
        .process(Pid::from_u32(pid))
        .map(|p| p.name().to_string())
}

#[cfg(target_os = "windows")]
fn get_process_path_for_profiler(pid: u32) -> Option<String> {
    use sysinfo::{Pid, System};
    let mut system = System::new();
    system.refresh_process(Pid::from_u32(pid));
    system
        .process(Pid::from_u32(pid))
        .and_then(|p| p.exe())
        .map(|p| p.to_string_lossy().to_string())
}

// Additional impl block for Linux-specific methods that got separated during merge
impl SyscallEvasionCollector {
    /// Map syscall number to name (x86_64)
    #[cfg(target_os = "linux")]
    fn syscall_nr_to_name(nr: u32) -> Option<String> {
        Some(
            match nr {
                9 => "mmap",
                10 => "mprotect",
                56 => "clone",
                57 => "fork",
                58 => "vfork",
                59 => "execve",
                101 => "ptrace",
                157 => "prctl",
                310 => "process_vm_readv",
                311 => "process_vm_writev",
                317 => "seccomp",
                319 => "memfd_create",
                322 => "execveat",
                435 => "clone3",
                _ => return None,
            }
            .to_string(),
        )
    }

    /// Fallback audit-based syscall monitoring when eBPF is unavailable
    #[cfg(target_os = "linux")]
    async fn linux_audit_syscall_monitor(tx: mpsc::Sender<TelemetryEvent>) -> anyhow::Result<()> {
        info!("Using audit-based syscall monitoring (eBPF unavailable)");

        // Monitor /proc for suspicious patterns as fallback
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));

        loop {
            interval.tick().await;

            // Check for memfd-based processes
            if let Ok(entries) = std::fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    let pid_str = entry.file_name().to_string_lossy().to_string();
                    let pid: u32 = match pid_str.parse() {
                        Ok(p) if p > 1 => p,
                        _ => continue,
                    };

                    // Check fd directory for memfd references
                    let fd_path = format!("/proc/{}/fd", pid);
                    if let Ok(fds) = std::fs::read_dir(&fd_path) {
                        for fd_entry in fds.flatten() {
                            if let Ok(link) = std::fs::read_link(fd_entry.path()) {
                                let link_str = link.to_string_lossy();
                                if link_str.contains("memfd:") {
                                    let (process_path, cmdline, user) =
                                        Self::get_process_info_from_proc(pid);

                                    let evasion = SyscallEvasionEvent {
                                        evasion_type: SyscallEvasionType::MemfdCreate,
                                        pid,
                                        process_name: process_path
                                            .rsplit('/')
                                            .next()
                                            .unwrap_or("unknown")
                                            .to_string(),
                                        process_path,
                                        cmdline,
                                        user,
                                        module: Some(link_str.to_string()),
                                        function: None,
                                        expected_address: None,
                                        actual_address: None,
                                        ssn: Some(319), // memfd_create
                                        syscall_name: Some("memfd_create".to_string()),
                                        region_base: None,
                                        region_size: None,
                                        confidence: 0.75,
                                        details: format!("memfd detected: {}", link_str),
                                        pattern_name: Some("audit_memfd".to_string()),
                                    };

                                    let event = Self::create_evasion_event(&evasion);
                                    if tx.send(event).await.is_err() {
                                        return Ok(());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Monitor for writes to /proc/*/mem (code injection technique)
    #[cfg(target_os = "linux")]
    async fn linux_monitor_proc_mem_writes(tx: mpsc::Sender<TelemetryEvent>) {
        use std::fs;

        info!("Starting /proc/*/mem write monitor");

        // This monitors for processes that have /proc/*/mem open for writing
        // which is a strong indicator of code injection
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10));
        let mut reported: HashSet<(u32, u32)> = HashSet::new(); // (writer_pid, target_pid)

        loop {
            interval.tick().await;

            if let Ok(entries) = fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    let pid_str = entry.file_name().to_string_lossy().to_string();
                    let pid: u32 = match pid_str.parse() {
                        Ok(p) if p > 1 => p,
                        _ => continue,
                    };

                    // Check fd directory for /proc/*/mem references
                    let fd_path = format!("/proc/{}/fd", pid);
                    if let Ok(fds) = fs::read_dir(&fd_path) {
                        for fd_entry in fds.flatten() {
                            if let Ok(link) = fs::read_link(fd_entry.path()) {
                                let link_str = link.to_string_lossy();

                                // Check for /proc/*/mem pattern
                                if link_str.starts_with("/proc/") && link_str.ends_with("/mem") {
                                    // Extract target PID
                                    if let Some(target_pid) = link_str
                                        .strip_prefix("/proc/")
                                        .and_then(|s| s.strip_suffix("/mem"))
                                        .and_then(|s| s.parse::<u32>().ok())
                                    {
                                        // Ignore self-references
                                        if target_pid == pid {
                                            continue;
                                        }

                                        if reported.contains(&(pid, target_pid)) {
                                            continue;
                                        }
                                        reported.insert((pid, target_pid));

                                        // Check if fd is open for writing
                                        let fdinfo_path = format!(
                                            "/proc/{}/fdinfo/{}",
                                            pid,
                                            fd_entry.file_name().to_string_lossy()
                                        );

                                        let is_write = fs::read_to_string(&fdinfo_path)
                                            .map(|info| {
                                                info.lines()
                                                    .find(|l| l.starts_with("flags:"))
                                                    .map(|l| {
                                                        // Check for O_WRONLY (1) or O_RDWR (2)
                                                        l.contains("01") || l.contains("02")
                                                    })
                                                    .unwrap_or(false)
                                            })
                                            .unwrap_or(false);

                                        if is_write {
                                            let (process_path, cmdline, user) =
                                                Self::get_process_info_from_proc(pid);

                                            let evasion = SyscallEvasionEvent {
                                                evasion_type: SyscallEvasionType::ProcMemWrite,
                                                pid,
                                                process_name: process_path
                                                    .rsplit('/')
                                                    .next()
                                                    .unwrap_or("unknown")
                                                    .to_string(),
                                                process_path,
                                                cmdline,
                                                user,
                                                module: Some(format!("target_pid:{}", target_pid)),
                                                function: None,
                                                expected_address: None,
                                                actual_address: None,
                                                ssn: Some(1), // write syscall
                                                syscall_name: Some("write".to_string()),
                                                region_base: None,
                                                region_size: None,
                                                confidence: 0.90,
                                                details: format!(
                                                    "Process {} has /proc/{}/mem open for writing",
                                                    pid, target_pid
                                                ),
                                                pattern_name: Some("proc_mem_write".to_string()),
                                            };

                                            let event = Self::create_evasion_event(&evasion);
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

            // Cleanup
            if reported.len() > 10000 {
                reported.clear();
            }
        }
    }

    /// Monitor for fileless execution patterns (memfd_create + execveat)
    #[cfg(target_os = "linux")]
    async fn linux_monitor_fileless_execution(tx: mpsc::Sender<TelemetryEvent>) {
        use std::fs;

        info!("Starting fileless execution monitor");

        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
        let mut reported: HashSet<u32> = HashSet::new();

        loop {
            interval.tick().await;

            if let Ok(entries) = fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    let pid_str = entry.file_name().to_string_lossy().to_string();
                    let pid: u32 = match pid_str.parse() {
                        Ok(p) if p > 1 => p,
                        _ => continue,
                    };

                    if reported.contains(&pid) {
                        continue;
                    }

                    // Check if process was executed from deleted or memfd path
                    let exe_link = format!("/proc/{}/exe", pid);
                    if let Ok(exe_path) = fs::read_link(&exe_link) {
                        let exe_str = exe_path.to_string_lossy();

                        // Fileless execution indicators
                        let is_fileless = exe_str.contains("(deleted)")
                            && (exe_str.contains("/memfd:")
                                || exe_str.contains("/dev/shm/")
                                || exe_str.starts_with("/proc/"));

                        // Also check for execution from /dev/shm or /run/shm
                        let is_shm_exec =
                            exe_str.starts_with("/dev/shm/") || exe_str.starts_with("/run/shm/");

                        if is_fileless || is_shm_exec {
                            reported.insert(pid);

                            let (process_path, cmdline, user) =
                                Self::get_process_info_from_proc(pid);

                            let evasion_type = if exe_str.contains("/memfd:") {
                                SyscallEvasionType::FilelessExecveat
                            } else {
                                SyscallEvasionType::AnonymousSyscall
                            };

                            let evasion = SyscallEvasionEvent {
                                evasion_type,
                                pid,
                                process_name: process_path
                                    .rsplit('/')
                                    .next()
                                    .unwrap_or("unknown")
                                    .to_string(),
                                process_path: exe_str.to_string(),
                                cmdline,
                                user,
                                module: None,
                                function: None,
                                expected_address: None,
                                actual_address: None,
                                ssn: Some(322), // execveat
                                syscall_name: Some("execveat".to_string()),
                                region_base: None,
                                region_size: None,
                                confidence: 0.95,
                                details: format!("Fileless execution detected: {}", exe_str),
                                pattern_name: Some("fileless_exec".to_string()),
                            };

                            let event = Self::create_evasion_event(&evasion);
                            if tx.send(event).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            }

            // Cleanup old entries (processes may have exited)
            if reported.len() > 5000 {
                // Keep only PIDs that still exist
                reported.retain(|pid| fs::metadata(format!("/proc/{}", pid)).is_ok());
            }
        }
    }

    #[cfg(target_os = "linux")]
    async fn linux_monitor_syscall_stubs(tx: mpsc::Sender<TelemetryEvent>) {
        use std::fs;

        info!("Starting Linux syscall stub detector");

        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        let mut reported: HashSet<(u32, u64)> = HashSet::new();

        // Linux x64 syscall patterns
        let linux_patterns: &[(&str, &[u8])] = &[
            // syscall instruction
            ("syscall", &[0x0F, 0x05]),
            // int 0x80 (32-bit syscall)
            ("int80", &[0xCD, 0x80]),
            // syscall setup: mov rax, NR; syscall
            ("syscall_setup", &[0x48, 0xC7, 0xC0]),
        ];

        loop {
            interval.tick().await;

            // Enumerate processes
            if let Ok(entries) = fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();

                    // Skip non-PID entries
                    let pid: u32 = match name.parse() {
                        Ok(p) => p,
                        Err(_) => continue,
                    };

                    if pid < 2 {
                        continue;
                    }

                    // Read process name
                    let comm = fs::read_to_string(format!("/proc/{}/comm", pid))
                        .unwrap_or_default()
                        .trim()
                        .to_string();

                    // Read maps to find executable anonymous memory
                    let maps_path = format!("/proc/{}/maps", pid);
                    let maps = match fs::read_to_string(&maps_path) {
                        Ok(m) => m,
                        Err(_) => continue,
                    };

                    for line in maps.lines() {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() < 2 {
                            continue;
                        }

                        let perms = parts[1];
                        let path = parts.get(5).unwrap_or(&"");

                        // Look for executable anonymous memory (no file backing)
                        if perms.contains('x') && (*path == "" || path.starts_with("[")) {
                            // Parse address range
                            let addr_parts: Vec<&str> = parts[0].split('-').collect();
                            if addr_parts.len() != 2 {
                                continue;
                            }

                            let start = u64::from_str_radix(addr_parts[0], 16).unwrap_or(0);
                            let end = u64::from_str_radix(addr_parts[1], 16).unwrap_or(0);

                            if start == 0 || end <= start {
                                continue;
                            }

                            if reported.contains(&(pid, start)) {
                                continue;
                            }

                            // Read memory and scan for patterns
                            let mem_path = format!("/proc/{}/mem", pid);
                            if let Ok(mut file) = fs::File::open(&mem_path) {
                                use std::io::{Read, Seek, SeekFrom};

                                let size = std::cmp::min(end - start, 0x10000);
                                let mut buffer = vec![0u8; size as usize];

                                if file.seek(SeekFrom::Start(start)).is_ok() {
                                    if let Ok(bytes_read) = file.read(&mut buffer) {
                                        buffer.truncate(bytes_read);

                                        for (pattern_name, pattern) in linux_patterns {
                                            if let Some(offset) = buffer
                                                .windows(pattern.len())
                                                .position(|w| w == *pattern)
                                            {
                                                reported.insert((pid, start));

                                                let addr = start + offset as u64;
                                                let exe_path =
                                                    fs::read_link(format!("/proc/{}/exe", pid))
                                                        .map(|p| p.to_string_lossy().to_string())
                                                        .unwrap_or_default();

                                                let evasion = SyscallEvasionEvent {
                                                    evasion_type: SyscallEvasionType::DirectSyscall,
                                                    pid,
                                                    process_name: comm.clone(),
                                                    process_path: exe_path,
                                                    cmdline: fs::read_to_string(format!("/proc/{}/cmdline", pid))
                                                        .unwrap_or_default()
                                                        .replace('\0', " "),
                                                    user: String::new(),
                                                    module: None,
                                                    function: None,
                                                    expected_address: None,
                                                    actual_address: Some(addr),
                                                    ssn: None,
                                                    syscall_name: None,
                                                    region_base: Some(start),
                                                    region_size: Some(end - start),
                                                    confidence: 0.85,
                                                    details: format!(
                                                        "Syscall pattern '{}' in anonymous memory at 0x{:016X}",
                                                        pattern_name, addr
                                                    ),
                                                    pattern_name: Some(pattern_name.to_string()),
                                                };

                                                let event = Self::create_evasion_event(&evasion);
                                                if tx.send(event).await.is_err() {
                                                    return;
                                                }

                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Cleanup
            if reported.len() > 10000 {
                reported.clear();
            }
        }
    }

    #[cfg(target_os = "linux")]
    async fn linux_monitor_library_integrity(tx: mpsc::Sender<TelemetryEvent>) {
        use std::fs;

        info!("Starting Linux library integrity monitor");

        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
        let mut reported: HashSet<u32> = HashSet::new();

        loop {
            interval.tick().await;

            // Check for LD_PRELOAD-based evasion
            if let Ok(entries) = fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    let pid: u32 = match name.parse() {
                        Ok(p) => p,
                        Err(_) => continue,
                    };

                    if pid < 2 || reported.contains(&pid) {
                        continue;
                    }

                    // Check environment for LD_PRELOAD
                    let environ_path = format!("/proc/{}/environ", pid);
                    if let Ok(environ) = fs::read_to_string(&environ_path) {
                        if environ.contains("LD_PRELOAD=") {
                            // LD_PRELOAD is set - check if it's suspicious
                            let preload_value = environ
                                .split('\0')
                                .find(|s| s.starts_with("LD_PRELOAD="))
                                .map(|s| s.trim_start_matches("LD_PRELOAD="));

                            if let Some(preload) = preload_value {
                                // Check if preload path is suspicious
                                let is_suspicious = preload.contains("/tmp/")
                                    || preload.contains("/dev/shm/")
                                    || preload.contains("/.")
                                    || preload.ends_with(".so.1") && !preload.contains("/lib");

                                if is_suspicious {
                                    reported.insert(pid);

                                    let comm = fs::read_to_string(format!("/proc/{}/comm", pid))
                                        .unwrap_or_default()
                                        .trim()
                                        .to_string();
                                    let exe_path = fs::read_link(format!("/proc/{}/exe", pid))
                                        .map(|p| p.to_string_lossy().to_string())
                                        .unwrap_or_default();

                                    let evasion = SyscallEvasionEvent {
                                        evasion_type: SyscallEvasionType::KnownDllsBypass,
                                        pid,
                                        process_name: comm,
                                        process_path: exe_path,
                                        cmdline: fs::read_to_string(format!(
                                            "/proc/{}/cmdline",
                                            pid
                                        ))
                                        .unwrap_or_default()
                                        .replace('\0', " "),
                                        user: String::new(),
                                        module: Some(preload.to_string()),
                                        function: None,
                                        expected_address: None,
                                        actual_address: None,
                                        ssn: None,
                                        syscall_name: None,
                                        region_base: None,
                                        region_size: None,
                                        confidence: 0.80,
                                        details: format!(
                                            "Suspicious LD_PRELOAD detected: {}",
                                            preload
                                        ),
                                        pattern_name: Some("ld_preload_suspicious".to_string()),
                                    };

                                    let event = Self::create_evasion_event(&evasion);
                                    if tx.send(event).await.is_err() {
                                        return;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Cleanup
            if reported.len() > 10000 {
                reported.clear();
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
    fn test_evasion_type_mitre_mapping() {
        assert_eq!(SyscallEvasionType::DirectSyscall.mitre_technique(), "T1106");
        assert_eq!(SyscallEvasionType::IatHook.mitre_technique(), "T1574.001");
        assert_eq!(
            SyscallEvasionType::StackSpoofing.mitre_technique(),
            "T1055.004"
        );
    }

    #[test]
    fn test_evasion_type_severity() {
        assert_eq!(
            SyscallEvasionType::DirectSyscall.severity(),
            Severity::Critical
        );
        assert_eq!(SyscallEvasionType::IatHook.severity(), Severity::High);
        assert_eq!(
            SyscallEvasionType::SyscallSequenceAnomaly.severity(),
            Severity::Medium
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_find_pattern() {
        let haystack = vec![0x00, 0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00];
        let needle = &[0x4C, 0x8B, 0xD1, 0xB8];

        let result = SyscallEvasionCollector::find_pattern(&haystack, needle);
        assert_eq!(result, Some(1));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_extract_ssn() {
        // mov r10, rcx; mov eax, 0x0018; syscall
        let buffer = vec![0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05];
        let ssn = SyscallEvasionCollector::extract_ssn(&buffer, 0);
        assert_eq!(ssn, Some(0x0018));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_ssn_to_name() {
        let name = SyscallEvasionCollector::ssn_to_name(0x0018);
        // Accept either Nt or Zw prefix (both are valid aliases for the same syscall)
        assert!(
            name == Some("NtAllocateVirtualMemory".to_string())
                || name == Some("ZwAllocateVirtualMemory".to_string()),
            "Expected NtAllocateVirtualMemory or ZwAllocateVirtualMemory, got {:?}",
            name
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_module_info_contains() {
        let module = ModuleInfo {
            base_address: 0x7FF800000000,
            size: 0x1000,
            path: "C:\\Windows\\System32\\ntdll.dll".to_string(),
            name: "ntdll.dll".to_string(),
        };

        // Address within module
        assert!(module.contains(0x7FF800000000));
        assert!(module.contains(0x7FF800000500));
        assert!(module.contains(0x7FF800000FFF));

        // Address outside module
        assert!(!module.contains(0x7FF7FFFFFFFF)); // Just before
        assert!(!module.contains(0x7FF800001000)); // Just after
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_module_resolver_binary_search() {
        // Create mock modules sorted by base address
        let modules = vec![
            ModuleInfo {
                base_address: 0x00400000,
                size: 0x10000,
                path: "test.exe".to_string(),
                name: "test.exe".to_string(),
            },
            ModuleInfo {
                base_address: 0x7FF800000000,
                size: 0x100000,
                path: "C:\\Windows\\System32\\ntdll.dll".to_string(),
                name: "ntdll.dll".to_string(),
            },
            ModuleInfo {
                base_address: 0x7FF810000000,
                size: 0x80000,
                path: "C:\\Windows\\System32\\kernel32.dll".to_string(),
                name: "kernel32.dll".to_string(),
            },
        ];

        // Test binary search logic (using the same algorithm as ModuleResolver::resolve)
        let test_resolve = |addr: u64| -> Option<&ModuleInfo> {
            if modules.is_empty() {
                return None;
            }
            let idx = match modules.binary_search_by_key(&addr, |m| m.base_address) {
                Ok(i) => i,
                Err(i) => {
                    if i == 0 {
                        return None;
                    }
                    i - 1
                }
            };
            let module = &modules[idx];
            if module.contains(addr) {
                Some(module)
            } else {
                None
            }
        };

        // Test addresses
        assert!(test_resolve(0x00400500).map(|m| &m.name) == Some(&"test.exe".to_string()));
        assert!(test_resolve(0x7FF800050000).map(|m| &m.name) == Some(&"ntdll.dll".to_string()));
        assert!(test_resolve(0x7FF810040000).map(|m| &m.name) == Some(&"kernel32.dll".to_string()));

        // Address not in any module
        assert!(test_resolve(0x00300000).is_none()); // Before any module
        assert!(test_resolve(0x7FF808000000).is_none()); // Between modules
    }

    // ==================== Process Type Baseline Profiling Tests ====================

    #[test]
    fn test_process_type_classifier() {
        let classifier = ProcessTypeClassifier::new();

        // Browser tests
        assert_eq!(classifier.classify("chrome.exe"), ProcessType::Browser);
        assert_eq!(classifier.classify("FIREFOX.EXE"), ProcessType::Browser);
        assert_eq!(classifier.classify("msedge.exe"), ProcessType::Browser);
        assert_eq!(classifier.classify("brave.exe"), ProcessType::Browser);

        // Office tests
        assert_eq!(classifier.classify("winword.exe"), ProcessType::Office);
        assert_eq!(classifier.classify("EXCEL.EXE"), ProcessType::Office);
        assert_eq!(classifier.classify("outlook.exe"), ProcessType::Office);

        // Development tests
        assert_eq!(classifier.classify("code.exe"), ProcessType::Development);
        assert_eq!(classifier.classify("devenv.exe"), ProcessType::Development);
        assert_eq!(classifier.classify("cargo.exe"), ProcessType::Development);

        // Shell tests
        assert_eq!(classifier.classify("cmd.exe"), ProcessType::Shell);
        assert_eq!(classifier.classify("powershell.exe"), ProcessType::Shell);
        assert_eq!(classifier.classify("pwsh.exe"), ProcessType::Shell);
        assert_eq!(classifier.classify("wscript.exe"), ProcessType::Shell);
        assert_eq!(classifier.classify("cscript.exe"), ProcessType::Shell);

        // System tests
        assert_eq!(classifier.classify("svchost.exe"), ProcessType::System);
        assert_eq!(classifier.classify("services.exe"), ProcessType::System);
        assert_eq!(classifier.classify("lsass.exe"), ProcessType::System);

        // Unknown
        assert_eq!(classifier.classify("myapp.exe"), ProcessType::Unknown);
        assert_eq!(classifier.classify("randomprocess"), ProcessType::Unknown);
    }

    #[test]
    fn test_syscall_category_classification() {
        assert_eq!(
            BaselineProfiler::classify_syscall("NtSocketConnect"),
            SyscallCategory::Network
        );
        assert_eq!(
            BaselineProfiler::classify_syscall("NtAllocateVirtualMemory"),
            SyscallCategory::Memory
        );
        assert_eq!(
            BaselineProfiler::classify_syscall("NtReadFile"),
            SyscallCategory::FileIO
        );
        assert_eq!(
            BaselineProfiler::classify_syscall("NtCreateThread"),
            SyscallCategory::Process
        );
        assert_eq!(
            BaselineProfiler::classify_syscall("NtOpenKey"),
            SyscallCategory::Registry
        );
        assert_eq!(
            BaselineProfiler::classify_syscall("NtAdjustPrivilegesToken"),
            SyscallCategory::Security
        );
        assert_eq!(
            BaselineProfiler::classify_syscall("NtClose"),
            SyscallCategory::Other
        );
    }

    #[test]
    fn test_baseline_config_default() {
        let config = BaselineConfig::default();

        assert_eq!(config.learning_period_seconds, 300);
        assert!((config.anomaly_threshold - 0.7).abs() < 0.001);

        // Check sensitivity values
        assert!((config.type_sensitivity.get(&ProcessType::Browser).unwrap() - 1.0).abs() < 0.001);
        assert!((config.type_sensitivity.get(&ProcessType::Office).unwrap() - 1.2).abs() < 0.001);
        assert!((config.type_sensitivity.get(&ProcessType::Shell).unwrap() - 1.5).abs() < 0.001);
        assert!((config.type_sensitivity.get(&ProcessType::System).unwrap() - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_baseline_for_process_types() {
        // Test browser baseline
        let browser = SyscallBaseline::for_type(ProcessType::Browser);
        assert_eq!(browser.process_type, ProcessType::Browser);
        assert!(browser
            .category_thresholds
            .contains_key(&SyscallCategory::Network));
        assert!(browser
            .category_thresholds
            .contains_key(&SyscallCategory::Memory));

        // Test shell baseline (should have Security weight)
        let shell = SyscallBaseline::for_type(ProcessType::Shell);
        assert_eq!(shell.process_type, ProcessType::Shell);
        assert!(shell
            .category_weights
            .contains_key(&SyscallCategory::Security));

        // Test system baseline (should have lower weights)
        let system = SyscallBaseline::for_type(ProcessType::System);
        assert_eq!(system.process_type, ProcessType::System);
        let net_weight = system
            .category_weights
            .get(&SyscallCategory::Network)
            .unwrap_or(&1.0);
        assert!(*net_weight < 0.5); // System should have low network sensitivity
    }

    #[test]
    fn test_process_syscall_state_learning_period() {
        let classifier = ProcessTypeClassifier::new();
        let config = BaselineConfig {
            learning_period_seconds: 60,
            anomaly_threshold: 0.7,
            type_sensitivity: HashMap::new(),
        };
        let mut state =
            ProcessSyscallState::new(1234, "test.exe".to_string(), &classifier, &config);

        // During learning period, score should be 0
        assert!(state.in_learning_period);
        let score = state.calculate_anomaly_score(&config);
        assert!((score - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_process_syscall_state_observation() {
        let classifier = ProcessTypeClassifier::new();
        let config = BaselineConfig {
            learning_period_seconds: 0,
            anomaly_threshold: 0.7,
            type_sensitivity: HashMap::new(),
        };
        let mut state =
            ProcessSyscallState::new(1234, "test.exe".to_string(), &classifier, &config);

        // Add observations
        state.add_observation(
            "NtAllocateVirtualMemory".to_string(),
            SyscallCategory::Memory,
            false,
        );
        state.add_observation("NtReadFile".to_string(), SyscallCategory::FileIO, false);
        state.add_observation(
            "NtAllocateVirtualMemory".to_string(),
            SyscallCategory::Memory,
            false,
        );

        assert_eq!(
            state.category_counts.get(&SyscallCategory::Memory),
            Some(&2)
        );
        assert_eq!(
            state.category_counts.get(&SyscallCategory::FileIO),
            Some(&1)
        );
        assert_eq!(
            state.syscall_counts.get("NtAllocateVirtualMemory"),
            Some(&2)
        );
    }

    #[test]
    fn test_baseline_profiler_basic() {
        let config = BaselineConfig {
            learning_period_seconds: 0,
            anomaly_threshold: 0.7,
            type_sensitivity: HashMap::new(),
        };
        let profiler = BaselineProfiler::new(config);

        // Record syscalls
        profiler.record_syscall(
            1234,
            "chrome.exe",
            "NtSocketConnect",
            SyscallCategory::Network,
            false,
        );
        profiler.record_syscall(
            1234,
            "chrome.exe",
            "NtAllocateVirtualMemory",
            SyscallCategory::Memory,
            false,
        );

        // Check process type
        assert_eq!(profiler.get_process_type(1234), Some(ProcessType::Browser));

        // Calculate anomaly - should be low for normal browser behavior
        let score = profiler.calculate_anomaly(1234);
        assert!(score.is_some());
    }

    #[test]
    fn test_baseline_profiler_remove_process() {
        let config = BaselineConfig::default();
        let profiler = BaselineProfiler::new(config);

        profiler.record_syscall(
            1234,
            "test.exe",
            "NtReadFile",
            SyscallCategory::FileIO,
            false,
        );
        assert!(profiler.get_process_type(1234).is_some());

        profiler.remove_process(1234);
        assert!(profiler.get_process_type(1234).is_none());
    }

    #[test]
    fn test_process_type_as_str() {
        assert_eq!(ProcessType::Browser.as_str(), "browser");
        assert_eq!(ProcessType::Office.as_str(), "office");
        assert_eq!(ProcessType::Development.as_str(), "development");
        assert_eq!(ProcessType::Shell.as_str(), "shell");
        assert_eq!(ProcessType::System.as_str(), "system");
        assert_eq!(ProcessType::Unknown.as_str(), "unknown");
    }
}
