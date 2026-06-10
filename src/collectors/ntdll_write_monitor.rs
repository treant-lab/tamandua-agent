//! NTDLL Write Monitor
//!
//! Monitors for memory operations targeting ntdll regions to detect:
//! - NTDLL unhooking (EDR bypass technique)
//! - Direct syscall preparation (manual ntdll mapping)
//! - API hook removal/modification
//!
//! ## Detection Methods
//!
//! ### Windows
//! - Track VirtualProtect/VirtualProtectEx calls where target is ntdll
//! - Track WriteProcessMemory/NtWriteVirtualMemory targeting ntdll
//! - Track MapViewOfFile/NtMapViewOfSection creating fresh ntdll mappings
//! - Monitor for processes that map ntdll from disk (unhooking signature)
//! - Behavioral correlation of suspicious sequences
//!
//! ### Linux
//! - Track mprotect calls on libc/ld.so regions
//! - Detect process_vm_writev targeting shared library memory
//! - Monitor /proc/self/maps for fresh library mappings
//!
//! ## MITRE ATT&CK
//! - T1562.006 (Impair Defenses: Indicator Blocking)
//! - T1055 (Process Injection)
//! - T1027 (Obfuscated Files or Information)

#![allow(unused_imports)]
// This collector tracks NTDLL unhooking / VirtualProtect / WriteProcessMemory /
// section-mapping sequences targeting ntdll. Many helper fields and detection
// functions are kept exhaustive for forthcoming correlation paths even when
// not yet wired into every dispatch.
#![allow(dead_code, unused_variables, unused_assignments)]

use super::{
    Detection, DetectionType, EventPayload, EventType, MemoryPermissionEvent, ProcessEvent,
    Severity, TelemetryEvent,
};
use crate::config::AgentConfig;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, trace, warn};

// ============================================================================
// Advanced Unhooking Detection Types
// ============================================================================

/// Known unhooking technique patterns
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnhookingTechnique {
    /// Classic unhooking: VirtualProtect -> memcpy -> VirtualProtect
    ClassicUnhook,
    /// Fresh ntdll mapping from disk (KnownDlls bypass)
    FreshNtdllMapping,
    /// Perun's Fart: Syscall-only unhooking (restores only syscall stubs)
    PerunsFart,
    /// Hell's Gate: Dynamic syscall number resolution
    HellsGate,
    /// Halo's Gate: Neighboring syscall number inference
    HalosGate,
    /// Tartarus Gate: Exception-based syscall resolution
    TartarusGate,
    /// SysWhispers: Inline syscall stub generation
    SysWhispers,
    /// Module rebasing: Loading ntdll at non-standard address
    ModuleRebasing,
    /// Cross-process section copying
    CrossProcessCopy,
    /// Partial .text restoration (selective functions)
    PartialTextRestore,
    /// Direct syscall via manual assembly
    DirectSyscallAsm,
    /// Section remapping via NtMapViewOfSection
    SectionRemapping,
    /// Module stomping with ntdll sections
    ModuleStomping,
    /// Egg hunter pattern (searching for syscall gadgets)
    EggHunter,
    /// Unknown/custom technique
    Unknown,
}

impl UnhookingTechnique {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ClassicUnhook => "ClassicUnhook",
            Self::FreshNtdllMapping => "FreshNtdllMapping",
            Self::PerunsFart => "PerunsFart",
            Self::HellsGate => "HellsGate",
            Self::HalosGate => "HalosGate",
            Self::TartarusGate => "TartarusGate",
            Self::SysWhispers => "SysWhispers",
            Self::ModuleRebasing => "ModuleRebasing",
            Self::CrossProcessCopy => "CrossProcessCopy",
            Self::PartialTextRestore => "PartialTextRestore",
            Self::DirectSyscallAsm => "DirectSyscallAsm",
            Self::SectionRemapping => "SectionRemapping",
            Self::ModuleStomping => "ModuleStomping",
            Self::EggHunter => "EggHunter",
            Self::Unknown => "Unknown",
        }
    }

    pub fn confidence(&self) -> f32 {
        match self {
            Self::ClassicUnhook => 0.95,
            Self::FreshNtdllMapping => 0.90,
            Self::PerunsFart => 0.92,
            Self::HellsGate | Self::HalosGate | Self::TartarusGate => 0.88,
            Self::SysWhispers => 0.93,
            Self::ModuleRebasing => 0.85,
            Self::CrossProcessCopy => 0.90,
            Self::PartialTextRestore => 0.87,
            Self::DirectSyscallAsm => 0.85,
            Self::SectionRemapping => 0.88,
            Self::ModuleStomping => 0.90,
            Self::EggHunter => 0.80,
            Self::Unknown => 0.70,
        }
    }
}

/// Information about an unhooked function
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnhookedFunction {
    /// Function name (e.g., "NtWriteVirtualMemory")
    pub name: String,
    /// RVA (Relative Virtual Address) within ntdll
    pub rva: u32,
    /// Size of the function (bytes restored)
    pub size: u32,
    /// Original bytes (first 16 bytes of hook)
    pub original_bytes: Vec<u8>,
    /// Restored bytes (first 16 bytes after unhook)
    pub restored_bytes: Vec<u8>,
    /// Whether this is a syscall stub
    pub is_syscall_stub: bool,
    /// Syscall number if applicable
    pub syscall_number: Option<u16>,
    /// Hook type that was removed (JMP, CALL, etc.)
    pub removed_hook_type: Option<HookType>,
}

/// Types of inline hooks that can be detected/removed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookType {
    /// JMP rel32 (E9 xx xx xx xx)
    JmpRel32,
    /// JMP [rip+disp] (FF 25 xx xx xx xx)
    JmpRipRelative,
    /// CALL rel32 (E8 xx xx xx xx)
    CallRel32,
    /// MOV r10, imm64 + JMP r10 (push/ret trampoline)
    PushRetTrampoline,
    /// INT3 breakpoint (CC)
    Int3Breakpoint,
    /// Software breakpoint pattern
    DebugBreak,
    /// Unknown hook type
    Unknown,
}

impl HookType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::JmpRel32 => "JMP_REL32",
            Self::JmpRipRelative => "JMP_RIP_REL",
            Self::CallRel32 => "CALL_REL32",
            Self::PushRetTrampoline => "PUSH_RET",
            Self::Int3Breakpoint => "INT3",
            Self::DebugBreak => "DEBUG_BREAK",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// Section comparison result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionComparisonResult {
    /// Section name (.text, .rdata, etc.)
    pub section_name: String,
    /// Section RVA
    pub section_rva: u32,
    /// Section size
    pub section_size: u32,
    /// Number of differences found
    pub difference_count: u32,
    /// Percentage of section that differs
    pub difference_percent: f32,
    /// Whether section appears to be selectively modified
    pub selective_modification: bool,
    /// Functions that were modified
    pub modified_functions: Vec<String>,
    /// First difference offset (for debugging)
    pub first_diff_offset: Option<u32>,
}

/// Advanced unhooking detection event with rich context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedUnhookingEvent {
    /// Source process ID
    pub source_pid: u32,
    /// Source process name
    pub source_process: String,
    /// Source process path
    pub source_path: String,
    /// Detected unhooking technique
    pub technique: UnhookingTechnique,
    /// Specific functions that were unhooked
    pub unhooked_functions: Vec<UnhookedFunction>,
    /// Section comparison results
    pub section_analysis: Vec<SectionComparisonResult>,
    /// Whether this is syscall-only unhooking (Perun's Fart indicator)
    pub syscall_only: bool,
    /// Number of syscall stubs restored
    pub syscall_stubs_restored: u32,
    /// Number of non-syscall functions restored
    pub other_functions_restored: u32,
    /// Cross-process source PID (if unhooking from another process)
    pub cross_process_source: Option<u32>,
    /// Fresh ntdll mapping address (if applicable)
    pub fresh_mapping_address: Option<u64>,
    /// Module rebasing detected (non-standard base address)
    pub rebased_address: Option<u64>,
    /// Expected base address for comparison
    pub expected_base_address: Option<u64>,
    /// Matched tool signature (SysWhispers, etc.)
    pub tool_signature: Option<String>,
    /// Confidence score
    pub confidence: f32,
    /// MITRE ATT&CK technique
    pub mitre_technique: String,
    /// Evidence details
    pub evidence: Vec<String>,
    /// Subsequent suspicious API calls observed
    pub subsequent_api_calls: Vec<String>,
    /// Timestamp
    pub timestamp: u64,
}

impl AdvancedUnhookingEvent {
    pub fn to_telemetry_event(&self) -> TelemetryEvent {
        let severity = if self.syscall_only || self.technique == UnhookingTechnique::PerunsFart {
            Severity::Critical
        } else if self.unhooked_functions.len() > 5 {
            Severity::Critical
        } else if self.cross_process_source.is_some() {
            Severity::Critical
        } else {
            Severity::High
        };

        let mut event = TelemetryEvent::new(
            EventType::DefenseEvasion,
            severity,
            EventPayload::MemoryPermission(MemoryPermissionEvent {
                pid: self.source_pid,
                process_name: self.source_process.clone(),
                process_path: self.source_path.clone(),
                base_address: self
                    .fresh_mapping_address
                    .or(self.rebased_address)
                    .unwrap_or(0),
                region_size: 0,
                old_protection: 0x20, // PAGE_EXECUTE_READ
                new_protection: 0x20,
                old_protection_str: "PAGE_EXECUTE_READ".to_string(),
                new_protection_str: "PAGE_EXECUTE_READ".to_string(),
                mem_type: 0x1000000, // MEM_IMAGE
                mem_type_str: "MEM_IMAGE".to_string(),
                entropy: 0.0,
                transition_type: format!("unhooking_{}", self.technique.as_str().to_lowercase()),
                thread_from_unbacked: false,
                thread_id: None,
                thread_start_address: None,
            }),
        );

        let function_list = self
            .unhooked_functions
            .iter()
            .take(5)
            .map(|f| f.name.clone())
            .collect::<Vec<_>>()
            .join(", ");

        let description =
            format!(
            "Advanced DLL unhooking detected: {} using {} technique. {} functions unhooked{}. {}",
            self.source_process,
            self.technique.as_str(),
            self.unhooked_functions.len(),
            if self.syscall_only { " (syscall-only - Perun's Fart indicator)" } else { "" },
            if !function_list.is_empty() {
                format!("Functions: {}", function_list)
            } else {
                String::new()
            }
        );

        event.add_detection(Detection {
            detection_type: DetectionType::DefenseEvasion,
            rule_name: format!("advanced_unhook_{}", self.technique.as_str().to_lowercase()),
            confidence: self.confidence,
            description,
            mitre_tactics: vec!["defense-evasion".to_string(), "execution".to_string()],
            mitre_techniques: vec![self.mitre_technique.clone()],
        });

        // Add rich metadata
        event
            .metadata
            .insert("technique".to_string(), self.technique.as_str().to_string());
        event.metadata.insert(
            "unhooked_count".to_string(),
            self.unhooked_functions.len().to_string(),
        );
        event
            .metadata
            .insert("syscall_only".to_string(), self.syscall_only.to_string());
        event.metadata.insert(
            "syscall_stubs_restored".to_string(),
            self.syscall_stubs_restored.to_string(),
        );

        if let Some(tool) = &self.tool_signature {
            event
                .metadata
                .insert("tool_signature".to_string(), tool.clone());
        }
        if let Some(cross_pid) = self.cross_process_source {
            event
                .metadata
                .insert("cross_process_source".to_string(), cross_pid.to_string());
        }
        if let Some(addr) = self.fresh_mapping_address {
            event.metadata.insert(
                "fresh_mapping_address".to_string(),
                format!("0x{:016x}", addr),
            );
        }
        if !self.subsequent_api_calls.is_empty() {
            event.metadata.insert(
                "subsequent_apis".to_string(),
                self.subsequent_api_calls.join(", "),
            );
        }

        // Add function details
        let func_details: Vec<String> = self
            .unhooked_functions
            .iter()
            .map(|f| format!("{}@0x{:x}", f.name, f.rva))
            .collect();
        if !func_details.is_empty() {
            event
                .metadata
                .insert("unhooked_functions".to_string(), func_details.join("; "));
        }

        event
    }
}

/// Tool signature patterns for known unhooking tools
#[derive(Debug, Clone)]
pub struct ToolSignature {
    /// Tool name
    pub name: &'static str,
    /// Byte patterns to search for
    pub patterns: Vec<&'static [u8]>,
    /// String patterns to search for
    pub strings: Vec<&'static str>,
    /// Associated technique
    pub technique: UnhookingTechnique,
}

/// Get known unhooking tool signatures
pub fn get_tool_signatures() -> Vec<ToolSignature> {
    vec![
        ToolSignature {
            name: "SysWhispers",
            patterns: vec![
                // mov r10, rcx; mov eax, <syscall>; syscall; ret pattern
                &[0x4C, 0x8B, 0xD1, 0xB8],
            ],
            strings: vec![
                "NtAllocateVirtualMemory",
                "NtProtectVirtualMemory",
                "NtWriteVirtualMemory",
                "Syscall",
            ],
            technique: UnhookingTechnique::SysWhispers,
        },
        ToolSignature {
            name: "HellsGate",
            patterns: vec![
                // mov eax, [r10+4]; mov ecx, [r10]; syscall pattern
                &[0x41, 0x8B, 0x42, 0x04],
            ],
            strings: vec!["HellsGate", "GetSyscallNumber", "FindSyscallTable"],
            technique: UnhookingTechnique::HellsGate,
        },
        ToolSignature {
            name: "HalosGate",
            patterns: vec![
                // Pattern for searching neighboring syscalls
                &[0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00],
            ],
            strings: vec!["HalosGate", "FindCleanSyscall"],
            technique: UnhookingTechnique::HalosGate,
        },
        ToolSignature {
            name: "TartarusGate",
            patterns: vec![],
            strings: vec!["TartarusGate", "ExceptionDispatcher"],
            technique: UnhookingTechnique::TartarusGate,
        },
        ToolSignature {
            name: "PerunsFart",
            patterns: vec![
                // Pattern for selective syscall restoration
                &[0x0F, 0x05, 0xC3], // syscall; ret
            ],
            strings: vec!["PerunsFart", "UnhookSyscalls", "RestoreSyscall"],
            technique: UnhookingTechnique::PerunsFart,
        },
        ToolSignature {
            name: "FreshyCalls",
            patterns: vec![],
            strings: vec!["FreshyCalls", "GetFreshSyscall"],
            technique: UnhookingTechnique::FreshNtdllMapping,
        },
        ToolSignature {
            name: "RecycledGate",
            patterns: vec![],
            strings: vec!["RecycledGate", "FindSyscallStub"],
            technique: UnhookingTechnique::HellsGate,
        },
    ]
}

/// Critical NT functions commonly targeted for unhooking
pub const CRITICAL_FUNCTIONS: &[&str] = &[
    // Memory operations
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "NtWriteVirtualMemory",
    "NtReadVirtualMemory",
    "NtMapViewOfSection",
    "NtUnmapViewOfSection",
    "NtCreateSection",
    // Process/Thread operations
    "NtCreateThreadEx",
    "NtCreateProcess",
    "NtCreateProcessEx",
    "NtOpenProcess",
    "NtOpenThread",
    "NtSuspendThread",
    "NtResumeThread",
    "NtQueueApcThread",
    "NtSetContextThread",
    "NtGetContextThread",
    // File operations (credential dumping)
    "NtCreateFile",
    "NtOpenFile",
    "NtReadFile",
    "NtWriteFile",
    // Registry operations (persistence)
    "NtOpenKey",
    "NtCreateKey",
    "NtSetValueKey",
    // Object operations
    "NtDuplicateObject",
    "NtQuerySystemInformation",
    "NtQueryInformationProcess",
    // Security operations
    "NtAdjustPrivilegesToken",
    "NtOpenProcessToken",
    "NtCreateToken",
    // Device operations
    "NtDeviceIoControlFile",
    "NtFsControlFile",
];

/// Memory operation types tracked for NTDLL monitoring
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryOperationType {
    /// VirtualProtect changing protection on ntdll region
    VirtualProtect,
    /// VirtualProtectEx changing protection on remote ntdll
    VirtualProtectEx,
    /// WriteProcessMemory to ntdll region
    WriteProcessMemory,
    /// NtWriteVirtualMemory to ntdll region
    NtWriteVirtualMemory,
    /// MapViewOfFile creating new ntdll mapping
    MapViewOfFile,
    /// NtMapViewOfSection creating new section
    NtMapViewOfSection,
    /// Section created from ntdll.dll file
    SectionCreate,
    /// Manual syscall stub detected
    ManualSyscall,
    /// Direct syscall instruction detected
    DirectSyscall,
    /// mprotect on shared library region (Linux)
    Mprotect,
    /// process_vm_writev to library region (Linux)
    ProcessVmWritev,
}

impl MemoryOperationType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::VirtualProtect => "VirtualProtect",
            Self::VirtualProtectEx => "VirtualProtectEx",
            Self::WriteProcessMemory => "WriteProcessMemory",
            Self::NtWriteVirtualMemory => "NtWriteVirtualMemory",
            Self::MapViewOfFile => "MapViewOfFile",
            Self::NtMapViewOfSection => "NtMapViewOfSection",
            Self::SectionCreate => "NtCreateSection",
            Self::ManualSyscall => "ManualSyscallStub",
            Self::DirectSyscall => "DirectSyscall",
            Self::Mprotect => "mprotect",
            Self::ProcessVmWritev => "process_vm_writev",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Self::WriteProcessMemory | Self::NtWriteVirtualMemory => Severity::Critical,
            Self::VirtualProtectEx => Severity::High,
            Self::ManualSyscall | Self::DirectSyscall => Severity::Critical,
            Self::MapViewOfFile | Self::NtMapViewOfSection | Self::SectionCreate => Severity::High,
            Self::VirtualProtect | Self::Mprotect => Severity::Medium,
            Self::ProcessVmWritev => Severity::Critical,
        }
    }
}

/// NTDLL write event with rich context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtdllWriteEvent {
    /// Source process ID (the one performing the operation)
    pub source_pid: u32,
    /// Source process name
    pub source_process: String,
    /// Source process path
    pub source_path: String,
    /// Target process ID (may be same as source for self-modification)
    pub target_pid: u32,
    /// Target process name
    pub target_process: String,
    /// Target address in ntdll region
    pub target_address: u64,
    /// Resolved function name if available (e.g., "NtWriteVirtualMemory")
    pub target_function: Option<String>,
    /// Type of memory operation detected
    pub operation: MemoryOperationType,
    /// Previous memory protection flags
    pub old_protection: Option<u32>,
    /// New memory protection flags
    pub new_protection: Option<u32>,
    /// Bytes written (first 64 bytes if available)
    pub bytes_written: Option<Vec<u8>>,
    /// Size of the modified region
    pub region_size: Option<u64>,
    /// MITRE ATT&CK technique ID
    pub mitre_technique: String,
    /// Confidence score (0.0-1.0)
    pub confidence: f32,
    /// Whether this is part of a suspicious sequence
    pub is_sequence_part: bool,
    /// Sequence ID if part of a sequence
    pub sequence_id: Option<u64>,
    /// Additional evidence details
    pub evidence: Vec<String>,
}

impl NtdllWriteEvent {
    pub fn to_telemetry_event(&self) -> TelemetryEvent {
        let mut event = TelemetryEvent::new(
            EventType::DefenseEvasion,
            self.operation.severity(),
            EventPayload::MemoryPermission(MemoryPermissionEvent {
                pid: self.source_pid,
                process_name: self.source_process.clone(),
                process_path: self.source_path.clone(),
                base_address: self.target_address,
                region_size: self.region_size.unwrap_or(0),
                old_protection: self.old_protection.unwrap_or(0),
                new_protection: self.new_protection.unwrap_or(0),
                old_protection_str: protection_to_string(self.old_protection.unwrap_or(0)),
                new_protection_str: protection_to_string(self.new_protection.unwrap_or(0)),
                mem_type: 0x1000000, // MEM_IMAGE
                mem_type_str: "MEM_IMAGE".to_string(),
                entropy: 0.0,
                transition_type: "ntdll_modification".to_string(),
                thread_from_unbacked: false,
                thread_id: None,
                thread_start_address: None,
            }),
        );

        let description = format!(
            "NTDLL write detected: {} performing {} on {} (PID {}) at 0x{:016x}{}",
            self.source_process,
            self.operation.as_str(),
            self.target_process,
            self.target_pid,
            self.target_address,
            self.target_function
                .as_ref()
                .map(|f| format!(" ({})", f))
                .unwrap_or_default()
        );

        event.add_detection(Detection {
            detection_type: DetectionType::DefenseEvasion,
            rule_name: format!("ntdll_write_{}", self.operation.as_str().to_lowercase()),
            confidence: self.confidence,
            description,
            mitre_tactics: vec!["defense-evasion".to_string(), "execution".to_string()],
            mitre_techniques: vec![self.mitre_technique.clone()],
        });

        // Add metadata
        event
            .metadata
            .insert("source_pid".to_string(), self.source_pid.to_string());
        event
            .metadata
            .insert("target_pid".to_string(), self.target_pid.to_string());
        event
            .metadata
            .insert("operation".to_string(), self.operation.as_str().to_string());
        event.metadata.insert(
            "target_address".to_string(),
            format!("0x{:016x}", self.target_address),
        );

        if let Some(func) = &self.target_function {
            event
                .metadata
                .insert("target_function".to_string(), func.clone());
        }
        if let Some(old_prot) = self.old_protection {
            event
                .metadata
                .insert("old_protection".to_string(), format!("0x{:x}", old_prot));
        }
        if let Some(new_prot) = self.new_protection {
            event
                .metadata
                .insert("new_protection".to_string(), format!("0x{:x}", new_prot));
        }
        if let Some(bytes) = &self.bytes_written {
            let hex_bytes: String = bytes
                .iter()
                .take(32)
                .map(|b| format!("{:02x}", b))
                .collect();
            event
                .metadata
                .insert("bytes_written".to_string(), hex_bytes);
        }
        if !self.evidence.is_empty() {
            event
                .metadata
                .insert("evidence".to_string(), self.evidence.join("; "));
        }

        // Explicit cross-process flag so the backend does not have to infer it
        // from comparing PIDs. Self-writes and cross-process writes carry very
        // different triage weight.
        event.metadata.insert(
            "cross_process".to_string(),
            (self.source_pid != self.target_pid).to_string(),
        );

        // Region classification (text / export_table / rwx / data) derived from
        // the resolved function name and the protection flags, so the backend
        // can score executable-code writes differently from data writes.
        event.metadata.insert(
            "region_class".to_string(),
            classify_region(
                self.target_function.as_deref(),
                self.old_protection,
                self.new_protection,
            ),
        );

        // Source process signature context. We reuse the agent's existing
        // Authenticode verifier so the backend can score the legitimacy of a
        // cross-process writer (signed tooling vs unbacked injector) without
        // re-reading the binary. Absent on non-Windows / unresolved paths, in
        // which case the backend treats it as unknown.
        #[cfg(target_os = "windows")]
        if !self.source_path.is_empty() {
            let is_signed = crate::collectors::win_compat::is_file_signed(&self.source_path);
            event
                .metadata
                .insert("source_is_signed".to_string(), is_signed.to_string());

            if let Some(signer) = crate::collectors::win_compat::get_file_signer(&self.source_path)
            {
                if !signer.is_empty() {
                    event.metadata.insert("source_signer".to_string(), signer);
                }
            }
        }

        event
    }
}

/// Tracked memory operation for sequence detection
#[derive(Debug, Clone)]
pub(crate) struct TrackedOperation {
    /// Operation type
    op_type: MemoryOperationType,
    /// Source PID
    source_pid: u32,
    /// Target PID
    target_pid: u32,
    /// Target address
    address: u64,
    /// Protection before (if applicable)
    old_protection: Option<u32>,
    /// Protection after (if applicable)
    new_protection: Option<u32>,
    /// Timestamp (Unix epoch millis)
    timestamp: u64,
    /// Size of region
    size: Option<u64>,
}

/// Baseline ntdll section data for comparison
#[derive(Debug, Clone)]
pub struct NtdllBaseline {
    /// Section name -> (rva, size, hash)
    pub sections: HashMap<String, (u32, u32, Vec<u8>)>,
    /// Function name -> (rva, first 32 bytes)
    pub function_prologues: HashMap<String, (u32, Vec<u8>)>,
    /// Base address when baseline was taken
    pub base_address: u64,
    /// Total module size
    pub module_size: u64,
    /// Timestamp when baseline was created
    pub created_at: u64,
}

/// API call tracking for correlation
#[derive(Debug, Clone)]
pub struct TrackedApiCall {
    /// Function name called
    pub function_name: String,
    /// Thread ID
    pub thread_id: u32,
    /// Timestamp
    pub timestamp: u64,
    /// Whether this was called via direct syscall
    pub via_direct_syscall: bool,
}

/// Cross-process unhooking detection state
#[derive(Debug, Clone)]
pub struct CrossProcessUnhookState {
    /// Source process that performed the unhooking
    pub source_pid: u32,
    /// Target process that was unhooked
    pub target_pid: u32,
    /// Handle value used
    pub handle_value: u64,
    /// Functions that were modified
    pub modified_functions: Vec<String>,
    /// Timestamp
    pub timestamp: u64,
}

/// State machine for tracking NTDLL write sequences
///
/// Detects patterns like:
/// 1. OpenProcess with VM_WRITE
/// 2. VirtualProtectEx PAGE_EXECUTE_READWRITE on ntdll region
/// 3. WriteProcessMemory to that region
/// 4. VirtualProtectEx restore to PAGE_EXECUTE_READ
///
/// Also detects advanced techniques:
/// - Perun's Fart (syscall-only unhooking)
/// - Section-by-section comparison
/// - Module rebasing
/// - Cross-process section copying
/// - Tool signature matching
#[derive(Debug)]
pub struct NtdllWriteTracker {
    /// Active suspicious sequences keyed by (source_pid, target_pid)
    suspicious_sequences: HashMap<(u32, u32), Vec<TrackedOperation>>,
    /// Known ntdll base addresses per process (pid -> base address)
    ntdll_bases: HashMap<u32, u64>,
    /// Known ntdll sizes per process (pid -> size)
    ntdll_sizes: HashMap<u32, u64>,
    /// Known ntdll exports per process (pid -> (function_name -> rva))
    ntdll_exports: HashMap<u32, HashMap<String, u32>>,
    /// Processes that have created sections from ntdll.dll
    section_creators: HashSet<u32>,
    /// Processes that have mapped fresh ntdll copies
    fresh_mappers: HashSet<u32>,
    /// Sequence counter for correlation
    sequence_counter: u64,
    /// Maximum age of tracked operations (seconds)
    max_op_age_secs: u64,
    /// Last cleanup timestamp
    last_cleanup: std::time::Instant,

    // Advanced detection state
    /// Baseline ntdll data for each process
    ntdll_baselines: HashMap<u32, NtdllBaseline>,
    /// Functions that have been detected as unhooked per process
    unhooked_functions: HashMap<u32, Vec<UnhookedFunction>>,
    /// Cross-process unhooking attempts detected
    cross_process_unhooks: Vec<CrossProcessUnhookState>,
    /// API calls observed after unhooking (for correlation)
    post_unhook_api_calls: HashMap<u32, Vec<TrackedApiCall>>,
    /// Processes with detected module rebasing
    rebased_modules: HashMap<u32, (u64, u64)>, // pid -> (actual_base, expected_base)
    /// Tool signatures detected per process
    detected_tools: HashMap<u32, Vec<String>>,
    /// Processes with partial .text restoration detected
    partial_restorations: HashSet<u32>,
    /// Expected ntdll base addresses per architecture
    expected_ntdll_bases: HashMap<&'static str, u64>,
}

impl NtdllWriteTracker {
    pub fn new() -> Self {
        // Common expected ntdll base addresses
        let mut expected_bases = HashMap::new();
        expected_bases.insert("x64", 0x7FFE0000_00000000u64); // Typical x64 base
        expected_bases.insert("wow64", 0x77000000u64); // WoW64 ntdll base
        expected_bases.insert("x86", 0x77000000u64); // Native x86 base

        Self {
            suspicious_sequences: HashMap::new(),
            ntdll_bases: HashMap::new(),
            ntdll_sizes: HashMap::new(),
            ntdll_exports: HashMap::new(),
            section_creators: HashSet::new(),
            fresh_mappers: HashSet::new(),
            sequence_counter: 0,
            max_op_age_secs: 30,
            last_cleanup: std::time::Instant::now(),
            // Initialize advanced detection state
            ntdll_baselines: HashMap::new(),
            unhooked_functions: HashMap::new(),
            cross_process_unhooks: Vec::new(),
            post_unhook_api_calls: HashMap::new(),
            rebased_modules: HashMap::new(),
            detected_tools: HashMap::new(),
            partial_restorations: HashSet::new(),
            expected_ntdll_bases: expected_bases,
        }
    }

    /// Store baseline ntdll data for a process
    pub fn store_baseline(&mut self, pid: u32, baseline: NtdllBaseline) {
        self.ntdll_baselines.insert(pid, baseline);
    }

    /// Get baseline for a process
    pub fn get_baseline(&self, pid: u32) -> Option<&NtdllBaseline> {
        self.ntdll_baselines.get(&pid)
    }

    /// Record an unhooked function detection
    pub fn record_unhooked_function(&mut self, pid: u32, func: UnhookedFunction) {
        self.unhooked_functions
            .entry(pid)
            .or_insert_with(Vec::new)
            .push(func);
    }

    /// Get all unhooked functions for a process
    pub fn get_unhooked_functions(&self, pid: u32) -> Option<&Vec<UnhookedFunction>> {
        self.unhooked_functions.get(&pid)
    }

    /// Record a cross-process unhooking attempt
    pub fn record_cross_process_unhook(&mut self, state: CrossProcessUnhookState) {
        self.cross_process_unhooks.push(state);
    }

    /// Record an API call after unhooking (for correlation)
    pub fn record_post_unhook_api(&mut self, pid: u32, call: TrackedApiCall) {
        let calls = self
            .post_unhook_api_calls
            .entry(pid)
            .or_insert_with(Vec::new);
        // Keep only last 100 calls per process
        if calls.len() >= 100 {
            calls.remove(0);
        }
        calls.push(call);
    }

    /// Get recent API calls after unhooking
    pub fn get_post_unhook_apis(&self, pid: u32) -> Vec<String> {
        self.post_unhook_api_calls
            .get(&pid)
            .map(|calls| calls.iter().map(|c| c.function_name.clone()).collect())
            .unwrap_or_default()
    }

    /// Record module rebasing detection
    pub fn record_rebasing(&mut self, pid: u32, actual_base: u64, expected_base: u64) {
        self.rebased_modules
            .insert(pid, (actual_base, expected_base));
    }

    /// Check if a module is rebased
    pub fn is_rebased(&self, pid: u32) -> Option<(u64, u64)> {
        self.rebased_modules.get(&pid).copied()
    }

    /// Record a detected tool signature
    pub fn record_tool_detection(&mut self, pid: u32, tool_name: String) {
        self.detected_tools
            .entry(pid)
            .or_insert_with(Vec::new)
            .push(tool_name);
    }

    /// Get detected tools for a process
    pub fn get_detected_tools(&self, pid: u32) -> Option<&Vec<String>> {
        self.detected_tools.get(&pid)
    }

    /// Mark a process as having partial .text restoration
    pub fn mark_partial_restoration(&mut self, pid: u32) {
        self.partial_restorations.insert(pid);
    }

    /// Check if process has partial restoration
    pub fn has_partial_restoration(&self, pid: u32) -> bool {
        self.partial_restorations.contains(&pid)
    }

    /// Analyze unhooking pattern and classify the technique
    pub fn classify_unhooking_technique(
        &self,
        pid: u32,
        unhooked_funcs: &[UnhookedFunction],
        has_fresh_mapping: bool,
        is_cross_process: bool,
    ) -> UnhookingTechnique {
        // Check for syscall-only unhooking (Perun's Fart)
        let syscall_count = unhooked_funcs.iter().filter(|f| f.is_syscall_stub).count();
        let non_syscall_count = unhooked_funcs.len() - syscall_count;

        if syscall_count > 0 && non_syscall_count == 0 {
            return UnhookingTechnique::PerunsFart;
        }

        // Check for tool signatures
        if let Some(tools) = self.detected_tools.get(&pid) {
            if tools.iter().any(|t| t.contains("SysWhispers")) {
                return UnhookingTechnique::SysWhispers;
            }
            if tools.iter().any(|t| t.contains("HellsGate")) {
                return UnhookingTechnique::HellsGate;
            }
            if tools.iter().any(|t| t.contains("HalosGate")) {
                return UnhookingTechnique::HalosGate;
            }
        }

        // Check for fresh ntdll mapping
        if has_fresh_mapping || self.fresh_mappers.contains(&pid) {
            return UnhookingTechnique::FreshNtdllMapping;
        }

        // Check for cross-process unhooking
        if is_cross_process {
            return UnhookingTechnique::CrossProcessCopy;
        }

        // Check for module rebasing
        if self.rebased_modules.contains_key(&pid) {
            return UnhookingTechnique::ModuleRebasing;
        }

        // Check for partial restoration
        if self.partial_restorations.contains(&pid) {
            return UnhookingTechnique::PartialTextRestore;
        }

        // Default to classic unhooking if sequence was detected
        if self.suspicious_sequences.contains_key(&(pid, pid)) {
            return UnhookingTechnique::ClassicUnhook;
        }

        UnhookingTechnique::Unknown
    }

    /// Record a new memory operation
    pub(crate) fn record_operation(
        &mut self,
        op: TrackedOperation,
    ) -> Option<Vec<TrackedOperation>> {
        let key = (op.source_pid, op.target_pid);
        let ops = self
            .suspicious_sequences
            .entry(key)
            .or_insert_with(Vec::new);
        ops.push(op);

        // Check if we have a complete suspicious sequence
        self.analyze_sequence(key)
    }

    /// Analyze operations for a given (source, target) pair
    fn analyze_sequence(&mut self, key: (u32, u32)) -> Option<Vec<TrackedOperation>> {
        let ops = self.suspicious_sequences.get(&key)?;

        if ops.len() < 2 {
            return None;
        }

        // Look for classic unhooking pattern:
        // VirtualProtect(Ex) to RWX -> WriteProcessMemory -> VirtualProtect(Ex) back to RX
        let has_protect_rwx = ops.iter().any(|op| {
            matches!(
                op.op_type,
                MemoryOperationType::VirtualProtect | MemoryOperationType::VirtualProtectEx
            ) && op.new_protection.map(|p| is_rwx(p)).unwrap_or(false)
        });

        let has_write = ops.iter().any(|op| {
            matches!(
                op.op_type,
                MemoryOperationType::WriteProcessMemory | MemoryOperationType::NtWriteVirtualMemory
            )
        });

        let has_protect_restore = ops.iter().any(|op| {
            matches!(
                op.op_type,
                MemoryOperationType::VirtualProtect | MemoryOperationType::VirtualProtectEx
            ) && op.new_protection.map(|p| is_rx(p)).unwrap_or(false)
        });

        // Classic unhooking sequence
        if has_protect_rwx && has_write && has_protect_restore {
            self.sequence_counter += 1;
            return Some(ops.clone());
        }

        // Fresh ntdll mapping (unhooking via section)
        let has_section_create = ops
            .iter()
            .any(|op| matches!(op.op_type, MemoryOperationType::SectionCreate));

        let has_map = ops.iter().any(|op| {
            matches!(
                op.op_type,
                MemoryOperationType::MapViewOfFile | MemoryOperationType::NtMapViewOfSection
            )
        });

        if has_section_create && has_map {
            self.sequence_counter += 1;
            return Some(ops.clone());
        }

        None
    }

    /// Update ntdll base address for a process
    pub fn set_ntdll_base(&mut self, pid: u32, base: u64, size: u64) {
        self.ntdll_bases.insert(pid, base);
        self.ntdll_sizes.insert(pid, size);
    }

    /// Check if an address falls within ntdll for a given process
    pub fn is_ntdll_address(&self, pid: u32, address: u64) -> bool {
        if let (Some(&base), Some(&size)) = (self.ntdll_bases.get(&pid), self.ntdll_sizes.get(&pid))
        {
            address >= base && address < base + size
        } else {
            false
        }
    }

    /// Try to resolve a function name from an ntdll address
    pub fn resolve_function(&self, pid: u32, address: u64) -> Option<String> {
        let base = *self.ntdll_bases.get(&pid)?;
        let exports = self.ntdll_exports.get(&pid)?;
        let rva = (address - base) as u32;

        // Find the export with the closest RVA <= the target RVA
        let mut best_match: Option<(&String, u32)> = None;
        for (name, &export_rva) in exports {
            if export_rva <= rva {
                if let Some((_, best_rva)) = best_match {
                    if export_rva > best_rva {
                        best_match = Some((name, export_rva));
                    }
                } else {
                    best_match = Some((name, export_rva));
                }
            }
        }

        // Only return if within reasonable offset (256 bytes)
        best_match
            .filter(|(_, export_rva)| rva - *export_rva < 256)
            .map(|(name, _)| name.clone())
    }

    /// Mark a process as having created a section from ntdll
    pub fn mark_section_creator(&mut self, pid: u32) {
        self.section_creators.insert(pid);
    }

    /// Mark a process as having mapped a fresh ntdll copy
    pub fn mark_fresh_mapper(&mut self, pid: u32) {
        self.fresh_mappers.insert(pid);
    }

    /// Check if process is a known section creator
    pub fn is_section_creator(&self, pid: u32) -> bool {
        self.section_creators.contains(&pid)
    }

    /// Check if process has mapped fresh ntdll
    pub fn is_fresh_mapper(&self, pid: u32) -> bool {
        self.fresh_mappers.contains(&pid)
    }

    /// Clean up old operations and stale process data
    pub fn cleanup(&mut self) {
        let now = std::time::Instant::now();
        if now.duration_since(self.last_cleanup).as_secs() < 30 {
            return;
        }
        self.last_cleanup = now;

        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let max_age_ms = self.max_op_age_secs * 1000;

        // Remove old operations
        for ops in self.suspicious_sequences.values_mut() {
            ops.retain(|op| now_epoch - op.timestamp < max_age_ms);
        }

        // Remove empty sequences
        self.suspicious_sequences.retain(|_, ops| !ops.is_empty());

        // Clean up old cross-process unhook records (keep last 5 minutes)
        let cross_process_max_age = 5 * 60 * 1000; // 5 minutes
        self.cross_process_unhooks
            .retain(|state| now_epoch - state.timestamp < cross_process_max_age);

        // Clean up old API call records
        for calls in self.post_unhook_api_calls.values_mut() {
            calls.retain(|call| now_epoch - call.timestamp < max_age_ms);
        }
        self.post_unhook_api_calls
            .retain(|_, calls| !calls.is_empty());

        // Note: We don't clean up ntdll_bases, baselines, etc. as those are still valid
        // until the process terminates. A separate process termination handler
        // should call remove_process().
    }

    /// Remove all tracking data for a terminated process
    pub fn remove_process(&mut self, pid: u32) {
        self.ntdll_bases.remove(&pid);
        self.ntdll_sizes.remove(&pid);
        self.ntdll_exports.remove(&pid);
        self.section_creators.remove(&pid);
        self.fresh_mappers.remove(&pid);

        // Remove advanced detection state
        self.ntdll_baselines.remove(&pid);
        self.unhooked_functions.remove(&pid);
        self.post_unhook_api_calls.remove(&pid);
        self.rebased_modules.remove(&pid);
        self.detected_tools.remove(&pid);
        self.partial_restorations.remove(&pid);

        // Remove cross-process records involving this PID
        self.cross_process_unhooks
            .retain(|state| state.source_pid != pid && state.target_pid != pid);

        // Remove sequences involving this PID
        self.suspicious_sequences
            .retain(|(src, tgt), _| *src != pid && *tgt != pid);
    }
}

impl Default for NtdllWriteTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// NTDLL Write Monitor collector
pub struct NtdllWriteMonitor {
    #[allow(dead_code)]
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    #[allow(dead_code)]
    event_tx: mpsc::Sender<TelemetryEvent>,
    #[allow(dead_code)]
    tracker: Arc<RwLock<NtdllWriteTracker>>,
}

impl NtdllWriteMonitor {
    /// Create a new NTDLL write monitor
    pub fn new(config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(500);
        let tracker = Arc::new(RwLock::new(NtdllWriteTracker::new()));

        // Start platform-specific monitoring
        #[cfg(target_os = "windows")]
        {
            let tx_clone = tx.clone();
            let tracker_clone = tracker.clone();
            let config_clone = config.clone();
            tokio::spawn(async move {
                windows_impl::monitor_loop(tx_clone, tracker_clone, config_clone).await;
            });
        }

        #[cfg(target_os = "linux")]
        {
            let tx_clone = tx.clone();
            let tracker_clone = tracker.clone();
            let config_clone = config.clone();
            tokio::spawn(async move {
                linux_impl::monitor_loop(tx_clone, tracker_clone, config_clone).await;
            });
        }

        info!("NTDLL write monitor initialized");
        Self {
            config: config.clone(),
            event_rx: rx,
            event_tx: tx,
            tracker,
        }
    }

    /// Get next event from the collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert protection flags to human-readable string
fn protection_to_string(protection: u32) -> String {
    #[cfg(target_os = "windows")]
    {
        const PAGE_NOACCESS: u32 = 0x01;
        const PAGE_READONLY: u32 = 0x02;
        const PAGE_READWRITE: u32 = 0x04;
        const PAGE_WRITECOPY: u32 = 0x08;
        const PAGE_EXECUTE: u32 = 0x10;
        const PAGE_EXECUTE_READ: u32 = 0x20;
        const PAGE_EXECUTE_READWRITE: u32 = 0x40;
        const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
        const PAGE_GUARD: u32 = 0x100;

        match protection {
            PAGE_NOACCESS => "PAGE_NOACCESS".to_string(),
            PAGE_READONLY => "PAGE_READONLY".to_string(),
            PAGE_READWRITE => "PAGE_READWRITE".to_string(),
            PAGE_WRITECOPY => "PAGE_WRITECOPY".to_string(),
            PAGE_EXECUTE => "PAGE_EXECUTE".to_string(),
            PAGE_EXECUTE_READ => "PAGE_EXECUTE_READ".to_string(),
            PAGE_EXECUTE_READWRITE => "PAGE_EXECUTE_READWRITE".to_string(),
            PAGE_EXECUTE_WRITECOPY => "PAGE_EXECUTE_WRITECOPY".to_string(),
            _ if protection & PAGE_GUARD != 0 => {
                format!("PAGE_GUARD | 0x{:x}", protection & !PAGE_GUARD)
            }
            _ => format!("0x{:x}", protection),
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        // Linux mprotect flags
        const PROT_NONE: u32 = 0x0;
        const PROT_READ: u32 = 0x1;
        const PROT_WRITE: u32 = 0x2;
        const PROT_EXEC: u32 = 0x4;

        let mut parts = Vec::new();
        if protection == PROT_NONE {
            return "PROT_NONE".to_string();
        }
        if protection & PROT_READ != 0 {
            parts.push("PROT_READ");
        }
        if protection & PROT_WRITE != 0 {
            parts.push("PROT_WRITE");
        }
        if protection & PROT_EXEC != 0 {
            parts.push("PROT_EXEC");
        }
        if parts.is_empty() {
            format!("0x{:x}", protection)
        } else {
            parts.join(" | ")
        }
    }
}

/// Check if protection flags indicate RWX (Read-Write-Execute)
fn is_rwx(protection: u32) -> bool {
    #[cfg(target_os = "windows")]
    {
        const PAGE_EXECUTE_READWRITE: u32 = 0x40;
        const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
        protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY
    }

    #[cfg(not(target_os = "windows"))]
    {
        const PROT_READ: u32 = 0x1;
        const PROT_WRITE: u32 = 0x2;
        const PROT_EXEC: u32 = 0x4;
        (protection & PROT_READ != 0)
            && (protection & PROT_WRITE != 0)
            && (protection & PROT_EXEC != 0)
    }
}

/// Classify the targeted memory region for backend triage.
///
/// Distinguishes a write into the export table (strongest tampering signal),
/// executable code (`.text`), an RWX scratch region, or plain data. Derived
/// from the resolved function name and the protection flags. Pure
/// classification of a detection event; carries no side effects.
fn classify_region(
    target_function: Option<&str>,
    old_protection: Option<u32>,
    new_protection: Option<u32>,
) -> String {
    let func = target_function.unwrap_or("").to_lowercase();

    if func.contains("export") || func.contains("eat") {
        return "export_table".to_string();
    }

    let prot = new_protection.or(old_protection).unwrap_or(0);
    if is_rwx(prot) {
        return "rwx".to_string();
    }

    if func.contains(".text") || is_rx(prot) {
        return "text".to_string();
    }

    "data".to_string()
}

/// Check if protection flags indicate RX (Read-Execute, no Write)
fn is_rx(protection: u32) -> bool {
    #[cfg(target_os = "windows")]
    {
        const PAGE_EXECUTE_READ: u32 = 0x20;
        protection == PAGE_EXECUTE_READ
    }

    #[cfg(not(target_os = "windows"))]
    {
        const PROT_READ: u32 = 0x1;
        const PROT_WRITE: u32 = 0x2;
        const PROT_EXEC: u32 = 0x4;
        (protection & PROT_READ != 0)
            && (protection & PROT_WRITE == 0)
            && (protection & PROT_EXEC != 0)
    }
}

// ============================================================================
// Windows Implementation
// ============================================================================

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::*;
    use std::collections::HashSet;
    use std::ffi::c_void;
    use std::mem;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, HMODULE};
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW,
        MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
    use windows::Win32::System::ProcessStatus::{
        EnumProcessModules, GetModuleBaseNameW, GetModuleInformation, K32GetProcessImageFileNameW,
        MODULEINFO,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    const PAGE_EXECUTE: u32 = 0x10;
    const PAGE_EXECUTE_READ: u32 = 0x20;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
    const MEM_COMMIT: u32 = 0x1000;
    const MEM_IMAGE: u32 = 0x1000000;

    /// Main monitoring loop for Windows
    pub async fn monitor_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        tracker: Arc<RwLock<NtdllWriteTracker>>,
        config: AgentConfig,
    ) {
        let mul = config.sub_loop_interval_multiplier;
        info!(multiplier = mul, "Starting Windows NTDLL write monitor");

        // Track known ntdll hashes per process to detect modifications
        let ntdll_hashes: Arc<RwLock<HashMap<u32, Vec<u8>>>> =
            Arc::new(RwLock::new(HashMap::new()));

        // Track known section mappings
        let section_mappings: Arc<RwLock<HashMap<u32, Vec<(u64, u64)>>>> =
            Arc::new(RwLock::new(HashMap::new()));

        // Track processes with suspicious characteristics
        let suspicious_procs: Arc<RwLock<HashSet<u32>>> = Arc::new(RwLock::new(HashSet::new()));

        // Start ntdll integrity scanner (5s base, scaled by multiplier)
        let tx_scan = tx.clone();
        let tracker_scan = tracker.clone();
        let hashes_scan = ntdll_hashes.clone();
        let scan_interval_ms = ((5000.0 * mul) as u64).max(5000);
        tokio::spawn(async move {
            ntdll_integrity_scanner(tx_scan, tracker_scan, hashes_scan, scan_interval_ms).await;
        });

        // Start fresh mapping detector (3s base, scaled by multiplier)
        let tx_map = tx.clone();
        let tracker_map = tracker.clone();
        let mappings_map = section_mappings.clone();
        let map_interval_ms = ((3000.0 * mul) as u64).max(3000);
        tokio::spawn(async move {
            fresh_mapping_detector(tx_map, tracker_map, mappings_map, map_interval_ms).await;
        });

        // Start syscall stub scanner (10s base, scaled by multiplier)
        let tx_syscall = tx.clone();
        let tracker_syscall = tracker.clone();
        let suspicious_syscall = suspicious_procs.clone();
        let syscall_interval_ms = ((10000.0 * mul) as u64).max(10000);
        tokio::spawn(async move {
            syscall_stub_scanner(
                tx_syscall,
                tracker_syscall,
                suspicious_syscall,
                syscall_interval_ms,
            )
            .await;
        });

        // Start advanced unhooking detector (15s base, scaled by multiplier)
        let tx_advanced = tx.clone();
        let tracker_advanced = tracker.clone();
        let advanced_interval_ms = ((15000.0 * mul) as u64).max(15000);
        tokio::spawn(async move {
            advanced_unhooking_detector(tx_advanced, tracker_advanced, advanced_interval_ms).await;
        });

        // Main cleanup loop
        let mut cleanup_interval = tokio::time::interval(tokio::time::Duration::from_secs(60));

        loop {
            cleanup_interval.tick().await;
            let mut tracker_guard = tracker.write().await;
            tracker_guard.cleanup();
        }
    }

    /// Scan ntdll integrity by comparing .text section hashes
    async fn ntdll_integrity_scanner(
        tx: mpsc::Sender<TelemetryEvent>,
        tracker: Arc<RwLock<NtdllWriteTracker>>,
        hashes: Arc<RwLock<HashMap<u32, Vec<u8>>>>,
        interval_ms: u64,
    ) {
        info!("Starting NTDLL integrity scanner");
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        // Known processes that legitimately modify ntdll hooks (security tools)
        let legitimate_hookers: HashSet<&str> = [
            "msmpeng.exe",         // Windows Defender
            "mssense.exe",         // Microsoft Defender for Endpoint
            "csfalconservice.exe", // CrowdStrike
            "carbonblack.exe",     // VMware Carbon Black
            "sentinel.exe",        // SentinelOne
            "tamandua-agent.exe",  // Our own agent
        ]
        .iter()
        .cloned()
        .collect();

        loop {
            interval.tick().await;

            unsafe {
                // Enumerate all processes
                let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                    Ok(h) => h,
                    Err(_) => continue,
                };

                let mut entry = PROCESSENTRY32W {
                    dwSize: mem::size_of::<PROCESSENTRY32W>() as u32,
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

                        // Skip system processes and legitimate hookers
                        if pid > 10
                            && !legitimate_hookers
                                .iter()
                                .any(|&h| name.to_lowercase().contains(h))
                        {
                            if let Some(event) =
                                check_ntdll_integrity(pid, &name, &tracker, &hashes).await
                            {
                                if tx.send(event).await.is_err() {
                                    return;
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

    /// Check ntdll integrity for a single process
    async fn check_ntdll_integrity(
        pid: u32,
        process_name: &str,
        tracker: &Arc<RwLock<NtdllWriteTracker>>,
        hashes: &Arc<RwLock<HashMap<u32, Vec<u8>>>>,
    ) -> Option<TelemetryEvent> {
        unsafe {
            let handle =
                OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid).ok()?;

            // Find ntdll base
            let ntdll_info = find_ntdll_module(handle)?;
            let ntdll_base = ntdll_info.0;
            let ntdll_size = ntdll_info.1;

            // Update tracker with ntdll location
            {
                let mut tracker_guard = tracker.write().await;
                tracker_guard.set_ntdll_base(pid, ntdll_base, ntdll_size);
            }

            // Read ntdll .text section and compute hash
            let text_section = read_text_section(handle, ntdll_base)?;
            let current_hash = compute_hash(&text_section);

            // Compare with baseline
            let mut hashes_guard = hashes.write().await;
            if let Some(baseline) = hashes_guard.get(&pid) {
                if *baseline != current_hash {
                    // NTDLL has been modified!
                    let _ = CloseHandle(handle);

                    let process_path = get_process_path(pid);
                    let event = NtdllWriteEvent {
                        source_pid: pid,
                        source_process: process_name.to_string(),
                        source_path: process_path.clone(),
                        target_pid: pid,
                        target_process: process_name.to_string(),
                        target_address: ntdll_base,
                        target_function: Some("ntdll.dll!.text".to_string()),
                        operation: MemoryOperationType::WriteProcessMemory,
                        old_protection: Some(PAGE_EXECUTE_READ),
                        new_protection: Some(PAGE_EXECUTE_READ),
                        bytes_written: None,
                        region_size: Some(text_section.len() as u64),
                        mitre_technique: "T1562.006".to_string(),
                        confidence: 0.95,
                        is_sequence_part: false,
                        sequence_id: None,
                        evidence: vec![
                            "NTDLL .text section hash mismatch detected".to_string(),
                            format!("Process: {} (PID {})", process_name, pid),
                            "Possible unhooking or inline hook modification".to_string(),
                        ],
                    };

                    return Some(event.to_telemetry_event());
                }
            } else {
                // First time seeing this process - store baseline
                hashes_guard.insert(pid, current_hash);
            }

            let _ = CloseHandle(handle);
        }

        None
    }

    /// Find ntdll.dll module in a process
    unsafe fn find_ntdll_module(handle: HANDLE) -> Option<(u64, u64)> {
        let mut modules = [HMODULE::default(); 1024];
        let mut needed: u32 = 0;

        if EnumProcessModules(
            handle,
            modules.as_mut_ptr(),
            (modules.len() * mem::size_of::<HMODULE>()) as u32,
            &mut needed,
        )
        .is_err()
        {
            return None;
        }

        let count = (needed as usize / mem::size_of::<HMODULE>()).min(modules.len());

        for &module in &modules[..count] {
            let mut name_buf = [0u16; 260];
            let name_len = GetModuleBaseNameW(handle, module, &mut name_buf);

            if name_len > 0 {
                let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                if name.to_lowercase() == "ntdll.dll" {
                    let mut info = MODULEINFO::default();
                    if GetModuleInformation(
                        handle,
                        module,
                        &mut info,
                        mem::size_of::<MODULEINFO>() as u32,
                    )
                    .is_ok()
                    {
                        return Some((info.lpBaseOfDll as u64, info.SizeOfImage as u64));
                    }
                }
            }
        }

        None
    }

    /// Read the .text section of ntdll
    unsafe fn read_text_section(handle: HANDLE, base: u64) -> Option<Vec<u8>> {
        // Read DOS header
        let mut dos_header = [0u8; 64];
        let mut bytes_read: usize = 0;

        if ReadProcessMemory(
            handle,
            base as *const c_void,
            dos_header.as_mut_ptr() as *mut c_void,
            dos_header.len(),
            Some(&mut bytes_read),
        )
        .is_err()
        {
            return None;
        }

        // Check MZ signature
        if dos_header[0] != b'M' || dos_header[1] != b'Z' {
            return None;
        }

        // Get PE header offset
        let pe_offset = u32::from_le_bytes([
            dos_header[60],
            dos_header[61],
            dos_header[62],
            dos_header[63],
        ]) as u64;

        // Read PE header (enough for section headers)
        let pe_header_size = 0x1000usize; // 4KB should be enough
        let mut pe_header = vec![0u8; pe_header_size];

        if ReadProcessMemory(
            handle,
            (base + pe_offset) as *const c_void,
            pe_header.as_mut_ptr() as *mut c_void,
            pe_header_size,
            Some(&mut bytes_read),
        )
        .is_err()
        {
            return None;
        }

        // Check PE signature
        if pe_header[0] != b'P' || pe_header[1] != b'E' {
            return None;
        }

        // Get number of sections (offset 6 from PE signature, in COFF header)
        let num_sections = u16::from_le_bytes([pe_header[6], pe_header[7]]) as usize;

        // Get optional header size (offset 20 from PE signature)
        let optional_header_size = u16::from_le_bytes([pe_header[20], pe_header[21]]) as usize;

        // Section headers start after optional header
        let section_offset = 24 + optional_header_size; // 24 = COFF header size

        // Parse section headers to find .text
        for i in 0..num_sections {
            let section_start = section_offset + i * 40; // Each section header is 40 bytes
            if section_start + 40 > pe_header.len() {
                break;
            }

            let section_name = std::str::from_utf8(&pe_header[section_start..section_start + 8])
                .unwrap_or("")
                .trim_end_matches('\0');

            if section_name == ".text" {
                let virtual_size = u32::from_le_bytes([
                    pe_header[section_start + 8],
                    pe_header[section_start + 9],
                    pe_header[section_start + 10],
                    pe_header[section_start + 11],
                ]) as usize;

                let virtual_address = u32::from_le_bytes([
                    pe_header[section_start + 12],
                    pe_header[section_start + 13],
                    pe_header[section_start + 14],
                    pe_header[section_start + 15],
                ]) as u64;

                // Read .text section
                let text_address = base + virtual_address;
                let mut text_data = vec![0u8; virtual_size.min(1024 * 1024)]; // Cap at 1MB

                if ReadProcessMemory(
                    handle,
                    text_address as *const c_void,
                    text_data.as_mut_ptr() as *mut c_void,
                    text_data.len(),
                    Some(&mut bytes_read),
                )
                .is_ok()
                {
                    text_data.truncate(bytes_read);
                    return Some(text_data);
                }
            }
        }

        None
    }

    /// Compute a simple hash of data
    fn compute_hash(data: &[u8]) -> Vec<u8> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // Use a simple hash for comparison (not cryptographic)
        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        hasher.finish().to_le_bytes().to_vec()
    }

    /// Detect fresh ntdll mappings (unhooking via section)
    async fn fresh_mapping_detector(
        tx: mpsc::Sender<TelemetryEvent>,
        tracker: Arc<RwLock<NtdllWriteTracker>>,
        mappings: Arc<RwLock<HashMap<u32, Vec<(u64, u64)>>>>,
        interval_ms: u64,
    ) {
        info!("Starting fresh NTDLL mapping detector");
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        loop {
            interval.tick().await;

            unsafe {
                let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                    Ok(h) => h,
                    Err(_) => continue,
                };

                let mut entry = PROCESSENTRY32W {
                    dwSize: mem::size_of::<PROCESSENTRY32W>() as u32,
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

                        if pid > 10 {
                            if let Some(event) =
                                check_fresh_mappings(pid, &name, &tracker, &mappings).await
                            {
                                if tx.send(event).await.is_err() {
                                    return;
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

    /// Check for fresh ntdll mappings in a process
    async fn check_fresh_mappings(
        pid: u32,
        process_name: &str,
        tracker: &Arc<RwLock<NtdllWriteTracker>>,
        mappings: &Arc<RwLock<HashMap<u32, Vec<(u64, u64)>>>>,
    ) -> Option<TelemetryEvent> {
        // Collect ntdll mappings synchronously (no await while holding Windows structs)
        let ntdll_mappings = collect_ntdll_mappings_sync(pid);

        if ntdll_mappings.is_empty() {
            return None;
        }

        // Now we can safely use await - all Windows structs are dropped
        let mut mappings_guard = mappings.write().await;
        let previous = mappings_guard.get(&pid).cloned().unwrap_or_default();

        // Detect new mappings (fresh ntdll copies)
        for &(base, size) in &ntdll_mappings {
            if !previous.iter().any(|(b, _)| *b == base) && !previous.is_empty() {
                // New ntdll mapping detected!
                let mut tracker_guard = tracker.write().await;
                tracker_guard.mark_fresh_mapper(pid);
                drop(tracker_guard);

                let process_path = get_process_path(pid);
                let event = NtdllWriteEvent {
                    source_pid: pid,
                    source_process: process_name.to_string(),
                    source_path: process_path.clone(),
                    target_pid: pid,
                    target_process: process_name.to_string(),
                    target_address: base,
                    target_function: Some("ntdll.dll (fresh mapping)".to_string()),
                    operation: MemoryOperationType::NtMapViewOfSection,
                    old_protection: None,
                    new_protection: Some(PAGE_EXECUTE_READ),
                    bytes_written: None,
                    region_size: Some(size),
                    mitre_technique: "T1562.006".to_string(),
                    confidence: 0.9,
                    is_sequence_part: false,
                    sequence_id: None,
                    evidence: vec![
                        "Fresh NTDLL mapping detected".to_string(),
                        format!("New mapping at 0x{:016x}, size {} bytes", base, size),
                        format!("Process: {} (PID {})", process_name, pid),
                        "Possible unhooking via manual NTDLL mapping".to_string(),
                    ],
                };

                mappings_guard.insert(pid, ntdll_mappings);
                return Some(event.to_telemetry_event());
            }
        }

        // Update mappings
        mappings_guard.insert(pid, ntdll_mappings);

        None
    }

    /// Synchronously collect ntdll mappings (no async, so Windows structs are safe)
    fn collect_ntdll_mappings_sync(pid: u32) -> Vec<(u64, u64)> {
        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            {
                Ok(h) => h,
                Err(_) => return Vec::new(),
            };

            let mut ntdll_mappings = Vec::new();

            // Enumerate modules
            let module_snapshot =
                match CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) {
                    Ok(h) => h,
                    Err(_) => {
                        let _ = CloseHandle(handle);
                        return Vec::new();
                    }
                };

            let mut module_entry = MODULEENTRY32W {
                dwSize: mem::size_of::<MODULEENTRY32W>() as u32,
                ..Default::default()
            };

            if Module32FirstW(module_snapshot, &mut module_entry).is_ok() {
                loop {
                    let module_name = String::from_utf16_lossy(
                        &module_entry.szModule[..module_entry
                            .szModule
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(module_entry.szModule.len())],
                    );

                    if module_name.to_lowercase() == "ntdll.dll" {
                        ntdll_mappings.push((
                            module_entry.modBaseAddr as u64,
                            module_entry.modBaseSize as u64,
                        ));
                    }

                    if Module32NextW(module_snapshot, &mut module_entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(module_snapshot);
            let _ = CloseHandle(handle);

            ntdll_mappings
        }
    }

    /// Scan for manual syscall stubs
    async fn syscall_stub_scanner(
        tx: mpsc::Sender<TelemetryEvent>,
        tracker: Arc<RwLock<NtdllWriteTracker>>,
        suspicious: Arc<RwLock<HashSet<u32>>>,
        interval_ms: u64,
    ) {
        info!("Starting syscall stub scanner");
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        // Syscall instruction patterns
        // x64: syscall (0F 05)
        // x64: sysenter (0F 34) - less common
        // int 2e (CD 2E) - legacy
        let syscall_patterns: &[&[u8]] = &[
            &[0x0F, 0x05], // syscall
            &[0x0F, 0x34], // sysenter
            &[0xCD, 0x2E], // int 2e
        ];

        loop {
            interval.tick().await;

            unsafe {
                let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                    Ok(h) => h,
                    Err(_) => continue,
                };

                let mut entry = PROCESSENTRY32W {
                    dwSize: mem::size_of::<PROCESSENTRY32W>() as u32,
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

                        if pid > 10 {
                            // Check if process has fresh ntdll mapping (indicator)
                            let is_fresh_mapper = {
                                let tracker_guard = tracker.read().await;
                                tracker_guard.is_fresh_mapper(pid)
                            };

                            if is_fresh_mapper {
                                if let Some(event) =
                                    scan_for_syscall_stubs(pid, &name, &tracker, syscall_patterns)
                                        .await
                                {
                                    let mut suspicious_guard = suspicious.write().await;
                                    suspicious_guard.insert(pid);
                                    drop(suspicious_guard);

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

    /// Scan process for manual syscall stubs in private executable memory
    async fn scan_for_syscall_stubs(
        pid: u32,
        process_name: &str,
        _tracker: &Arc<RwLock<NtdllWriteTracker>>,
        patterns: &[&[u8]],
    ) -> Option<TelemetryEvent> {
        unsafe {
            let handle =
                OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid).ok()?;

            // Scan memory regions for syscall patterns in private executable memory
            let mut address: usize = 0;

            loop {
                let mut mbi = MEMORY_BASIC_INFORMATION::default();
                let result = VirtualQueryEx(
                    handle,
                    Some(address as *const c_void),
                    &mut mbi,
                    mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                );

                if result == 0 {
                    break;
                }

                // Check for private executable memory (not backed by file)
                let is_executable = mbi.Protect.0 & PAGE_EXECUTE != 0
                    || mbi.Protect.0 & PAGE_EXECUTE_READ != 0
                    || mbi.Protect.0 & PAGE_EXECUTE_READWRITE != 0
                    || mbi.Protect.0 & PAGE_EXECUTE_WRITECOPY != 0;

                let is_private = mbi.Type.0 != MEM_IMAGE;
                let is_committed = mbi.State.0 & MEM_COMMIT != 0;

                if is_executable && is_private && is_committed && mbi.RegionSize > 0 {
                    // Read memory and search for syscall patterns
                    let region_size = (mbi.RegionSize as usize).min(64 * 1024); // Cap at 64KB
                    let mut buffer = vec![0u8; region_size];
                    let mut bytes_read: usize = 0;

                    if ReadProcessMemory(
                        handle,
                        mbi.BaseAddress,
                        buffer.as_mut_ptr() as *mut c_void,
                        region_size,
                        Some(&mut bytes_read),
                    )
                    .is_ok()
                    {
                        // Search for syscall patterns
                        for pattern in patterns {
                            if let Some(offset) = find_pattern(&buffer[..bytes_read], pattern) {
                                let _ = CloseHandle(handle);

                                let process_path = get_process_path(pid);
                                let event = NtdllWriteEvent {
                                    source_pid: pid,
                                    source_process: process_name.to_string(),
                                    source_path: process_path.clone(),
                                    target_pid: pid,
                                    target_process: process_name.to_string(),
                                    target_address: mbi.BaseAddress as u64 + offset as u64,
                                    target_function: Some(format!(
                                        "syscall stub at private memory 0x{:x}",
                                        mbi.BaseAddress as u64 + offset as u64
                                    )),
                                    operation: MemoryOperationType::DirectSyscall,
                                    old_protection: None,
                                    new_protection: Some(mbi.Protect.0),
                                    bytes_written: Some(
                                        buffer[offset..].iter().take(16).cloned().collect(),
                                    ),
                                    region_size: Some(mbi.RegionSize as u64),
                                    mitre_technique: "T1562.006".to_string(),
                                    confidence: 0.85,
                                    is_sequence_part: false,
                                    sequence_id: None,
                                    evidence: vec![
                                        "Direct syscall instruction found in private executable memory".to_string(),
                                        format!("Pattern: {:02x?}", pattern),
                                        format!("Address: 0x{:x}", mbi.BaseAddress as u64 + offset as u64),
                                        format!("Process: {} (PID {})", process_name, pid),
                                        "Possible direct syscall evasion technique".to_string(),
                                    ],
                                };

                                return Some(event.to_telemetry_event());
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
        }

        None
    }

    /// Find a pattern in a buffer
    fn find_pattern(buffer: &[u8], pattern: &[u8]) -> Option<usize> {
        if pattern.is_empty() || buffer.len() < pattern.len() {
            return None;
        }

        buffer
            .windows(pattern.len())
            .position(|window| window == pattern)
    }

    /// Get process path
    fn get_process_path(pid: u32) -> String {
        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            {
                Ok(h) => h,
                Err(_) => return String::new(),
            };

            let mut path_buf = [0u16; 260];
            let len = K32GetProcessImageFileNameW(handle, &mut path_buf);
            let _ = CloseHandle(handle);

            if len > 0 {
                String::from_utf16_lossy(&path_buf[..len as usize])
            } else {
                String::new()
            }
        }
    }

    // ========================================================================
    // Advanced Unhooking Detection Functions
    // ========================================================================

    /// Detect inline hook type from first bytes of a function
    pub fn detect_hook_type(bytes: &[u8]) -> Option<HookType> {
        if bytes.is_empty() {
            return None;
        }

        // JMP rel32 (E9 xx xx xx xx)
        if bytes.len() >= 5 && bytes[0] == 0xE9 {
            return Some(HookType::JmpRel32);
        }

        // JMP [rip+disp] (FF 25 xx xx xx xx) - 6 bytes
        if bytes.len() >= 6 && bytes[0] == 0xFF && bytes[1] == 0x25 {
            return Some(HookType::JmpRipRelative);
        }

        // CALL rel32 (E8 xx xx xx xx)
        if bytes.len() >= 5 && bytes[0] == 0xE8 {
            return Some(HookType::CallRel32);
        }

        // INT3 breakpoint (CC)
        if bytes[0] == 0xCC {
            return Some(HookType::Int3Breakpoint);
        }

        // Push/ret trampoline: MOV RAX, imm64 (48 B8); JMP RAX (FF E0)
        // or: PUSH imm64; RET pattern
        if bytes.len() >= 12 && bytes[0] == 0x48 && bytes[1] == 0xB8 {
            // Check for JMP RAX at offset 10
            if bytes.len() >= 12 && bytes[10] == 0xFF && bytes[11] == 0xE0 {
                return Some(HookType::PushRetTrampoline);
            }
        }

        // mov r10, imm64 (49 BA xx xx xx xx xx xx xx xx); jmp r10 (41 FF E2)
        if bytes.len() >= 12 && bytes[0] == 0x49 && bytes[1] == 0xBA {
            if bytes.len() >= 14 && bytes[10] == 0x41 && bytes[11] == 0xFF && bytes[12] == 0xE2 {
                return Some(HookType::PushRetTrampoline);
            }
        }

        None
    }

    /// Check if bytes represent a clean syscall stub (not hooked)
    /// x64 Windows syscall stub pattern:
    /// 4C 8B D1        mov r10, rcx
    /// B8 XX XX 00 00  mov eax, <syscall_number>
    /// 0F 05           syscall
    /// C3              ret
    pub fn is_clean_syscall_stub(bytes: &[u8]) -> Option<u16> {
        if bytes.len() < 12 {
            return None;
        }

        // Check for mov r10, rcx (4C 8B D1)
        if bytes[0] != 0x4C || bytes[1] != 0x8B || bytes[2] != 0xD1 {
            return None;
        }

        // Check for mov eax, imm32 (B8 xx xx xx xx)
        if bytes[3] != 0xB8 {
            return None;
        }

        // Extract syscall number (little-endian)
        let syscall_num = u16::from_le_bytes([bytes[4], bytes[5]]);

        // Verify upper bytes are 0
        if bytes[6] != 0x00 || bytes[7] != 0x00 {
            return None;
        }

        // Check for syscall (0F 05) and ret (C3)
        // Note: There may be test/jnz for Meltdown mitigation between mov and syscall
        // Pattern: test byte ptr [SharedUserData+0x308], 1; jnz +3

        // Simple check: look for syscall instruction in the stub
        for i in 8..bytes.len().min(20) {
            if bytes.len() > i + 1 && bytes[i] == 0x0F && bytes[i + 1] == 0x05 {
                return Some(syscall_num);
            }
        }

        None
    }

    /// Detect if a function prologue was hooked and then restored
    pub fn detect_hook_restoration(
        original_bytes: &[u8],
        current_bytes: &[u8],
    ) -> Option<HookType> {
        if original_bytes.len() < 5 || current_bytes.len() < 5 {
            return None;
        }

        // If original had a hook pattern and current is clean syscall stub
        let original_hook = detect_hook_type(original_bytes);
        let current_is_clean = is_clean_syscall_stub(current_bytes).is_some();

        if original_hook.is_some() && current_is_clean {
            return original_hook;
        }

        None
    }

    /// Parse PE sections from module base
    pub fn parse_pe_sections(handle: HANDLE, base: u64) -> Option<Vec<(String, u32, u32)>> {
        unsafe {
            // Read DOS header
            let mut dos_header = [0u8; 64];
            let mut bytes_read: usize = 0;

            if ReadProcessMemory(
                handle,
                base as *const c_void,
                dos_header.as_mut_ptr() as *mut c_void,
                dos_header.len(),
                Some(&mut bytes_read),
            )
            .is_err()
            {
                return None;
            }

            // Check MZ signature
            if dos_header[0] != b'M' || dos_header[1] != b'Z' {
                return None;
            }

            // Get PE header offset
            let pe_offset = u32::from_le_bytes([
                dos_header[60],
                dos_header[61],
                dos_header[62],
                dos_header[63],
            ]) as u64;

            // Read PE header
            let pe_header_size = 0x1000usize;
            let mut pe_header = vec![0u8; pe_header_size];

            if ReadProcessMemory(
                handle,
                (base + pe_offset) as *const c_void,
                pe_header.as_mut_ptr() as *mut c_void,
                pe_header_size,
                Some(&mut bytes_read),
            )
            .is_err()
            {
                return None;
            }

            // Check PE signature
            if pe_header[0] != b'P' || pe_header[1] != b'E' {
                return None;
            }

            // Get number of sections
            let num_sections = u16::from_le_bytes([pe_header[6], pe_header[7]]) as usize;

            // Get optional header size
            let optional_header_size = u16::from_le_bytes([pe_header[20], pe_header[21]]) as usize;

            // Section headers start after optional header
            let section_offset = 24 + optional_header_size;

            let mut sections = Vec::new();

            for i in 0..num_sections {
                let section_start = section_offset + i * 40;
                if section_start + 40 > pe_header.len() {
                    break;
                }

                let section_name =
                    std::str::from_utf8(&pe_header[section_start..section_start + 8])
                        .unwrap_or("")
                        .trim_end_matches('\0')
                        .to_string();

                let virtual_size = u32::from_le_bytes([
                    pe_header[section_start + 8],
                    pe_header[section_start + 9],
                    pe_header[section_start + 10],
                    pe_header[section_start + 11],
                ]);

                let virtual_address = u32::from_le_bytes([
                    pe_header[section_start + 12],
                    pe_header[section_start + 13],
                    pe_header[section_start + 14],
                    pe_header[section_start + 15],
                ]);

                sections.push((section_name, virtual_address, virtual_size));
            }

            Some(sections)
        }
    }

    /// Compare sections between baseline and current memory state
    pub async fn compare_sections(
        pid: u32,
        handle: HANDLE,
        base: u64,
        baseline: &NtdllBaseline,
    ) -> Vec<SectionComparisonResult> {
        let mut results = Vec::new();

        // Get current sections
        let current_sections = match parse_pe_sections(handle, base) {
            Some(s) => s,
            None => return results,
        };

        for (section_name, rva, size) in current_sections {
            // Only compare .text section for unhooking detection
            if section_name != ".text" {
                continue;
            }

            // Read current section data
            let section_addr = base + rva as u64;
            let mut current_data = vec![0u8; size.min(1024 * 1024) as usize];
            let mut bytes_read: usize = 0;

            unsafe {
                if ReadProcessMemory(
                    handle,
                    section_addr as *const c_void,
                    current_data.as_mut_ptr() as *mut c_void,
                    current_data.len(),
                    Some(&mut bytes_read),
                )
                .is_err()
                {
                    continue;
                }
            }
            current_data.truncate(bytes_read);

            // Get baseline hash for this section
            let baseline_hash = match baseline.sections.get(&section_name) {
                Some((_, _, hash)) => hash,
                None => continue,
            };

            // Compute current hash
            let current_hash = compute_hash(&current_data);

            // If hashes differ, analyze the differences
            if current_hash != *baseline_hash {
                // Count byte differences
                let mut diff_count = 0u32;
                let mut first_diff: Option<u32> = None;
                let mut modified_funcs = Vec::new();

                // For detailed comparison, we'd need to read baseline data
                // For now, just report that the section differs
                diff_count = 1; // At least one difference
                first_diff = Some(0);

                // Check which functions might have been modified
                for func_name in CRITICAL_FUNCTIONS {
                    if let Some((func_rva, _baseline_bytes)) =
                        baseline.function_prologues.get(*func_name)
                    {
                        // Check if this function's RVA falls within the section
                        if *func_rva >= rva && *func_rva < rva + size {
                            modified_funcs.push(func_name.to_string());
                        }
                    }
                }

                let diff_percent = if size > 0 {
                    (diff_count as f32 / size as f32) * 100.0
                } else {
                    0.0
                };

                results.push(SectionComparisonResult {
                    section_name: section_name.clone(),
                    section_rva: rva,
                    section_size: size,
                    difference_count: diff_count,
                    difference_percent: diff_percent,
                    selective_modification: modified_funcs.len() < CRITICAL_FUNCTIONS.len() / 2,
                    modified_functions: modified_funcs,
                    first_diff_offset: first_diff,
                });
            }
        }

        results
    }

    /// Analyze function-level unhooking by comparing prologues
    pub fn analyze_function_unhooking(
        handle: HANDLE,
        base: u64,
        baseline: &NtdllBaseline,
    ) -> Vec<UnhookedFunction> {
        let mut unhooked = Vec::new();

        for (func_name, (func_rva, baseline_bytes)) in &baseline.function_prologues {
            if baseline_bytes.len() < 12 {
                continue;
            }

            // Read current function prologue
            let func_addr = base + *func_rva as u64;
            let mut current_bytes = vec![0u8; 32];
            let mut bytes_read: usize = 0;

            unsafe {
                if ReadProcessMemory(
                    handle,
                    func_addr as *const c_void,
                    current_bytes.as_mut_ptr() as *mut c_void,
                    current_bytes.len(),
                    Some(&mut bytes_read),
                )
                .is_err()
                {
                    continue;
                }
            }
            current_bytes.truncate(bytes_read);

            // Check if baseline had a hook
            let baseline_hook = detect_hook_type(baseline_bytes);

            // Check if current is a clean syscall stub
            let current_syscall = is_clean_syscall_stub(&current_bytes);

            // Detect unhooking: baseline was hooked, current is clean
            if baseline_hook.is_some() && current_syscall.is_some() {
                unhooked.push(UnhookedFunction {
                    name: func_name.clone(),
                    rva: *func_rva,
                    size: 32, // Approximate
                    original_bytes: baseline_bytes.iter().take(16).cloned().collect(),
                    restored_bytes: current_bytes.iter().take(16).cloned().collect(),
                    is_syscall_stub: true,
                    syscall_number: current_syscall,
                    removed_hook_type: baseline_hook,
                });
            }

            // Also detect if baseline was clean but now hooked (for completeness)
            let baseline_syscall = is_clean_syscall_stub(baseline_bytes);
            let current_hook = detect_hook_type(&current_bytes);

            if baseline_syscall.is_some() && current_hook.is_some() {
                // This is hooking, not unhooking - but still suspicious
                // (Another process installed a hook)
                debug!(
                    "Function {} appears to have been hooked (was clean, now {:?})",
                    func_name, current_hook
                );
            }
        }

        unhooked
    }

    /// Detect Perun's Fart technique (syscall-only unhooking)
    pub fn detect_peruns_fart(unhooked_funcs: &[UnhookedFunction]) -> bool {
        if unhooked_funcs.is_empty() {
            return false;
        }

        // Perun's Fart characteristic: only syscall stubs are restored
        let syscall_count = unhooked_funcs.iter().filter(|f| f.is_syscall_stub).count();
        let non_syscall_count = unhooked_funcs.len() - syscall_count;

        // If >90% are syscall stubs, likely Perun's Fart
        let syscall_ratio = syscall_count as f32 / unhooked_funcs.len() as f32;
        syscall_ratio > 0.9 && non_syscall_count == 0
    }

    /// Detect module rebasing by checking ntdll base address
    pub fn detect_module_rebasing(base: u64, is_wow64: bool) -> Option<(u64, u64)> {
        // Expected base addresses
        let expected_base = if is_wow64 {
            0x77000000u64 // WoW64 ntdll
        } else {
            // x64 ntdll is usually loaded in high memory
            // Typical range: 0x7FFE0000_00000000 - 0x7FFF0000_00000000
            // If base is significantly different, it's rebased
            0x7FFE0000_00000000u64
        };

        // Check for significant deviation from expected base
        // Allow for ASLR within expected range
        let is_rebased = if is_wow64 {
            // WoW64: should be in low 32-bit space
            base > 0x80000000 || base < 0x10000000
        } else {
            // x64: should be in high 48-bit space
            base < 0x7F00_0000_0000 || base > 0x7FFF_FFFF_FFFF
        };

        if is_rebased {
            Some((base, expected_base))
        } else {
            None
        }
    }

    /// Scan for tool signatures in process memory
    pub async fn scan_for_tool_signatures(pid: u32, handle: HANDLE) -> Vec<String> {
        let mut detected_tools = Vec::new();
        let tool_signatures = get_tool_signatures();

        // Scan private executable memory for tool patterns
        let mut address: usize = 0;

        unsafe {
            loop {
                let mut mbi = MEMORY_BASIC_INFORMATION::default();
                let result = VirtualQueryEx(
                    handle,
                    Some(address as *const c_void),
                    &mut mbi,
                    mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                );

                if result == 0 {
                    break;
                }

                // Check private executable memory
                let is_executable = mbi.Protect.0 & PAGE_EXECUTE != 0
                    || mbi.Protect.0 & PAGE_EXECUTE_READ != 0
                    || mbi.Protect.0 & PAGE_EXECUTE_READWRITE != 0;

                let is_private = mbi.Type.0 != MEM_IMAGE;
                let is_committed = mbi.State.0 & MEM_COMMIT != 0;

                if is_executable && is_private && is_committed && mbi.RegionSize > 0 {
                    // Read memory
                    let region_size = (mbi.RegionSize as usize).min(256 * 1024); // Cap at 256KB
                    let mut buffer = vec![0u8; region_size];
                    let mut bytes_read: usize = 0;

                    if ReadProcessMemory(
                        handle,
                        mbi.BaseAddress,
                        buffer.as_mut_ptr() as *mut c_void,
                        region_size,
                        Some(&mut bytes_read),
                    )
                    .is_ok()
                    {
                        // Search for tool patterns
                        for sig in &tool_signatures {
                            // Check byte patterns
                            for pattern in &sig.patterns {
                                if find_pattern(&buffer[..bytes_read], pattern).is_some() {
                                    if !detected_tools.contains(&sig.name.to_string()) {
                                        detected_tools.push(sig.name.to_string());
                                        debug!(
                                            "Detected {} signature in PID {} at 0x{:x}",
                                            sig.name, pid, mbi.BaseAddress as u64
                                        );
                                    }
                                }
                            }

                            // Check string patterns (simple search)
                            for string in &sig.strings {
                                if bytes_read > string.len() {
                                    let string_bytes = string.as_bytes();
                                    if find_pattern(&buffer[..bytes_read], string_bytes).is_some() {
                                        if !detected_tools.contains(&sig.name.to_string()) {
                                            detected_tools.push(sig.name.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Move to next region
                address = mbi.BaseAddress as usize + mbi.RegionSize;
                if address < mbi.BaseAddress as usize {
                    break;
                }
            }
        }

        detected_tools
    }

    /// Advanced unhooking detector - main entry point
    pub async fn advanced_unhooking_detector(
        tx: mpsc::Sender<TelemetryEvent>,
        tracker: Arc<RwLock<NtdllWriteTracker>>,
        interval_ms: u64,
    ) {
        info!("Starting advanced unhooking detector");
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        loop {
            interval.tick().await;

            unsafe {
                let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                    Ok(h) => h,
                    Err(_) => continue,
                };

                let mut entry = PROCESSENTRY32W {
                    dwSize: mem::size_of::<PROCESSENTRY32W>() as u32,
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

                        // Skip system processes
                        if pid > 10 {
                            if let Some(event) =
                                perform_advanced_unhooking_analysis(pid, &name, &tracker).await
                            {
                                if tx.send(event).await.is_err() {
                                    let _ = CloseHandle(snapshot);
                                    return;
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

    /// Perform advanced unhooking analysis on a single process
    async fn perform_advanced_unhooking_analysis(
        pid: u32,
        process_name: &str,
        tracker: &Arc<RwLock<NtdllWriteTracker>>,
    ) -> Option<TelemetryEvent> {
        unsafe {
            let handle =
                OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid).ok()?;

            // Find ntdll base
            let (ntdll_base, ntdll_size) = find_ntdll_module(handle)?;

            // Get or create baseline
            let baseline = {
                let tracker_guard = tracker.read().await;
                tracker_guard.get_baseline(pid).cloned()
            };

            let baseline = match baseline {
                Some(b) => b,
                None => {
                    // Create baseline on first encounter
                    let new_baseline = create_ntdll_baseline(handle, ntdll_base, ntdll_size);
                    if let Some(b) = new_baseline {
                        let mut tracker_guard = tracker.write().await;
                        tracker_guard.store_baseline(pid, b.clone());
                        drop(tracker_guard);
                        let _ = CloseHandle(handle);
                        return None; // No detection on first baseline
                    }
                    let _ = CloseHandle(handle);
                    return None;
                }
            };

            // Perform section comparison
            let section_results = compare_sections(pid, handle, ntdll_base, &baseline).await;

            // If sections are unchanged, no unhooking detected
            if section_results.is_empty() {
                let _ = CloseHandle(handle);
                return None;
            }

            // Analyze function-level unhooking
            let unhooked_functions = analyze_function_unhooking(handle, ntdll_base, &baseline);

            if unhooked_functions.is_empty() {
                let _ = CloseHandle(handle);
                return None;
            }

            // Scan for tool signatures
            let detected_tools = scan_for_tool_signatures(pid, handle).await;

            // Check for module rebasing
            let is_wow64 = false; // Would need to check IsWow64Process
            let rebasing = detect_module_rebasing(ntdll_base, is_wow64);

            // Detect Perun's Fart
            let is_peruns_fart = detect_peruns_fart(&unhooked_functions);

            // Update tracker with findings
            {
                let mut tracker_guard = tracker.write().await;

                for func in &unhooked_functions {
                    tracker_guard.record_unhooked_function(pid, func.clone());
                }

                for tool in &detected_tools {
                    tracker_guard.record_tool_detection(pid, tool.clone());
                }

                if rebasing.is_some() {
                    let (actual, expected) = rebasing.unwrap();
                    tracker_guard.record_rebasing(pid, actual, expected);
                }

                if is_peruns_fart {
                    // Mark as partial restoration since only syscalls were restored
                    tracker_guard.mark_partial_restoration(pid);
                }
            }

            let _ = CloseHandle(handle);

            // Classify the technique
            let technique = {
                let tracker_guard = tracker.read().await;
                tracker_guard.classify_unhooking_technique(
                    pid,
                    &unhooked_functions,
                    tracker_guard.is_fresh_mapper(pid),
                    false, // Not cross-process for self-analysis
                )
            };

            // Count syscall vs non-syscall functions
            let syscall_count = unhooked_functions
                .iter()
                .filter(|f| f.is_syscall_stub)
                .count() as u32;
            let other_count = unhooked_functions.len() as u32 - syscall_count;

            // Get subsequent API calls for correlation
            let subsequent_apis = {
                let tracker_guard = tracker.read().await;
                tracker_guard.get_post_unhook_apis(pid)
            };

            // Build evidence list
            let mut evidence = vec![
                format!("Process: {} (PID {})", process_name, pid),
                format!("Technique: {}", technique.as_str()),
                format!("Functions unhooked: {}", unhooked_functions.len()),
                format!("Syscall stubs restored: {}", syscall_count),
            ];

            if !detected_tools.is_empty() {
                evidence.push(format!(
                    "Tool signatures detected: {}",
                    detected_tools.join(", ")
                ));
            }

            if is_peruns_fart {
                evidence
                    .push("Perun's Fart technique indicator: syscall-only unhooking".to_string());
            }

            if let Some((actual, expected)) = rebasing {
                evidence.push(format!(
                    "Module rebasing detected: actual=0x{:x}, expected=0x{:x}",
                    actual, expected
                ));
            }

            let process_path = get_process_path(pid);

            let event = AdvancedUnhookingEvent {
                source_pid: pid,
                source_process: process_name.to_string(),
                source_path: process_path,
                technique,
                unhooked_functions,
                section_analysis: section_results,
                syscall_only: is_peruns_fart,
                syscall_stubs_restored: syscall_count,
                other_functions_restored: other_count,
                cross_process_source: None,
                fresh_mapping_address: None,
                rebased_address: rebasing.map(|(a, _)| a),
                expected_base_address: rebasing.map(|(_, e)| e),
                tool_signature: detected_tools.first().cloned(),
                confidence: technique.confidence(),
                mitre_technique: "T1562.006".to_string(),
                evidence,
                subsequent_api_calls: subsequent_apis,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
            };

            Some(event.to_telemetry_event())
        }
    }

    /// Create a baseline snapshot of ntdll for comparison
    fn create_ntdll_baseline(handle: HANDLE, base: u64, size: u64) -> Option<NtdllBaseline> {
        let mut sections = HashMap::new();
        let function_prologues = HashMap::new();

        // Parse PE sections
        let pe_sections = parse_pe_sections(handle, base)?;

        for (section_name, rva, section_size) in pe_sections {
            // Read section data
            let section_addr = base + rva as u64;
            let read_size = (section_size as usize).min(2 * 1024 * 1024); // Cap at 2MB
            let mut section_data = vec![0u8; read_size];
            let mut bytes_read: usize = 0;

            unsafe {
                if ReadProcessMemory(
                    handle,
                    section_addr as *const c_void,
                    section_data.as_mut_ptr() as *mut c_void,
                    read_size,
                    Some(&mut bytes_read),
                )
                .is_ok()
                {
                    section_data.truncate(bytes_read);
                    let hash = compute_hash(&section_data);
                    sections.insert(section_name.clone(), (rva, section_size, hash));
                }
            }
        }

        // Get function prologues for critical functions
        // This would ideally parse the export table, but for now we use known RVAs
        // In a real implementation, you'd parse the PE export directory
        for func_name in CRITICAL_FUNCTIONS {
            // Try to find the function by reading export directory
            // For now, we'll skip this and rely on section comparison
            // A full implementation would parse the export table here
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Some(NtdllBaseline {
            sections,
            function_prologues,
            base_address: base,
            module_size: size,
            created_at: now,
        })
    }

    /// Detect cross-process ntdll section copying
    pub async fn detect_cross_process_unhooking(
        source_pid: u32,
        target_pid: u32,
        address: u64,
        size: u64,
        tracker: &Arc<RwLock<NtdllWriteTracker>>,
    ) -> Option<TelemetryEvent> {
        // Check if the target address falls within ntdll
        let is_ntdll = {
            let tracker_guard = tracker.read().await;
            tracker_guard.is_ntdll_address(target_pid, address)
        };

        if !is_ntdll {
            return None;
        }

        // Record cross-process unhooking
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let state = CrossProcessUnhookState {
            source_pid,
            target_pid,
            handle_value: 0,                // Would need handle tracking
            modified_functions: Vec::new(), // Would need function resolution
            timestamp: now,
        };

        {
            let mut tracker_guard = tracker.write().await;
            tracker_guard.record_cross_process_unhook(state);
        }

        let source_name = get_process_name_sync(source_pid);
        let target_name = get_process_name_sync(target_pid);
        let source_path = get_process_path(source_pid);

        let event = AdvancedUnhookingEvent {
            source_pid,
            source_process: source_name.clone(),
            source_path,
            technique: UnhookingTechnique::CrossProcessCopy,
            unhooked_functions: Vec::new(),
            section_analysis: Vec::new(),
            syscall_only: false,
            syscall_stubs_restored: 0,
            other_functions_restored: 0,
            cross_process_source: Some(source_pid),
            fresh_mapping_address: None,
            rebased_address: None,
            expected_base_address: None,
            tool_signature: None,
            confidence: 0.90,
            mitre_technique: "T1562.006".to_string(),
            evidence: vec![
                format!("Cross-process NTDLL modification detected"),
                format!("Source: {} (PID {})", source_name, source_pid),
                format!("Target: {} (PID {})", target_name, target_pid),
                format!("Address: 0x{:016x}, Size: {} bytes", address, size),
            ],
            subsequent_api_calls: Vec::new(),
            timestamp: now,
        };

        Some(event.to_telemetry_event())
    }

    /// Get process name synchronously
    fn get_process_name_sync(pid: u32) -> String {
        unsafe {
            let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(h) => h,
                Err(_) => return String::new(),
            };

            let mut entry = PROCESSENTRY32W {
                dwSize: mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    if entry.th32ProcessID == pid {
                        let name = String::from_utf16_lossy(
                            &entry.szExeFile[..entry
                                .szExeFile
                                .iter()
                                .position(|&c| c == 0)
                                .unwrap_or(entry.szExeFile.len())],
                        );
                        let _ = CloseHandle(snapshot);
                        return name;
                    }

                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snapshot);
        }
        String::new()
    }
}

// ============================================================================
// Linux Implementation
// ============================================================================

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use std::fs;
    use std::io::{BufRead, BufReader, Read};
    use std::path::Path;

    /// Main monitoring loop for Linux
    pub async fn monitor_loop(
        tx: mpsc::Sender<TelemetryEvent>,
        tracker: Arc<RwLock<NtdllWriteTracker>>,
        config: AgentConfig,
    ) {
        let mul = config.sub_loop_interval_multiplier;
        info!(multiplier = mul, "Starting Linux library write monitor");

        // Start libc integrity scanner (5s base, scaled by multiplier)
        let tx_scan = tx.clone();
        let tracker_scan = tracker.clone();
        let scan_interval_ms = ((5000.0 * mul) as u64).max(5000);
        tokio::spawn(async move {
            libc_integrity_scanner(tx_scan, tracker_scan, scan_interval_ms).await;
        });

        // Main cleanup loop
        let mut cleanup_interval = tokio::time::interval(tokio::time::Duration::from_secs(60));

        loop {
            cleanup_interval.tick().await;
            let mut tracker_guard = tracker.write().await;
            tracker_guard.cleanup();
        }
    }

    /// Scan libc/ld.so integrity by checking /proc/[pid]/maps for anomalies
    async fn libc_integrity_scanner(
        tx: mpsc::Sender<TelemetryEvent>,
        _tracker: Arc<RwLock<NtdllWriteTracker>>,
        interval_ms: u64,
    ) {
        info!("Starting libc integrity scanner");
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(interval_ms));

        loop {
            interval.tick().await;

            // Enumerate all processes
            let proc_dir = match fs::read_dir("/proc") {
                Ok(d) => d,
                Err(_) => continue,
            };

            for entry in proc_dir.flatten() {
                let pid_str = entry.file_name().to_string_lossy().to_string();
                let pid: u32 = match pid_str.parse() {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                // Skip kernel threads
                if pid == 0 {
                    continue;
                }

                if let Some(event) = check_libc_integrity(pid).await {
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }
            }
        }
    }

    /// Check libc integrity for a single process
    async fn check_libc_integrity(pid: u32) -> Option<TelemetryEvent> {
        let maps_path = format!("/proc/{}/maps", pid);
        let maps_file = fs::File::open(&maps_path).ok()?;
        let reader = BufReader::new(maps_file);

        let mut libc_mappings = Vec::new();

        for line in reader.lines().flatten() {
            // Parse /proc/pid/maps line
            // Format: address perms offset dev inode pathname
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 {
                continue;
            }

            let pathname = parts[5];
            if pathname.contains("libc") || pathname.contains("ld-linux") {
                let addr_range = parts[0];
                let perms = parts[1];

                // Check for suspicious permissions on library regions
                // Libraries should have r-xp (read-execute) for .text
                // rwxp (read-write-execute) is suspicious
                if perms.contains("rwx") {
                    let addrs: Vec<&str> = addr_range.split('-').collect();
                    if addrs.len() == 2 {
                        let start = u64::from_str_radix(addrs[0], 16).unwrap_or(0);
                        let end = u64::from_str_radix(addrs[1], 16).unwrap_or(0);

                        libc_mappings.push((start, end, pathname.to_string()));
                    }
                }
            }
        }

        // Check for anomalies
        for (start, end, pathname) in libc_mappings {
            let process_name = get_process_name(pid);
            let process_path = get_process_path(pid);

            let event = NtdllWriteEvent {
                source_pid: pid,
                source_process: process_name.clone(),
                source_path: process_path.clone(),
                target_pid: pid,
                target_process: process_name.clone(),
                target_address: start,
                target_function: Some(pathname.clone()),
                operation: MemoryOperationType::Mprotect,
                old_protection: None,
                new_protection: Some(0x7), // PROT_READ | PROT_WRITE | PROT_EXEC
                bytes_written: None,
                region_size: Some(end - start),
                mitre_technique: "T1562.006".to_string(),
                confidence: 0.85,
                is_sequence_part: false,
                sequence_id: None,
                evidence: vec![
                    format!("RWX permissions on library: {}", pathname),
                    format!("Address range: 0x{:x}-0x{:x}", start, end),
                    format!("Process: {} (PID {})", process_name, pid),
                    "Possible library unhooking or hook injection".to_string(),
                ],
            };

            return Some(event.to_telemetry_event());
        }

        None
    }

    /// Get process name from /proc/[pid]/comm
    fn get_process_name(pid: u32) -> String {
        fs::read_to_string(format!("/proc/{}/comm", pid))
            .unwrap_or_default()
            .trim()
            .to_string()
    }

    /// Get process path from /proc/[pid]/exe
    fn get_process_path(pid: u32) -> String {
        fs::read_link(format!("/proc/{}/exe", pid))
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_operation_type() {
        assert_eq!(
            MemoryOperationType::VirtualProtect.as_str(),
            "VirtualProtect"
        );
        assert_eq!(
            MemoryOperationType::WriteProcessMemory.severity(),
            Severity::Critical
        );
    }

    #[test]
    fn test_ntdll_write_tracker() {
        let mut tracker = NtdllWriteTracker::new();

        // Test ntdll base tracking
        tracker.set_ntdll_base(1234, 0x7FFE0000, 0x1000);
        assert!(tracker.is_ntdll_address(1234, 0x7FFE0500));
        assert!(!tracker.is_ntdll_address(1234, 0x7FFD0000));

        // Test section creator tracking
        tracker.mark_section_creator(1234);
        assert!(tracker.is_section_creator(1234));
        assert!(!tracker.is_section_creator(5678));

        // Test fresh mapper tracking
        tracker.mark_fresh_mapper(1234);
        assert!(tracker.is_fresh_mapper(1234));

        // Test process removal
        tracker.remove_process(1234);
        assert!(!tracker.is_ntdll_address(1234, 0x7FFE0500));
        assert!(!tracker.is_section_creator(1234));
        assert!(!tracker.is_fresh_mapper(1234));
    }

    #[test]
    fn test_protection_flags() {
        // Windows flags
        #[cfg(target_os = "windows")]
        {
            assert!(is_rwx(0x40)); // PAGE_EXECUTE_READWRITE
            assert!(is_rwx(0x80)); // PAGE_EXECUTE_WRITECOPY
            assert!(!is_rwx(0x20)); // PAGE_EXECUTE_READ

            assert!(is_rx(0x20)); // PAGE_EXECUTE_READ
            assert!(!is_rx(0x40)); // PAGE_EXECUTE_READWRITE
        }

        // Linux flags
        #[cfg(target_os = "linux")]
        {
            assert!(is_rwx(0x7)); // PROT_READ | PROT_WRITE | PROT_EXEC
            assert!(!is_rwx(0x5)); // PROT_READ | PROT_EXEC

            assert!(is_rx(0x5)); // PROT_READ | PROT_EXEC
            assert!(!is_rx(0x7)); // PROT_READ | PROT_WRITE | PROT_EXEC
        }
    }

    #[test]
    fn test_sequence_detection() {
        let mut tracker = NtdllWriteTracker::new();

        // Record unhooking sequence
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // Step 1: VirtualProtect to RWX
        tracker.record_operation(TrackedOperation {
            op_type: MemoryOperationType::VirtualProtect,
            source_pid: 1234,
            target_pid: 1234,
            address: 0x7FFE0000,
            old_protection: Some(0x20), // PAGE_EXECUTE_READ
            new_protection: Some(0x40), // PAGE_EXECUTE_READWRITE
            timestamp: now,
            size: Some(0x1000),
        });

        // Step 2: WriteProcessMemory
        let result = tracker.record_operation(TrackedOperation {
            op_type: MemoryOperationType::WriteProcessMemory,
            source_pid: 1234,
            target_pid: 1234,
            address: 0x7FFE0000,
            old_protection: None,
            new_protection: None,
            timestamp: now + 100,
            size: Some(16),
        });

        // Should not trigger yet (need restore step)
        assert!(result.is_none());

        // Step 3: VirtualProtect restore to RX
        let result = tracker.record_operation(TrackedOperation {
            op_type: MemoryOperationType::VirtualProtect,
            source_pid: 1234,
            target_pid: 1234,
            address: 0x7FFE0000,
            old_protection: Some(0x40), // PAGE_EXECUTE_READWRITE
            new_protection: Some(0x20), // PAGE_EXECUTE_READ
            timestamp: now + 200,
            size: Some(0x1000),
        });

        // Should now detect the complete unhooking sequence
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 3);
    }

    // ========================================================================
    // Advanced Unhooking Detection Tests
    // ========================================================================

    #[test]
    fn test_unhooking_technique_classification() {
        assert_eq!(UnhookingTechnique::ClassicUnhook.as_str(), "ClassicUnhook");
        assert_eq!(UnhookingTechnique::PerunsFart.as_str(), "PerunsFart");
        assert_eq!(UnhookingTechnique::SysWhispers.as_str(), "SysWhispers");
        assert_eq!(UnhookingTechnique::HellsGate.as_str(), "HellsGate");
        assert_eq!(
            UnhookingTechnique::ModuleRebasing.as_str(),
            "ModuleRebasing"
        );
        assert_eq!(
            UnhookingTechnique::CrossProcessCopy.as_str(),
            "CrossProcessCopy"
        );

        // Test confidence scores
        assert!(UnhookingTechnique::ClassicUnhook.confidence() > 0.9);
        assert!(UnhookingTechnique::PerunsFart.confidence() > 0.9);
        assert!(UnhookingTechnique::Unknown.confidence() < 0.8);
    }

    #[test]
    fn test_hook_type_detection() {
        assert_eq!(HookType::JmpRel32.as_str(), "JMP_REL32");
        assert_eq!(HookType::JmpRipRelative.as_str(), "JMP_RIP_REL");
        assert_eq!(HookType::Int3Breakpoint.as_str(), "INT3");
        assert_eq!(HookType::PushRetTrampoline.as_str(), "PUSH_RET");
    }

    #[test]
    fn test_unhooked_function_creation() {
        let func = UnhookedFunction {
            name: "NtWriteVirtualMemory".to_string(),
            rva: 0x1000,
            size: 32,
            original_bytes: vec![0xE9, 0x00, 0x00, 0x00, 0x00], // JMP rel32
            restored_bytes: vec![0x4C, 0x8B, 0xD1, 0xB8, 0x3A, 0x00, 0x00, 0x00], // mov r10, rcx; mov eax, 0x3A
            is_syscall_stub: true,
            syscall_number: Some(0x3A),
            removed_hook_type: Some(HookType::JmpRel32),
        };

        assert_eq!(func.name, "NtWriteVirtualMemory");
        assert!(func.is_syscall_stub);
        assert_eq!(func.syscall_number, Some(0x3A));
        assert_eq!(func.removed_hook_type, Some(HookType::JmpRel32));
    }

    #[test]
    fn test_section_comparison_result() {
        let result = SectionComparisonResult {
            section_name: ".text".to_string(),
            section_rva: 0x1000,
            section_size: 0x50000,
            difference_count: 10,
            difference_percent: 0.01,
            selective_modification: true,
            modified_functions: vec![
                "NtWriteVirtualMemory".to_string(),
                "NtAllocateVirtualMemory".to_string(),
            ],
            first_diff_offset: Some(0x2000),
        };

        assert_eq!(result.section_name, ".text");
        assert!(result.selective_modification);
        assert_eq!(result.modified_functions.len(), 2);
    }

    #[test]
    fn test_advanced_unhooking_event_creation() {
        let event = AdvancedUnhookingEvent {
            source_pid: 1234,
            source_process: "malware.exe".to_string(),
            source_path: "C:\\Users\\test\\malware.exe".to_string(),
            technique: UnhookingTechnique::PerunsFart,
            unhooked_functions: vec![UnhookedFunction {
                name: "NtWriteVirtualMemory".to_string(),
                rva: 0x1000,
                size: 32,
                original_bytes: vec![0xE9],
                restored_bytes: vec![0x4C, 0x8B, 0xD1],
                is_syscall_stub: true,
                syscall_number: Some(0x3A),
                removed_hook_type: Some(HookType::JmpRel32),
            }],
            section_analysis: vec![],
            syscall_only: true,
            syscall_stubs_restored: 5,
            other_functions_restored: 0,
            cross_process_source: None,
            fresh_mapping_address: None,
            rebased_address: None,
            expected_base_address: None,
            tool_signature: Some("PerunsFart".to_string()),
            confidence: 0.92,
            mitre_technique: "T1562.006".to_string(),
            evidence: vec!["Syscall-only unhooking detected".to_string()],
            subsequent_api_calls: vec!["NtAllocateVirtualMemory".to_string()],
            timestamp: 1234567890,
        };

        assert_eq!(event.source_pid, 1234);
        assert_eq!(event.technique, UnhookingTechnique::PerunsFart);
        assert!(event.syscall_only);
        assert_eq!(event.syscall_stubs_restored, 5);
        assert_eq!(event.other_functions_restored, 0);

        // Test conversion to TelemetryEvent
        let telemetry = event.to_telemetry_event();
        assert_eq!(telemetry.event_type, EventType::DefenseEvasion);
        assert_eq!(telemetry.severity, Severity::Critical); // Perun's Fart is Critical
        assert!(!telemetry.detections.is_empty());
    }

    #[test]
    fn test_tool_signatures() {
        let signatures = get_tool_signatures();

        // Should have multiple known tool signatures
        assert!(signatures.len() >= 5);

        // Check for specific tools
        let tool_names: Vec<&str> = signatures.iter().map(|s| s.name).collect();
        assert!(tool_names.contains(&"SysWhispers"));
        assert!(tool_names.contains(&"HellsGate"));
        assert!(tool_names.contains(&"PerunsFart"));

        // Check SysWhispers signature
        let syswhispers = signatures.iter().find(|s| s.name == "SysWhispers").unwrap();
        assert!(!syswhispers.patterns.is_empty());
        assert_eq!(syswhispers.technique, UnhookingTechnique::SysWhispers);
    }

    #[test]
    fn test_critical_functions_list() {
        // Should have memory, process, file operations
        assert!(CRITICAL_FUNCTIONS.contains(&"NtWriteVirtualMemory"));
        assert!(CRITICAL_FUNCTIONS.contains(&"NtAllocateVirtualMemory"));
        assert!(CRITICAL_FUNCTIONS.contains(&"NtProtectVirtualMemory"));
        assert!(CRITICAL_FUNCTIONS.contains(&"NtCreateThreadEx"));
        assert!(CRITICAL_FUNCTIONS.contains(&"NtOpenProcess"));
        assert!(CRITICAL_FUNCTIONS.contains(&"NtCreateFile"));
        assert!(CRITICAL_FUNCTIONS.contains(&"NtSetValueKey"));

        // Should have reasonable number of critical functions
        assert!(CRITICAL_FUNCTIONS.len() >= 20);
    }

    #[test]
    fn test_tracker_advanced_features() {
        let mut tracker = NtdllWriteTracker::new();

        // Test baseline storage
        let baseline = NtdllBaseline {
            sections: HashMap::new(),
            function_prologues: HashMap::new(),
            base_address: 0x7FFE0000,
            module_size: 0x100000,
            created_at: 1234567890,
        };
        tracker.store_baseline(1234, baseline.clone());
        assert!(tracker.get_baseline(1234).is_some());

        // Test unhooked function recording
        let func = UnhookedFunction {
            name: "NtWriteVirtualMemory".to_string(),
            rva: 0x1000,
            size: 32,
            original_bytes: vec![0xE9],
            restored_bytes: vec![0x4C, 0x8B, 0xD1],
            is_syscall_stub: true,
            syscall_number: Some(0x3A),
            removed_hook_type: Some(HookType::JmpRel32),
        };
        tracker.record_unhooked_function(1234, func);
        assert!(tracker.get_unhooked_functions(1234).is_some());
        assert_eq!(tracker.get_unhooked_functions(1234).unwrap().len(), 1);

        // Test tool detection recording
        tracker.record_tool_detection(1234, "SysWhispers".to_string());
        assert!(tracker.get_detected_tools(1234).is_some());
        assert!(tracker
            .get_detected_tools(1234)
            .unwrap()
            .contains(&"SysWhispers".to_string()));

        // Test rebasing recording
        tracker.record_rebasing(1234, 0x10000000, 0x7FFE0000);
        assert!(tracker.is_rebased(1234).is_some());
        let (actual, expected) = tracker.is_rebased(1234).unwrap();
        assert_eq!(actual, 0x10000000);
        assert_eq!(expected, 0x7FFE0000);

        // Test partial restoration marking
        tracker.mark_partial_restoration(1234);
        assert!(tracker.has_partial_restoration(1234));

        // Test process removal cleans up all advanced state
        tracker.remove_process(1234);
        assert!(tracker.get_baseline(1234).is_none());
        assert!(tracker.get_unhooked_functions(1234).is_none());
        assert!(tracker.get_detected_tools(1234).is_none());
        assert!(tracker.is_rebased(1234).is_none());
        assert!(!tracker.has_partial_restoration(1234));
    }

    #[test]
    fn test_technique_classification() {
        let mut tracker = NtdllWriteTracker::new();

        // Test syscall-only classification (Perun's Fart)
        let syscall_funcs = vec![
            UnhookedFunction {
                name: "NtWriteVirtualMemory".to_string(),
                rva: 0x1000,
                size: 32,
                original_bytes: vec![],
                restored_bytes: vec![],
                is_syscall_stub: true,
                syscall_number: Some(0x3A),
                removed_hook_type: Some(HookType::JmpRel32),
            },
            UnhookedFunction {
                name: "NtAllocateVirtualMemory".to_string(),
                rva: 0x2000,
                size: 32,
                original_bytes: vec![],
                restored_bytes: vec![],
                is_syscall_stub: true,
                syscall_number: Some(0x18),
                removed_hook_type: Some(HookType::JmpRel32),
            },
        ];

        let technique = tracker.classify_unhooking_technique(
            1234,
            &syscall_funcs,
            false, // no fresh mapping
            false, // not cross-process
        );
        assert_eq!(technique, UnhookingTechnique::PerunsFart);

        // Test fresh mapping classification
        tracker.mark_fresh_mapper(5678);
        let technique = tracker.classify_unhooking_technique(
            5678,
            &[],   // empty funcs
            true,  // has fresh mapping
            false, // not cross-process
        );
        assert_eq!(technique, UnhookingTechnique::FreshNtdllMapping);

        // Test cross-process classification
        let technique = tracker.classify_unhooking_technique(
            9999,
            &[],
            false,
            true, // is cross-process
        );
        assert_eq!(technique, UnhookingTechnique::CrossProcessCopy);

        // Test tool signature classification
        tracker.record_tool_detection(4444, "SysWhispers".to_string());
        let technique = tracker.classify_unhooking_technique(4444, &[], false, false);
        assert_eq!(technique, UnhookingTechnique::SysWhispers);
    }

    #[test]
    fn test_cross_process_unhook_state() {
        let mut tracker = NtdllWriteTracker::new();

        let state = CrossProcessUnhookState {
            source_pid: 1234,
            target_pid: 5678,
            handle_value: 0x100,
            modified_functions: vec!["NtWriteVirtualMemory".to_string()],
            timestamp: 1234567890,
        };

        tracker.record_cross_process_unhook(state.clone());

        // Verify state was recorded (would need accessor method for full test)
        // For now, just verify it compiles
        assert_eq!(state.source_pid, 1234);
        assert_eq!(state.target_pid, 5678);
    }

    #[test]
    fn test_api_call_tracking() {
        let mut tracker = NtdllWriteTracker::new();

        // Record some API calls
        for i in 0..50 {
            let call = TrackedApiCall {
                function_name: format!("NtFunction{}", i),
                thread_id: 1000,
                timestamp: 1234567890 + i,
                via_direct_syscall: i % 2 == 0,
            };
            tracker.record_post_unhook_api(1234, call);
        }

        let apis = tracker.get_post_unhook_apis(1234);
        assert_eq!(apis.len(), 50);

        // Test buffer limit (should cap at 100)
        for i in 50..150 {
            let call = TrackedApiCall {
                function_name: format!("NtFunction{}", i),
                thread_id: 1000,
                timestamp: 1234567890 + i,
                via_direct_syscall: false,
            };
            tracker.record_post_unhook_api(1234, call);
        }

        let apis = tracker.get_post_unhook_apis(1234);
        assert_eq!(apis.len(), 100); // Should be capped at 100
    }

    #[cfg(target_os = "windows")]
    mod windows_tests {
        use super::super::windows_impl::*;
        use super::*;

        #[test]
        fn test_detect_hook_type_jmp_rel32() {
            // JMP rel32: E9 xx xx xx xx
            let bytes = vec![0xE9, 0x12, 0x34, 0x56, 0x78];
            let hook = detect_hook_type(&bytes);
            assert_eq!(hook, Some(HookType::JmpRel32));
        }

        #[test]
        fn test_detect_hook_type_jmp_rip_relative() {
            // JMP [rip+disp]: FF 25 xx xx xx xx
            let bytes = vec![0xFF, 0x25, 0x00, 0x00, 0x00, 0x00];
            let hook = detect_hook_type(&bytes);
            assert_eq!(hook, Some(HookType::JmpRipRelative));
        }

        #[test]
        fn test_detect_hook_type_call_rel32() {
            // CALL rel32: E8 xx xx xx xx
            let bytes = vec![0xE8, 0x12, 0x34, 0x56, 0x78];
            let hook = detect_hook_type(&bytes);
            assert_eq!(hook, Some(HookType::CallRel32));
        }

        #[test]
        fn test_detect_hook_type_int3() {
            // INT3: CC
            let bytes = vec![0xCC, 0x90, 0x90];
            let hook = detect_hook_type(&bytes);
            assert_eq!(hook, Some(HookType::Int3Breakpoint));
        }

        #[test]
        fn test_detect_hook_type_no_hook() {
            // Normal syscall stub prologue
            let bytes = vec![0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00];
            let hook = detect_hook_type(&bytes);
            assert!(hook.is_none());
        }

        #[test]
        fn test_is_clean_syscall_stub() {
            // Clean syscall stub for NtAllocateVirtualMemory (syscall 0x18)
            // 4C 8B D1        mov r10, rcx
            // B8 18 00 00 00  mov eax, 0x18
            // 0F 05           syscall
            // C3              ret
            let bytes = vec![
                0x4C, 0x8B, 0xD1, // mov r10, rcx
                0xB8, 0x18, 0x00, 0x00, 0x00, // mov eax, 0x18
                0x0F, 0x05, // syscall
                0xC3, // ret
                0x00, // padding to meet 12-byte minimum
            ];
            let syscall_num = is_clean_syscall_stub(&bytes);
            assert_eq!(syscall_num, Some(0x18));
        }

        #[test]
        fn test_is_clean_syscall_stub_hooked() {
            // Hooked syscall stub (JMP at start)
            let bytes = vec![
                0xE9, 0x12, 0x34, 0x56, 0x78, // JMP
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ];
            let syscall_num = is_clean_syscall_stub(&bytes);
            assert!(syscall_num.is_none());
        }

        #[test]
        fn test_detect_peruns_fart() {
            // All syscall stubs - Perun's Fart indicator
            let funcs = vec![
                UnhookedFunction {
                    name: "NtWriteVirtualMemory".to_string(),
                    rva: 0x1000,
                    size: 32,
                    original_bytes: vec![],
                    restored_bytes: vec![],
                    is_syscall_stub: true,
                    syscall_number: Some(0x3A),
                    removed_hook_type: Some(HookType::JmpRel32),
                },
                UnhookedFunction {
                    name: "NtAllocateVirtualMemory".to_string(),
                    rva: 0x2000,
                    size: 32,
                    original_bytes: vec![],
                    restored_bytes: vec![],
                    is_syscall_stub: true,
                    syscall_number: Some(0x18),
                    removed_hook_type: Some(HookType::JmpRel32),
                },
            ];

            assert!(detect_peruns_fart(&funcs));
        }

        #[test]
        fn test_detect_peruns_fart_mixed() {
            // Mixed syscall and non-syscall - NOT Perun's Fart
            let funcs = vec![
                UnhookedFunction {
                    name: "NtWriteVirtualMemory".to_string(),
                    rva: 0x1000,
                    size: 32,
                    original_bytes: vec![],
                    restored_bytes: vec![],
                    is_syscall_stub: true,
                    syscall_number: Some(0x3A),
                    removed_hook_type: Some(HookType::JmpRel32),
                },
                UnhookedFunction {
                    name: "SomeHelperFunction".to_string(),
                    rva: 0x2000,
                    size: 32,
                    original_bytes: vec![],
                    restored_bytes: vec![],
                    is_syscall_stub: false, // Not a syscall stub
                    syscall_number: None,
                    removed_hook_type: Some(HookType::JmpRel32),
                },
            ];

            assert!(!detect_peruns_fart(&funcs));
        }

        #[test]
        fn test_detect_module_rebasing_x64() {
            // Normal x64 base (within expected range)
            let normal_base = 0x7FFE_0000_0000u64;
            assert!(detect_module_rebasing(normal_base, false).is_none());

            // Rebased x64 (unusual location)
            let rebased_base = 0x1000_0000u64;
            let result = detect_module_rebasing(rebased_base, false);
            assert!(result.is_some());
        }

        #[test]
        fn test_detect_module_rebasing_wow64() {
            // Normal WoW64 base
            let normal_base = 0x77000000u64;
            assert!(detect_module_rebasing(normal_base, true).is_none());

            // Rebased WoW64 (unusual high location)
            let rebased_base = 0xFFFF0000u64;
            let result = detect_module_rebasing(rebased_base, true);
            assert!(result.is_some());
        }
    }
}
