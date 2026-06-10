//! Return Address Validation for ROP Chain Detection
//!
//! Detects Return-Oriented Programming (ROP) attacks by validating that return
//! addresses on the call stack point to valid code locations that follow CALL
//! instructions. ROP attacks chain together small code snippets ("gadgets") ending
//! in RET instructions to execute arbitrary operations without injecting new code.
//!
//! ## Detection Methods
//!
//! 1. **Call Site Validation**: Verifies return addresses are preceded by valid
//!    CALL instructions (E8, FF 15, FF D0-D7, etc.)
//!
//! 2. **Gadget Detection**: Identifies suspicious small code sequences ending in
//!    RET, JMP REG, or SYSCALL;RET patterns
//!
//! 3. **Module Validation**: Ensures return addresses fall within legitimate
//!    module code sections
//!
//! 4. **Stack Walking Integration**: Combines with DbgHelp/RtlVirtualUnwind for
//!    comprehensive call stack analysis
//!
//! ## MITRE ATT&CK Techniques
//!
//! - T1055: Process Injection
//! - T1574: Hijack Execution Flow
//!
//! ## Usage
//!
//! ```ignore
//! use tamandua_agent::analyzers::return_address::ReturnAddressValidator;
//!
//! let validator = ReturnAddressValidator::new();
//! let result = validator.validate_return_address(ret_addr, pid);
//! ```

use crate::collectors::{
    Detection, DetectionType, EventPayload, EventType, Severity, TelemetryEvent,
};
use anyhow::{anyhow, Result};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::debug;

#[cfg(target_os = "windows")]
use std::ffi::c_void;

// ============================================================================
// Core Types and Structures
// ============================================================================

/// Result of validating a single return address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationResult {
    /// Return address is valid - points to code after a CALL instruction
    Valid {
        /// Module containing the return address
        module: String,
        /// Offset within the module
        offset: usize,
        /// The CALL instruction type that preceded this address
        call_type: CallInstructionType,
    },
    /// Return address points to a suspicious gadget (small code ending in RET/JMP)
    SuspiciousGadget {
        /// The gadget address
        addr: usize,
        /// Size of the gadget in bytes
        gadget_size: usize,
        /// Type of gadget detected
        gadget_info: RopGadgetInfo,
    },
    /// Return address not in any valid module
    InvalidModule {
        /// The invalid address
        addr: usize,
        /// Memory protection at this address (if queryable)
        protection: Option<u32>,
        /// Memory type string
        mem_type: Option<String>,
    },
    /// Return address doesn't follow a CALL instruction
    NotAfterCall {
        /// The address being validated
        addr: usize,
        /// Bytes preceding the return address (for analysis)
        preceding_bytes: Vec<u8>,
        /// Module name if in a module
        module: Option<String>,
    },
    /// Address is null or in low memory (invalid)
    NullOrInvalid { addr: usize },
    /// Unable to read memory at the address
    Unreadable { addr: usize, reason: String },
}

impl ValidationResult {
    /// Check if this result indicates a potential ROP attack
    pub fn is_suspicious(&self) -> bool {
        matches!(
            self,
            Self::SuspiciousGadget { .. }
                | Self::InvalidModule { .. }
                | Self::NotAfterCall { .. }
                | Self::NullOrInvalid { .. }
        )
    }

    /// Get a risk score for this validation result (0.0 - 1.0)
    pub fn risk_score(&self) -> f32 {
        match self {
            Self::Valid { .. } => 0.0,
            Self::SuspiciousGadget { gadget_info, .. } => gadget_info.risk_score as f32 / 100.0,
            Self::InvalidModule { .. } => 0.8,
            Self::NotAfterCall { module, .. } => {
                if module.is_some() {
                    0.6 // In a module but not after CALL - moderately suspicious
                } else {
                    0.9 // Not in module and not after CALL - highly suspicious
                }
            }
            Self::NullOrInvalid { .. } => 0.95,
            Self::Unreadable { .. } => 0.3, // Can't determine, low confidence
        }
    }

    /// Get a human-readable description
    pub fn description(&self) -> String {
        match self {
            Self::Valid {
                module,
                offset,
                call_type,
            } => {
                format!(
                    "Valid return to {}+0x{:x} after {:?}",
                    module, offset, call_type
                )
            }
            Self::SuspiciousGadget {
                addr,
                gadget_size,
                gadget_info,
            } => {
                format!(
                    "ROP gadget at 0x{:x} ({} bytes): {:?}",
                    addr, gadget_size, gadget_info.gadget_type
                )
            }
            Self::InvalidModule { addr, mem_type, .. } => {
                format!(
                    "Return to 0x{:x} not in any module ({})",
                    addr,
                    mem_type.as_deref().unwrap_or("unknown")
                )
            }
            Self::NotAfterCall { addr, module, .. } => {
                format!(
                    "Return to 0x{:x} ({}) not after CALL instruction",
                    addr,
                    module.as_deref().unwrap_or("no module")
                )
            }
            Self::NullOrInvalid { addr } => {
                format!("Invalid return address: 0x{:x}", addr)
            }
            Self::Unreadable { addr, reason } => {
                format!("Cannot read at 0x{:x}: {}", addr, reason)
            }
        }
    }
}

/// Types of CALL instructions that can precede a return address
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallInstructionType {
    /// E8 xx xx xx xx - CALL rel32
    CallRel32,
    /// FF 15 xx xx xx xx - CALL [rip+disp32]
    CallRipRel,
    /// FF D0 - FF D7 - CALL reg
    CallReg,
    /// FF 10 - FF 17 - CALL [reg]
    CallRegIndirect,
    /// FF 50 xx - CALL [reg+disp8]
    CallRegDisp8,
    /// FF 90 xx xx xx xx - CALL [reg+disp32]
    CallRegDisp32,
    /// FF 14 xx - CALL [reg+reg*scale]
    CallSib,
    /// 9A xx xx xx xx xx xx - CALL FAR (32-bit legacy)
    CallFar,
    /// Unknown CALL variant
    Unknown,
}

impl CallInstructionType {
    /// Get the size in bytes of this CALL instruction
    pub fn instruction_size(&self) -> usize {
        match self {
            Self::CallRel32 => 5,
            Self::CallRipRel => 6,
            Self::CallReg => 2,
            Self::CallRegIndirect => 2,
            Self::CallRegDisp8 => 3,
            Self::CallRegDisp32 => 6,
            Self::CallSib => 3,
            Self::CallFar => 7,
            Self::Unknown => 0,
        }
    }
}

/// Information about a detected ROP gadget
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RopGadgetInfo {
    /// Memory address of the gadget
    pub address: usize,
    /// Raw bytes of the gadget
    pub gadget_bytes: Vec<u8>,
    /// Classification of the gadget type
    pub gadget_type: GadgetType,
    /// Risk score (0-100)
    pub risk_score: u8,
    /// Human-readable description
    pub description: String,
    /// Module containing the gadget (if any)
    pub module: Option<String>,
}

/// Types of ROP gadgets
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GadgetType {
    /// RET with stack adjustment (RET n)
    RetN,
    /// Simple RET
    Ret,
    /// JMP to register (JMP RAX, etc.)
    JmpReg,
    /// CALL to register (CALL RAX, etc.)
    CallReg,
    /// SYSCALL followed by RET
    SyscallRet,
    /// POP register followed by RET (e.g., POP RAX; RET)
    PopRet,
    /// Multiple POPs followed by RET
    MultiPopRet,
    /// MOV followed by RET
    MovRet,
    /// XCHG followed by RET
    XchgRet,
    /// ADD/SUB RSP followed by RET (stack pivot)
    StackPivot,
    /// LEAVE; RET sequence
    LeaveRet,
    /// INT 2E; RET (syscall via interrupt)
    Int2eRet,
    /// SYSENTER; RET
    SysenterRet,
}

impl GadgetType {
    /// Get a human-readable name
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RetN => "ret_n",
            Self::Ret => "ret",
            Self::JmpReg => "jmp_reg",
            Self::CallReg => "call_reg",
            Self::SyscallRet => "syscall_ret",
            Self::PopRet => "pop_ret",
            Self::MultiPopRet => "multi_pop_ret",
            Self::MovRet => "mov_ret",
            Self::XchgRet => "xchg_ret",
            Self::StackPivot => "stack_pivot",
            Self::LeaveRet => "leave_ret",
            Self::Int2eRet => "int2e_ret",
            Self::SysenterRet => "sysenter_ret",
        }
    }

    /// Get the base risk score for this gadget type
    pub fn base_risk(&self) -> u8 {
        match self {
            Self::SyscallRet => 95,
            Self::SysenterRet => 95,
            Self::Int2eRet => 90,
            Self::StackPivot => 90,
            Self::CallReg => 80,
            Self::JmpReg => 80,
            Self::MultiPopRet => 70,
            Self::PopRet => 60,
            Self::RetN => 50,
            Self::LeaveRet => 40,
            Self::MovRet => 40,
            Self::XchgRet => 40,
            Self::Ret => 30,
        }
    }
}

/// Stack frame information for validation
#[derive(Debug, Clone)]
pub struct StackFrame {
    /// Frame index (0 = current, 1 = caller, etc.)
    pub index: u32,
    /// Return address from this frame
    pub return_address: usize,
    /// Frame base pointer (RBP)
    pub frame_base: usize,
    /// Stack pointer for this frame
    pub stack_pointer: usize,
    /// Module containing the return address
    pub module: Option<String>,
    /// Validation result for this frame
    pub validation: Option<ValidationResult>,
}

/// Cached module information
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    /// Module base address
    pub base: usize,
    /// Module size
    pub size: usize,
    /// Module name
    pub name: String,
    /// Module path
    pub path: String,
    /// Code section ranges (start offset, size)
    pub code_sections: Vec<(usize, usize)>,
    /// Whether this is a system module
    pub is_system: bool,
}

/// Module cache for efficient lookups
#[derive(Debug, Default)]
pub struct ModuleCache {
    /// PID -> Module list
    modules: HashMap<u32, Vec<ModuleInfo>>,
    /// Last refresh time per PID
    last_refresh: HashMap<u32, Instant>,
    /// Cache lifetime
    cache_lifetime: Duration,
}

impl ModuleCache {
    /// Create a new module cache
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
            last_refresh: HashMap::new(),
            cache_lifetime: Duration::from_secs(60),
        }
    }

    /// Check if cache needs refresh for a PID
    pub fn needs_refresh(&self, pid: u32) -> bool {
        match self.last_refresh.get(&pid) {
            Some(time) => time.elapsed() > self.cache_lifetime,
            None => true,
        }
    }

    /// Find module containing an address
    pub fn find_module(&self, pid: u32, addr: usize) -> Option<&ModuleInfo> {
        self.modules
            .get(&pid)?
            .iter()
            .find(|m| addr >= m.base && addr < m.base + m.size)
    }

    /// Get module and offset for an address
    pub fn get_module_offset(&self, pid: u32, addr: usize) -> Option<(&str, usize)> {
        let module = self.find_module(pid, addr)?;
        Some((&module.name, addr - module.base))
    }

    /// Update cache for a PID
    pub fn update(&mut self, pid: u32, modules: Vec<ModuleInfo>) {
        self.modules.insert(pid, modules);
        self.last_refresh.insert(pid, Instant::now());
    }

    /// Clear cache for a PID
    pub fn invalidate(&mut self, pid: u32) {
        self.modules.remove(&pid);
        self.last_refresh.remove(&pid);
    }
}

// ============================================================================
// ROP Detection Alert
// ============================================================================

/// Alert generated when ROP chain is detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RopDetectionAlert {
    /// Process ID where ROP was detected
    pub pid: u32,
    /// Thread ID where ROP was detected
    pub tid: u32,
    /// Process name
    pub process_name: String,
    /// Process path
    pub process_path: String,
    /// Invalid/suspicious stack frames
    pub invalid_frames: Vec<InvalidFrame>,
    /// Estimated gadget chain length
    pub gadget_chain_length: usize,
    /// Target API being called (if detectable)
    pub target_api: Option<String>,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// Detailed evidence
    pub evidence: Vec<String>,
    /// MITRE ATT&CK technique IDs
    pub mitre_techniques: Vec<String>,
    /// Timestamp of detection
    pub timestamp: u64,
}

/// Information about an invalid stack frame
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvalidFrame {
    /// Frame index
    pub index: u32,
    /// Return address
    pub return_address: usize,
    /// Validation result
    pub result: String,
    /// Risk score
    pub risk_score: f32,
    /// Gadget info if applicable
    pub gadget_type: Option<String>,
}

impl RopDetectionAlert {
    /// Create a telemetry event from this alert
    pub fn to_telemetry_event(&self) -> TelemetryEvent {
        let severity = if self.confidence > 0.8 {
            Severity::Critical
        } else if self.confidence > 0.6 {
            Severity::High
        } else {
            Severity::Medium
        };

        let mut event = TelemetryEvent::new(
            EventType::MemoryScan,
            severity,
            EventPayload::Custom(serde_json::json!({
                "detection_type": "rop_chain",
                "pid": self.pid,
                "tid": self.tid,
                "process_name": self.process_name,
                "process_path": self.process_path,
                "invalid_frames": self.invalid_frames,
                "gadget_chain_length": self.gadget_chain_length,
                "target_api": self.target_api,
                "confidence": self.confidence,
                "evidence": self.evidence,
            })),
        );

        event.add_detection(Detection {
            detection_type: DetectionType::MemoryThreat,
            rule_name: "rop_chain_detected".to_string(),
            confidence: self.confidence,
            description: format!(
                "ROP chain detected in {} (PID: {}, TID: {}): {} suspicious frames, chain length ~{}",
                self.process_name,
                self.pid,
                self.tid,
                self.invalid_frames.len(),
                self.gadget_chain_length
            ),
            mitre_tactics: vec![
                "execution".to_string(),
                "defense-evasion".to_string(),
            ],
            mitre_techniques: self.mitre_techniques.clone(),
        });

        // Add metadata
        event.metadata.insert(
            "gadget_chain_length".to_string(),
            self.gadget_chain_length.to_string(),
        );
        event.metadata.insert(
            "invalid_frame_count".to_string(),
            self.invalid_frames.len().to_string(),
        );
        if let Some(ref api) = self.target_api {
            event.metadata.insert("target_api".to_string(), api.clone());
        }

        event
    }
}

// ============================================================================
// Return Address Validator Implementation
// ============================================================================

/// Main validator for return addresses and ROP detection
pub struct ReturnAddressValidator {
    /// Cached module information per process
    module_cache: Arc<RwLock<ModuleCache>>,
    /// Configuration
    config: ValidatorConfig,
    /// Known gadget patterns (precompiled)
    gadget_patterns: Vec<GadgetPattern>,
    /// Statistics
    stats: Arc<RwLock<ValidatorStats>>,
}

/// Configuration for the validator
#[derive(Debug, Clone)]
pub struct ValidatorConfig {
    /// Maximum bytes to read before return address for CALL detection
    pub max_call_lookback: usize,
    /// Maximum gadget size to consider
    pub max_gadget_size: usize,
    /// Minimum suspicious frames to trigger alert
    pub min_suspicious_frames: usize,
    /// Enable deep gadget analysis
    pub deep_analysis: bool,
    /// Cache lifetime for modules
    pub module_cache_lifetime: Duration,
}

impl Default for ValidatorConfig {
    fn default() -> Self {
        Self {
            max_call_lookback: 16,
            max_gadget_size: 20,
            min_suspicious_frames: 3,
            deep_analysis: true,
            module_cache_lifetime: Duration::from_secs(60),
        }
    }
}

/// Gadget pattern for detection
#[derive(Debug, Clone)]
struct GadgetPattern {
    /// Pattern bytes (with wildcards as 0x100+)
    bytes: Vec<u16>,
    /// Gadget type
    gadget_type: GadgetType,
    /// Description
    description: &'static str,
}

/// Validator statistics
#[derive(Debug, Default)]
struct ValidatorStats {
    total_validations: u64,
    valid_count: u64,
    suspicious_count: u64,
    gadgets_detected: u64,
    alerts_generated: u64,
}

impl ReturnAddressValidator {
    /// Create a new return address validator
    pub fn new() -> Self {
        Self::with_config(ValidatorConfig::default())
    }

    /// Create validator with custom configuration
    pub fn with_config(config: ValidatorConfig) -> Self {
        Self {
            module_cache: Arc::new(RwLock::new(ModuleCache::new())),
            config,
            gadget_patterns: Self::build_gadget_patterns(),
            stats: Arc::new(RwLock::new(ValidatorStats::default())),
        }
    }

    /// Build the list of gadget patterns to detect
    fn build_gadget_patterns() -> Vec<GadgetPattern> {
        vec![
            // Simple RET
            GadgetPattern {
                bytes: vec![0xC3],
                gadget_type: GadgetType::Ret,
                description: "ret",
            },
            // RET n (stack cleanup)
            GadgetPattern {
                bytes: vec![0xC2, 0x100, 0x100], // wildcards for imm16
                gadget_type: GadgetType::RetN,
                description: "ret imm16",
            },
            // SYSCALL; RET
            GadgetPattern {
                bytes: vec![0x0F, 0x05, 0xC3],
                gadget_type: GadgetType::SyscallRet,
                description: "syscall; ret",
            },
            // SYSENTER; RET
            GadgetPattern {
                bytes: vec![0x0F, 0x34, 0xC3],
                gadget_type: GadgetType::SysenterRet,
                description: "sysenter; ret",
            },
            // INT 2E; RET
            GadgetPattern {
                bytes: vec![0xCD, 0x2E, 0xC3],
                gadget_type: GadgetType::Int2eRet,
                description: "int 0x2e; ret",
            },
            // POP RAX; RET
            GadgetPattern {
                bytes: vec![0x58, 0xC3],
                gadget_type: GadgetType::PopRet,
                description: "pop rax; ret",
            },
            // POP RCX; RET
            GadgetPattern {
                bytes: vec![0x59, 0xC3],
                gadget_type: GadgetType::PopRet,
                description: "pop rcx; ret",
            },
            // POP RDX; RET
            GadgetPattern {
                bytes: vec![0x5A, 0xC3],
                gadget_type: GadgetType::PopRet,
                description: "pop rdx; ret",
            },
            // POP RBX; RET
            GadgetPattern {
                bytes: vec![0x5B, 0xC3],
                gadget_type: GadgetType::PopRet,
                description: "pop rbx; ret",
            },
            // POP RSP; RET (stack pivot!)
            GadgetPattern {
                bytes: vec![0x5C, 0xC3],
                gadget_type: GadgetType::StackPivot,
                description: "pop rsp; ret",
            },
            // POP RBP; RET
            GadgetPattern {
                bytes: vec![0x5D, 0xC3],
                gadget_type: GadgetType::PopRet,
                description: "pop rbp; ret",
            },
            // POP RSI; RET
            GadgetPattern {
                bytes: vec![0x5E, 0xC3],
                gadget_type: GadgetType::PopRet,
                description: "pop rsi; ret",
            },
            // POP RDI; RET
            GadgetPattern {
                bytes: vec![0x5F, 0xC3],
                gadget_type: GadgetType::PopRet,
                description: "pop rdi; ret",
            },
            // POP R8-R15; RET (REX.B prefix)
            GadgetPattern {
                bytes: vec![0x41, 0x58, 0xC3],
                gadget_type: GadgetType::PopRet,
                description: "pop r8; ret",
            },
            // LEAVE; RET
            GadgetPattern {
                bytes: vec![0xC9, 0xC3],
                gadget_type: GadgetType::LeaveRet,
                description: "leave; ret",
            },
            // JMP RAX
            GadgetPattern {
                bytes: vec![0xFF, 0xE0],
                gadget_type: GadgetType::JmpReg,
                description: "jmp rax",
            },
            // JMP RCX
            GadgetPattern {
                bytes: vec![0xFF, 0xE1],
                gadget_type: GadgetType::JmpReg,
                description: "jmp rcx",
            },
            // JMP RDX
            GadgetPattern {
                bytes: vec![0xFF, 0xE2],
                gadget_type: GadgetType::JmpReg,
                description: "jmp rdx",
            },
            // JMP RBX
            GadgetPattern {
                bytes: vec![0xFF, 0xE3],
                gadget_type: GadgetType::JmpReg,
                description: "jmp rbx",
            },
            // CALL RAX
            GadgetPattern {
                bytes: vec![0xFF, 0xD0],
                gadget_type: GadgetType::CallReg,
                description: "call rax",
            },
            // CALL RCX
            GadgetPattern {
                bytes: vec![0xFF, 0xD1],
                gadget_type: GadgetType::CallReg,
                description: "call rcx",
            },
            // XCHG EAX, ESP; RET (stack pivot)
            GadgetPattern {
                bytes: vec![0x94, 0xC3],
                gadget_type: GadgetType::StackPivot,
                description: "xchg eax, esp; ret",
            },
            // ADD RSP, xx; RET (can skip stack frames)
            GadgetPattern {
                bytes: vec![0x48, 0x83, 0xC4, 0x100, 0xC3],
                gadget_type: GadgetType::StackPivot,
                description: "add rsp, imm8; ret",
            },
            // MOV RSP, RBP; POP RBP; RET (epilogue gadget)
            GadgetPattern {
                bytes: vec![0x48, 0x89, 0xEC, 0x5D, 0xC3],
                gadget_type: GadgetType::LeaveRet,
                description: "mov rsp, rbp; pop rbp; ret",
            },
        ]
    }

    /// Validate a single return address
    #[cfg(target_os = "windows")]
    pub fn validate_return_address(&self, ret_addr: usize, pid: u32) -> ValidationResult {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows::Win32::System::Memory::{
            VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, PAGE_EXECUTE,
            PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        // Update stats
        {
            let mut stats = self.stats.write();
            stats.total_validations += 1;
        }

        // Basic validation
        if ret_addr == 0 || ret_addr < 0x10000 {
            return ValidationResult::NullOrInvalid { addr: ret_addr };
        }

        // Refresh module cache if needed
        if self.module_cache.read().needs_refresh(pid) {
            if let Err(e) = self.refresh_module_cache(pid) {
                debug!("Failed to refresh module cache for PID {}: {}", pid, e);
            }
        }

        // Check if in a known module
        let cache = self.module_cache.read();
        let module_info = cache.find_module(pid, ret_addr);

        unsafe {
            // Open process for reading
            let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            {
                Ok(h) => h,
                Err(e) => {
                    return ValidationResult::Unreadable {
                        addr: ret_addr,
                        reason: format!("OpenProcess failed: {:?}", e),
                    };
                }
            };

            // Query memory information at the address
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let query_result = VirtualQueryEx(
                handle,
                Some(ret_addr as *const c_void),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            if query_result == 0 {
                let _ = CloseHandle(handle);
                return ValidationResult::Unreadable {
                    addr: ret_addr,
                    reason: "VirtualQueryEx failed".to_string(),
                };
            }

            // Check if executable
            let is_executable = mbi.Protect.0 == PAGE_EXECUTE.0
                || mbi.Protect.0 == PAGE_EXECUTE_READ.0
                || mbi.Protect.0 == PAGE_EXECUTE_READWRITE.0
                || (mbi.Protect.0 & 0xF0) != 0; // Any execute permission

            let is_committed = mbi.State.0 == MEM_COMMIT.0;
            let is_image = (mbi.Type.0 & MEM_IMAGE.0) != 0;

            if !is_committed || !is_executable {
                let _ = CloseHandle(handle);
                return ValidationResult::InvalidModule {
                    addr: ret_addr,
                    protection: Some(mbi.Protect.0),
                    mem_type: Some(if is_image { "MEM_IMAGE" } else { "MEM_PRIVATE" }.to_string()),
                };
            }

            // Read bytes before the return address to check for CALL
            let lookback = self.config.max_call_lookback;
            let mut preceding_bytes = vec![0u8; lookback];
            let read_addr = ret_addr.saturating_sub(lookback);
            let mut bytes_read = 0usize;

            let read_result = ReadProcessMemory(
                handle,
                read_addr as *const c_void,
                preceding_bytes.as_mut_ptr() as *mut c_void,
                lookback,
                Some(&mut bytes_read),
            );

            if read_result.is_err() || bytes_read < lookback {
                // Adjust if we couldn't read the full lookback
                preceding_bytes.truncate(bytes_read);
            }

            let _ = CloseHandle(handle);

            // Check if preceded by a CALL instruction
            if let Some(call_type) = self.find_preceding_call(&preceding_bytes) {
                // Valid - preceded by CALL
                {
                    let mut stats = self.stats.write();
                    stats.valid_count += 1;
                }

                return ValidationResult::Valid {
                    module: module_info
                        .map(|m| m.name.clone())
                        .unwrap_or_else(|| "unknown".to_string()),
                    offset: module_info.map(|m| ret_addr - m.base).unwrap_or(0),
                    call_type,
                };
            }

            // Not after a CALL - check if it looks like a gadget
            if self.config.deep_analysis {
                if let Some(gadget) = self.detect_gadget_at_address(pid, ret_addr) {
                    {
                        let mut stats = self.stats.write();
                        stats.suspicious_count += 1;
                        stats.gadgets_detected += 1;
                    }

                    return ValidationResult::SuspiciousGadget {
                        addr: ret_addr,
                        gadget_size: gadget.gadget_bytes.len(),
                        gadget_info: gadget,
                    };
                }
            }

            // Not after CALL and not a clear gadget
            {
                let mut stats = self.stats.write();
                stats.suspicious_count += 1;
            }

            ValidationResult::NotAfterCall {
                addr: ret_addr,
                preceding_bytes,
                module: module_info.map(|m| m.name.clone()),
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn validate_return_address(&self, ret_addr: usize, _pid: u32) -> ValidationResult {
        // Linux/macOS would use ptrace or /proc/pid/mem
        // For now, return unreadable
        ValidationResult::Unreadable {
            addr: ret_addr,
            reason: "Not implemented for this platform".to_string(),
        }
    }

    /// Validate an entire call stack
    pub fn validate_stack(&self, stack_frames: &[StackFrame], pid: u32) -> Vec<ValidationResult> {
        stack_frames
            .iter()
            .map(|frame| self.validate_return_address(frame.return_address, pid))
            .collect()
    }

    /// Analyze stack for ROP attack indicators
    pub fn analyze_for_rop(
        &self,
        pid: u32,
        tid: u32,
        frames: &[StackFrame],
    ) -> Option<RopDetectionAlert> {
        let validations: Vec<_> = frames
            .iter()
            .map(|f| (f, self.validate_return_address(f.return_address, pid)))
            .collect();

        // Count suspicious frames
        let suspicious: Vec<_> = validations
            .iter()
            .filter(|(_, v)| v.is_suspicious())
            .collect();

        if suspicious.len() < self.config.min_suspicious_frames {
            return None;
        }

        // Calculate confidence based on findings
        let total_risk: f32 = suspicious.iter().map(|(_, v)| v.risk_score()).sum();
        let avg_risk = total_risk / suspicious.len() as f32;

        // Count gadgets
        let gadget_count = suspicious
            .iter()
            .filter(|(_, v)| matches!(v, ValidationResult::SuspiciousGadget { .. }))
            .count();

        // Check for consecutive suspicious frames (strong ROP indicator)
        let mut max_consecutive = 0;
        let mut current_consecutive = 0;
        for (_, validation) in &validations {
            if validation.is_suspicious() {
                current_consecutive += 1;
                max_consecutive = max_consecutive.max(current_consecutive);
            } else {
                current_consecutive = 0;
            }
        }

        // Confidence calculation
        let mut confidence = avg_risk;
        if max_consecutive >= 4 {
            confidence += 0.2;
        }
        if gadget_count >= 2 {
            confidence += 0.15;
        }
        confidence = confidence.min(0.99);

        // Build evidence
        let mut evidence = Vec::new();
        evidence.push(format!(
            "{} suspicious frames out of {}",
            suspicious.len(),
            frames.len()
        ));
        evidence.push(format!(
            "Max {} consecutive suspicious frames",
            max_consecutive
        ));
        evidence.push(format!("{} ROP gadgets detected", gadget_count));

        for (frame, validation) in &suspicious {
            evidence.push(format!(
                "Frame {}: {}",
                frame.index,
                validation.description()
            ));
        }

        // Build invalid frames list
        let invalid_frames: Vec<InvalidFrame> = suspicious
            .iter()
            .map(|(frame, validation)| InvalidFrame {
                index: frame.index,
                return_address: frame.return_address,
                result: validation.description(),
                risk_score: validation.risk_score(),
                gadget_type: if let ValidationResult::SuspiciousGadget { gadget_info, .. } =
                    validation
                {
                    Some(gadget_info.gadget_type.as_str().to_string())
                } else {
                    None
                },
            })
            .collect();

        // Get process info
        let (process_name, process_path) = self.get_process_info(pid);

        // Update stats
        {
            let mut stats = self.stats.write();
            stats.alerts_generated += 1;
        }

        Some(RopDetectionAlert {
            pid,
            tid,
            process_name,
            process_path,
            invalid_frames,
            gadget_chain_length: max_consecutive,
            target_api: None, // Would need call stack context
            confidence,
            evidence,
            mitre_techniques: vec!["T1055".to_string(), "T1574".to_string()],
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        })
    }

    /// Check if address follows a CALL instruction
    fn find_preceding_call(&self, bytes: &[u8]) -> Option<CallInstructionType> {
        if bytes.is_empty() {
            return None;
        }

        let len = bytes.len();

        // Check for different CALL patterns from right to left (most recent to oldest)
        // Pattern: E8 xx xx xx xx (CALL rel32) - 5 bytes before return
        if len >= 5 && bytes[len - 5] == 0xE8 {
            return Some(CallInstructionType::CallRel32);
        }

        // Pattern: FF 15 xx xx xx xx (CALL [rip+disp32]) - 6 bytes before return
        if len >= 6 && bytes[len - 6] == 0xFF && bytes[len - 5] == 0x15 {
            return Some(CallInstructionType::CallRipRel);
        }

        // Pattern: FF D0-D7 (CALL reg) - 2 bytes before return
        if len >= 2 && bytes[len - 2] == 0xFF && (bytes[len - 1] & 0xF8) == 0xD0 {
            return Some(CallInstructionType::CallReg);
        }

        // Pattern: FF 10-17 (CALL [reg]) - 2 bytes before return
        if len >= 2 && bytes[len - 2] == 0xFF && (bytes[len - 1] & 0xF8) == 0x10 {
            return Some(CallInstructionType::CallRegIndirect);
        }

        // Pattern: FF 50 xx (CALL [reg+disp8]) - 3 bytes before return
        if len >= 3 && bytes[len - 3] == 0xFF && (bytes[len - 2] & 0xF8) == 0x50 {
            return Some(CallInstructionType::CallRegDisp8);
        }

        // Pattern: FF 90 xx xx xx xx (CALL [reg+disp32]) - 6 bytes before return
        if len >= 6 && bytes[len - 6] == 0xFF && (bytes[len - 5] & 0xF8) == 0x90 {
            return Some(CallInstructionType::CallRegDisp32);
        }

        // Pattern: FF 14 xx (CALL [reg+reg*scale]) - 3 bytes before return
        if len >= 3 && bytes[len - 3] == 0xFF && bytes[len - 2] == 0x14 {
            return Some(CallInstructionType::CallSib);
        }

        // Pattern: 41 FF D0-D7 (CALL r8-r15 with REX.B) - 3 bytes before
        if len >= 3
            && bytes[len - 3] == 0x41
            && bytes[len - 2] == 0xFF
            && (bytes[len - 1] & 0xF8) == 0xD0
        {
            return Some(CallInstructionType::CallReg);
        }

        // Pattern: 48 FF D0-D7 (CALL reg with REX.W) - 3 bytes before
        if len >= 3
            && bytes[len - 3] == 0x48
            && bytes[len - 2] == 0xFF
            && (bytes[len - 1] & 0xF8) == 0xD0
        {
            return Some(CallInstructionType::CallReg);
        }

        None
    }

    /// Detect if address points to a ROP gadget
    #[cfg(target_os = "windows")]
    fn detect_gadget_at_address(&self, pid: u32, addr: usize) -> Option<RopGadgetInfo> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_READ};

        unsafe {
            let handle = match OpenProcess(PROCESS_VM_READ, false, pid) {
                Ok(h) => h,
                Err(_) => return None,
            };

            // Read bytes at the address
            let mut buffer = vec![0u8; self.config.max_gadget_size];
            let mut bytes_read = 0usize;

            let read_result = ReadProcessMemory(
                handle,
                addr as *const c_void,
                buffer.as_mut_ptr() as *mut c_void,
                self.config.max_gadget_size,
                Some(&mut bytes_read),
            );

            let _ = CloseHandle(handle);

            if read_result.is_err() || bytes_read == 0 {
                return None;
            }

            buffer.truncate(bytes_read);

            // Check against gadget patterns
            for pattern in &self.gadget_patterns {
                if self.matches_pattern(&buffer, &pattern.bytes) {
                    let cache = self.module_cache.read();
                    let module = cache.find_module(pid, addr).map(|m| m.name.clone());

                    let risk = self.calculate_gadget_risk(&pattern.gadget_type, &buffer, &module);

                    return Some(RopGadgetInfo {
                        address: addr,
                        gadget_bytes: buffer[..pattern.bytes.len().min(buffer.len())].to_vec(),
                        gadget_type: pattern.gadget_type,
                        risk_score: risk,
                        description: pattern.description.to_string(),
                        module,
                    });
                }
            }

            None
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn detect_gadget_at_address(&self, _pid: u32, _addr: usize) -> Option<RopGadgetInfo> {
        None
    }

    /// Check if bytes match a gadget pattern (0x100+ values are wildcards)
    fn matches_pattern(&self, bytes: &[u8], pattern: &[u16]) -> bool {
        if bytes.len() < pattern.len() {
            return false;
        }

        for (i, &p) in pattern.iter().enumerate() {
            if p < 0x100 && bytes[i] != p as u8 {
                return false;
            }
            // p >= 0x100 is wildcard, matches any byte
        }

        true
    }

    /// Calculate risk score for a gadget
    fn calculate_gadget_risk(
        &self,
        gadget_type: &GadgetType,
        _bytes: &[u8],
        module: &Option<String>,
    ) -> u8 {
        let mut risk = gadget_type.base_risk();

        // Increase risk if in a writable module or no module
        if module.is_none() {
            risk = risk.saturating_add(15);
        }

        // Syscall gadgets are always high risk
        if matches!(
            gadget_type,
            GadgetType::SyscallRet | GadgetType::SysenterRet | GadgetType::Int2eRet
        ) {
            risk = risk.max(90);
        }

        // Stack pivot gadgets are very dangerous
        if matches!(gadget_type, GadgetType::StackPivot) {
            risk = risk.max(85);
        }

        risk.min(100)
    }

    /// Refresh the module cache for a process
    #[cfg(target_os = "windows")]
    fn refresh_module_cache(&self, pid: u32) -> Result<()> {
        use windows::Win32::Foundation::{CloseHandle, HMODULE};
        use windows::Win32::System::ProcessStatus::{
            EnumProcessModulesEx, GetModuleFileNameExW, GetModuleInformation, LIST_MODULES_ALL,
            MODULEINFO,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        let mut modules = Vec::new();

        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
                .map_err(|e| anyhow!("OpenProcess failed: {:?}", e))?;

            let mut module_handles: Vec<HMODULE> = vec![HMODULE::default(); 1024];
            let mut cb_needed = 0u32;

            if EnumProcessModulesEx(
                handle,
                module_handles.as_mut_ptr(),
                (module_handles.len() * std::mem::size_of::<HMODULE>()) as u32,
                &mut cb_needed,
                LIST_MODULES_ALL,
            )
            .is_ok()
            {
                let module_count = cb_needed as usize / std::mem::size_of::<HMODULE>();

                for i in 0..module_count {
                    let module = module_handles[i];
                    if module.is_invalid() {
                        continue;
                    }

                    let mut mod_info = MODULEINFO::default();
                    if GetModuleInformation(
                        handle,
                        module,
                        &mut mod_info,
                        std::mem::size_of::<MODULEINFO>() as u32,
                    )
                    .is_err()
                    {
                        continue;
                    }

                    let mut path_buf = vec![0u16; 512];
                    let len = GetModuleFileNameExW(handle, module, &mut path_buf);
                    if len == 0 {
                        continue;
                    }

                    let module_path = String::from_utf16_lossy(&path_buf[..len as usize]);
                    let module_name = std::path::Path::new(&module_path)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                        .to_string();

                    let is_system = module_path.to_lowercase().contains("\\windows\\");

                    modules.push(ModuleInfo {
                        base: mod_info.lpBaseOfDll as usize,
                        size: mod_info.SizeOfImage as usize,
                        name: module_name,
                        path: module_path,
                        code_sections: Vec::new(), // Would need PE parsing
                        is_system,
                    });
                }
            }

            let _ = CloseHandle(handle);
        }

        let mut cache = self.module_cache.write();
        cache.update(pid, modules);

        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn refresh_module_cache(&self, _pid: u32) -> Result<()> {
        Ok(())
    }

    /// Get process name and path
    #[cfg(target_os = "windows")]
    fn get_process_info(&self, pid: u32) -> (String, String) {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

        unsafe {
            if let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                let mut buffer = vec![0u16; 260];
                let len = GetModuleFileNameExW(handle, None, &mut buffer);
                let _ = CloseHandle(handle);

                if len > 0 {
                    let path = String::from_utf16_lossy(&buffer[..len as usize]);
                    let name = std::path::Path::new(&path)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| format!("pid_{}", pid));
                    return (name, path);
                }
            }
        }

        (format!("pid_{}", pid), String::new())
    }

    #[cfg(not(target_os = "windows"))]
    fn get_process_info(&self, pid: u32) -> (String, String) {
        (format!("pid_{}", pid), String::new())
    }

    /// Get validator statistics
    pub fn get_stats(&self) -> (u64, u64, u64, u64, u64) {
        let stats = self.stats.read();
        (
            stats.total_validations,
            stats.valid_count,
            stats.suspicious_count,
            stats.gadgets_detected,
            stats.alerts_generated,
        )
    }

    /// Clear module cache for a process (e.g., on termination)
    pub fn invalidate_cache(&self, pid: u32) {
        self.module_cache.write().invalidate(pid);
    }
}

impl Default for ReturnAddressValidator {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Stack Walking Integration (Windows)
// ============================================================================

/// Walk the call stack using DbgHelp StackWalk64 or RtlVirtualUnwind
#[cfg(target_os = "windows")]
pub fn walk_stack_and_validate(
    pid: u32,
    tid: u32,
    validator: &ReturnAddressValidator,
) -> Result<Vec<StackFrame>> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Diagnostics::Debug::{
        GetThreadContext, CONTEXT, CONTEXT_ALL_AMD64,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, OpenThread, ResumeThread, SuspendThread, PROCESS_QUERY_INFORMATION,
        PROCESS_VM_READ, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION, THREAD_SUSPEND_RESUME,
    };

    let mut frames = Vec::new();

    unsafe {
        // Open thread
        let thread_handle = OpenThread(
            THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME,
            false,
            tid,
        )
        .map_err(|e| anyhow!("OpenThread failed: {:?}", e))?;

        // Suspend thread
        let suspend_count = SuspendThread(thread_handle);
        if suspend_count == u32::MAX {
            let _ = CloseHandle(thread_handle);
            return Err(anyhow!("SuspendThread failed"));
        }

        // Get thread context
        let mut context = CONTEXT::default();
        context.ContextFlags = CONTEXT_ALL_AMD64;

        let context_result = GetThreadContext(thread_handle, &mut context);

        if context_result.is_err() {
            ResumeThread(thread_handle);
            let _ = CloseHandle(thread_handle);
            return Err(anyhow!("GetThreadContext failed"));
        }

        // Resume thread
        ResumeThread(thread_handle);
        let _ = CloseHandle(thread_handle);

        // Open process for memory reading
        let proc_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            .map_err(|e| anyhow!("OpenProcess failed: {:?}", e))?;

        // Walk stack manually via RBP chain
        #[cfg(target_arch = "x86_64")]
        {
            let mut rbp = context.Rbp as usize;
            let rsp = context.Rsp as usize;
            let rip = context.Rip as usize;

            // Add current frame
            frames.push(StackFrame {
                index: 0,
                return_address: rip,
                frame_base: rbp,
                stack_pointer: rsp,
                module: None,
                validation: None,
            });

            let mut frame_index = 1u32;
            let max_frames = 64u32;

            while frame_index < max_frames && rbp != 0 && rbp % 8 == 0 {
                // Read saved RBP and return address
                let mut saved_rbp = 0usize;
                let mut ret_addr = 0usize;
                let mut bytes_read = 0usize;

                // Read saved RBP at [rbp]
                if ReadProcessMemory(
                    proc_handle,
                    rbp as *const c_void,
                    &mut saved_rbp as *mut usize as *mut c_void,
                    std::mem::size_of::<usize>(),
                    Some(&mut bytes_read),
                )
                .is_err()
                {
                    break;
                }

                // Read return address at [rbp+8]
                if ReadProcessMemory(
                    proc_handle,
                    (rbp + 8) as *const c_void,
                    &mut ret_addr as *mut usize as *mut c_void,
                    std::mem::size_of::<usize>(),
                    Some(&mut bytes_read),
                )
                .is_err()
                {
                    break;
                }

                // Validate return address is reasonable
                if ret_addr == 0 || ret_addr < 0x10000 {
                    break;
                }

                frames.push(StackFrame {
                    index: frame_index,
                    return_address: ret_addr,
                    frame_base: saved_rbp,
                    stack_pointer: rbp + 16,
                    module: None,
                    validation: None,
                });

                // Check for valid frame chain
                if saved_rbp <= rbp {
                    break;
                }

                rbp = saved_rbp;
                frame_index += 1;
            }
        }

        let _ = CloseHandle(proc_handle);
    }

    // Validate all frames
    for frame in &mut frames {
        let validation = validator.validate_return_address(frame.return_address, pid);
        frame.validation = Some(validation);
    }

    Ok(frames)
}

#[cfg(not(target_os = "windows"))]
pub fn walk_stack_and_validate(
    _pid: u32,
    _tid: u32,
    _validator: &ReturnAddressValidator,
) -> Result<Vec<StackFrame>> {
    // Would use ptrace on Linux, mach APIs on macOS
    Ok(Vec::new())
}

/// Check if a specific address is immediately after a CALL instruction
#[cfg(target_os = "windows")]
pub fn is_after_call_instruction(addr: usize, pid: u32) -> Result<bool> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_READ};

    if addr < 16 {
        return Ok(false);
    }

    unsafe {
        let handle = OpenProcess(PROCESS_VM_READ, false, pid)
            .map_err(|e| anyhow!("OpenProcess failed: {:?}", e))?;

        let lookback = 16usize;
        let mut buffer = vec![0u8; lookback];
        let read_addr = addr.saturating_sub(lookback);
        let mut bytes_read = 0usize;

        let read_result = ReadProcessMemory(
            handle,
            read_addr as *const c_void,
            buffer.as_mut_ptr() as *mut c_void,
            lookback,
            Some(&mut bytes_read),
        );

        let _ = CloseHandle(handle);

        if read_result.is_err() || bytes_read < lookback {
            return Err(anyhow!("Failed to read memory"));
        }

        // Check for CALL patterns
        // E8 xx xx xx xx (CALL rel32)
        if buffer[lookback - 5] == 0xE8 {
            return Ok(true);
        }

        // FF 15 xx xx xx xx (CALL [rip+disp32])
        if buffer[lookback - 6] == 0xFF && buffer[lookback - 5] == 0x15 {
            return Ok(true);
        }

        // FF D0-D7 (CALL reg)
        if buffer[lookback - 2] == 0xFF && (buffer[lookback - 1] & 0xF8) == 0xD0 {
            return Ok(true);
        }

        // FF 10-17 (CALL [reg])
        if buffer[lookback - 2] == 0xFF && (buffer[lookback - 1] & 0xF8) == 0x10 {
            return Ok(true);
        }

        Ok(false)
    }
}

#[cfg(not(target_os = "windows"))]
pub fn is_after_call_instruction(_addr: usize, _pid: u32) -> Result<bool> {
    Ok(false)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_result_risk_scores() {
        let valid = ValidationResult::Valid {
            module: "test.dll".to_string(),
            offset: 0x1000,
            call_type: CallInstructionType::CallRel32,
        };
        assert_eq!(valid.risk_score(), 0.0);
        assert!(!valid.is_suspicious());

        let gadget = ValidationResult::SuspiciousGadget {
            addr: 0x1000,
            gadget_size: 3,
            gadget_info: RopGadgetInfo {
                address: 0x1000,
                gadget_bytes: vec![0x0F, 0x05, 0xC3],
                gadget_type: GadgetType::SyscallRet,
                risk_score: 95,
                description: "syscall; ret".to_string(),
                module: Some("ntdll.dll".to_string()),
            },
        };
        assert!(gadget.risk_score() > 0.9);
        assert!(gadget.is_suspicious());

        let invalid = ValidationResult::InvalidModule {
            addr: 0x1000,
            protection: Some(0x20),
            mem_type: Some("MEM_PRIVATE".to_string()),
        };
        assert!(invalid.risk_score() > 0.7);
        assert!(invalid.is_suspicious());
    }

    #[test]
    fn test_call_instruction_types() {
        assert_eq!(CallInstructionType::CallRel32.instruction_size(), 5);
        assert_eq!(CallInstructionType::CallRipRel.instruction_size(), 6);
        assert_eq!(CallInstructionType::CallReg.instruction_size(), 2);
    }

    #[test]
    fn test_gadget_types() {
        assert!(GadgetType::SyscallRet.base_risk() > GadgetType::Ret.base_risk());
        assert!(GadgetType::StackPivot.base_risk() > GadgetType::PopRet.base_risk());
    }

    #[test]
    fn test_find_preceding_call() {
        let validator = ReturnAddressValidator::new();

        // E8 xx xx xx xx - CALL rel32
        let bytes_call_rel32 = vec![0x00, 0x00, 0xE8, 0x10, 0x00, 0x00, 0x00];
        assert!(matches!(
            validator.find_preceding_call(&bytes_call_rel32),
            Some(CallInstructionType::CallRel32)
        ));

        // FF D0 - CALL RAX
        let bytes_call_reg = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0];
        assert!(matches!(
            validator.find_preceding_call(&bytes_call_reg),
            Some(CallInstructionType::CallReg)
        ));

        // No CALL instruction
        let bytes_no_call = vec![0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90];
        assert!(validator.find_preceding_call(&bytes_no_call).is_none());
    }

    #[test]
    fn test_pattern_matching() {
        let validator = ReturnAddressValidator::new();

        // Exact match
        let bytes = [0x0F, 0x05, 0xC3];
        let pattern = vec![0x0F, 0x05, 0xC3];
        assert!(validator.matches_pattern(&bytes, &pattern));

        // Wildcard match (0x100 = any byte)
        let bytes2 = [0xC2, 0x10, 0x00];
        let pattern2 = vec![0xC2, 0x100, 0x100];
        assert!(validator.matches_pattern(&bytes2, &pattern2));

        // No match
        let bytes3 = [0x0F, 0x06, 0xC3];
        assert!(!validator.matches_pattern(&bytes3, &pattern));
    }

    #[test]
    fn test_module_cache() {
        let mut cache = ModuleCache::new();

        let modules = vec![ModuleInfo {
            base: 0x10000,
            size: 0x1000,
            name: "test.dll".to_string(),
            path: "C:\\test.dll".to_string(),
            code_sections: vec![],
            is_system: false,
        }];

        cache.update(1234, modules);

        assert!(cache.find_module(1234, 0x10500).is_some());
        assert!(cache.find_module(1234, 0x20000).is_none());
        assert!(cache.find_module(5678, 0x10500).is_none());

        cache.invalidate(1234);
        assert!(cache.find_module(1234, 0x10500).is_none());
    }

    #[test]
    fn test_validator_config() {
        let config = ValidatorConfig {
            max_call_lookback: 32,
            max_gadget_size: 30,
            min_suspicious_frames: 2,
            deep_analysis: true,
            module_cache_lifetime: Duration::from_secs(120),
        };

        let validator = ReturnAddressValidator::with_config(config);
        assert_eq!(validator.config.max_call_lookback, 32);
        assert_eq!(validator.config.min_suspicious_frames, 2);
    }

    #[test]
    fn test_rop_detection_alert() {
        let alert = RopDetectionAlert {
            pid: 1234,
            tid: 5678,
            process_name: "test.exe".to_string(),
            process_path: "C:\\test.exe".to_string(),
            invalid_frames: vec![InvalidFrame {
                index: 1,
                return_address: 0x1000,
                result: "Gadget detected".to_string(),
                risk_score: 0.9,
                gadget_type: Some("syscall_ret".to_string()),
            }],
            gadget_chain_length: 5,
            target_api: Some("NtAllocateVirtualMemory".to_string()),
            confidence: 0.85,
            evidence: vec!["Test evidence".to_string()],
            mitre_techniques: vec!["T1055".to_string()],
            timestamp: 0,
        };

        let event = alert.to_telemetry_event();
        assert_eq!(event.event_type, EventType::MemoryScan);
        assert!(event.detections.len() > 0);
    }
}
