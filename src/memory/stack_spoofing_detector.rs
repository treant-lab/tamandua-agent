//! Stack Spoofing / Call Stack Masking Detection Module
//!
//! Detects sophisticated stack manipulation techniques used by advanced malware to hide
//! malicious call origins during API calls. These techniques are used by tools like
//! SpoofStack, Unwinder, and custom implementations.
//!
//! ## Detection Methods
//!
//! 1. **Synthetic/Fabricated Stack Frames**
//!    - Detect stack frames that don't correspond to valid code execution paths
//!    - Identify artificially constructed frame chains
//!
//! 2. **Return Address Manipulation**
//!    - Validate return addresses point to valid executable memory
//!    - Detect return addresses pointing after CALL instructions
//!    - Check for return addresses in non-image memory
//!
//! 3. **Invalid Return Addresses**
//!    - Return addresses pointing to non-executable memory
//!    - Return addresses outside any loaded module
//!    - Return addresses to writeable memory (potential shellcode)
//!
//! 4. **Frame Pointer Chain Inconsistencies**
//!    - RBP chain validation
//!    - Stack growth direction violations
//!    - Frame size anomalies
//!
//! 5. **Known Spoofing Technique Detection**
//!    - SpoofStack gadget patterns
//!    - Unwinder tool signatures
//!    - Custom ROP-like call masking
//!
//! ## MITRE ATT&CK
//!
//! - T1055 (Process Injection)
//! - T1562.001 (Impair Defenses: Disable or Modify Tools)
//! - T1027.009 (Obfuscated Files or Information: Embedded Payloads)

// This detector enumerates stack-spoofing technique families (SpoofStack,
// Unwinder, custom ROP-like masking), known-good patterns, frame validation
// state and severity tiers. Reserved cross-platform parameters (pid,
// thread_id, frames) and reference structures are kept exhaustive for
// downstream correlation even when not all paths are wired yet.
#![allow(dead_code, unused_variables)]

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tracing::info;

/// Stack spoofing detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackSpoofingDetection {
    /// Process ID
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// Thread ID where spoofing was detected
    pub thread_id: u32,
    /// Type of stack spoofing detected
    pub technique: StackSpoofingTechnique,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// Severity level
    pub severity: SpoofingSeverity,
    /// Stack pointer (RSP/ESP) at time of detection
    pub stack_pointer: u64,
    /// Suspicious return addresses found
    pub suspicious_returns: Vec<SuspiciousReturnAddress>,
    /// Frame chain anomalies detected
    pub frame_anomalies: Vec<FrameAnomaly>,
    /// Evidence details
    pub evidence: Vec<String>,
    /// MITRE ATT&CK technique ID
    pub mitre_id: &'static str,
}

/// Types of stack spoofing techniques
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StackSpoofingTechnique {
    /// SpoofStack tool - fabricates entire call stack
    SpoofStack,
    /// Unwinder-based stack manipulation
    Unwinder,
    /// Return address pointing to non-executable memory
    ReturnToNonExecutable,
    /// Return address outside all loaded modules
    ReturnOutsideModules,
    /// Return address to unbacked (private) executable memory
    ReturnToUnbacked,
    /// Frame pointer (RBP) chain is broken or inconsistent
    BrokenFrameChain,
    /// Stack frames don't align with call depth
    FrameDepthMismatch,
    /// Synthetic frames with impossible caller relationships
    SyntheticFrames,
    /// ROP gadget chain detected as call stack
    RopChainAsStack,
    /// Thread hijacking with forged stack
    ThreadHijackWithForgedStack,
    /// NtContinue/RtlRestoreContext abuse for stack replacement
    ContextSwitchAbuse,
    /// SetThreadContext used to forge stack
    SetThreadContextAbuse,
    /// Stack pivot detected (RSP points to heap/other region)
    StackPivot,
    /// Timer/APC callback with spoofed origin
    CallbackSpoofing,
}

/// Severity levels for stack spoofing
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpoofingSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl StackSpoofingTechnique {
    pub fn mitre_id(&self) -> &'static str {
        match self {
            Self::SpoofStack | Self::Unwinder => "T1562.001",
            Self::ReturnToNonExecutable | Self::ReturnOutsideModules => "T1055",
            Self::ReturnToUnbacked => "T1055",
            Self::BrokenFrameChain | Self::FrameDepthMismatch => "T1562.001",
            Self::SyntheticFrames => "T1562.001",
            Self::RopChainAsStack => "T1055",
            Self::ThreadHijackWithForgedStack => "T1055.003",
            Self::ContextSwitchAbuse => "T1055",
            Self::SetThreadContextAbuse => "T1055.003",
            Self::StackPivot => "T1055",
            Self::CallbackSpoofing => "T1055.004",
        }
    }

    pub fn severity(&self) -> SpoofingSeverity {
        match self {
            Self::SpoofStack | Self::Unwinder => SpoofingSeverity::Critical,
            Self::ReturnToNonExecutable => SpoofingSeverity::High,
            Self::ReturnOutsideModules => SpoofingSeverity::High,
            Self::ReturnToUnbacked => SpoofingSeverity::Critical,
            Self::BrokenFrameChain => SpoofingSeverity::Medium,
            Self::FrameDepthMismatch => SpoofingSeverity::Medium,
            Self::SyntheticFrames => SpoofingSeverity::Critical,
            Self::RopChainAsStack => SpoofingSeverity::Critical,
            Self::ThreadHijackWithForgedStack => SpoofingSeverity::Critical,
            Self::ContextSwitchAbuse => SpoofingSeverity::High,
            Self::SetThreadContextAbuse => SpoofingSeverity::High,
            Self::StackPivot => SpoofingSeverity::Critical,
            Self::CallbackSpoofing => SpoofingSeverity::High,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::SpoofStack => {
                "SpoofStack technique - fabricated call stack to hide malicious origin"
            }
            Self::Unwinder => {
                "Unwinder-based stack manipulation - modified unwind data for spoofing"
            }
            Self::ReturnToNonExecutable => "Return address points to non-executable memory",
            Self::ReturnOutsideModules => "Return address outside any loaded module bounds",
            Self::ReturnToUnbacked => {
                "Return address in unbacked executable memory (potential shellcode)"
            }
            Self::BrokenFrameChain => "Frame pointer (RBP) chain is inconsistent or broken",
            Self::FrameDepthMismatch => "Stack frame depth doesn't match expected call hierarchy",
            Self::SyntheticFrames => "Artificially constructed stack frames detected",
            Self::RopChainAsStack => "ROP gadget chain masquerading as legitimate call stack",
            Self::ThreadHijackWithForgedStack => "Thread hijacked with forged stack context",
            Self::ContextSwitchAbuse => "NtContinue/RtlRestoreContext used for stack replacement",
            Self::SetThreadContextAbuse => "SetThreadContext used to manipulate stack",
            Self::StackPivot => "Stack pointer moved to non-stack memory region",
            Self::CallbackSpoofing => "Timer/APC callback with spoofed caller origin",
        }
    }
}

/// Suspicious return address information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousReturnAddress {
    /// The return address value
    pub address: u64,
    /// Frame index (0 = current, 1 = caller, etc.)
    pub frame_index: u32,
    /// Reason for suspicion
    pub reason: ReturnAddressIssue,
    /// Module name if resolvable
    pub module_name: Option<String>,
    /// Expected to be after a CALL instruction?
    pub after_call_instruction: bool,
    /// Memory protection at this address
    pub memory_protection: Option<u32>,
    /// Memory type at this address
    pub memory_type: Option<String>,
}

/// Issues with return addresses
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReturnAddressIssue {
    /// Address is not in executable memory
    NotExecutable,
    /// Address is in writable+executable memory (suspicious)
    WritableExecutable,
    /// Address is not in any known module
    NotInModule,
    /// Address is in private (unbacked) memory
    InUnbackedMemory,
    /// Address doesn't follow a CALL instruction
    NotAfterCall,
    /// Address is null or invalid
    NullOrInvalid,
    /// Address points to a ROP gadget
    RopGadget,
    /// Address is in a different process's memory space
    WrongAddressSpace,
}

/// Frame chain anomaly
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameAnomaly {
    /// Frame index
    pub frame_index: u32,
    /// Frame base address (RBP value)
    pub frame_base: u64,
    /// Type of anomaly
    pub anomaly_type: FrameAnomalyType,
    /// Description
    pub description: String,
}

/// Types of frame chain anomalies
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameAnomalyType {
    /// RBP doesn't point to stack memory
    FrameBaseNotOnStack,
    /// RBP chain goes backwards (wrong direction)
    ChainDirectionWrong,
    /// Frame size is impossibly large
    ImpossibleFrameSize,
    /// Frame size is zero or negative
    ZeroOrNegativeFrameSize,
    /// RBP chain forms a loop
    CircularChain,
    /// Gap in frame chain
    GapInChain,
    /// Frame overlaps with previous frame
    OverlappingFrames,
    /// Unwind info mismatch
    UnwindInfoMismatch,
}

/// Loaded module information for validation
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    /// Module base address
    pub base_address: u64,
    /// Module size
    pub size: u64,
    /// Module name
    pub name: String,
    /// Module path
    pub path: String,
    /// Is the module signed
    pub is_signed: bool,
    /// Code section bounds (RVA start, size)
    pub code_sections: Vec<(u32, u32)>,
}

/// Stack region information
#[derive(Debug, Clone)]
pub struct StackInfo {
    /// Stack base (highest address, bottom of stack)
    pub base: u64,
    /// Stack limit (lowest address, top of allocated stack)
    pub limit: u64,
    /// Current stack pointer
    pub current_sp: u64,
}

/// Stack frame for analysis
#[derive(Debug, Clone)]
pub struct StackFrame {
    /// Frame index (0 = current function)
    pub index: u32,
    /// Return address
    pub return_address: u64,
    /// Frame base pointer (RBP)
    pub frame_base: u64,
    /// Stack pointer at this frame
    pub stack_pointer: u64,
    /// Module containing return address
    pub module: Option<String>,
    /// Function name if available (from symbols)
    pub function_name: Option<String>,
}

/// Stack spoofing detector
pub struct StackSpoofingDetector {
    /// Cached module information
    module_cache: HashMap<u32, Vec<ModuleInfo>>,
    /// Known good return address patterns (for baseline)
    known_good_patterns: HashSet<u64>,
    /// Detection sensitivity (0.0 - 1.0)
    sensitivity: f32,
    /// Maximum frames to analyze
    max_frames: u32,
    /// Enable deep frame validation
    deep_validation: bool,
}

impl Default for StackSpoofingDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl StackSpoofingDetector {
    /// Create a new stack spoofing detector
    pub fn new() -> Self {
        Self {
            module_cache: HashMap::new(),
            known_good_patterns: HashSet::new(),
            sensitivity: 0.7,
            max_frames: 64,
            deep_validation: true,
        }
    }

    /// Configure detection sensitivity
    pub fn with_sensitivity(mut self, sensitivity: f32) -> Self {
        self.sensitivity = sensitivity.clamp(0.0, 1.0);
        self
    }

    /// Configure maximum frames to analyze
    pub fn with_max_frames(mut self, max_frames: u32) -> Self {
        self.max_frames = max_frames;
        self
    }

    /// Enable/disable deep frame validation
    pub fn with_deep_validation(mut self, enabled: bool) -> Self {
        self.deep_validation = enabled;
        self
    }

    /// Scan a process for stack spoofing across all threads
    #[cfg(target_os = "windows")]
    pub async fn scan_process(&mut self, pid: u32) -> Result<Vec<StackSpoofingDetection>> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
        };

        let mut all_detections = Vec::new();
        let process_name = get_process_name(pid).unwrap_or_else(|| format!("pid_{}", pid));

        // Refresh module cache
        self.refresh_module_cache(pid).await?;

        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)?;

            let mut thread_entry = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..Default::default()
            };

            if Thread32First(snapshot, &mut thread_entry).is_ok() {
                loop {
                    if thread_entry.th32OwnerProcessID == pid {
                        if let Ok(detections) = self
                            .scan_thread(pid, thread_entry.th32ThreadID, &process_name)
                            .await
                        {
                            all_detections.extend(detections);
                        }
                    }

                    thread_entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
                    if Thread32Next(snapshot, &mut thread_entry).is_err() {
                        break;
                    }
                }
            }

            CloseHandle(snapshot)?;
        }

        if !all_detections.is_empty() {
            info!(
                pid = pid,
                detections = all_detections.len(),
                "Stack spoofing detected"
            );
        }

        Ok(all_detections)
    }

    /// Scan a specific thread for stack spoofing
    #[cfg(target_os = "windows")]
    pub async fn scan_thread(
        &self,
        pid: u32,
        thread_id: u32,
        process_name: &str,
    ) -> Result<Vec<StackSpoofingDetection>> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::Debug::{
            GetThreadContext, CONTEXT, CONTEXT_ALL_AMD64,
        };
        use windows::Win32::System::Threading::{
            OpenThread, ResumeThread, SuspendThread, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION,
            THREAD_SUSPEND_RESUME,
        };

        let mut detections = Vec::new();

        unsafe {
            let thread_handle = OpenThread(
                THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME,
                false,
                thread_id,
            )?;

            // Suspend thread to get consistent stack state
            let suspend_count = SuspendThread(thread_handle);
            if suspend_count == u32::MAX {
                CloseHandle(thread_handle)?;
                return Err(anyhow!("Failed to suspend thread {}", thread_id));
            }

            // Get thread context
            let mut context = CONTEXT::default();
            context.ContextFlags = CONTEXT_ALL_AMD64;

            let context_result = GetThreadContext(thread_handle, &mut context);

            // Always resume thread
            ResumeThread(thread_handle);

            if context_result.is_err() {
                CloseHandle(thread_handle)?;
                return Err(anyhow!("Failed to get thread context"));
            }

            // Analyze the stack
            #[cfg(target_arch = "x86_64")]
            {
                let stack_pointer = context.Rsp;
                let frame_pointer = context.Rbp;
                let instruction_pointer = context.Rip;

                // Get stack bounds
                if let Ok(stack_info) = self.get_stack_info(pid, thread_id).await {
                    // Walk and validate the stack
                    let frames = self
                        .walk_stack(
                            pid,
                            stack_pointer,
                            frame_pointer,
                            instruction_pointer,
                            &stack_info,
                        )
                        .await?;

                    // Analyze frames for spoofing indicators
                    if let Some(detection) = self
                        .analyze_frames(
                            pid,
                            thread_id,
                            process_name,
                            &frames,
                            &stack_info,
                            stack_pointer,
                        )
                        .await
                    {
                        detections.push(detection);
                    }

                    // Check for stack pivot
                    if let Some(detection) = self
                        .detect_stack_pivot(
                            pid,
                            thread_id,
                            process_name,
                            stack_pointer,
                            &stack_info,
                        )
                        .await
                    {
                        detections.push(detection);
                    }
                }
            }

            CloseHandle(thread_handle)?;
        }

        Ok(detections)
    }

    /// Refresh cached module information for a process
    #[cfg(target_os = "windows")]
    async fn refresh_module_cache(&mut self, pid: u32) -> Result<()> {
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
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)?;

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

                    // Get module info
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

                    // Get module path
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

                    modules.push(ModuleInfo {
                        base_address: mod_info.lpBaseOfDll as u64,
                        size: mod_info.SizeOfImage as u64,
                        name: module_name,
                        path: module_path,
                        is_signed: false, // Would need additional signature check
                        code_sections: Vec::new(), // Would need PE parsing
                    });
                }
            }

            CloseHandle(handle)?;
        }

        self.module_cache.insert(pid, modules);
        Ok(())
    }

    /// Get stack bounds for a thread
    #[cfg(target_os = "windows")]
    async fn get_stack_info(&self, pid: u32, thread_id: u32) -> Result<StackInfo> {
        // For now, use a heuristic approach - get stack from TEB
        // In a full implementation, we'd query NT_TIB from the TEB

        // Fallback: Use typical stack bounds
        // Windows allocates 1MB stack by default, guard page at end
        // This is a simplified approach; real impl would query TEB

        Ok(StackInfo {
            base: 0x0000_0100_0000_0000u64,  // Placeholder - should query TEB
            limit: 0x0000_00FF_FFF0_0000u64, // Placeholder
            current_sp: 0,
        })
    }

    /// Walk the stack and collect frames
    #[cfg(target_os = "windows")]
    async fn walk_stack(
        &self,
        pid: u32,
        sp: u64,
        rbp: u64,
        rip: u64,
        stack_info: &StackInfo,
    ) -> Result<Vec<StackFrame>> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_READ};

        let mut frames = Vec::new();

        // Add current frame
        frames.push(StackFrame {
            index: 0,
            return_address: rip,
            frame_base: rbp,
            stack_pointer: sp,
            module: self.find_module_for_address(pid, rip),
            function_name: None,
        });

        unsafe {
            let handle = OpenProcess(PROCESS_VM_READ, false, pid)?;

            let mut current_rbp = rbp;
            let mut frame_index = 1u32;

            // Walk frame chain via RBP
            while frame_index < self.max_frames {
                // Validate RBP is reasonable (on stack, properly aligned)
                if current_rbp == 0 || current_rbp % 8 != 0 {
                    break;
                }

                // Read saved RBP and return address
                // Stack layout at function entry:
                // [RBP+8] = Return Address
                // [RBP+0] = Saved RBP
                let mut saved_rbp = 0u64;
                let mut return_addr = 0u64;
                let mut bytes_read = 0usize;

                // Read saved RBP
                if ReadProcessMemory(
                    handle,
                    current_rbp as *const std::ffi::c_void,
                    &mut saved_rbp as *mut u64 as *mut std::ffi::c_void,
                    8,
                    Some(&mut bytes_read),
                )
                .is_err()
                {
                    break;
                }

                // Read return address
                if ReadProcessMemory(
                    handle,
                    (current_rbp + 8) as *const std::ffi::c_void,
                    &mut return_addr as *mut u64 as *mut std::ffi::c_void,
                    8,
                    Some(&mut bytes_read),
                )
                .is_err()
                {
                    break;
                }

                // Validate return address is reasonable
                if return_addr == 0 || return_addr < 0x10000 {
                    break;
                }

                frames.push(StackFrame {
                    index: frame_index,
                    return_address: return_addr,
                    frame_base: saved_rbp,
                    stack_pointer: current_rbp + 16, // RSP after return
                    module: self.find_module_for_address(pid, return_addr),
                    function_name: None,
                });

                // Check for chain issues
                if saved_rbp <= current_rbp {
                    // Frame chain should grow upward in memory (toward stack base)
                    // If not, chain might be corrupted or spoofed
                    break;
                }

                current_rbp = saved_rbp;
                frame_index += 1;
            }

            CloseHandle(handle)?;
        }

        Ok(frames)
    }

    /// Find which module contains an address
    fn find_module_for_address(&self, pid: u32, address: u64) -> Option<String> {
        if let Some(modules) = self.module_cache.get(&pid) {
            for module in modules {
                if address >= module.base_address && address < module.base_address + module.size {
                    return Some(module.name.clone());
                }
            }
        }
        None
    }

    /// Check if address is in valid executable module memory
    fn is_address_in_module(&self, pid: u32, address: u64) -> bool {
        self.find_module_for_address(pid, address).is_some()
    }

    /// Analyze collected frames for spoofing indicators
    #[cfg(target_os = "windows")]
    async fn analyze_frames(
        &self,
        pid: u32,
        thread_id: u32,
        process_name: &str,
        frames: &[StackFrame],
        stack_info: &StackInfo,
        stack_pointer: u64,
    ) -> Option<StackSpoofingDetection> {
        let mut suspicious_returns = Vec::new();
        let mut frame_anomalies = Vec::new();
        let mut evidence = Vec::new();
        let mut max_severity = SpoofingSeverity::Low;
        let mut technique = StackSpoofingTechnique::BrokenFrameChain;

        // Check each frame
        for frame in frames {
            // 1. Check if return address is in a known module
            if !self.is_address_in_module(pid, frame.return_address) {
                // Check memory attributes of the return address
                if let Ok(mem_info) = get_memory_info(pid, frame.return_address).await {
                    let reason = if !mem_info.is_executable {
                        ReturnAddressIssue::NotExecutable
                    } else if mem_info.is_private {
                        ReturnAddressIssue::InUnbackedMemory
                    } else {
                        ReturnAddressIssue::NotInModule
                    };

                    suspicious_returns.push(SuspiciousReturnAddress {
                        address: frame.return_address,
                        frame_index: frame.index,
                        reason,
                        module_name: frame.module.clone(),
                        after_call_instruction: false, // Would need instruction analysis
                        memory_protection: Some(mem_info.protection),
                        memory_type: Some(mem_info.type_string),
                    });

                    // Set appropriate technique and severity
                    match reason {
                        ReturnAddressIssue::NotExecutable => {
                            technique = StackSpoofingTechnique::ReturnToNonExecutable;
                            if SpoofingSeverity::High > max_severity {
                                max_severity = SpoofingSeverity::High;
                            }
                        }
                        ReturnAddressIssue::InUnbackedMemory => {
                            technique = StackSpoofingTechnique::ReturnToUnbacked;
                            max_severity = SpoofingSeverity::Critical;
                        }
                        ReturnAddressIssue::NotInModule => {
                            technique = StackSpoofingTechnique::ReturnOutsideModules;
                            if SpoofingSeverity::High > max_severity {
                                max_severity = SpoofingSeverity::High;
                            }
                        }
                        _ => {}
                    }

                    evidence.push(format!(
                        "Frame {}: return address 0x{:X} is {}",
                        frame.index,
                        frame.return_address,
                        reason_to_string(reason)
                    ));
                }
            }

            // 2. Check frame pointer validity
            if frame.index > 0 && frame.frame_base != 0 {
                // Frame base should be on the stack
                // Note: We'd need proper stack bounds for this check

                // Check for impossible frame sizes
                if frame.index > 0 && frames.len() > frame.index as usize {
                    let prev_frame = &frames[frame.index as usize - 1];
                    if prev_frame.frame_base > 0 && frame.frame_base > 0 {
                        let frame_size = frame.frame_base.saturating_sub(prev_frame.frame_base);

                        // Frame size > 1MB is suspicious (typical stack is 1MB total)
                        if frame_size > 1024 * 1024 {
                            frame_anomalies.push(FrameAnomaly {
                                frame_index: frame.index,
                                frame_base: frame.frame_base,
                                anomaly_type: FrameAnomalyType::ImpossibleFrameSize,
                                description: format!(
                                    "Frame size {} bytes is impossibly large",
                                    frame_size
                                ),
                            });

                            technique = StackSpoofingTechnique::SyntheticFrames;
                            max_severity = SpoofingSeverity::Critical;
                        }

                        // Frame going wrong direction
                        if frame.frame_base < prev_frame.frame_base {
                            frame_anomalies.push(FrameAnomaly {
                                frame_index: frame.index,
                                frame_base: frame.frame_base,
                                anomaly_type: FrameAnomalyType::ChainDirectionWrong,
                                description: "Frame chain goes in wrong direction".to_string(),
                            });

                            technique = StackSpoofingTechnique::BrokenFrameChain;
                            if SpoofingSeverity::Medium > max_severity {
                                max_severity = SpoofingSeverity::Medium;
                            }
                        }
                    }
                }
            }
        }

        // 3. Check for SpoofStack-specific patterns
        if let Some(spoof_detection) = self.detect_spoofstack_patterns(pid, frames).await {
            technique = StackSpoofingTechnique::SpoofStack;
            max_severity = SpoofingSeverity::Critical;
            evidence.push(spoof_detection);
        }

        // 4. Check for Unwinder patterns
        if let Some(unwinder_detection) = self.detect_unwinder_patterns(pid, frames).await {
            technique = StackSpoofingTechnique::Unwinder;
            max_severity = SpoofingSeverity::Critical;
            evidence.push(unwinder_detection);
        }

        // Only return detection if we found something suspicious
        if suspicious_returns.is_empty() && frame_anomalies.is_empty() {
            return None;
        }

        // Calculate confidence based on number and severity of findings
        let confidence = calculate_confidence(&suspicious_returns, &frame_anomalies);

        Some(StackSpoofingDetection {
            pid,
            process_name: process_name.to_string(),
            thread_id,
            technique,
            confidence,
            severity: max_severity,
            stack_pointer,
            suspicious_returns,
            frame_anomalies,
            evidence,
            mitre_id: technique.mitre_id(),
        })
    }

    /// Detect stack pivot (RSP pointing to non-stack memory)
    #[cfg(target_os = "windows")]
    async fn detect_stack_pivot(
        &self,
        pid: u32,
        thread_id: u32,
        process_name: &str,
        stack_pointer: u64,
        stack_info: &StackInfo,
    ) -> Option<StackSpoofingDetection> {
        // Check if stack pointer is in expected stack region
        // If RSP points to heap or other non-stack memory, it's a pivot

        if let Ok(mem_info) = get_memory_info(pid, stack_pointer).await {
            // Stack memory should be MEM_PRIVATE but have specific characteristics
            // A pivot would show RSP in heap (MEM_PRIVATE with different flags) or
            // mapped memory (MEM_MAPPED)

            // Check if memory type indicates non-stack
            let is_likely_heap = mem_info.is_private
                && (mem_info.protection & 0x04 != 0) // PAGE_READWRITE
                && !mem_info.type_string.contains("Stack");

            let is_mapped = mem_info.type_string.contains("Mapped");

            if is_likely_heap || is_mapped {
                let evidence = vec![
                    format!("RSP = 0x{:X}", stack_pointer),
                    format!("Memory type: {}", mem_info.type_string),
                    format!("Protection: 0x{:X}", mem_info.protection),
                    "Stack pointer is not in thread stack region".to_string(),
                    "Possible stack pivot for ROP/shellcode execution".to_string(),
                ];

                return Some(StackSpoofingDetection {
                    pid,
                    process_name: process_name.to_string(),
                    thread_id,
                    technique: StackSpoofingTechnique::StackPivot,
                    confidence: 0.9,
                    severity: SpoofingSeverity::Critical,
                    stack_pointer,
                    suspicious_returns: Vec::new(),
                    frame_anomalies: Vec::new(),
                    evidence,
                    mitre_id: "T1055",
                });
            }
        }

        None
    }

    /// Detect SpoofStack-specific patterns
    #[cfg(target_os = "windows")]
    async fn detect_spoofstack_patterns(&self, pid: u32, frames: &[StackFrame]) -> Option<String> {
        // SpoofStack characteristics:
        // 1. All return addresses are in ntdll.dll or kernel32.dll (clean chain)
        // 2. Return addresses specifically at certain offsets (gadget addresses)
        // 3. Chain looks "too clean" for the actual operation

        if frames.is_empty() {
            return None;
        }

        let modules: Vec<&Option<String>> = frames.iter().map(|f| &f.module).collect();

        // Count system DLL frames
        let system_dll_count = modules
            .iter()
            .filter(|m| {
                m.as_ref().map_or(false, |name| {
                    let lower = name.to_lowercase();
                    lower == "ntdll.dll" || lower == "kernel32.dll" || lower == "kernelbase.dll"
                })
            })
            .count();

        // If almost all frames are in system DLLs but we have suspicious activity,
        // this could indicate SpoofStack
        let system_ratio = system_dll_count as f32 / frames.len() as f32;

        if system_ratio > 0.8 && frames.len() > 3 {
            // Check for characteristic gadget patterns
            // SpoofStack often uses ROP gadgets that end with RET

            // This is a simplified check - real detection would verify actual gadgets
            return Some(format!(
                "Suspicious clean call stack: {}% system DLL frames ({}/{})",
                (system_ratio * 100.0) as u32,
                system_dll_count,
                frames.len()
            ));
        }

        None
    }

    /// Detect Unwinder-based spoofing patterns
    #[cfg(target_os = "windows")]
    async fn detect_unwinder_patterns(&self, pid: u32, frames: &[StackFrame]) -> Option<String> {
        // Unwinder manipulates unwind info to create fake stack frames
        // Detection would involve:
        // 1. Verifying unwind info matches actual frame layout
        // 2. Checking for mismatches between RtlVirtualUnwind and manual walk

        // For now, check for characteristic patterns:
        // - Frames that skip expected callees
        // - Return addresses that don't have matching unwind info

        // This would need full unwind info parsing - placeholder for now
        None
    }
}

/// Memory region information
#[derive(Debug, Clone)]
struct MemoryRegionInfo {
    base_address: u64,
    size: u64,
    protection: u32,
    is_executable: bool,
    is_writable: bool,
    is_private: bool,
    type_string: String,
}

/// Get memory information for an address
#[cfg(target_os = "windows")]
async fn get_memory_info(pid: u32, address: u64) -> Result<MemoryRegionInfo> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, PAGE_EXECUTE,
        PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_READWRITE,
        PAGE_WRITECOPY,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)?;

        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let result = VirtualQueryEx(
            handle,
            Some(address as *const std::ffi::c_void),
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        );

        CloseHandle(handle)?;

        if result == 0 {
            return Err(anyhow!("VirtualQueryEx failed for address 0x{:X}", address));
        }

        let protection = mbi.Protect.0;
        let is_executable = protection == PAGE_EXECUTE.0
            || protection == PAGE_EXECUTE_READ.0
            || protection == PAGE_EXECUTE_READWRITE.0
            || protection == PAGE_EXECUTE_WRITECOPY.0;
        let is_writable = protection == PAGE_READWRITE.0
            || protection == PAGE_WRITECOPY.0
            || protection == PAGE_EXECUTE_READWRITE.0
            || protection == PAGE_EXECUTE_WRITECOPY.0;

        let type_val = mbi.Type.0;
        let type_string = if type_val == MEM_IMAGE.0 {
            "Image".to_string()
        } else if type_val == MEM_MAPPED.0 {
            "Mapped".to_string()
        } else if type_val == MEM_PRIVATE.0 {
            "Private".to_string()
        } else {
            format!("Unknown(0x{:X})", type_val)
        };

        Ok(MemoryRegionInfo {
            base_address: mbi.BaseAddress as u64,
            size: mbi.RegionSize as u64,
            protection,
            is_executable,
            is_writable,
            is_private: type_val == MEM_PRIVATE.0,
            type_string,
        })
    }
}

/// Get process name by PID
#[cfg(target_os = "windows")]
fn get_process_name(pid: u32) -> Option<String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::ProcessStatus::GetModuleBaseNameW;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    unsafe {
        if let Ok(handle) = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
            let mut name_buf = vec![0u16; 256];
            let len = GetModuleBaseNameW(handle, None, &mut name_buf);
            CloseHandle(handle).ok();

            if len > 0 {
                return Some(String::from_utf16_lossy(&name_buf[..len as usize]));
            }
        }
    }
    None
}

/// Convert ReturnAddressIssue to descriptive string
fn reason_to_string(reason: ReturnAddressIssue) -> &'static str {
    match reason {
        ReturnAddressIssue::NotExecutable => "in non-executable memory",
        ReturnAddressIssue::WritableExecutable => "in writable+executable memory",
        ReturnAddressIssue::NotInModule => "not in any loaded module",
        ReturnAddressIssue::InUnbackedMemory => "in unbacked private memory",
        ReturnAddressIssue::NotAfterCall => "not following a CALL instruction",
        ReturnAddressIssue::NullOrInvalid => "null or invalid",
        ReturnAddressIssue::RopGadget => "a ROP gadget",
        ReturnAddressIssue::WrongAddressSpace => "in wrong address space",
    }
}

/// Calculate confidence score based on findings
fn calculate_confidence(
    suspicious_returns: &[SuspiciousReturnAddress],
    frame_anomalies: &[FrameAnomaly],
) -> f32 {
    let mut confidence = 0.0f32;

    // Weight suspicious returns
    for ret in suspicious_returns {
        confidence += match ret.reason {
            ReturnAddressIssue::InUnbackedMemory => 0.3,
            ReturnAddressIssue::NotExecutable => 0.25,
            ReturnAddressIssue::NotInModule => 0.2,
            ReturnAddressIssue::WritableExecutable => 0.2,
            ReturnAddressIssue::RopGadget => 0.35,
            _ => 0.1,
        };
    }

    // Weight frame anomalies
    for anomaly in frame_anomalies {
        confidence += match anomaly.anomaly_type {
            FrameAnomalyType::ImpossibleFrameSize => 0.25,
            FrameAnomalyType::ChainDirectionWrong => 0.2,
            FrameAnomalyType::CircularChain => 0.3,
            _ => 0.1,
        };
    }

    confidence.min(1.0)
}

// =============================================================================
// LINUX/MACOS STUBS
// =============================================================================

#[cfg(not(target_os = "windows"))]
impl StackSpoofingDetector {
    pub async fn scan_process(&mut self, _pid: u32) -> Result<Vec<StackSpoofingDetection>> {
        // Stack spoofing as described is primarily a Windows technique
        // Linux/macOS would need different approaches (ptrace, /proc/pid/maps, etc.)
        Ok(Vec::new())
    }

    pub async fn scan_thread(
        &self,
        _pid: u32,
        _thread_id: u32,
        _process_name: &str,
    ) -> Result<Vec<StackSpoofingDetection>> {
        Ok(Vec::new())
    }

    async fn refresh_module_cache(&mut self, _pid: u32) -> Result<()> {
        Ok(())
    }

    async fn get_stack_info(&self, _pid: u32, _thread_id: u32) -> Result<StackInfo> {
        Err(anyhow!("Not implemented for this platform"))
    }

    async fn walk_stack(
        &self,
        _pid: u32,
        _sp: u64,
        _rbp: u64,
        _rip: u64,
        _stack_info: &StackInfo,
    ) -> Result<Vec<StackFrame>> {
        Ok(Vec::new())
    }

    async fn analyze_frames(
        &self,
        _pid: u32,
        _thread_id: u32,
        _process_name: &str,
        _frames: &[StackFrame],
        _stack_info: &StackInfo,
        _stack_pointer: u64,
    ) -> Option<StackSpoofingDetection> {
        None
    }

    async fn detect_stack_pivot(
        &self,
        _pid: u32,
        _thread_id: u32,
        _process_name: &str,
        _stack_pointer: u64,
        _stack_info: &StackInfo,
    ) -> Option<StackSpoofingDetection> {
        None
    }

    async fn detect_spoofstack_patterns(
        &self,
        _pid: u32,
        _frames: &[StackFrame],
    ) -> Option<String> {
        None
    }

    async fn detect_unwinder_patterns(&self, _pid: u32, _frames: &[StackFrame]) -> Option<String> {
        None
    }
}

#[cfg(not(target_os = "windows"))]
async fn get_memory_info(_pid: u32, _address: u64) -> Result<MemoryRegionInfo> {
    Err(anyhow!("Not implemented for this platform"))
}

#[cfg(not(target_os = "windows"))]
fn get_process_name(_pid: u32) -> Option<String> {
    None
}

// =============================================================================
// UNIFIED SCANNER FUNCTION
// =============================================================================

/// Scan a process for stack spoofing across all threads
pub async fn scan_process_for_stack_spoofing(pid: u32) -> Result<Vec<StackSpoofingDetection>> {
    let mut detector = StackSpoofingDetector::new();
    detector.scan_process(pid).await
}

/// Scan a specific thread for stack spoofing
pub async fn scan_thread_for_stack_spoofing(
    pid: u32,
    thread_id: u32,
) -> Result<Vec<StackSpoofingDetection>> {
    let mut detector = StackSpoofingDetector::new();
    let process_name = get_process_name(pid).unwrap_or_else(|| format!("pid_{}", pid));
    detector.refresh_module_cache(pid).await?;
    detector.scan_thread(pid, thread_id, &process_name).await
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_technique_metadata() {
        assert_eq!(StackSpoofingTechnique::SpoofStack.mitre_id(), "T1562.001");
        assert_eq!(
            StackSpoofingTechnique::SpoofStack.severity(),
            SpoofingSeverity::Critical
        );
    }

    #[test]
    fn test_confidence_calculation() {
        let suspicious = vec![SuspiciousReturnAddress {
            address: 0x1000,
            frame_index: 0,
            reason: ReturnAddressIssue::InUnbackedMemory,
            module_name: None,
            after_call_instruction: false,
            memory_protection: Some(0x40),
            memory_type: Some("Private".to_string()),
        }];

        let anomalies = vec![FrameAnomaly {
            frame_index: 1,
            frame_base: 0x2000,
            anomaly_type: FrameAnomalyType::ImpossibleFrameSize,
            description: "Test".to_string(),
        }];

        let confidence = calculate_confidence(&suspicious, &anomalies);
        assert!(confidence > 0.5);
        assert!(confidence <= 1.0);
    }

    #[test]
    fn test_detector_creation() {
        let detector = StackSpoofingDetector::new()
            .with_sensitivity(0.8)
            .with_max_frames(32)
            .with_deep_validation(true);

        assert_eq!(detector.sensitivity, 0.8);
        assert_eq!(detector.max_frames, 32);
        assert!(detector.deep_validation);
    }

    #[test]
    fn test_return_address_issue_description() {
        assert_eq!(
            reason_to_string(ReturnAddressIssue::InUnbackedMemory),
            "in unbacked private memory"
        );
        assert_eq!(
            reason_to_string(ReturnAddressIssue::NotExecutable),
            "in non-executable memory"
        );
    }
}
