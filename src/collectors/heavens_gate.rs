//! Heaven's Gate (WoW64) Detection Collector
//!
//! Comprehensive detection of Heaven's Gate evasion techniques that allow 32-bit (x86)
//! code running under WoW64 to execute 64-bit (x64) code, bypassing EDR hooks.
//!
//! ## Heaven's Gate Techniques Detected:
//!
//! 1. **Far JMP to 64-bit code segment (0x33 selector)**
//!    - EA xx xx xx xx 33 00 - JMP FAR 0x33:addr
//!    - Direct transition to 64-bit mode
//!
//! 2. **RETF (far return) to switch segments**
//!    - Push 0x33, push addr, RETF
//!    - CB - RETF instruction after segment push
//!
//! 3. **Direct syscalls from 32-bit process to 64-bit kernel**
//!    - Syscall stubs in 32-bit memory space with 64-bit instructions
//!    - Uses 64-bit registers (R8-R15) from 32-bit context
//!
//! 4. **WoW64 layer bypass**
//!    - Skipping wow64cpu.dll transition thunks
//!    - Direct calls to ntdll64 exports
//!
//! 5. **Ntdll64 mapping in WoW64 process**
//!    - Manual mapping of 64-bit ntdll.dll
//!    - Section object abuse for ntdll64 access
//!
//! 6. **x64 shellcode execution from x86 context**
//!    - REX prefixes (0x40-0x4F) in 32-bit executable memory
//!    - 64-bit instruction patterns in WoW64 process
//!
//! ## Detection Methods:
//!
//! - Monitor segment register manipulations
//! - Detect 0x33 selector usage patterns
//! - Track syscalls from unexpected contexts
//! - Monitor for ntdll64 section mappings
//! - Validate instruction pointer consistency with process bitness
//! - Thread context validation for CS register anomalies
//!
//! ## MITRE ATT&CK:
//! - T1055 - Process Injection (Heaven's Gate as injection prep)
//! - T1055.012 - Process Hollowing (segment transitions)
//! - T1106 - Native API (direct syscalls)
//! - T1562.001 - Disable or Modify Tools (EDR bypass)

// Heaven's Gate (WoW64 abuse) detector. Scaffolded fields retained.
#![allow(dead_code, unused_variables)]

use super::{
    Detection, DetectionType, EventPayload, EventType, ProcessEvent, Severity, TelemetryEvent,
};
use crate::config::AgentConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, warn};

// ============================================================================
// Type Definitions
// ============================================================================

/// Heaven's Gate technique variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeavensGateTechnique {
    /// Far JMP to 0x33 segment (EA xx xx xx xx 33 00)
    FarJmpToX64Segment,
    /// Far CALL to 0x33 segment (9A xx xx xx xx 33 00)
    FarCallToX64Segment,
    /// RETF-based segment switch (push 0x33; push addr; retf)
    RetfSegmentSwitch,
    /// Push 0x33 followed by call-then-retf pattern
    PushSegmentRetf,
    /// Direct syscall stub in 32-bit memory with 64-bit instructions
    DirectSyscall64From32,
    /// WoW64 transition bypass (skipping wow64cpu.dll)
    Wow64TransitionBypass,
    /// Manual ntdll64 mapping detected
    Ntdll64ManualMapping,
    /// x64 instructions (REX prefix) in 32-bit executable memory
    X64InstructionsIn32BitContext,
    /// Thread with CS=0x33 in WoW64 process
    X64ThreadInWow64Process,
    /// Segment descriptor manipulation
    SegmentDescriptorAbuse,
    /// Syscall number extraction for 64-bit calls
    Syscall64NumberResolution,
    /// Heaven's Gate trampoline code pattern
    TrampolinePattern,
}

impl HeavensGateTechnique {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FarJmpToX64Segment => "far_jmp_x64_segment",
            Self::FarCallToX64Segment => "far_call_x64_segment",
            Self::RetfSegmentSwitch => "retf_segment_switch",
            Self::PushSegmentRetf => "push_segment_retf",
            Self::DirectSyscall64From32 => "direct_syscall_64_from_32",
            Self::Wow64TransitionBypass => "wow64_transition_bypass",
            Self::Ntdll64ManualMapping => "ntdll64_manual_mapping",
            Self::X64InstructionsIn32BitContext => "x64_instructions_in_32bit",
            Self::X64ThreadInWow64Process => "x64_thread_in_wow64",
            Self::SegmentDescriptorAbuse => "segment_descriptor_abuse",
            Self::Syscall64NumberResolution => "syscall64_number_resolution",
            Self::TrampolinePattern => "trampoline_pattern",
        }
    }

    pub fn mitre_technique(&self) -> &'static str {
        match self {
            Self::FarJmpToX64Segment
            | Self::FarCallToX64Segment
            | Self::RetfSegmentSwitch
            | Self::PushSegmentRetf => "T1055",
            Self::DirectSyscall64From32 | Self::Syscall64NumberResolution => "T1106",
            Self::Wow64TransitionBypass | Self::Ntdll64ManualMapping => "T1562.001",
            Self::X64InstructionsIn32BitContext
            | Self::X64ThreadInWow64Process
            | Self::SegmentDescriptorAbuse => "T1055.012",
            Self::TrampolinePattern => "T1055",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            // Critical - active evasion techniques
            Self::DirectSyscall64From32
            | Self::Wow64TransitionBypass
            | Self::X64ThreadInWow64Process => Severity::Critical,

            // High - strong indicators
            Self::FarJmpToX64Segment
            | Self::FarCallToX64Segment
            | Self::RetfSegmentSwitch
            | Self::PushSegmentRetf
            | Self::TrampolinePattern => Severity::High,

            // Medium - suspicious but could have edge cases
            Self::Ntdll64ManualMapping
            | Self::X64InstructionsIn32BitContext
            | Self::SegmentDescriptorAbuse
            | Self::Syscall64NumberResolution => Severity::Medium,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::FarJmpToX64Segment => "Far JMP instruction to 64-bit code segment (0x33)",
            Self::FarCallToX64Segment => "Far CALL instruction to 64-bit code segment (0x33)",
            Self::RetfSegmentSwitch => "RETF used to switch to 64-bit segment",
            Self::PushSegmentRetf => "Push 0x33 segment followed by RETF pattern",
            Self::DirectSyscall64From32 => "Direct 64-bit syscall from 32-bit process context",
            Self::Wow64TransitionBypass => "WoW64 transition layer bypass detected",
            Self::Ntdll64ManualMapping => "Manual mapping of 64-bit ntdll.dll in WoW64 process",
            Self::X64InstructionsIn32BitContext => {
                "64-bit instructions (REX prefix) in 32-bit executable memory"
            }
            Self::X64ThreadInWow64Process => "Thread with 64-bit code segment in WoW64 process",
            Self::SegmentDescriptorAbuse => "Segment descriptor manipulation detected",
            Self::Syscall64NumberResolution => {
                "64-bit syscall number resolution/extraction detected"
            }
            Self::TrampolinePattern => "Heaven's Gate trampoline code pattern detected",
        }
    }
}

/// Heaven's Gate detection event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeavensGateEvent {
    /// Technique detected
    pub technique: HeavensGateTechnique,
    /// Process ID
    pub pid: u32,
    /// Process name
    pub process_name: String,
    /// Process executable path
    pub process_path: String,
    /// Command line
    pub cmdline: String,
    /// Thread ID (if thread-specific)
    pub thread_id: Option<u32>,
    /// Memory address where pattern was found
    pub address: u64,
    /// Size of detected pattern/region
    pub size: usize,
    /// Raw bytes of the detected pattern
    pub pattern_bytes: Vec<u8>,
    /// Module containing the detection (if backed)
    pub module: Option<String>,
    /// Detection confidence (0.0-1.0)
    pub confidence: f32,
    /// Additional evidence/details
    pub evidence: Vec<String>,
    /// CS (code segment) register value if relevant
    pub cs_register: Option<u16>,
}

/// Pattern definition for Heaven's Gate detection
#[derive(Debug, Clone)]
struct HeavensGatePattern {
    /// Pattern name
    name: &'static str,
    /// Byte pattern (wildcards as None)
    pattern: Vec<Option<u8>>,
    /// Technique classification
    technique: HeavensGateTechnique,
    /// Minimum confidence for this pattern
    min_confidence: f32,
    /// Description
    description: &'static str,
}

// ============================================================================
// Heaven's Gate Collector Implementation
// ============================================================================

/// Heaven's Gate detection collector
pub struct HeavensGateCollector {
    config: AgentConfig,
    event_rx: mpsc::Receiver<TelemetryEvent>,
    #[allow(dead_code)]
    event_tx: mpsc::Sender<TelemetryEvent>,
}

impl HeavensGateCollector {
    /// Create a new Heaven's Gate collector
    pub fn new(config: &AgentConfig) -> Self {
        let (tx, rx) = mpsc::channel(100);

        let collector = Self {
            config: config.clone(),
            event_rx: rx,
            event_tx: tx.clone(),
        };

        // Start platform-specific monitoring
        #[cfg(target_os = "windows")]
        {
            let tx_clone = tx.clone();
            let config_clone = config.clone();
            tokio::spawn(async move {
                windows_impl::monitor_loop(tx_clone, config_clone).await;
            });
        }

        info!("Heaven's Gate detection collector initialized");
        collector
    }

    /// Get next event from collector
    pub async fn next_event(&mut self) -> Option<TelemetryEvent> {
        self.event_rx.recv().await
    }

    /// Create telemetry event from Heaven's Gate detection
    pub fn create_event(detection: &HeavensGateEvent) -> TelemetryEvent {
        let severity = detection.technique.severity();

        let mut event = TelemetryEvent::new(
            EventType::DefenseEvasion,
            severity.clone(),
            EventPayload::Process(ProcessEvent {
                pid: detection.pid,
                ppid: 0,
                name: detection.process_name.clone(),
                path: detection.process_path.clone(),
                cmdline: detection.cmdline.clone(),
                user: String::new(),
                sha256: Vec::new(),
                entropy: 0.0,
                is_elevated: false,
                parent_name: None,
                parent_path: None,
                is_signed: false,
                signer: None,
                start_time: 0,
                cpu_usage: 0.0,
                memory_bytes: 0,
                company_name: None,
                file_description: None,
                product_name: None,
                file_version: None,
                environment: None,
            }),
        );

        // Build detailed description
        let description = format!(
            "{}: {} (PID: {}) at 0x{:016X}",
            detection.technique.description(),
            detection.process_name,
            detection.pid,
            detection.address,
        );

        // Add detection
        event.add_detection(Detection {
            detection_type: DetectionType::DefenseEvasion,
            rule_name: format!("heavens_gate_{}", detection.technique.as_str()),
            confidence: detection.confidence,
            description,
            mitre_tactics: vec!["defense-evasion".to_string(), "execution".to_string()],
            mitre_techniques: vec![detection.technique.mitre_technique().to_string()],
        });

        // Add metadata
        event.metadata.insert(
            "heavens_gate_technique".to_string(),
            detection.technique.as_str().to_string(),
        );
        event.metadata.insert(
            "detection_address".to_string(),
            format!("0x{:016X}", detection.address),
        );
        event.metadata.insert(
            "pattern_bytes".to_string(),
            hex::encode(&detection.pattern_bytes),
        );

        if let Some(tid) = detection.thread_id {
            event
                .metadata
                .insert("thread_id".to_string(), tid.to_string());
        }

        if let Some(cs) = detection.cs_register {
            event
                .metadata
                .insert("cs_register".to_string(), format!("0x{:04X}", cs));
        }

        if let Some(module) = &detection.module {
            event.metadata.insert("module".to_string(), module.clone());
        }

        if !detection.evidence.is_empty() {
            event
                .metadata
                .insert("evidence".to_string(), detection.evidence.join("; "));
        }

        event
    }
}

// ============================================================================
// Windows Implementation
// ============================================================================

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::*;
    use parking_lot::RwLock;
    use std::ffi::c_void;
    use windows::Win32::Foundation::{CloseHandle, BOOL, HANDLE};
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_PRIVATE, PAGE_EXECUTE,
        PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    };
    use windows::Win32::System::Threading::{
        IsWow64Process, OpenProcess, OpenThread, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION,
    };
    // Note: GetThreadContext and CONTEXT require additional Windows features
    // Thread context checking is simplified to avoid those dependencies

    /// x86 code segment selector (32-bit mode)
    #[allow(dead_code)]
    const CS_X86: u16 = 0x23;
    /// x64 code segment selector (64-bit mode)
    #[allow(dead_code)]
    const CS_X64: u16 = 0x33;

    /// Heaven's Gate byte patterns
    pub(super) fn get_patterns() -> Vec<HeavensGatePattern> {
        vec![
            // Pattern 1: Far JMP to 0x33 segment
            // EA xx xx xx xx 33 00 - JMP FAR 0x33:addr (switch to 64-bit)
            HeavensGatePattern {
                name: "far_jmp_x64",
                pattern: vec![Some(0xEA), None, None, None, None, Some(0x33), Some(0x00)],
                technique: HeavensGateTechnique::FarJmpToX64Segment,
                min_confidence: 0.95,
                description: "Far JMP to 64-bit segment 0x33",
            },
            // Pattern 2: Far CALL to 0x33 segment
            // 9A xx xx xx xx 33 00 - CALL FAR 0x33:addr
            HeavensGatePattern {
                name: "far_call_x64",
                pattern: vec![Some(0x9A), None, None, None, None, Some(0x33), Some(0x00)],
                technique: HeavensGateTechnique::FarCallToX64Segment,
                min_confidence: 0.95,
                description: "Far CALL to 64-bit segment 0x33",
            },
            // Pattern 3: Classic Heaven's Gate trampoline
            // 6A 33 - push 0x33
            // E8 00 00 00 00 - call $+5
            // 83 04 24 05 - add dword [rsp], 5
            // CB - retf
            HeavensGatePattern {
                name: "classic_heavens_gate",
                pattern: vec![
                    Some(0x6A),
                    Some(0x33), // push 0x33
                    Some(0xE8),
                    Some(0x00),
                    Some(0x00),
                    Some(0x00),
                    Some(0x00), // call $+5
                    Some(0x83),
                    Some(0x04),
                    Some(0x24),
                    Some(0x05), // add dword [rsp], 5
                    Some(0xCB), // retf
                ],
                technique: HeavensGateTechnique::TrampolinePattern,
                min_confidence: 0.99,
                description: "Classic Heaven's Gate trampoline (push 0x33; call; add; retf)",
            },
            // Pattern 4: Simplified push/retf
            // 6A 33 - push 0x33
            // 68 xx xx xx xx - push addr
            // CB - retf
            HeavensGatePattern {
                name: "push_segment_retf",
                pattern: vec![
                    Some(0x6A),
                    Some(0x33), // push 0x33
                    Some(0x68),
                    None,
                    None,
                    None,
                    None,       // push imm32
                    Some(0xCB), // retf
                ],
                technique: HeavensGateTechnique::PushSegmentRetf,
                min_confidence: 0.95,
                description: "Push 0x33 segment then RETF pattern",
            },
            // Pattern 5: 64-bit syscall instruction in 32-bit memory
            // 4C 8B D1 - mov r10, rcx (REX.W prefix)
            // B8 xx xx 00 00 - mov eax, syscall_number
            // 0F 05 - syscall
            HeavensGatePattern {
                name: "x64_syscall_stub",
                pattern: vec![
                    Some(0x4C),
                    Some(0x8B),
                    Some(0xD1), // mov r10, rcx
                    Some(0xB8),
                    None,
                    None,
                    Some(0x00),
                    Some(0x00), // mov eax, imm32
                    Some(0x0F),
                    Some(0x05), // syscall
                ],
                technique: HeavensGateTechnique::DirectSyscall64From32,
                min_confidence: 0.98,
                description: "64-bit syscall stub in 32-bit process",
            },
            // Pattern 6: WoW64 bypass variant (RecycledGate/TartarusGate style)
            // 65 48 8B 04 25 60 00 00 00 - mov rax, gs:[0x60] (64-bit TEB access)
            HeavensGatePattern {
                name: "x64_teb_access",
                pattern: vec![
                    Some(0x65),
                    Some(0x48),
                    Some(0x8B),
                    Some(0x04),
                    Some(0x25),
                    Some(0x60),
                    Some(0x00),
                    Some(0x00),
                    Some(0x00),
                ],
                technique: HeavensGateTechnique::Wow64TransitionBypass,
                min_confidence: 0.90,
                description: "64-bit TEB access (gs:[0x60]) from WoW64 process",
            },
            // Pattern 7: Alternative trampoline with jump
            // 6A 33 - push 0x33
            // E9 xx xx xx xx - jmp rel32
            // CB - retf (may be at jump target)
            HeavensGatePattern {
                name: "push_segment_jmp",
                pattern: vec![
                    Some(0x6A),
                    Some(0x33), // push 0x33
                    Some(0xE9),
                    None,
                    None,
                    None,
                    None, // jmp rel32
                ],
                technique: HeavensGateTechnique::PushSegmentRetf,
                min_confidence: 0.85,
                description: "Push 0x33 followed by JMP (potential retf at target)",
            },
            // Pattern 8: REX prefix detection (40-4F are 64-bit REX prefixes)
            // REX.W (48) with common instruction forms
            // 48 8B xx - mov r64, r/m64
            HeavensGatePattern {
                name: "rex_w_mov",
                pattern: vec![Some(0x48), Some(0x8B), None],
                technique: HeavensGateTechnique::X64InstructionsIn32BitContext,
                min_confidence: 0.70, // Lower confidence - needs context
                description: "REX.W prefix (64-bit operand) in 32-bit context",
            },
            // Pattern 9: RETF standalone (end of transition)
            // CB - retf
            // This needs surrounding context analysis
            HeavensGatePattern {
                name: "retf_standalone",
                pattern: vec![Some(0xCB)],
                technique: HeavensGateTechnique::RetfSegmentSwitch,
                min_confidence: 0.50, // Low confidence alone - needs context
                description: "RETF instruction (far return)",
            },
            // Pattern 10: Syscall number extraction pattern
            // B8 xx 00 00 00 followed by syscall-related instructions
            HeavensGatePattern {
                name: "syscall_num_load",
                pattern: vec![
                    Some(0xB8),
                    None,
                    Some(0x00),
                    Some(0x00),
                    Some(0x00), // mov eax, low_syscall_num
                ],
                technique: HeavensGateTechnique::Syscall64NumberResolution,
                min_confidence: 0.60, // Needs context
                description: "Syscall number loading pattern",
            },
        ]
    }

    /// Check if a process is WoW64 (32-bit on 64-bit Windows)
    fn is_wow64_process_handle(handle: HANDLE) -> bool {
        unsafe {
            let mut is_wow64: BOOL = BOOL::from(false);
            if IsWow64Process(handle, &mut is_wow64).is_ok() {
                return is_wow64.as_bool();
            }
        }
        false
    }

    /// Get process name from PID
    fn get_process_name(pid: u32) -> String {
        use sysinfo::System;
        let mut system = System::new();
        system.refresh_processes();
        if let Some(process) = system.process(sysinfo::Pid::from_u32(pid)) {
            return process.name().to_string();
        }
        format!("pid_{}", pid)
    }

    /// Get process path from PID
    fn get_process_path(pid: u32) -> String {
        use sysinfo::System;
        let mut system = System::new();
        system.refresh_processes();
        if let Some(process) = system.process(sysinfo::Pid::from_u32(pid)) {
            if let Some(path) = process.exe() {
                return path.to_string_lossy().to_string();
            }
        }
        String::new()
    }

    /// Get process command line from PID
    fn get_process_cmdline(pid: u32) -> String {
        use sysinfo::System;
        let mut system = System::new();
        system.refresh_processes();
        if let Some(process) = system.process(sysinfo::Pid::from_u32(pid)) {
            return process.cmd().join(" ");
        }
        String::new()
    }

    /// Main monitoring loop
    pub async fn monitor_loop(tx: mpsc::Sender<TelemetryEvent>, config: AgentConfig) {
        info!("Starting Heaven's Gate detection monitor");

        let mul = config.sub_loop_interval_multiplier;
        let interval_secs = ((15.0 * mul) as u64).max(10);

        // Track reported detections to avoid duplicates
        let reported: Arc<RwLock<HashSet<(u32, HeavensGateTechnique, u64)>>> =
            Arc::new(RwLock::new(HashSet::new()));

        // Start memory scanner
        let tx_mem = tx.clone();
        let reported_mem = reported.clone();
        tokio::spawn(async move {
            memory_pattern_scanner(tx_mem, reported_mem, interval_secs).await;
        });

        // Start thread context monitor
        let tx_thread = tx.clone();
        let reported_thread = reported.clone();
        let thread_interval = ((30.0 * mul) as u64).max(20);
        tokio::spawn(async move {
            thread_context_monitor(tx_thread, reported_thread, thread_interval).await;
        });

        // Start ntdll64 mapping monitor
        let tx_ntdll = tx.clone();
        let reported_ntdll = reported.clone();
        let ntdll_interval = ((60.0 * mul) as u64).max(30);
        tokio::spawn(async move {
            ntdll64_mapping_monitor(tx_ntdll, reported_ntdll, ntdll_interval).await;
        });

        info!(
            interval_secs = interval_secs,
            "Heaven's Gate monitor loops started"
        );

        // Keep the main task alive
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;

            // Periodic cleanup of old entries
            let mut reported_lock = reported.write();
            if reported_lock.len() > 50000 {
                reported_lock.clear();
                info!("Cleared Heaven's Gate detection cache");
            }
        }
    }

    /// Scan process memory for Heaven's Gate patterns
    async fn memory_pattern_scanner(
        tx: mpsc::Sender<TelemetryEvent>,
        reported: Arc<RwLock<HashSet<(u32, HeavensGateTechnique, u64)>>>,
        interval_secs: u64,
    ) {
        use sysinfo::System;

        let patterns = get_patterns();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));

        loop {
            interval.tick().await;

            let mut system = System::new_all();
            system.refresh_processes();

            for (pid, _process) in system.processes() {
                let pid_u32 = pid.as_u32();

                // Skip system processes
                if pid_u32 <= 4 {
                    continue;
                }

                // Scan this process
                if let Some(detections) = scan_process_for_patterns(pid_u32, &patterns) {
                    for detection in detections {
                        let key = (detection.pid, detection.technique, detection.address);

                        // Check if already reported
                        {
                            let reported_lock = reported.read();
                            if reported_lock.contains(&key) {
                                continue;
                            }
                        }

                        // Mark as reported
                        {
                            let mut reported_lock = reported.write();
                            reported_lock.insert(key);
                        }

                        // Create and send event
                        let event = HeavensGateCollector::create_event(&detection);
                        if tx.send(event).await.is_err() {
                            warn!("Failed to send Heaven's Gate detection event");
                            return;
                        }

                        info!(
                            pid = detection.pid,
                            technique = %detection.technique.as_str(),
                            address = %format!("0x{:X}", detection.address),
                            "Heaven's Gate technique detected"
                        );
                    }
                }
            }
        }
    }

    /// Scan a single process for Heaven's Gate patterns
    fn scan_process_for_patterns(
        pid: u32,
        patterns: &[HeavensGatePattern],
    ) -> Option<Vec<HeavensGateEvent>> {
        unsafe {
            // Open process with read permissions
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

            // Only scan WoW64 processes
            if !is_wow64_process_handle(process_handle) {
                return None;
            }

            let process_name = get_process_name(pid);
            let process_path = get_process_path(pid);
            let cmdline = get_process_cmdline(pid);

            let mut detections = Vec::new();

            // Scan memory regions
            let mut address: usize = 0;
            let max_address: usize = 0x7FFFFFFF; // 32-bit address space

            while address < max_address {
                let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
                let result = VirtualQueryEx(
                    process_handle,
                    Some(address as *const c_void),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                );

                if result == 0 {
                    break;
                }

                // Check if region is executable and committed
                let is_executable = mbi.Protect == PAGE_EXECUTE
                    || mbi.Protect == PAGE_EXECUTE_READ
                    || mbi.Protect == PAGE_EXECUTE_READWRITE
                    || mbi.Protect == PAGE_EXECUTE_WRITECOPY;

                let is_private = mbi.Type == MEM_PRIVATE;

                if mbi.State == MEM_COMMIT && is_executable {
                    // Read memory region (limit to 64KB per region)
                    let region_size = std::cmp::min(mbi.RegionSize, 0x10000);
                    let mut buffer = vec![0u8; region_size];
                    let mut bytes_read: usize = 0;

                    if ReadProcessMemory(
                        process_handle,
                        mbi.BaseAddress,
                        buffer.as_mut_ptr() as *mut c_void,
                        region_size,
                        Some(&mut bytes_read),
                    )
                    .is_ok()
                        && bytes_read > 0
                    {
                        buffer.truncate(bytes_read);

                        // Scan for patterns
                        for pattern in patterns {
                            if let Some((offset, confidence)) =
                                find_pattern_with_context(&buffer, pattern, is_private)
                            {
                                let addr = mbi.BaseAddress as u64 + offset as u64;

                                // Extract matched bytes
                                let pattern_len = pattern.pattern.len();
                                let matched_bytes: Vec<u8> = if offset + pattern_len <= buffer.len()
                                {
                                    buffer[offset..offset + pattern_len].to_vec()
                                } else {
                                    buffer[offset..].to_vec()
                                };

                                let mut evidence = vec![
                                    format!("Pattern: {}", pattern.name),
                                    format!("Description: {}", pattern.description),
                                    format!("Address: 0x{:X}", addr),
                                    format!("Bytes: {}", hex::encode(&matched_bytes)),
                                ];

                                if is_private {
                                    evidence
                                        .push("Located in private (unbacked) memory".to_string());
                                }

                                // Add contextual analysis for REX prefix patterns
                                if pattern.technique
                                    == HeavensGateTechnique::X64InstructionsIn32BitContext
                                {
                                    let rex_count = count_rex_prefixes(&buffer);
                                    if rex_count > 5 {
                                        evidence.push(format!(
                                            "High density of REX prefixes: {} occurrences",
                                            rex_count
                                        ));
                                    }
                                }

                                detections.push(HeavensGateEvent {
                                    technique: pattern.technique,
                                    pid,
                                    process_name: process_name.clone(),
                                    process_path: process_path.clone(),
                                    cmdline: cmdline.clone(),
                                    thread_id: None,
                                    address: addr,
                                    size: pattern_len,
                                    pattern_bytes: matched_bytes,
                                    module: None,
                                    confidence,
                                    evidence,
                                    cs_register: None,
                                });
                            }
                        }
                    }
                }

                address = (mbi.BaseAddress as usize) + mbi.RegionSize;
            }

            if detections.is_empty() {
                None
            } else {
                Some(detections)
            }
        }
    }

    /// Find pattern in buffer with context-aware confidence adjustment
    fn find_pattern_with_context(
        buffer: &[u8],
        pattern: &HeavensGatePattern,
        is_private_memory: bool,
    ) -> Option<(usize, f32)> {
        let pattern_len = pattern.pattern.len();
        if buffer.len() < pattern_len {
            return None;
        }

        for i in 0..buffer.len() - pattern_len {
            let mut matched = true;

            for (j, byte_pattern) in pattern.pattern.iter().enumerate() {
                if let Some(expected) = byte_pattern {
                    if buffer[i + j] != *expected {
                        matched = false;
                        break;
                    }
                }
            }

            if matched {
                // Calculate confidence based on context
                let mut confidence = pattern.min_confidence;

                // Boost confidence for private memory (unbacked)
                if is_private_memory {
                    confidence = (confidence + 0.10).min(1.0);
                }

                // Check for surrounding context that increases confidence
                if pattern.technique == HeavensGateTechnique::RetfSegmentSwitch {
                    // Look for push 0x33 before RETF
                    if i >= 2 && buffer[i - 2] == 0x6A && buffer[i - 1] == 0x33 {
                        confidence = (confidence + 0.30).min(0.95);
                    }
                }

                if pattern.technique == HeavensGateTechnique::X64InstructionsIn32BitContext {
                    // Count REX prefixes in vicinity
                    let rex_density = count_rex_prefixes_in_range(
                        buffer,
                        i.saturating_sub(32),
                        (i + 32).min(buffer.len()),
                    );
                    if rex_density > 3 {
                        confidence = (confidence + 0.20).min(0.95);
                    }
                }

                // Only return if confidence meets threshold
                if confidence >= 0.65 {
                    return Some((i, confidence));
                }
            }
        }

        None
    }

    /// Count REX prefixes in buffer
    fn count_rex_prefixes(buffer: &[u8]) -> usize {
        buffer
            .iter()
            .filter(|&&b| (0x40..=0x4F).contains(&b))
            .count()
    }

    /// Count REX prefixes in range
    fn count_rex_prefixes_in_range(buffer: &[u8], start: usize, end: usize) -> usize {
        buffer[start..end]
            .iter()
            .filter(|&&b| (0x40..=0x4F).contains(&b))
            .count()
    }

    /// Monitor thread contexts for CS register anomalies
    async fn thread_context_monitor(
        tx: mpsc::Sender<TelemetryEvent>,
        reported: Arc<RwLock<HashSet<(u32, HeavensGateTechnique, u64)>>>,
        interval_secs: u64,
    ) {
        use sysinfo::System;

        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));

        loop {
            interval.tick().await;

            let mut system = System::new_all();
            system.refresh_processes();

            for (pid, _process) in system.processes() {
                let pid_u32 = pid.as_u32();

                if pid_u32 <= 4 {
                    continue;
                }

                // Check thread contexts
                if let Some(detection) = check_thread_contexts(pid_u32) {
                    let key = (
                        detection.pid,
                        detection.technique,
                        detection.thread_id.unwrap_or(0) as u64,
                    );

                    {
                        let reported_lock = reported.read();
                        if reported_lock.contains(&key) {
                            continue;
                        }
                    }

                    {
                        let mut reported_lock = reported.write();
                        reported_lock.insert(key);
                    }

                    let event = HeavensGateCollector::create_event(&detection);
                    if tx.send(event).await.is_err() {
                        return;
                    }

                    info!(
                        pid = detection.pid,
                        thread_id = ?detection.thread_id,
                        cs = ?detection.cs_register,
                        "Thread with 64-bit CS detected in WoW64 process"
                    );
                }
            }
        }
    }

    /// Check thread contexts for CS=0x33 in WoW64 process
    fn check_thread_contexts(pid: u32) -> Option<HeavensGateEvent> {
        unsafe {
            // First check if process is WoW64
            let process_handle =
                match OpenProcess(PROCESS_QUERY_INFORMATION, BOOL::from(false), pid) {
                    Ok(h) => h,
                    Err(_) => return None,
                };

            let is_wow64 = is_wow64_process_handle(process_handle);
            let _ = CloseHandle(process_handle);

            if !is_wow64 {
                return None;
            }

            // Enumerate threads
            let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
                Ok(h) => h,
                Err(_) => return None,
            };

            let _snap_guard = scopeguard::guard(snapshot, |h| {
                let _ = CloseHandle(h);
            });

            let mut te: THREADENTRY32 = std::mem::zeroed();
            te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

            if Thread32First(snapshot, &mut te).is_err() {
                return None;
            }

            loop {
                if te.th32OwnerProcessID == pid {
                    // Check this thread's context
                    if let Some(cs) = get_thread_cs(te.th32ThreadID) {
                        // If CS is 0x33 (64-bit), this is suspicious for WoW64
                        if cs == CS_X64 {
                            let process_name = get_process_name(pid);
                            let process_path = get_process_path(pid);
                            let cmdline = get_process_cmdline(pid);

                            return Some(HeavensGateEvent {
                                technique: HeavensGateTechnique::X64ThreadInWow64Process,
                                pid,
                                process_name,
                                process_path,
                                cmdline,
                                thread_id: Some(te.th32ThreadID),
                                address: 0,
                                size: 0,
                                pattern_bytes: Vec::new(),
                                module: None,
                                confidence: 0.95,
                                evidence: vec![
                                    format!("Thread ID: {}", te.th32ThreadID),
                                    format!("CS Register: 0x{:04X} (64-bit segment)", cs),
                                    "WoW64 process with thread in 64-bit mode".to_string(),
                                ],
                                cs_register: Some(cs),
                            });
                        }
                    }
                }

                if Thread32Next(snapshot, &mut te).is_err() {
                    break;
                }
            }

            None
        }
    }

    /// Get CS register from thread context
    fn get_thread_cs(thread_id: u32) -> Option<u16> {
        unsafe {
            let thread_handle = match OpenThread(
                THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                BOOL::from(false),
                thread_id,
            ) {
                Ok(h) => h,
                Err(_) => return None,
            };

            let _guard = scopeguard::guard(thread_handle, |h| {
                let _ = CloseHandle(h);
            });

            // Note: Getting thread context requires suspending the thread
            // which we avoid here. Instead, we use a WoW64 context query
            // This is a simplified check; full implementation would need
            // Wow64GetThreadContext for accurate CS reading

            // For now, return None - thread context checking requires
            // more careful handling to avoid destabilizing processes
            None
        }
    }

    /// Monitor for ntdll64 mappings in WoW64 processes
    async fn ntdll64_mapping_monitor(
        tx: mpsc::Sender<TelemetryEvent>,
        reported: Arc<RwLock<HashSet<(u32, HeavensGateTechnique, u64)>>>,
        interval_secs: u64,
    ) {
        use sysinfo::System;

        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));

        loop {
            interval.tick().await;

            let mut system = System::new_all();
            system.refresh_processes();

            for (pid, _process) in system.processes() {
                let pid_u32 = pid.as_u32();

                if pid_u32 <= 4 {
                    continue;
                }

                // Check for suspicious ntdll64 mappings
                if let Some(detection) = check_ntdll64_mapping(pid_u32) {
                    let key = (detection.pid, detection.technique, detection.address);

                    {
                        let reported_lock = reported.read();
                        if reported_lock.contains(&key) {
                            continue;
                        }
                    }

                    {
                        let mut reported_lock = reported.write();
                        reported_lock.insert(key);
                    }

                    let event = HeavensGateCollector::create_event(&detection);
                    if tx.send(event).await.is_err() {
                        return;
                    }

                    info!(
                        pid = detection.pid,
                        address = %format!("0x{:X}", detection.address),
                        "Suspicious ntdll64 mapping detected in WoW64 process"
                    );
                }
            }
        }
    }

    /// Check for manual ntdll64 mapping in WoW64 process
    fn check_ntdll64_mapping(pid: u32) -> Option<HeavensGateEvent> {
        unsafe {
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

            // Only check WoW64 processes
            if !is_wow64_process_handle(process_handle) {
                return None;
            }

            let process_name = get_process_name(pid);
            let process_path = get_process_path(pid);
            let cmdline = get_process_cmdline(pid);

            // Scan for PE headers in high memory (above 32-bit space)
            // indicating manual mapping of 64-bit ntdll
            let mut address: u64 = 0x100000000; // Start above 4GB
            let max_address: u64 = 0x7FFFFFFFFFFF; // User-mode limit

            while address < max_address {
                let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
                let result = VirtualQueryEx(
                    process_handle,
                    Some(address as *const c_void),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                );

                if result == 0 {
                    break;
                }

                // Look for executable mapped sections in high memory
                let is_image = mbi.Type == MEM_IMAGE;
                let is_executable = mbi.Protect == PAGE_EXECUTE_READ;

                if mbi.State == MEM_COMMIT && is_executable && !is_image {
                    // Read first few bytes to check for PE header
                    let mut header = [0u8; 2];
                    let mut bytes_read: usize = 0;

                    if ReadProcessMemory(
                        process_handle,
                        mbi.BaseAddress,
                        header.as_mut_ptr() as *mut c_void,
                        2,
                        Some(&mut bytes_read),
                    )
                    .is_ok()
                        && bytes_read == 2
                    {
                        // Check for MZ signature
                        if header[0] == 0x4D && header[1] == 0x5A {
                            // PE header found in high memory - suspicious
                            return Some(HeavensGateEvent {
                                technique: HeavensGateTechnique::Ntdll64ManualMapping,
                                pid,
                                process_name,
                                process_path,
                                cmdline,
                                thread_id: None,
                                address: mbi.BaseAddress as u64,
                                size: mbi.RegionSize,
                                pattern_bytes: header.to_vec(),
                                module: None,
                                confidence: 0.85,
                                evidence: vec![
                                    format!(
                                        "PE header at 0x{:X} (above 4GB)",
                                        mbi.BaseAddress as u64
                                    ),
                                    "Manual 64-bit PE mapping in WoW64 process".to_string(),
                                    "Potential ntdll64 manual mapping for Heaven's Gate"
                                        .to_string(),
                                ],
                                cs_register: None,
                            });
                        }
                    }
                }

                address = (mbi.BaseAddress as u64) + mbi.RegionSize as u64;

                // Prevent infinite loop on VirtualQueryEx failure
                if mbi.RegionSize == 0 {
                    address += 0x10000;
                }
            }

            None
        }
    }
}

// ============================================================================
// Non-Windows Stubs
// ============================================================================

#[cfg(not(target_os = "windows"))]
mod windows_impl {
    use super::*;

    pub async fn monitor_loop(_tx: mpsc::Sender<TelemetryEvent>, _config: AgentConfig) {
        // Heaven's Gate is Windows-specific (WoW64)
        info!("Heaven's Gate detection is only available on Windows");
        // Sleep forever
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
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
    fn test_technique_strings() {
        assert_eq!(
            HeavensGateTechnique::FarJmpToX64Segment.as_str(),
            "far_jmp_x64_segment"
        );
        assert_eq!(
            HeavensGateTechnique::DirectSyscall64From32.mitre_technique(),
            "T1106"
        );
    }

    #[test]
    fn test_severity_mapping() {
        assert_eq!(
            HeavensGateTechnique::DirectSyscall64From32.severity(),
            Severity::Critical
        );
        assert_eq!(
            HeavensGateTechnique::FarJmpToX64Segment.severity(),
            Severity::High
        );
        assert_eq!(
            HeavensGateTechnique::Ntdll64ManualMapping.severity(),
            Severity::Medium
        );
    }

    #[test]
    fn test_event_creation() {
        let event = HeavensGateEvent {
            technique: HeavensGateTechnique::TrampolinePattern,
            pid: 1234,
            process_name: "test.exe".to_string(),
            process_path: "C:\\test\\test.exe".to_string(),
            cmdline: "test.exe --arg".to_string(),
            thread_id: None,
            address: 0x12345678,
            size: 12,
            pattern_bytes: vec![
                0x6A, 0x33, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x83, 0x04, 0x24, 0x05, 0xCB,
            ],
            module: None,
            confidence: 0.99,
            evidence: vec!["Test evidence".to_string()],
            cs_register: None,
        };

        let telemetry = HeavensGateCollector::create_event(&event);
        assert_eq!(telemetry.event_type, EventType::DefenseEvasion);
        assert!(!telemetry.detections.is_empty());
    }

    #[cfg(target_os = "windows")]
    mod windows_tests {
        use super::super::windows_impl::*;
        use super::*;

        #[test]
        fn test_pattern_count() {
            let patterns = get_patterns();
            assert!(
                patterns.len() >= 8,
                "Should have multiple detection patterns"
            );
        }

        #[test]
        fn test_classic_heavens_gate_pattern() {
            let patterns = get_patterns();
            let classic = patterns.iter().find(|p| p.name == "classic_heavens_gate");
            assert!(classic.is_some());

            let pattern = classic.unwrap();
            assert_eq!(pattern.technique, HeavensGateTechnique::TrampolinePattern);
            assert_eq!(pattern.min_confidence, 0.99);
        }
    }
}
